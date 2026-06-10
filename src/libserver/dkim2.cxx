/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * DKIM2 verification, see draft-ietf-dkim-dkim2-spec.
 *
 * Unlike DKIM (RFC 6376), a DKIM2 signature covers only the Message-Instance
 * and DKIM2-Signature header fields; the message content is bound indirectly
 * via the hashes in the Message-Instance h= tag. Therefore all hop signatures
 * can be verified cryptographically even if the message was modified in
 * transit; only the hashes of the *current* instance are checked against the
 * message itself. Reconstruction of previous instances from r= recipes is not
 * implemented in this draft.
 */

#include "config.h"
#include "rspamd.h"
#include "message.h"
#include "dns.h"
#include "dkim.h"
#include "dkim2.h"
#include "dkim2.hxx"
#include "utlist.h"
#include "libutil/cxx/util.hxx"

#include "contrib/ankerl/unordered_dense.h"
#include "contrib/fmt/include/fmt/core.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#define msg_err_dkim2(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,              \
													   "dkim2", task->task_pool->tag.uid, \
													   RSPAMD_LOG_FUNC,                   \
													   __VA_ARGS__)
#define msg_info_dkim2(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,                  \
														"dkim2", task->task_pool->tag.uid, \
														RSPAMD_LOG_FUNC,                   \
														__VA_ARGS__)
#define msg_debug_dkim2(...) rspamd_conditional_debug_fast(NULL, NULL,                   \
														   rspamd_dkim2_log_id, "dkim2", \
														   task->task_pool->tag.uid,     \
														   RSPAMD_LOG_FUNC,              \
														   __VA_ARGS__)

INIT_LOG_MODULE(dkim2)

#define DKIM2_ERROR dkim2_error_quark()
static GQuark
dkim2_error_quark(void)
{
	return g_quark_from_static_string("dkim2-error-quark");
}

namespace rspamd::dkim2 {

constexpr std::string_view sha256_alg_name = "sha256";
constexpr std::string_view rsa_alg_name = "rsa-sha256";
constexpr std::string_view ed25519_alg_name = "ed25519-sha256";

static auto
trim(std::string_view in) -> std::string_view
{
	/* Values are unfolded by the caller, g_ascii_isspace covers CR/LF remnants */
	while (!in.empty() && g_ascii_isspace(in.front())) {
		in.remove_prefix(1);
	}
	while (!in.empty() && g_ascii_isspace(in.back())) {
		in.remove_suffix(1);
	}

	return in;
}

static auto
strip_wsp(std::string_view in) -> std::string
{
	std::string out;
	out.reserve(in.size());

	for (auto c: in) {
		if (!g_ascii_isspace(c)) {
			out.push_back(c);
		}
	}

	return out;
}

static auto
lc_string(std::string_view in) -> std::string
{
	std::string out{in};
	rspamd_str_lc(out.data(), out.size());

	return out;
}

static auto
eq_icase(std::string_view a, std::string_view b) -> bool
{
	return a.size() == b.size() &&
		   rspamd_lc_cmp(a.data(), b.data(), a.size()) == 0;
}

static auto
parse_uint(std::string_view in) -> std::optional<unsigned long>
{
	gulong res;

	if (!rspamd_strtoul(in.data(), in.size(), &res)) {
		return std::nullopt;
	}

	return res;
}

static auto
b64_decode(std::string_view in) -> std::optional<std::string>
{
	/* rspamd_cryptobox_base64_decode skips whitespace internally */
	std::string out;
	out.resize(in.size() / 4 * 3 + 3);
	std::size_t outlen = out.size();

	in = trim(in);

	if (!in.empty() &&
		!rspamd_cryptobox_base64_decode(in.data(), in.size(),
										reinterpret_cast<unsigned char *>(out.data()), &outlen)) {
		return std::nullopt;
	}

	out.resize(in.empty() ? 0 : outlen);

	return out;
}

auto parse_tag_list(std::string_view input) -> tl::expected<std::vector<tag_t>, std::string>
{
	std::vector<tag_t> res;
	std::string err;

	rspamd::string_foreach_delim(input, ";", [&](std::string_view seg) {
		if (!err.empty()) {
			return;
		}

		seg = trim(seg);

		if (seg.empty()) {
			/* Empty segment, e.g. a trailing `;` */
			return;
		}

		auto eq_pos = seg.find('=');

		if (eq_pos == std::string_view::npos || eq_pos == 0) {
			err = fmt::format("invalid tag: '{}'", seg);
			return;
		}

		auto name = trim(seg.substr(0, eq_pos));
		auto value = trim(seg.substr(eq_pos + 1));

		for (auto c: name) {
			if (!g_ascii_isalnum(c) && c != '-') {
				err = fmt::format("invalid tag name: '{}'", name);
				return;
			}
		}

		res.emplace_back(tag_t{name, value});
	});

	if (!err.empty()) {
		return tl::make_unexpected(std::move(err));
	}

	return res;
}

static auto
parse_hash_sets(std::string_view value) -> tl::expected<std::vector<hash_set_t>, std::string>
{
	std::vector<hash_set_t> res;
	std::string err;

	rspamd::string_foreach_delim(value, ",", [&](std::string_view set_str) {
		if (!err.empty()) {
			return;
		}

		/* hash-set = hash-name ":" header-hash ":" body-hash */
		std::vector<std::string_view> parts;
		rspamd::string_foreach_delim(
			set_str, ":", [&](std::string_view part) {
				parts.push_back(part);
			},
			false);

		if (parts.size() != 3) {
			err = fmt::format("invalid hash-set: '{}'", set_str);
			return;
		}

		auto hh = b64_decode(parts[1]);
		auto bh = b64_decode(parts[2]);

		if (!hh || !bh || hh->empty() || bh->empty()) {
			err = fmt::format("invalid base64 in hash-set: '{}'", set_str);
			return;
		}

		res.emplace_back(hash_set_t{
			std::string{trim(parts[0])},
			std::move(*hh),
			std::move(*bh),
		});
	});

	if (!err.empty()) {
		return tl::make_unexpected(std::move(err));
	}

	if (res.empty()) {
		return tl::make_unexpected(std::string{"empty h= tag"});
	}

	return res;
}

auto parse_mi(std::string_view value) -> tl::expected<mi_header_t, std::string>
{
	auto tags = parse_tag_list(value);

	if (!tags) {
		return tl::make_unexpected(tags.error());
	}

	mi_header_t res;
	bool seen_m = false, seen_h = false;

	for (const auto &tag: *tags) {
		if (tag.name == "m") {
			if (seen_m) {
				return tl::make_unexpected(std::string{"duplicate m= tag"});
			}
			auto m = parse_uint(tag.value);
			if (!m || *m == 0 || *m > RSPAMD_DKIM2_MAX_HOPS) {
				return tl::make_unexpected(fmt::format("invalid m= tag: '{}'", tag.value));
			}
			res.m = *m;
			seen_m = true;
		}
		else if (tag.name == "h") {
			if (seen_h) {
				return tl::make_unexpected(std::string{"duplicate h= tag"});
			}
			auto hashes = parse_hash_sets(tag.value);
			if (!hashes) {
				return tl::make_unexpected(hashes.error());
			}
			res.hashes = std::move(*hashes);
			seen_h = true;
		}
		else if (tag.name == "r") {
			res.has_recipe = true;
			res.recipe_b64 = strip_wsp(tag.value);
		}
		/* Unknown tags are ignored, but covered by the signature input */
	}

	if (!seen_m) {
		return tl::make_unexpected(std::string{"missing mandatory m= tag"});
	}
	if (!seen_h) {
		return tl::make_unexpected(std::string{"missing mandatory h= tag"});
	}

	return res;
}

static auto
parse_sig_sets(std::string_view value) -> tl::expected<std::vector<sig_set_t>, std::string>
{
	std::vector<sig_set_t> res;
	std::string err;

	rspamd::string_foreach_delim(value, ",", [&](std::string_view set_str) {
		if (!err.empty()) {
			return;
		}

		/* sig-set = selector ":" sig-name ":" message-sig */
		std::vector<std::string_view> parts;
		rspamd::string_foreach_delim(
			set_str, ":", [&](std::string_view part) {
				parts.push_back(part);
			},
			false);

		if (parts.size() != 3) {
			err = fmt::format("invalid sig-set: '{}'", set_str);
			return;
		}

		auto selector = trim(parts[0]);
		auto alg = trim(parts[1]);
		auto sig = b64_decode(parts[2]);

		if (selector.empty() || alg.empty()) {
			err = fmt::format("invalid sig-set: '{}'", set_str);
			return;
		}

		if (!sig || sig->empty()) {
			err = fmt::format("invalid base64 signature in sig-set for selector '{}'",
							  selector);
			return;
		}

		res.emplace_back(sig_set_t{
			std::string{selector},
			std::string{alg},
			std::move(*sig),
		});
	});

	if (!err.empty()) {
		return tl::make_unexpected(std::move(err));
	}

	if (res.empty()) {
		return tl::make_unexpected(std::string{"empty s= tag"});
	}

	return res;
}

auto parse_sig(std::string_view value) -> tl::expected<sig_header_t, std::string>
{
	auto tags = parse_tag_list(value);

	if (!tags) {
		return tl::make_unexpected(tags.error());
	}

	sig_header_t res;
	bool seen_i = false, seen_m = false, seen_mf = false, seen_rt = false,
		 seen_d = false, seen_s = false;

	for (const auto &tag: *tags) {
		if (tag.name == "i") {
			if (seen_i) {
				return tl::make_unexpected(std::string{"duplicate i= tag"});
			}
			auto i = parse_uint(tag.value);
			if (!i || *i == 0 || *i > RSPAMD_DKIM2_MAX_HOPS) {
				return tl::make_unexpected(fmt::format("invalid i= tag: '{}'", tag.value));
			}
			res.i = *i;
			seen_i = true;
		}
		else if (tag.name == "m") {
			if (seen_m) {
				return tl::make_unexpected(std::string{"duplicate m= tag"});
			}
			auto m = parse_uint(tag.value);
			if (!m || *m == 0 || *m > RSPAMD_DKIM2_MAX_HOPS) {
				return tl::make_unexpected(fmt::format("invalid m= tag: '{}'", tag.value));
			}
			res.m = *m;
			seen_m = true;
		}
		else if (tag.name == "t") {
			auto t = parse_uint(tag.value);
			if (!t || *t > (gulong) G_MAXINT64) {
				return tl::make_unexpected(fmt::format("invalid t= tag: '{}'", tag.value));
			}
			res.t = static_cast<std::time_t>(*t);
		}
		else if (tag.name == "mf") {
			if (seen_mf) {
				return tl::make_unexpected(std::string{"duplicate mf= tag"});
			}
			auto mf = b64_decode(tag.value);
			if (!mf) {
				return tl::make_unexpected(std::string{"invalid base64 in mf= tag"});
			}
			res.mf = std::move(*mf);
			seen_mf = true;
		}
		else if (tag.name == "rt") {
			if (seen_rt) {
				return tl::make_unexpected(std::string{"duplicate rt= tag"});
			}
			std::string err;
			rspamd::string_foreach_delim(tag.value, ",", [&](std::string_view rcpt_b64) {
				if (!err.empty()) {
					return;
				}
				auto rcpt = b64_decode(rcpt_b64);
				if (!rcpt) {
					err = "invalid base64 in rt= tag";
					return;
				}
				res.rt.emplace_back(std::move(*rcpt));
			});
			if (!err.empty()) {
				return tl::make_unexpected(std::move(err));
			}
			seen_rt = true;
		}
		else if (tag.name == "d") {
			if (seen_d) {
				return tl::make_unexpected(std::string{"duplicate d= tag"});
			}
			if (tag.value.empty()) {
				return tl::make_unexpected(std::string{"empty d= tag"});
			}
			res.domain = strip_wsp(tag.value);
			seen_d = true;
		}
		else if (tag.name == "s") {
			if (seen_s) {
				return tl::make_unexpected(std::string{"duplicate s= tag"});
			}
			auto sigs = parse_sig_sets(tag.value);
			if (!sigs) {
				return tl::make_unexpected(sigs.error());
			}
			res.sigs = std::move(*sigs);
			seen_s = true;
		}
		else if (tag.name == "f") {
			rspamd::string_foreach_delim(tag.value, ",", [&](std::string_view flag) {
				flag = trim(flag);
				if (flag == "donotmodify") {
					res.flags |= DKIM2_SIG_FLAG_DONOTMODIFY;
				}
				else if (flag == "donotexplode") {
					res.flags |= DKIM2_SIG_FLAG_DONOTEXPLODE;
				}
				else if (flag == "feedback") {
					res.flags |= DKIM2_SIG_FLAG_FEEDBACK;
				}
				else if (flag == "exploded") {
					res.flags |= DKIM2_SIG_FLAG_EXPLODED;
				}
				/* Unknown flags are ignored */
			});
		}
		/* n= and unknown tags are ignored, but covered by the signature input */
	}

	if (!seen_i || !seen_m || !seen_mf || !seen_rt || !seen_d || !seen_s) {
		return tl::make_unexpected(fmt::format(
			"missing mandatory tag(s):{}{}{}{}{}{}",
			seen_i ? "" : " i=", seen_m ? "" : " m=", seen_mf ? "" : " mf=",
			seen_rt ? "" : " rt=", seen_d ? "" : " d=", seen_s ? "" : " s="));
	}

	return res;
}

auto canon_hash_line(std::string_view name, std::string_view unfolded_value) -> std::string
{
	auto out = lc_string(name);
	out.push_back(':');

	auto value = trim(unfolded_value);
	bool got_sp = false;

	for (auto c: value) {
		if (g_ascii_isspace(c)) {
			got_sp = true;
		}
		else {
			if (got_sp) {
				out.push_back(' ');
				got_sp = false;
			}
			out.push_back(c);
		}
	}

	out.append("\r\n");

	return out;
}

auto canon_sig_line(std::string_view name, std::string_view unfolded_value) -> std::string
{
	auto out = lc_string(name);
	out.push_back(':');

	for (auto c: unfolded_value) {
		if (!g_ascii_isspace(c)) {
			out.push_back(c);
		}
	}

	out.append("\r\n");

	return out;
}

auto blank_sig_values(std::string_view canon_line) -> std::string
{
	/* Strip the trailing CRLF, process the tag list and restore it */
	auto line = canon_line;
	if (line.ends_with("\r\n")) {
		line.remove_suffix(2);
	}

	auto colon_pos = line.find(':');

	if (colon_pos == std::string_view::npos) {
		return std::string{canon_line};
	}

	std::string out{line.substr(0, colon_pos + 1)};
	auto tag_list = line.substr(colon_pos + 1);

	/*
	 * string_foreach_delim does not emit a trailing empty element, so trailing
	 * separators are restored explicitly to keep the canonical form byte-exact
	 */
	bool first_tag = true;
	rspamd::string_foreach_delim(
		tag_list, ";", [&](std::string_view seg) {
			if (!first_tag) {
				out.push_back(';');
			}
			first_tag = false;

			if (seg.starts_with("s=")) {
				out.append("s=");
				auto sets = seg.substr(2);
				bool first_set = true;
				rspamd::string_foreach_delim(
					sets, ",", [&](std::string_view set_str) {
						if (!first_set) {
							out.push_back(',');
						}
						first_set = false;
						/* selector ":" sig-name ":" message-sig -> blank the sig */
						auto last_colon = set_str.rfind(':');
						if (last_colon != std::string_view::npos) {
							out.append(set_str.substr(0, last_colon + 1));
						}
						else {
							out.append(set_str);
						}
					},
					false);

				if (sets.ends_with(',')) {
					out.push_back(',');
				}
			}
			else {
				out.append(seg);
			}
		},
		false);

	if (tag_list.ends_with(';')) {
		out.push_back(';');
	}

	out.append("\r\n");

	return out;
}

auto build_sig_input(std::span<const std::string> mi_lines,
					 std::span<const std::string> prev_sig_lines,
					 std::string_view current_sig_line) -> std::string
{
	std::string out;
	std::size_t total = current_sig_line.size();

	for (const auto &line: mi_lines) {
		total += line.size();
	}
	for (const auto &line: prev_sig_lines) {
		total += line.size();
	}

	out.reserve(total);

	for (const auto &line: mi_lines) {
		out.append(line);
	}
	for (const auto &line: prev_sig_lines) {
		out.append(line);
	}

	out.append(blank_sig_values(current_sig_line));

	return out;
}

auto relaxed_domain_match(std::string_view child, std::string_view base) -> bool
{
	if (base.empty() || child.empty()) {
		return false;
	}

	for (;;) {
		if (eq_icase(child, base)) {
			return true;
		}

		auto dot_pos = child.find('.');

		if (dot_pos == std::string_view::npos) {
			return false;
		}

		child.remove_prefix(dot_pos + 1);
	}
}

static auto
strip_angle(std::string_view addr) -> std::string_view
{
	addr = trim(addr);

	if (addr.size() >= 2 && addr.front() == '<' && addr.back() == '>') {
		addr.remove_prefix(1);
		addr.remove_suffix(1);
	}

	return addr;
}

auto smtp_addr_domain(std::string_view addr) -> std::string_view
{
	addr = strip_angle(addr);
	auto at_pos = addr.rfind('@');

	if (at_pos == std::string_view::npos) {
		return {};
	}

	return addr.substr(at_pos + 1);
}

auto smtp_addr_equal(std::string_view a, std::string_view b) -> bool
{
	a = strip_angle(a);
	b = strip_angle(b);

	auto at_a = a.rfind('@');
	auto at_b = b.rfind('@');

	if (at_a != at_b) {
		return false;
	}

	if (at_a == std::string_view::npos) {
		/* Both have no domain, e.g. null reverse-paths */
		return a == b;
	}

	/* Local part is case-sensitive, domain is not */
	return a.substr(0, at_a) == b.substr(0, at_b) &&
		   eq_icase(a.substr(at_a + 1), b.substr(at_b + 1));
}

}// namespace rspamd::dkim2

/*
 * Task-bound verification logic
 */

using namespace rspamd::dkim2;

namespace {

struct mi_entry_t {
	mi_header_t parsed;
	std::string canon_line;
};

struct sig_entry_t {
	sig_header_t parsed;
	std::string canon_line;
};

struct dkim2_key_slot {
	rspamd_dkim_key_t *key = nullptr;
	enum rspamd_dkim2_result_code rcode = RSPAMD_DKIM2_TEMPERROR;
	std::string reason = "key not yet fetched";
};

constexpr unsigned int DKIM2_DEFAULT_MAX_AGE = 14 * 24 * 3600;

static auto
severity(enum rspamd_dkim2_result_code rcode) -> int
{
	switch (rcode) {
	case RSPAMD_DKIM2_NONE:
	case RSPAMD_DKIM2_PASS:
		return 0;
	case RSPAMD_DKIM2_TEMPERROR:
		return 1;
	case RSPAMD_DKIM2_PERMERROR:
		return 2;
	case RSPAMD_DKIM2_FAIL:
		return 3;
	}

	return 0;
}

}// anonymous namespace

struct rspamd_dkim2_chain_s {
	struct rspamd_task *task = nullptr;
	std::vector<mi_entry_t> mis;   /* sorted by m=, mis[k] has m == k + 1 */
	std::vector<sig_entry_t> sigs; /* sorted by i=, sigs[k] has i == k + 1 */
	ankerl::unordered_dense::map<std::string, dkim2_key_slot> keys;
	struct rspamd_dkim2_verify_params params{};
	rspamd_dkim2_verify_cb cb = nullptr;
	void *ud = nullptr;
	unsigned int pending = 0;
	/* Results of the synchronous (hash, envelope, timestamp) checks */
	enum rspamd_dkim2_result_code prelim_rcode = RSPAMD_DKIM2_PASS;
	std::string prelim_reason;

	~rspamd_dkim2_chain_s()
	{
		for (auto &kv: keys) {
			if (kv.second.key) {
				rspamd_dkim_key_unref(kv.second.key);
			}
		}
	}

	void merge_prelim(enum rspamd_dkim2_result_code rcode, std::string reason)
	{
		if (severity(rcode) > severity(prelim_rcode)) {
			prelim_rcode = rcode;
			prelim_reason = std::move(reason);
		}
	}
};

struct dkim2_dns_cbdata {
	rspamd_dkim2_chain_t *chain;
	char *dns_name;
};

static void
dkim2_chain_dtor(void *p)
{
	delete static_cast<rspamd_dkim2_chain_s *>(p);
}

static auto
dkim2_validate_chain(rspamd_dkim2_chain_s *chain) -> tl::expected<void, std::string>
{
	if (chain->mis.empty()) {
		return tl::make_unexpected(std::string{"no Message-Instance headers"});
	}
	if (chain->sigs.empty()) {
		return tl::make_unexpected(std::string{"no DKIM2-Signature headers"});
	}

	for (std::size_t k = 0; k < chain->mis.size(); k++) {
		if (chain->mis[k].parsed.m != k + 1) {
			return tl::make_unexpected(fmt::format(
				"Message-Instance m= sequence broken: expected {}, got {}",
				k + 1, chain->mis[k].parsed.m));
		}
	}

	unsigned int prev_m = 0;

	for (std::size_t k = 0; k < chain->sigs.size(); k++) {
		const auto &sig = chain->sigs[k].parsed;

		if (sig.i != k + 1) {
			return tl::make_unexpected(fmt::format(
				"DKIM2-Signature i= sequence broken: expected {}, got {}",
				k + 1, sig.i));
		}
		if (sig.m > chain->mis.size()) {
			return tl::make_unexpected(fmt::format(
				"DKIM2-Signature i={} references unknown Message-Instance m={}",
				sig.i, sig.m));
		}
		if (sig.m < prev_m) {
			return tl::make_unexpected(fmt::format(
				"DKIM2-Signature i={} references older Message-Instance m={} than the previous hop",
				sig.i, sig.m));
		}
		prev_m = sig.m;
	}

	if (chain->sigs.back().parsed.m != chain->mis.size()) {
		return tl::make_unexpected(std::string{
			"the last DKIM2-Signature does not reference the latest Message-Instance"});
	}

	/* The latest instance must have a usable sha256 hash set */
	const auto &latest = chain->mis.back().parsed;
	auto found = std::find_if(latest.hashes.begin(), latest.hashes.end(),
							  [](const hash_set_t &hs) {
								  return hs.alg == sha256_alg_name &&
										 hs.header_hash.size() == 32 &&
										 hs.body_hash.size() == 32;
							  });

	if (found == latest.hashes.end()) {
		return tl::make_unexpected(std::string{
			"no valid sha256 hash-set in the latest Message-Instance"});
	}

	return {};
}

rspamd_dkim2_chain_t *
rspamd_dkim2_chain_parse(struct rspamd_task *task, GError **err)
{
	struct rspamd_mime_header *mi_hdrs, *sig_hdrs, *cur;

	if (task->message == nullptr) {
		return nullptr;
	}

	mi_hdrs = rspamd_message_get_header_array(task, RSPAMD_DKIM2_MIHEADER, false);
	sig_hdrs = rspamd_message_get_header_array(task, RSPAMD_DKIM2_SIGNHEADER, false);

	if (mi_hdrs == nullptr && sig_hdrs == nullptr) {
		/* No DKIM2 headers at all */
		return nullptr;
	}

	if (mi_hdrs == nullptr || sig_hdrs == nullptr) {
		g_set_error(err, DKIM2_ERROR, RSPAMD_DKIM2_PERMERROR,
					"%s headers without %s headers",
					mi_hdrs ? RSPAMD_DKIM2_MIHEADER : RSPAMD_DKIM2_SIGNHEADER,
					mi_hdrs ? RSPAMD_DKIM2_SIGNHEADER : RSPAMD_DKIM2_MIHEADER);
		return nullptr;
	}

	auto *chain = new rspamd_dkim2_chain_s;
	rspamd_mempool_add_destructor(task->task_pool, dkim2_chain_dtor, chain);

	DL_FOREACH(mi_hdrs, cur)
	{
		if (cur->value == nullptr) {
			continue;
		}

		auto parsed = parse_mi(cur->value);

		if (!parsed) {
			g_set_error(err, DKIM2_ERROR, RSPAMD_DKIM2_PERMERROR,
						"invalid Message-Instance header: %s", parsed.error().c_str());
			return nullptr;
		}

		chain->mis.emplace_back(mi_entry_t{
			std::move(*parsed),
			canon_sig_line(RSPAMD_DKIM2_MIHEADER, cur->value),
		});

		if (chain->mis.size() > RSPAMD_DKIM2_MAX_HOPS) {
			g_set_error(err, DKIM2_ERROR, RSPAMD_DKIM2_PERMERROR,
						"too many Message-Instance headers (max %d)",
						RSPAMD_DKIM2_MAX_HOPS);
			return nullptr;
		}
	}

	DL_FOREACH(sig_hdrs, cur)
	{
		if (cur->value == nullptr) {
			continue;
		}

		auto parsed = parse_sig(cur->value);

		if (!parsed) {
			g_set_error(err, DKIM2_ERROR, RSPAMD_DKIM2_PERMERROR,
						"invalid DKIM2-Signature header: %s", parsed.error().c_str());
			return nullptr;
		}

		chain->sigs.emplace_back(sig_entry_t{
			std::move(*parsed),
			canon_sig_line(RSPAMD_DKIM2_SIGNHEADER, cur->value),
		});

		if (chain->sigs.size() > RSPAMD_DKIM2_MAX_HOPS) {
			g_set_error(err, DKIM2_ERROR, RSPAMD_DKIM2_PERMERROR,
						"too many DKIM2-Signature headers (max %d)",
						RSPAMD_DKIM2_MAX_HOPS);
			return nullptr;
		}
	}

	std::sort(chain->mis.begin(), chain->mis.end(),
			  [](const mi_entry_t &a, const mi_entry_t &b) {
				  return a.parsed.m < b.parsed.m;
			  });
	std::sort(chain->sigs.begin(), chain->sigs.end(),
			  [](const sig_entry_t &a, const sig_entry_t &b) {
				  return a.parsed.i < b.parsed.i;
			  });

	auto valid = dkim2_validate_chain(chain);

	if (!valid) {
		g_set_error(err, DKIM2_ERROR, RSPAMD_DKIM2_PERMERROR,
					"invalid DKIM2 chain: %s", valid.error().c_str());
		return nullptr;
	}

	msg_debug_dkim2("parsed DKIM2 chain: %z instances, %z signatures, last domain %s",
					chain->mis.size(), chain->sigs.size(),
					chain->sigs.back().parsed.domain.c_str());

	return chain;
}

unsigned int
rspamd_dkim2_chain_len(const rspamd_dkim2_chain_t *chain)
{
	return chain ? chain->sigs.size() : 0;
}

static auto
dkim2_ignored_header(const char *name) -> bool
{
	static const char *exact[] = {
		"Received",
		"Return-Path",
		"Authentication-Results",
		"DKIM-Signature",
		RSPAMD_DKIM2_MIHEADER,
		RSPAMD_DKIM2_SIGNHEADER,
	};

	for (auto *ex: exact) {
		if (g_ascii_strcasecmp(name, ex) == 0) {
			return true;
		}
	}

	return g_ascii_strncasecmp(name, "X-", 2) == 0 ||
		   g_ascii_strncasecmp(name, "ARC-", 4) == 0;
}

static void
dkim2_check_hashes(rspamd_dkim2_chain_t *chain, struct rspamd_task *task)
{
	unsigned char digest[EVP_MAX_MD_SIZE];

	/* Body hash (Section 5.1) */
	const char *body_start = MESSAGE_FIELD(task, raw_headers_content).body_start;
	const char *msg_end = task->msg.begin + task->msg.len;
	std::string_view body;

	if (body_start != nullptr && msg_end > body_start) {
		body = std::string_view{body_start, static_cast<std::size_t>(msg_end - body_start)};
	}

	auto *md_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
	body_canon_foreach(body, [&](const char *p, std::size_t len) {
		EVP_DigestUpdate(md_ctx, p, len);
	});
	EVP_DigestFinal_ex(md_ctx, digest, nullptr);

	const auto &latest = chain->mis.back().parsed;
	const auto *hs = &*std::find_if(latest.hashes.begin(), latest.hashes.end(),
									[](const hash_set_t &h) {
										return h.alg == sha256_alg_name &&
											   h.header_hash.size() == 32 &&
											   h.body_hash.size() == 32;
									});

	if (memcmp(hs->body_hash.data(), digest, 32) != 0) {
		msg_info_dkim2("body hash mismatch for the current message instance m=%d",
					   latest.m);
		chain->merge_prelim(RSPAMD_DKIM2_FAIL,
							fmt::format("body hash mismatch for instance m={}", latest.m));
	}

	/* Header hash (Section 5.2) */
	struct hdr_row {
		std::string lc_name;
		unsigned int order;
		std::string canon;
	};
	std::vector<hdr_row> rows;
	unsigned int order = 0;

	for (auto *cur = MESSAGE_FIELD(task, headers_order); cur != nullptr;
		 cur = cur->ord_next, order++) {
		if (cur->name == nullptr || cur->value == nullptr) {
			continue;
		}
		if (dkim2_ignored_header(cur->name)) {
			continue;
		}

		rows.emplace_back(hdr_row{
			lc_string(cur->name),
			order,
			canon_hash_line(cur->name, cur->value),
		});
	}

	/*
	 * Sort alphabetically; header fields with the same name are emitted in
	 * the order they were likely inserted, i.e. from the bottom of the
	 * header block (oldest) to the top (newest)
	 */
	std::sort(rows.begin(), rows.end(), [](const hdr_row &a, const hdr_row &b) {
		if (a.lc_name != b.lc_name) {
			return a.lc_name < b.lc_name;
		}
		return a.order > b.order;
	});

	EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
	for (const auto &row: rows) {
		EVP_DigestUpdate(md_ctx, row.canon.data(), row.canon.size());
	}
	EVP_DigestFinal_ex(md_ctx, digest, nullptr);
	EVP_MD_CTX_free(md_ctx);

	if (memcmp(hs->header_hash.data(), digest, 32) != 0) {
		msg_info_dkim2("header hash mismatch for the current message instance m=%d",
					   latest.m);
		chain->merge_prelim(RSPAMD_DKIM2_FAIL,
							fmt::format("header hash mismatch for instance m={}", latest.m));
	}
}

static void
dkim2_check_envelope(rspamd_dkim2_chain_t *chain, struct rspamd_task *task)
{
	const auto &last = chain->sigs.back().parsed;

	if (chain->params.check_envelope) {
		if (task->from_envelope != nullptr) {
			std::string_view smtp_from;

			if (task->from_envelope->addr_len > 0) {
				smtp_from = std::string_view{task->from_envelope->addr,
											 task->from_envelope->addr_len};
			}

			if (!smtp_addr_equal(last.mf, smtp_from)) {
				msg_info_dkim2("MAIL FROM does not match mf= of the last hop");
				chain->merge_prelim(RSPAMD_DKIM2_PERMERROR,
									"MAIL FROM did not match mf= of the last hop");
			}
		}

		if (task->rcpt_envelope != nullptr) {
			unsigned int i;
			struct rspamd_email_address *rcpt;

			PTR_ARRAY_FOREACH(task->rcpt_envelope, i, rcpt)
			{
				if (rcpt->addr == nullptr) {
					continue;
				}

				std::string_view rcpt_sv{rcpt->addr, rcpt->addr_len};
				auto found = std::any_of(last.rt.begin(), last.rt.end(),
										 [&](const std::string &rt) {
											 return smtp_addr_equal(rt, rcpt_sv);
										 });

				if (!found) {
					msg_info_dkim2("RCPT TO <%*s> not found in rt= of the last hop",
								   (int) rcpt->addr_len, rcpt->addr);
					chain->merge_prelim(RSPAMD_DKIM2_PERMERROR,
										"RCPT TO did not match rt= of the last hop");
					break;
				}
			}
		}
	}

	/* Per-hop alignment of d= with the mf= domain (Section 8.3) */
	for (const auto &sig_entry: chain->sigs) {
		const auto &sig = sig_entry.parsed;
		auto mf_dom = smtp_addr_domain(sig.mf);

		if (mf_dom.empty()) {
			/* Null reverse-path (bounce), nothing to align */
			continue;
		}

		if (!relaxed_domain_match(mf_dom, sig.domain)) {
			msg_info_dkim2("hop i=%d: mf= domain does not align with d=%s",
						   sig.i, sig.domain.c_str());
			chain->merge_prelim(RSPAMD_DKIM2_PERMERROR,
								fmt::format("mf= domain is not aligned with d= for hop i={}",
											sig.i));
			break;
		}
	}
}

static void
dkim2_check_timestamps(rspamd_dkim2_chain_t *chain, struct rspamd_task *task)
{
	/*
	 * The last hop has the most recent timestamp, so it is the only one
	 * checked against the maximum age in this draft implementation
	 */
	const auto &last = chain->sigs.back().parsed;

	if (last.t == 0) {
		return;
	}

	auto now = time(nullptr);
	auto max_age = chain->params.max_age ? chain->params.max_age : DKIM2_DEFAULT_MAX_AGE;

	if (last.t > now + chain->params.time_jitter) {
		/* Implementations MAY ignore future timestamps; just log it */
		msg_info_dkim2("DKIM2 signature i=%d has a future timestamp %ud",
					   last.i, (unsigned int) last.t);
	}
	else if (now - last.t > (time_t) max_age) {
		chain->merge_prelim(RSPAMD_DKIM2_FAIL,
							fmt::format("signature is too old: {} seconds", now - last.t));
	}
}

static void
dkim2_verify_one_hop(rspamd_dkim2_chain_t *chain,
					 const sig_entry_t &entry,
					 std::size_t hop_idx,
					 struct rspamd_dkim2_hop_result *hop)
{
	struct rspamd_task *task = chain->task;
	const auto &sig = entry.parsed;
	unsigned char digest[EVP_MAX_MD_SIZE];

	auto merge_hop = [&](enum rspamd_dkim2_result_code rcode, std::string_view reason) {
		if (severity(rcode) > severity(hop->rcode)) {
			hop->rcode = rcode;
			hop->fail_reason = rspamd_mempool_strdup(task->task_pool,
													 std::string{reason}.c_str());
		}
	};

	hop->rcode = RSPAMD_DKIM2_PASS;
	hop->fail_reason = nullptr;
	hop->idx = sig.i;
	hop->domain = rspamd_mempool_strdup(task->task_pool, sig.domain.c_str());
	hop->selector = rspamd_mempool_strdup(task->task_pool, sig.sigs[0].selector.c_str());

	/* Build the signature input: MI lines up to m=, previous sig lines, self */
	std::vector<std::string> mi_lines, prev_lines;
	mi_lines.reserve(sig.m);
	prev_lines.reserve(hop_idx);

	for (std::size_t k = 0; k < sig.m; k++) {
		mi_lines.push_back(chain->mis[k].canon_line);
	}
	for (std::size_t k = 0; k < hop_idx; k++) {
		prev_lines.push_back(chain->sigs[k].canon_line);
	}

	auto input = build_sig_input(mi_lines, prev_lines, entry.canon_line);
	EVP_Digest(input.data(), input.size(), digest, nullptr, EVP_sha256(), nullptr);

	msg_debug_dkim2("hop i=%d: signature input is %z bytes", sig.i, input.size());

	auto supported_algs = 0;

	for (const auto &ss: sig.sigs) {
		auto dns_name = fmt::format("{}._domainkey.{}", ss.selector, sig.domain);
		auto slot_it = chain->keys.find(dns_name);

		if (slot_it == chain->keys.end()) {
			/* Should not happen: all names are inserted in chain_verify */
			merge_hop(RSPAMD_DKIM2_PERMERROR, "internal error: no key slot");
			continue;
		}

		const auto &slot = slot_it->second;

		if (ss.alg == rsa_alg_name) {
			supported_algs++;

			if (slot.key == nullptr) {
				merge_hop(slot.rcode, slot.reason);
				continue;
			}

			if (rspamd_dkim_key_get_type(slot.key) != RSPAMD_DKIM_KEY_RSA) {
				merge_hop(RSPAMD_DKIM2_PERMERROR,
						  fmt::format("key type mismatch for rsa-sha256, selector {}",
									  ss.selector));
				continue;
			}

			GError *err = nullptr;

			if (!rspamd_cryptobox_verify_evp_rsa(NID_sha256,
												 reinterpret_cast<const unsigned char *>(ss.sig.data()),
												 ss.sig.size(),
												 digest, 32,
												 static_cast<EVP_PKEY *>(rspamd_dkim_key_evp(slot.key)),
												 &err)) {
				if (err != nullptr) {
					merge_hop(RSPAMD_DKIM2_PERMERROR,
							  fmt::format("openssl error: {}", err->message));
					g_error_free(err);
					ERR_clear_error();
				}
				else {
					msg_info_dkim2("hop i=%d: rsa-sha256 signature did not verify; "
								   "d=%s, selector=%s",
								   sig.i, sig.domain.c_str(), ss.selector.c_str());
					merge_hop(RSPAMD_DKIM2_FAIL, "rsa-sha256 signature did not verify");
				}
			}
		}
		else if (ss.alg == ed25519_alg_name) {
			supported_algs++;

			if (slot.key == nullptr) {
				merge_hop(slot.rcode, slot.reason);
				continue;
			}

			if (rspamd_dkim_key_get_type(slot.key) != RSPAMD_DKIM_KEY_EDDSA) {
				merge_hop(RSPAMD_DKIM2_PERMERROR,
						  fmt::format("key type mismatch for ed25519-sha256, selector {}",
									  ss.selector));
				continue;
			}

			gsize pklen = 0;
			const unsigned char *pk = rspamd_dkim_key_eddsa(slot.key, &pklen);

			if (pk == nullptr || pklen != crypto_sign_publickeybytes() ||
				ss.sig.size() != crypto_sign_bytes()) {
				merge_hop(RSPAMD_DKIM2_PERMERROR, "invalid ed25519 key or signature size");
				continue;
			}

			if (!rspamd_cryptobox_verify(reinterpret_cast<const unsigned char *>(ss.sig.data()),
										 ss.sig.size(),
										 digest, 32,
										 pk)) {
				msg_info_dkim2("hop i=%d: ed25519-sha256 signature did not verify; "
							   "d=%s, selector=%s",
							   sig.i, sig.domain.c_str(), ss.selector.c_str());
				merge_hop(RSPAMD_DKIM2_FAIL, "ed25519-sha256 signature did not verify");
			}
		}
		/* Unknown algorithms are skipped */
	}

	if (supported_algs == 0) {
		merge_hop(RSPAMD_DKIM2_PERMERROR, "no supported signature algorithms");
	}
}

static void
dkim2_finalize(rspamd_dkim2_chain_t *chain)
{
	struct rspamd_task *task = chain->task;
	auto nhops = chain->sigs.size();

	auto *hops = rspamd_mempool_alloc_array_type(task->task_pool, nhops,
												 struct rspamd_dkim2_hop_result);
	auto *res = rspamd_mempool_alloc0_type(task->task_pool,
										   struct rspamd_dkim2_verify_result);

	res->rcode = chain->prelim_rcode;
	res->fail_reason = chain->prelim_reason.empty() ? nullptr : rspamd_mempool_strdup(task->task_pool, chain->prelim_reason.c_str());
	res->nhops = nhops;
	res->hops = hops;

	for (std::size_t k = 0; k < nhops; k++) {
		dkim2_verify_one_hop(chain, chain->sigs[k], k, &hops[k]);

		if (severity(hops[k].rcode) > severity(res->rcode)) {
			res->rcode = hops[k].rcode;
			res->fail_reason = hops[k].fail_reason != nullptr ? rspamd_mempool_strdup(task->task_pool, fmt::format("hop i={}: {}", hops[k].idx, hops[k].fail_reason).c_str()) : nullptr;
		}
	}

	msg_debug_dkim2("DKIM2 chain verification finished: rcode=%d, %z hops",
					(int) res->rcode, nhops);

	chain->cb(task, res, chain->ud);
}

static void
dkim2_dns_key_cb(struct rdns_reply *reply, void *arg)
{
	auto *cbd = static_cast<dkim2_dns_cbdata *>(arg);
	auto *chain = cbd->chain;
	struct rspamd_task *task = chain->task;

	auto slot_it = chain->keys.find(cbd->dns_name);

	if (slot_it != chain->keys.end()) {
		auto &slot = slot_it->second;

		if (reply->code == RDNS_RC_NOERROR) {
			struct rdns_reply_entry *elt;
			GError *err = nullptr;

			slot.rcode = RSPAMD_DKIM2_PERMERROR;
			slot.reason = "no DKIM2 key record";

			LL_FOREACH(reply->entries, elt)
			{
				if (elt->type != RDNS_REQUEST_TXT) {
					continue;
				}

				if (err != nullptr) {
					g_error_free(err);
					err = nullptr;
				}

				std::size_t keylen = 0;
				auto *key = rspamd_dkim_parse_key(elt->content.txt.data, &keylen, &err);

				if (key != nullptr) {
					slot.key = key;
					slot.rcode = RSPAMD_DKIM2_PASS;
					slot.reason.clear();
					break;
				}
			}

			if (slot.key == nullptr && err != nullptr) {
				slot.reason = fmt::format("invalid key record for {}: {}",
										  cbd->dns_name, err->message);
			}

			if (err != nullptr) {
				g_error_free(err);
			}
		}
		else if (reply->code == RDNS_RC_NXDOMAIN || reply->code == RDNS_RC_NOREC) {
			slot.rcode = RSPAMD_DKIM2_PERMERROR;
			slot.reason = fmt::format("no DKIM2 key record for {}", cbd->dns_name);
		}
		else {
			slot.rcode = RSPAMD_DKIM2_TEMPERROR;
			slot.reason = fmt::format("DNS request for {} failed: {}",
									  cbd->dns_name, rdns_strerror(reply->code));
		}

		msg_debug_dkim2("DKIM2 key %s: %s", cbd->dns_name,
						slot.key ? "fetched" : slot.reason.c_str());
	}

	chain->pending--;

	if (chain->pending == 0) {
		dkim2_finalize(chain);
	}
}

bool rspamd_dkim2_chain_verify(rspamd_dkim2_chain_t *chain,
							   struct rspamd_task *task,
							   const struct rspamd_dkim2_verify_params *params,
							   rspamd_dkim2_verify_cb cb,
							   void *ud)
{
	if (chain == nullptr || cb == nullptr || task->message == nullptr) {
		return false;
	}

	chain->task = task;
	chain->cb = cb;
	chain->ud = ud;

	if (params != nullptr) {
		chain->params = *params;
	}

	/* Synchronous checks first */
	dkim2_check_hashes(chain, task);
	dkim2_check_envelope(chain, task);
	dkim2_check_timestamps(chain, task);

	/* Collect all unique key names */
	for (const auto &sig_entry: chain->sigs) {
		for (const auto &ss: sig_entry.parsed.sigs) {
			if (ss.alg != rsa_alg_name && ss.alg != ed25519_alg_name) {
				/* Do not fetch keys for unsupported algorithms */
				continue;
			}

			auto dns_name = fmt::format("{}._domainkey.{}", ss.selector,
										sig_entry.parsed.domain);
			chain->keys.try_emplace(std::move(dns_name));
		}
	}

	unsigned int scheduled = 0;

	for (auto &kv: chain->keys) {
		auto *cbd = rspamd_mempool_alloc_type(task->task_pool, struct dkim2_dns_cbdata);

		cbd->chain = chain;
		cbd->dns_name = rspamd_mempool_strdup(task->task_pool, kv.first.c_str());

		if (rspamd_dns_resolver_request_task_forced(task,
													dkim2_dns_key_cb,
													cbd,
													RDNS_REQUEST_TXT,
													cbd->dns_name)) {
			scheduled++;
		}
		else {
			kv.second.rcode = RSPAMD_DKIM2_TEMPERROR;
			kv.second.reason = "cannot schedule DNS request";
		}
	}

	chain->pending = scheduled;

	if (scheduled == 0) {
		/* No DNS requests could be scheduled: finalize synchronously */
		dkim2_finalize(chain);
	}

	return true;
}
