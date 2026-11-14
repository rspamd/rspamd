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
 * DKIM2 verification, see draft-ietf-dkim-dkim2-spec-09.
 *
 * Unlike DKIM (RFC 6376), a DKIM2 signature covers only the Message-Instance
 * and DKIM2-Signature header fields; the message content is bound indirectly
 * via the hashes in the Message-Instance h= tag. A message is a Fully Verified
 * DKIM2 Message when every signature verifies, the hashes of every instance
 * match the message recreated with the r= recipes, the Chain of Custody is
 * unbroken and matches the SMTP envelope, the timestamps are sane and the
 * From header fields are Authentic.
 *
 * Not implemented: verification of the messages returned in DSNs
 * (Section 16.4) and reporting of the result in Authentication-Results.
 */

#include "config.h"
#include "rspamd.h"
#include "message.h"
#include "dns.h"
#include "dkim.h"
#include "dkim2.h"
#include "dkim2.hxx"
#include "utlist.h"
#include "libmime/email_addr.h"
#include "libutil/cxx/util.hxx"

#include "contrib/ankerl/unordered_dense.h"
#include "contrib/fmt/include/fmt/core.h"

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>

/* Pure ML-DSA and its context string need OpenSSL 3.5 */
#if OPENSSL_VERSION_NUMBER >= 0x30500000L && !defined(LIBRESSL_VERSION_NUMBER)
#define DKIM2_HAVE_MLDSA 1
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#include <algorithm>
#include <array>
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
constexpr std::string_view sha512_alg_name = "sha512";
constexpr std::string_view rsa_alg_name = "rsa-sha256";
constexpr std::string_view ed25519_alg_name = "ed25519-sha256";
constexpr std::string_view mldsa44_alg_name = "mldsa44";

/* A tag-list cannot reasonably have more tags; bounds the duplicate check */
constexpr std::size_t DKIM2_MAX_TAGS = 64;
/* RFC 5321 limits a path to 256 octets */
constexpr std::size_t DKIM2_MAX_SMTP_PATH = 256;


auto combine_all(std::span<const result_t> results) -> result_t
{
	bool all_pass = true, any_fail = false, only_temp = true;

	for (auto r: results) {
		if (r == result_t::pass) {
			continue;
		}

		all_pass = false;

		if (r == result_t::fail) {
			any_fail = true;
		}
		if (r != result_t::temperror) {
			only_temp = false;
		}
	}

	if (all_pass) {
		return results.empty() ? result_t::permerror : result_t::pass;
	}
	if (only_temp) {
		return result_t::temperror;
	}

	return any_fail ? result_t::fail : result_t::permerror;
}

auto combine_any(std::span<const result_t> results) -> result_t
{
	bool any_temp = false, any_fail = false;

	for (auto r: results) {
		switch (r) {
		case result_t::pass:
			return result_t::pass;
		case result_t::temperror:
			any_temp = true;
			break;
		case result_t::fail:
			any_fail = true;
			break;
		case result_t::permerror:
			break;
		}
	}

	if (any_temp) {
		return result_t::temperror;
	}

	return any_fail ? result_t::fail : result_t::permerror;
}

auto parse_tag_list(std::string_view input, bool strict)
	-> tl::expected<std::vector<tag_t>, std::string>
{
	std::vector<tag_t> res;
	std::size_t first = 0;

	/* One pass and nothing is kept but the tags: the input can be huge */
	for (bool last = false; !last;) {
		auto second = input.find(';', first);

		last = second == std::string_view::npos;

		auto seg = trim(input.substr(first, last ? second : second - first));
		auto is_first = first == 0;

		first = second + 1;

		if (seg.empty()) {
			/* Only the optional trailing `;` yields an empty tag-spec */
			if (!strict || (last && !is_first)) {
				continue;
			}

			return tl::make_unexpected(std::string{"empty tag"});
		}

		auto eq_pos = seg.find('=');

		if (eq_pos == std::string_view::npos || eq_pos == 0) {
			return tl::make_unexpected(std::string{"tag without a name or a value"});
		}

		auto name = trim(seg.substr(0, eq_pos));
		auto value = trim(seg.substr(eq_pos + 1));

		if (name.empty() || !g_ascii_isalpha(name.front()) ||
			!std::all_of(name.begin(), name.end(), [](char c) {
				return g_ascii_isalnum(c) || c == '_';
			})) {
			return tl::make_unexpected(std::string{"invalid tag name"});
		}

		if (strict && std::any_of(name.begin(), name.end(), [](char c) { return g_ascii_isupper(c); })) {
			/* All tag-names MUST be in lower case (Sections 9 and 10) */
			return tl::make_unexpected(std::string{"tag name is not in lower case"});
		}

		if (strict) {
			for (auto c: value) {
				if (!is_wsp(c) && (c < 0x21 || c > 0x7e)) {
					return tl::make_unexpected(fmt::format("invalid character in tag {}", name));
				}
			}
		}

		if (res.size() >= DKIM2_MAX_TAGS) {
			return tl::make_unexpected(std::string{"too many tags"});
		}

		for (const auto &seen: res) {
			if (seen.name == name) {
				return tl::make_unexpected(fmt::format("duplicate tag {}", name));
			}
		}

		res.emplace_back(tag_t{name, value});
	}

	return res;
}

static auto
find_tag(const std::vector<tag_t> &tags, std::string_view name) -> const tag_t *
{
	for (const auto &tag: tags) {
		if (tag.name == name) {
			return &tag;
		}
	}

	return nullptr;
}


/*
 * Parse the h= value: `|` separated groups of `,` separated hash-sets.
 * Returns the error text on failure.
 */
static auto
parse_hash_groups(std::string_view value, std::vector<std::vector<hash_set_t>> &out)
	-> std::optional<std::string>
{
	std::optional<std::string> err;
	std::size_t nsets = 0;

	split_keep_empty(value, '|', [&](std::string_view group_str) {
		if (err) {
			return;
		}

		auto &group = out.emplace_back();

		split_keep_empty(group_str, ',', [&](std::string_view set_str) {
			if (err) {
				return;
			}

			if (++nsets > DKIM2_MAX_HASH_SETS) {
				err = fmt::format("syntax error: too many hash-sets (max {})",
								  DKIM2_MAX_HASH_SETS);
				return;
			}

			/* hash-set = hash-name ":" header-hash ":" body-hash */
			std::vector<std::string_view> parts;
			split_keep_empty(set_str, ':', [&](std::string_view part) {
				parts.push_back(part);
			});

			if (parts.size() != 3) {
				err = "syntax error: invalid hash-set";
				return;
			}

			auto alg = trim(parts[0]);
			auto hh = b64_decode(parts[1]);
			auto bh = b64_decode(parts[2]);

			if (!is_textstring(alg) || !hh || !bh || hh->empty() || bh->empty()) {
				err = "syntax error: invalid hash-set";
				return;
			}

			for (const auto &other_group: out) {
				for (const auto &hs: other_group) {
					if (hs.alg == alg) {
						err = "has a duplicate hash algorithm";
						return;
					}
				}
			}

			group.emplace_back(hash_set_t{
				std::string{alg},
				std::move(*hh),
				std::move(*bh),
			});
		});
	});

	return err;
}

auto parse_mi(std::string_view value) -> tl::expected<mi_header_t, parse_error_t>
{
	auto tags = parse_tag_list(value);

	if (!tags) {
		return tl::make_unexpected(parse_error_t{0, "syntax error: " + tags.error()});
	}

	mi_header_t res;
	const auto *m_tag = find_tag(*tags, "m");

	if (m_tag == nullptr) {
		return tl::make_unexpected(parse_error_t{0, "tag=m missing"});
	}

	auto m = parse_uint(m_tag->value);

	if (!m || *m == 0 || *m > RSPAMD_DKIM2_MAX_HOPS) {
		return tl::make_unexpected(parse_error_t{0, "syntax error: invalid m= tag"});
	}

	res.m = static_cast<unsigned int>(*m);

	const auto *h_tag = find_tag(*tags, "h");

	if (h_tag == nullptr) {
		return tl::make_unexpected(parse_error_t{res.m, "tag=h missing"});
	}

	if (auto err = parse_hash_groups(h_tag->value, res.hash_groups)) {
		return tl::make_unexpected(parse_error_t{res.m, std::move(*err)});
	}

	if (const auto *r_tag = find_tag(*tags, "r")) {
		res.has_recipe = true;
		res.recipe_b64 = strip_wsp(r_tag->value);
	}

	/* Unknown tags are ignored, but covered by the signature input */

	return res;
}

/*
 * Parse the s= value: `|` separated groups of `,` separated signatures.
 * Returns the error text on failure.
 */
static auto
parse_sig_groups(std::string_view value, std::vector<std::vector<sig_set_t>> &out)
	-> std::optional<std::string>
{
	std::optional<std::string> err;
	std::size_t nsets = 0;

	split_keep_empty(value, '|', [&](std::string_view group_str) {
		if (err) {
			return;
		}

		auto &group = out.emplace_back();

		split_keep_empty(group_str, ',', [&](std::string_view set_str) {
			if (err) {
				return;
			}

			if (++nsets > DKIM2_MAX_SIG_SETS_PER_HOP) {
				err = fmt::format("syntax error: too many signatures (max {})",
								  DKIM2_MAX_SIG_SETS_PER_HOP);
				return;
			}

			/* sig-set = selector ":" sig-name ":" message-sig */
			std::vector<std::string_view> parts;
			split_keep_empty(set_str, ':', [&](std::string_view part) {
				parts.push_back(part);
			});

			if (parts.size() != 3) {
				err = "syntax error: invalid signature in s= tag";
				return;
			}

			auto selector = trim(parts[0]);
			auto alg = trim(parts[1]);
			auto sig = b64_decode(parts[2]);

			if (!valid_domain(selector) || !is_textstring(alg) || !sig || sig->empty()) {
				err = "syntax error: invalid signature in s= tag";
				return;
			}

			for (const auto &other_group: out) {
				for (const auto &ss: other_group) {
					if (eq_icase(ss.selector, selector)) {
						err = "has a duplicate selector";
						return;
					}
				}
			}

			group.emplace_back(sig_set_t{
				std::string{selector},
				std::string{alg},
				std::move(*sig),
			});
		});
	});

	return err;
}

/* Decode an mf=/rt= element: an SMTP path with the angle brackets */
static auto
decode_smtp_path(std::string_view b64) -> std::optional<std::string>
{
	if (b64.size() > DKIM2_MAX_SMTP_PATH * 2) {
		/* Do not even decode it */
		return std::nullopt;
	}

	auto path = b64_decode(b64);

	if (!path || path->size() < 2 || path->size() > DKIM2_MAX_SMTP_PATH ||
		path->front() != '<' || path->back() != '>') {
		return std::nullopt;
	}

	for (auto c: *path) {
		/* 8bit octets are fine: local parts are recorded unchanged (Section 18) */
		if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
			return std::nullopt;
		}
	}

	if (path->size() > 2 && smtp_addr_is_null(*path)) {
		/* A source route to nowhere is not the null path */
		return std::nullopt;
	}

	/* Domains are recorded as A-labels (Section 18) or are domain literals */
	auto domain = smtp_addr_domain(*path);

	if (!domain.empty() && domain.front() != '[' && !valid_domain(domain)) {
		return std::nullopt;
	}

	return path;
}

auto parse_sig(std::string_view value) -> tl::expected<sig_header_t, parse_error_t>
{
	auto tags = parse_tag_list(value);

	if (!tags) {
		return tl::make_unexpected(parse_error_t{0, "syntax error: " + tags.error()});
	}

	sig_header_t res;
	const auto *i_tag = find_tag(*tags, "i");

	if (i_tag == nullptr) {
		return tl::make_unexpected(parse_error_t{0, "tag=i missing"});
	}

	auto i = parse_uint(i_tag->value);

	if (!i || *i == 0 || *i > RSPAMD_DKIM2_MAX_HOPS) {
		return tl::make_unexpected(parse_error_t{0, "syntax error: invalid i= tag"});
	}

	res.i = static_cast<unsigned int>(*i);

	auto fail = [&](std::string what) {
		return tl::make_unexpected(parse_error_t{res.i, std::move(what)});
	};

	const auto *m_tag = find_tag(*tags, "m");
	const auto *t_tag = find_tag(*tags, "t");
	const auto *d_tag = find_tag(*tags, "d");
	const auto *s_tag = find_tag(*tags, "s");
	const auto *mf_tag = find_tag(*tags, "mf");
	const auto *rt_tag = find_tag(*tags, "rt");
	const auto *nd_tag = find_tag(*tags, "nd");

	/* i=, m=, t=, d= and s= MUST be present (Section 10) */
	for (auto [tag, name]: {std::pair{m_tag, "m"}, std::pair{t_tag, "t"},
							std::pair{d_tag, "d"}, std::pair{s_tag, "s"}}) {
		if (tag == nullptr) {
			return fail(fmt::format("tag={} missing", name));
		}
	}

	/* There MUST be either an nd= tag or both mf= and rt= tags */
	if (nd_tag != nullptr) {
		if (mf_tag != nullptr || rt_tag != nullptr) {
			return fail(fmt::format("tag={} was unexpected", mf_tag ? "mf" : "rt"));
		}
	}
	else if (mf_tag == nullptr || rt_tag == nullptr) {
		return fail(fmt::format("tag={} missing", mf_tag ? "rt" : "mf"));
	}

	auto m = parse_uint(m_tag->value);

	if (!m || *m == 0 || *m > RSPAMD_DKIM2_MAX_HOPS) {
		return fail("syntax error: invalid m= tag");
	}

	res.m = static_cast<unsigned int>(*m);

	auto t = parse_uint(t_tag->value);

	if (!t) {
		return fail("syntax error: invalid t= tag");
	}

	res.t = *t;

	if (!valid_domain(d_tag->value)) {
		return fail("syntax error: invalid d= tag");
	}

	res.domain = std::string{d_tag->value};

	if (nd_tag != nullptr) {
		if (!valid_domain(nd_tag->value)) {
			return fail("syntax error: invalid nd= tag");
		}

		res.has_nd = true;
		res.nd = std::string{nd_tag->value};
	}
	else {
		auto mf = decode_smtp_path(mf_tag->value);

		if (!mf) {
			return fail("syntax error: invalid mf= tag");
		}

		res.mf = std::move(*mf);

		bool rt_ok = true;

		split_keep_empty(rt_tag->value, ',', [&](std::string_view rcpt_b64) {
			if (!rt_ok) {
				return;
			}

			auto rcpt = res.rt.size() < DKIM2_MAX_RT_ENTRIES ? decode_smtp_path(rcpt_b64) : std::nullopt;

			if (!rcpt || rcpt->size() == 2) {
				/* Over the limit, undecodable or a null forward-path */
				rt_ok = false;
				return;
			}

			res.rt.emplace_back(std::move(*rcpt));
		});

		if (!rt_ok) {
			return fail("syntax error: invalid rt= tag");
		}
	}

	if (auto err = parse_sig_groups(s_tag->value, res.sig_groups)) {
		return fail(std::move(*err));
	}

	if (const auto *f_tag = find_tag(*tags, "f")) {
		bool flags_ok = true;

		split_keep_empty(f_tag->value, ',', [&](std::string_view flag) {
			flag = trim(flag);

			if (!is_textstring(flag)) {
				flags_ok = false;
			}
			else if (flag == "exploded") {
				res.flags |= DKIM2_SIG_FLAG_EXPLODED;
			}
			else if (flag == "feedback") {
				res.flags |= DKIM2_SIG_FLAG_FEEDBACK;
			}
			else if (flag == "feedhere") {
				res.flags |= DKIM2_SIG_FLAG_FEEDHERE;
			}
			/* A flag that is not recognized has no effect */
		});

		if (!flags_ok) {
			return fail("syntax error: invalid f= tag");
		}
	}

	if (const auto *n_tag = find_tag(*tags, "n")) {
		if (n_tag->value.size() > DKIM2_MAX_NONCE_LEN ||
			std::any_of(n_tag->value.begin(), n_tag->value.end(), is_wsp)) {
			return fail("syntax error: invalid n= tag");
		}

		res.nonce = std::string{n_tag->value};
	}

	/* Unknown tags are ignored, but covered by the signature input */

	return res;
}

auto canon_hash_line(std::string_view name, std::string_view unfolded_value) -> std::string
{
	auto out = lc_string(trim(name));
	out.push_back(':');

	auto value = trim(unfolded_value);
	bool got_sp = false;

	for (auto c: value) {
		if (is_wsp(c)) {
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
	auto out = lc_string(trim(name));
	out.push_back(':');

	for (auto c: unfolded_value) {
		if (!is_wsp(c)) {
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

	std::string out;
	out.reserve(line.size() + 2);
	out.append(line.substr(0, colon_pos + 1));

	bool first_tag = true;

	split_keep_empty(line.substr(colon_pos + 1), ';', [&](std::string_view seg) {
		if (!first_tag) {
			out.push_back(';');
		}
		first_tag = false;

		if (!seg.starts_with("s=")) {
			out.append(seg);
			return;
		}

		/*
		 * sig-set = selector ":" sig-name ":" message-sig, sets are separated
		 * by `,` and `|`: drop everything from the second colon of a set up to
		 * the next separator
		 */
		unsigned int ncolons = 0;

		for (auto c: seg) {
			if (c == ',' || c == '|') {
				ncolons = 0;
				out.push_back(c);
			}
			else if (ncolons < 2) {
				if (c == ':') {
					ncolons++;
				}
				out.push_back(c);
			}
		}
	});

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


auto check_custody(std::span<const sig_header_t> sigs) -> std::optional<std::string>
{
	for (std::size_t k = 0; k < sigs.size(); k++) {
		const auto &sig = sigs[k];

		/* Section 7.1 item 2: d= against the mf= domain of the same field */
		if (!sig.has_nd && !smtp_addr_is_null(sig.mf) &&
			!relaxed_domain_match(smtp_addr_domain(sig.mf), sig.domain)) {
			return fmt::format("DKIM2-Signature i={} mf= and d= do not match", sig.i);
		}

		if (k == 0) {
			/* The i=1 field has nothing to be linked with */
			continue;
		}

		/* Section 7.1 item 1: the link with the previous field */
		const auto &prev = sigs[k - 1];

		if (prev.has_nd) {
			/* An imaginary hop: this field must be signed by the announced domain */
			if (!eq_icase(sig.domain, prev.nd)) {
				return fmt::format("DKIM2-Signature i={} nd= does not match", prev.i);
			}

			continue;
		}

		if (sig.has_nd || smtp_addr_is_null(sig.mf)) {
			/* No usable MAIL FROM: the signing domain must be a recipient one */
			auto found = std::any_of(prev.rt.begin(), prev.rt.end(), [&](const std::string &rt) {
				return relaxed_domain_match(smtp_addr_domain(rt), sig.domain);
			});

			if (!found) {
				return fmt::format("DKIM2-Signature i={} d= does not match the rt= of i={}",
								   sig.i, prev.i);
			}
		}
		else {
			auto mf_dom = smtp_addr_domain(sig.mf);
			auto found = std::any_of(prev.rt.begin(), prev.rt.end(), [&](const std::string &rt) {
				return relaxed_domain_match(mf_dom, smtp_addr_domain(rt));
			});

			if (!found) {
				return fmt::format("DKIM2-Signature i={} mf= does not match the rt= of i={}",
								   sig.i, prev.i);
			}
		}
	}

	if (!sigs.empty() && sigs.back().has_nd) {
		/*
		 * Sending a message whose last field has nd= needs out-of-band
		 * arrangements (Section 12.3) that we cannot know about
		 */
		return fmt::format("DKIM2-Signature i={} unexpected nd= tag", sigs.back().i);
	}

	return std::nullopt;
}

/*
 * Check how a TXT record begins: the value of its first tag if that is v=.
 * It tells a DKIM record from everything else that lives at the same name
 * without parsing the rest, which may be not a tag-list at all.
 */
static auto
record_version(std::string_view txt) -> std::optional<std::string_view>
{
	auto first = txt.substr(0, txt.find(';'));
	auto eq_pos = first.find('=');

	if (eq_pos == std::string_view::npos || trim(first.substr(0, eq_pos)) != "v") {
		return std::nullopt;
	}

	return trim(first.substr(eq_pos + 1));
}

auto parse_key_record(std::string_view txt, key_record_t &out) -> record_status
{
	auto version = record_version(txt);

	if (version && *version != "DKIM1") {
		/* Records that begin with another v= are ignored (Section 3.7) */
		return record_status::ignored;
	}

	auto tags = parse_tag_list(txt, false);

	if (!tags) {
		return record_status::syntax_error;
	}

	const tag_t *p_tag = nullptr;

	for (std::size_t idx = 0; idx < tags->size(); idx++) {
		const auto &tag = (*tags)[idx];

		if (tag.name == "v") {
			/* v= MUST be the first tag and MUST be DKIM1 */
			if (idx != 0 || tag.value != "DKIM1") {
				return record_status::syntax_error;
			}
		}
		else if (tag.name == "k") {
			out.k = std::string{tag.value};
		}
		else if (tag.name == "p") {
			p_tag = &tag;
		}
		/* h=, n=, s=, t= are retired and ignored, as well as unknown tags */
	}

	if (p_tag == nullptr) {
		return record_status::syntax_error;
	}

	out.p = strip_wsp(p_tag->value);
	out.revoked = out.p.empty();

	return record_status::ok;
}

auto parse_policy_record(std::string_view txt, policy_record_t &out) -> record_status
{
	auto version = record_version(txt);

	if (!version || *version != "DKIM1") {
		/* Purported records that do not begin with v=DKIM1 are ignored */
		return record_status::ignored;
	}

	auto tags = parse_tag_list(txt, false);

	if (!tags) {
		/* A policy that cannot be read must not become a permissive one */
		return record_status::syntax_error;
	}

	if (const auto *f_tag = find_tag(*tags, "f")) {
		split_keep_empty(f_tag->value, ':', [&](std::string_view flag) {
			if (trim(flag) == "strict") {
				out.strict = true;
			}
			/* Unrecognized flags are ignored */
		});
	}

	return record_status::ok;
}

auto sig_alg_key_type(std::string_view sig_alg) -> std::string_view
{
	if (sig_alg == rsa_alg_name) {
		return "rsa";
	}
	if (sig_alg == ed25519_alg_name) {
		return "ed25519";
	}
	if (sig_alg == mldsa44_alg_name) {
		return "mldsa44";
	}

	return {};
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

/* A public key record, shared by all signatures that use it */
struct dkim2_key_slot {
	rspamd_dkim_key_t *key = nullptr; /* rsa and ed25519 keys */
	std::string raw_pk;               /* mldsa44 key */
	std::string k;                    /* key type of the record */
	enum rspamd_dkim2_result_code rcode = RSPAMD_DKIM2_TEMPERROR;
	/* What follows `public key <s1>` in the error (Section 14.5) */
	const char *problem = "could not be fetched";
};

/* A Domain Policy Record (Section 3.8) */
struct dkim2_policy_slot {
	enum rspamd_dkim2_result_code rcode = RSPAMD_DKIM2_TEMPERROR;
	bool strict = false;
	const char *problem = "unavailable";
};

/* A From that is Authentic only if its domain allows subdomains to sign */
struct dkim2_from_check {
	unsigned int sig_i;
	std::string from_domain;
	std::string policy_name;
};

constexpr std::uint64_t DKIM2_DEFAULT_MAX_AGE = 14 * 24 * 3600;
constexpr std::uint64_t DKIM2_DEFAULT_MAX_FUTURE = 24 * 3600;
constexpr std::size_t DKIM2_MAX_DNS_NAME = 253;
/*
 * Size limit of a Message-Instance or a DKIM2-Signature field: it fits the
 * largest recipe that is accepted, in base64, and a full list of recipients
 */
constexpr std::size_t DKIM2_MAX_FIELD_LEN = 512 * 1024;
/* Octets charged to the work budget for every hashed element on top of its size */
constexpr std::size_t DKIM2_ELEMENT_COST = 16;
/* How much of an untrusted value is quoted in an error */
constexpr std::size_t DKIM2_MAX_QUOTED_VALUE = 64;

/*
 * Shared work budget for recipe application and reconstructed-state hashing
 * across the whole chain. It is proportional to the message size with a floor
 * and a hard ceiling.
 */
constexpr std::size_t DKIM2_RECIPE_MIN_BUDGET = 1024 * 1024;
constexpr std::size_t DKIM2_RECIPE_MAX_BUDGET = 64 * 1024 * 1024;
constexpr std::size_t DKIM2_RECIPE_BUDGET_FACTOR = 8;

/* Shared input-hashing budget for all hop signatures in a chain */
constexpr std::size_t DKIM2_SIGNATURE_MIN_BUDGET = 1024 * 1024;
constexpr std::size_t DKIM2_SIGNATURE_MAX_BUDGET = 64 * 1024 * 1024;
constexpr std::size_t DKIM2_SIGNATURE_BUDGET_FACTOR = 16;

static auto
dkim2_bounded_budget(std::size_t message_len,
					 std::size_t factor,
					 std::size_t minimum,
					 std::size_t maximum) -> std::size_t
{
	if (message_len > maximum / factor) {
		return maximum;
	}

	return std::clamp(message_len * factor, minimum, maximum);
}

/*
 * A reconstructed message state: header field instances per name and body
 * lines. Views point into the original message, or into the data strings of
 * the recipes applied so far (which must outlive the state).
 */
struct dkim2_msg_state {
	/* lc header name -> instances; index 0 is the bottom-most one (number 1) */
	ankerl::unordered_dense::map<std::string, std::vector<std::string_view>> headers;
	std::vector<std::string_view> body_lines;
};

/* Header and body digests of one message state for one hash algorithm */
struct dkim2_digests {
	std::string hdr;
	std::string body;
};

/*
 * A digest fed through a buffer: canonical forms come in tiny pieces (a line,
 * a CRLF), and a call into the crypto library for each one costs far more
 * than hashing the bytes
 */
class dkim2_digest {
public:
	explicit dkim2_digest(const EVP_MD *md)
		: md(md), ctx(EVP_MD_CTX_new())
	{
		ok = ctx != nullptr && EVP_DigestInit_ex(ctx, md, nullptr) == 1;
	}

	~dkim2_digest()
	{
		EVP_MD_CTX_free(ctx);
		ERR_clear_error();
	}

	dkim2_digest(const dkim2_digest &) = delete;
	dkim2_digest &operator=(const dkim2_digest &) = delete;

	void update(const char *data, std::size_t len)
	{
		if (len >= sizeof(buf)) {
			flush();
			ok = ok && EVP_DigestUpdate(ctx, data, len) == 1;
			return;
		}

		if (len > sizeof(buf) - fill) {
			flush();
		}

		memcpy(buf + fill, data, len);
		fill += len;
	}

	void update(std::string_view data)
	{
		update(data.data(), data.size());
	}

	/* Returns the digest and restarts; an empty string means a failure */
	auto finish() -> std::string
	{
		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int dlen = 0;

		flush();
		ok = ok && EVP_DigestFinal_ex(ctx, digest, &dlen) == 1;

		std::string res{reinterpret_cast<const char *>(digest), ok ? dlen : 0};

		ok = ok && EVP_DigestInit_ex(ctx, md, nullptr) == 1;

		return res;
	}

private:
	const EVP_MD *md;
	EVP_MD_CTX *ctx;
	bool ok = false;
	std::size_t fill = 0;
	char buf[8192];

	void flush()
	{
		if (fill > 0) {
			ok = ok && EVP_DigestUpdate(ctx, buf, fill) == 1;
			fill = 0;
		}
	}
};

static auto
dkim2_hash_md(std::string_view alg) -> const EVP_MD *
{
	if (alg == sha256_alg_name) {
		return EVP_sha256();
	}
	if (alg == sha512_alg_name) {
		return EVP_sha512();
	}

	return nullptr;
}

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

static auto
to_rcode(result_t res) -> enum rspamd_dkim2_result_code
{
	switch (res) {
	case result_t::pass:
		return RSPAMD_DKIM2_PASS;
	case result_t::fail:
		return RSPAMD_DKIM2_FAIL;
	case result_t::temperror:
		return RSPAMD_DKIM2_TEMPERROR;
	case result_t::permerror:
		break;
	}

	return RSPAMD_DKIM2_PERMERROR;
}

static auto
from_rcode(enum rspamd_dkim2_result_code rcode) -> result_t
{
	switch (rcode) {
	case RSPAMD_DKIM2_PASS:
		return result_t::pass;
	case RSPAMD_DKIM2_FAIL:
		return result_t::fail;
	case RSPAMD_DKIM2_TEMPERROR:
		return result_t::temperror;
	default:
		break;
	}

	return result_t::permerror;
}

/* An untrusted value as it can be shown in logs and symbol options */
static auto
dkim2_quote(std::string_view in) -> std::string
{
	std::string out;

	for (auto c: in.substr(0, DKIM2_MAX_QUOTED_VALUE)) {
		auto uc = static_cast<unsigned char>(c);
		out.push_back(uc < 0x21 || uc >= 0x7f ? '?' : c);
	}

	return out;
}

/* A header or a sequence number for an error message */
static auto
dkim2_num(unsigned int num) -> std::string
{
	return num ? fmt::format("{}", num) : std::string{"?"};
}

}// anonymous namespace

struct rspamd_dkim2_chain_s {
	struct rspamd_task *task = nullptr;
	std::vector<raw_header_t> headers;  /* all header fields, from the top */
	std::vector<mi_entry_t> mis;        /* sorted by m=, mis[k] has m == k + 1 */
	std::vector<sig_header_t> sigs;     /* sorted by i=, sigs[k] has i == k + 1 */
	std::vector<std::string> sig_lines; /* canonical lines of sigs */
	ankerl::unordered_dense::map<std::string, dkim2_key_slot> keys;
	ankerl::unordered_dense::map<std::string, dkim2_policy_slot> policies;
	std::vector<dkim2_from_check> from_checks;
	struct rspamd_dkim2_verify_params params{};
	rspamd_dkim2_verify_cb cb = nullptr;
	void *ud = nullptr;
	unsigned int pending = 0;
	unsigned int ninstances = 0;
	unsigned int verified_instances = 0;
	std::size_t signature_work_budget = 0;
	bool latest_hashes_ok = false;
	bool envelope_ok = false;
	bool last_hop_only = false;
	bool finalized = false;
	/* Results of the synchronous (hash, envelope, timestamp, custody) checks */
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
	bool is_policy;
};

static void
dkim2_chain_dtor(void *p)
{
	delete static_cast<rspamd_dkim2_chain_s *>(p);
}

/*
 * Structural validation of the chain (Section 14.2); both vectors are sorted.
 * Returns the human-readable error.
 */
static auto
dkim2_validate_chain(const std::vector<mi_entry_t> &mis,
					 const std::vector<sig_entry_t> &sigs) -> std::optional<std::string>
{
	if (mis.empty()) {
		return "Message-Instance m=1 missing";
	}
	if (sigs.empty()) {
		return "DKIM2-Signature i=1 missing";
	}

	for (std::size_t k = 0; k < mis.size(); k++) {
		auto m = mis[k].parsed.m;

		if (k > 0 && m == mis[k - 1].parsed.m) {
			return fmt::format("Message-Instance m={} is duplicated", m);
		}
		if (m != k + 1) {
			return fmt::format("Message-Instance m={} missing", k + 1);
		}
	}

	unsigned int prev_m = 0;
	std::size_t nsig_sets = 0;

	for (std::size_t k = 0; k < sigs.size(); k++) {
		const auto &sig = sigs[k].parsed;

		if (k > 0 && sig.i == sigs[k - 1].parsed.i) {
			return fmt::format("DKIM2-Signature i={} is duplicated", sig.i);
		}
		if (sig.i != k + 1) {
			return fmt::format("DKIM2-Signature i={} missing", k + 1);
		}

		for (const auto &group: sig.sig_groups) {
			nsig_sets += group.size();
		}

		if (nsig_sets > DKIM2_MAX_SIG_SETS_TOTAL) {
			return fmt::format("DKIM2-Signature i={} syntax error: too many signatures "
							   "in the chain (max {})",
							   sig.i, DKIM2_MAX_SIG_SETS_TOTAL);
		}

		if (sig.m > mis.size()) {
			return fmt::format("Message-Instance m={} missing", sig.m);
		}
		if (sig.m < prev_m) {
			return fmt::format("DKIM2-Signature i={} syntax error: m= is lower than "
							   "in the previous field",
							   sig.i);
		}

		prev_m = sig.m;
	}

	if (sigs.back().parsed.m != mis.size()) {
		/* No signature covers the instances above its m= */
		return fmt::format("Message-Instance m={} is not signed", sigs.back().parsed.m + 1);
	}

	if (sigs.front().parsed.flags & DKIM2_SIG_FLAG_EXPLODED) {
		return "DKIM2-Signature i=1 has an exploded flag";
	}

	return std::nullopt;
}

rspamd_dkim2_chain_t *
rspamd_dkim2_chain_parse(struct rspamd_task *task, GError **err)
{
	struct rspamd_mime_header *mi_hdrs, *sig_hdrs;

	if (task->message == nullptr) {
		return nullptr;
	}

	mi_hdrs = rspamd_message_get_header_array(task, RSPAMD_DKIM2_MIHEADER, false);
	sig_hdrs = rspamd_message_get_header_array(task, RSPAMD_DKIM2_SIGNHEADER, false);

	if (mi_hdrs == nullptr && sig_hdrs == nullptr) {
		/* No DKIM2 headers at all */
		return nullptr;
	}

	auto set_err = [&](const std::string &what) -> rspamd_dkim2_chain_t * {
		g_set_error(err, DKIM2_ERROR, RSPAMD_DKIM2_PERMERROR, "%s", what.c_str());
		return nullptr;
	};

	/*
	 * The MIME parser is tolerant: it skips what it cannot understand, cuts
	 * values at stray characters and stops after a number of fields. Whatever
	 * it drops would not be covered by the header hash, so the header is
	 * read again here, strictly, and a message whose header is not a
	 * sequence of RFC 5322 fields cannot be verified.
	 */
	const auto &raw = MESSAGE_FIELD(task, raw_headers_content);
	auto headers = scan_headers(raw.begin != nullptr ? std::string_view{raw.begin, raw.len} : std::string_view{});

	if (!headers) {
		return set_err(fmt::format("message header cannot be verified: {}", headers.error()));
	}

	std::vector<mi_entry_t> mis;
	std::vector<sig_entry_t> sigs;

	for (const auto &hdr: *headers) {
		if (eq_icase(hdr.name, RSPAMD_DKIM2_MIHEADER)) {
			if (mis.size() >= RSPAMD_DKIM2_MAX_HOPS) {
				return set_err(fmt::format("too many Message-Instance header fields (max {})",
										   RSPAMD_DKIM2_MAX_HOPS));
			}

			if (hdr.value.size() > DKIM2_MAX_FIELD_LEN) {
				return set_err("Message-Instance m=? JSON is unacceptably complex");
			}

			auto parsed = parse_mi(hdr.value);

			if (!parsed) {
				return set_err(fmt::format("Message-Instance m={} {}",
										   dkim2_num(parsed.error().num), parsed.error().what));
			}

			mis.emplace_back(mi_entry_t{
				std::move(*parsed),
				canon_sig_line(RSPAMD_DKIM2_MIHEADER, hdr.value),
			});
		}
		else if (eq_icase(hdr.name, RSPAMD_DKIM2_SIGNHEADER)) {
			if (sigs.size() >= RSPAMD_DKIM2_MAX_HOPS) {
				return set_err(fmt::format("too many DKIM2-Signature header fields (max {})",
										   RSPAMD_DKIM2_MAX_HOPS));
			}

			if (hdr.value.size() > DKIM2_MAX_FIELD_LEN) {
				return set_err("DKIM2-Signature i=? syntax error: the field is too large");
			}

			auto parsed = parse_sig(hdr.value);

			if (!parsed) {
				return set_err(fmt::format("DKIM2-Signature i={} {}",
										   dkim2_num(parsed.error().num), parsed.error().what));
			}

			sigs.emplace_back(sig_entry_t{
				std::move(*parsed),
				canon_sig_line(RSPAMD_DKIM2_SIGNHEADER, hdr.value),
			});
		}
	}

	std::stable_sort(mis.begin(), mis.end(),
					 [](const mi_entry_t &a, const mi_entry_t &b) {
						 return a.parsed.m < b.parsed.m;
					 });
	std::stable_sort(sigs.begin(), sigs.end(),
					 [](const sig_entry_t &a, const sig_entry_t &b) {
						 return a.parsed.i < b.parsed.i;
					 });

	if (auto invalid = dkim2_validate_chain(mis, sigs)) {
		return set_err(*invalid);
	}

	auto *chain = new rspamd_dkim2_chain_s;
	rspamd_mempool_add_destructor(task->task_pool, dkim2_chain_dtor, chain);

	chain->headers = std::move(*headers);
	/* Moving the vector keeps the strings in place, but be explicit about it */
	for (auto &hdr: chain->headers) {
		if (!hdr.unfolded.empty()) {
			hdr.value = hdr.unfolded;
		}
	}

	chain->mis = std::move(mis);
	chain->sigs.reserve(sigs.size());
	chain->sig_lines.reserve(sigs.size());

	for (auto &entry: sigs) {
		chain->sigs.emplace_back(std::move(entry.parsed));
		chain->sig_lines.emplace_back(std::move(entry.canon_line));
	}

	msg_debug_dkim2("parsed DKIM2 chain: %z instances, %z signatures, last domain %s",
					chain->mis.size(), chain->sigs.size(),
					chain->sigs.back().domain.c_str());

	return chain;
}

unsigned int
rspamd_dkim2_chain_len(const rspamd_dkim2_chain_t *chain)
{
	return chain ? chain->sigs.size() : 0;
}

static auto
dkim2_message_body(struct rspamd_task *task) -> std::string_view
{
	const char *body_start = MESSAGE_FIELD(task, raw_headers_content).body_start;
	const char *msg_end = task->msg.begin + task->msg.len;

	if (body_start != nullptr && msg_end > body_start) {
		return std::string_view{body_start, static_cast<std::size_t>(msg_end - body_start)};
	}

	return {};
}

/*
 * Compute the header and body hashes (Sections 6.1, 6.2) of the message as it
 * was received
 */
static auto
dkim2_hash_current(const rspamd_dkim2_chain_t *chain, struct rspamd_task *task,
				   const EVP_MD *md) -> std::optional<dkim2_digests>
{
	dkim2_digests res;
	dkim2_digest digest{md};

	/* Body hash */
	body_canon_foreach(dkim2_message_body(task), [&](const char *p, std::size_t len) {
		digest.update(p, len);
	});
	res.body = digest.finish();

	/* Header hash */
	struct hdr_row {
		std::string lc_name;
		std::size_t order;
		const raw_header_t *hdr;
	};
	std::vector<hdr_row> rows;

	for (std::size_t k = 0; k < chain->headers.size(); k++) {
		const auto &hdr = chain->headers[k];

		if (!is_unsigned_header(hdr.name)) {
			rows.emplace_back(hdr_row{lc_string(hdr.name), k, &hdr});
		}
	}

	/*
	 * Ascending order of the names; header fields with the same name go in
	 * the order they were placed into the message, that is from the bottom of
	 * the header (oldest) to the top (newest)
	 */
	std::sort(rows.begin(), rows.end(), [](const hdr_row &a, const hdr_row &b) {
		auto cmp = a.lc_name.compare(b.lc_name);

		return cmp != 0 ? cmp < 0 : a.order > b.order;
	});

	for (const auto &row: rows) {
		digest.update(canon_hash_line(row.lc_name, row.hdr->value));
	}

	res.hdr = digest.finish();

	if (res.hdr.empty() || res.body.empty()) {
		return std::nullopt;
	}

	return res;
}

/*
 * Build the current (latest instance) message state for recipe application.
 * Only the headers participating in the hash are collected. Returns false if
 * the message exceeds the reconstruction limits.
 */
static bool
dkim2_build_current_state(const rspamd_dkim2_chain_t *chain,
						  struct rspamd_task *task,
						  const recipe_limits_t &limits,
						  dkim2_msg_state &state)
{
	for (const auto &hdr: chain->headers) {
		if (is_unsigned_header(hdr.name)) {
			continue;
		}

		auto &vec = state.headers[lc_string(hdr.name)];

		if (vec.size() >= limits.max_header_instances) {
			return false;
		}

		vec.emplace_back(hdr.value);
	}

	/* Recipe numbering is bottom-up: index 0 must be the bottom-most instance */
	for (auto &kv: state.headers) {
		std::reverse(kv.second.begin(), kv.second.end());
	}

	auto lines = split_body_lines(dkim2_message_body(task), limits.max_body_lines);

	if (!lines) {
		return false;
	}

	state.body_lines = std::move(*lines);

	return true;
}

/*
 * Compute the header and body hashes of a reconstructed message state,
 * charging the hashed octets to the work budget; nullopt if it is exhausted
 */
static auto
dkim2_hash_state(const dkim2_msg_state &state,
				 const EVP_MD *md,
				 std::size_t &work_budget) -> std::optional<dkim2_digests>
{
	dkim2_digests res;
	dkim2_digest digest{md};
	bool in_budget = true;

	/* Every element costs something, whatever its size is */
	auto charge = [&](std::size_t len) -> bool {
		auto cost = len + DKIM2_ELEMENT_COST;

		if (cost > work_budget) {
			in_budget = false;
			return false;
		}

		work_budget -= cost;

		return true;
	};

	/* Header hash: names in ascending order, instances bottom-up within a name */
	using hdr_entry_t = std::pair<std::string, std::vector<std::string_view>>;
	std::vector<const hdr_entry_t *> entries;
	entries.reserve(state.headers.size());

	for (const auto &kv: state.headers) {
		if (!kv.second.empty()) {
			entries.push_back(&kv);
		}
	}

	if (!charge(entries.size() * DKIM2_ELEMENT_COST)) {
		return std::nullopt;
	}

	std::sort(entries.begin(), entries.end(),
			  [](const hdr_entry_t *a, const hdr_entry_t *b) {
				  return a->first < b->first;
			  });

	for (const auto *entry: entries) {
		for (auto value: entry->second) {
			if (!charge(entry->first.size() + value.size())) {
				return std::nullopt;
			}

			digest.update(canon_hash_line(entry->first, value));
		}
	}

	res.hdr = digest.finish();

	/* Body hash: lines joined with CRLF, trailing empty lines ignored */
	auto nlines = state.body_lines.size();

	while (nlines > 0 && state.body_lines[nlines - 1].empty()) {
		nlines--;
	}

	if (nlines == 0) {
		digest.update("\r\n", 2);
	}

	for (std::size_t k = 0; k < nlines; k++) {
		const auto &line = state.body_lines[k];

		if (!charge(line.size())) {
			return std::nullopt;
		}

		digest.update(line);
		digest.update("\r\n", 2);
	}

	res.body = digest.finish();

	if (!in_budget || res.hdr.empty() || res.body.empty()) {
		return std::nullopt;
	}

	return res;
}

/*
 * Evaluate the h= tag of an instance against a message state (Section 14.7).
 * `compute(md)` returns the digests of the state, or nullopt if they cannot
 * be computed (then `no_digests` is set). Returns the result and, unless it is
 * a pass, the human-readable reason.
 */
template<typename Compute>
static auto
dkim2_eval_hashes(const mi_header_t &mi, Compute &&compute, bool &no_digests)
	-> std::pair<result_t, std::string>
{
	std::vector<result_t> group_results;
	std::vector<std::pair<result_t, std::string>> set_results;

	for (const auto &group: mi.hash_groups) {
		std::vector<result_t> results;

		for (const auto &hs: group) {
			const auto *md = dkim2_hash_md(hs.alg);
			auto res = result_t::pass;
			std::string reason;

			if (md == nullptr) {
				res = result_t::permerror;
				reason = fmt::format("Message-Instance m={} algorithm {} unknown", mi.m, hs.alg);
			}
			else {
				/* An algorithm cannot repeat in a field, so nothing to cache */
				auto digests = compute(md);

				if (!digests) {
					no_digests = true;
					res = result_t::permerror;
					reason = fmt::format("Message-Instance m={} hashes cannot be computed", mi.m);
				}
				else if (digests->hdr != hs.header_hash) {
					res = result_t::fail;
					reason = fmt::format("Message-Instance m={} header hash {} mismatch",
										 mi.m, hs.alg);
				}
				else if (digests->body != hs.body_hash) {
					res = result_t::fail;
					reason = fmt::format("Message-Instance m={} body hash {} mismatch",
										 mi.m, hs.alg);
				}
			}

			results.push_back(res);
			set_results.emplace_back(res, std::move(reason));
		}

		group_results.push_back(combine_all(results));
	}

	auto overall = combine_any(group_results);

	if (overall == result_t::pass) {
		return {overall, {}};
	}

	if (overall == result_t::fail && group_results.size() > 1) {
		return {overall, fmt::format("Message-Instance m={} no group of hashes passed", mi.m)};
	}

	for (auto &[res, reason]: set_results) {
		if (res == overall) {
			return {overall, std::move(reason)};
		}
	}

	return {overall, fmt::format("Message-Instance m={} no group of hashes passed", mi.m)};
}

/* Lowercase ASCII form (A-labels) of a domain, nullopt if it has none */
static auto
dkim2_alabel(struct rspamd_task *task, std::string_view domain) -> std::optional<std::string>
{
	auto is_ascii = std::all_of(domain.begin(), domain.end(), [](char c) {
		return static_cast<unsigned char>(c) < 0x80;
	});

	if (is_ascii) {
		return lc_string(domain);
	}

	unsigned int outlen = 0;
	const char *converted = rspamd_dns_resolver_idna_convert_utf8(task->resolver,
																  task->task_pool,
																  domain.data(), domain.size(),
																  &outlen);

	if (converted == nullptr) {
		return std::nullopt;
	}

	return lc_string(std::string_view{converted, outlen});
}

/*
 * Check that a From header field is Authentic for a signature (Sections 11,
 * 14.8). `values` are the unfolded values of all From header fields of the
 * message state that the signature is responsible for.
 */
static void
dkim2_check_from(rspamd_dkim2_chain_t *chain, struct rspamd_task *task,
				 std::span<const std::string_view> values, const sig_header_t &sig)
{
	auto not_authentic = [&](const char *what) {
		msg_info_dkim2("DKIM2 From header is not authentic for d=%s (i=%d): %s",
					   sig.domain.c_str(), sig.i, what);
		chain->merge_prelim(RSPAMD_DKIM2_FAIL,
							fmt::format("DKIM2-Signature i={} {}", sig.i, what));
	};

	if (values.empty()) {
		return not_authentic("matching From is not authentic");
	}
	if (values.size() > 1) {
		return not_authentic("From has more than one address");
	}

	auto value = values.front();

	if (!from_is_single_mailbox(value)) {
		/* Nothing or several things that look like addresses */
		return not_authentic(value.find('@') == std::string_view::npos ? "matching From is not authentic" : "From has more than one address");
	}

	auto *addrs = rspamd_email_address_from_mime(task->task_pool, value.data(),
												 value.size(), nullptr, -1);

	if (addrs == nullptr || addrs->len == 0) {
		return not_authentic("matching From is not authentic");
	}
	if (addrs->len > 1) {
		return not_authentic("From has more than one address");
	}

	const auto *addr = static_cast<const struct rspamd_email_address *>(g_ptr_array_index(addrs, 0));

	if (addr->domain == nullptr || addr->domain_len == 0) {
		return not_authentic("matching From is not authentic");
	}

	std::string_view raw_domain{addr->domain, addr->domain_len};

	if ((addr->flags & RSPAMD_EMAIL_ADDR_IP) || raw_domain.front() == '[') {
		return not_authentic("From uses a domain literal");
	}

	auto from_domain = dkim2_alabel(task, raw_domain);

	if (!from_domain || !valid_domain(*from_domain)) {
		return not_authentic("matching From is not authentic");
	}

	if (relaxed_domain_match(*from_domain, sig.domain)) {
		/* The signing domain is the From domain or its parent */
		return;
	}

	if (!relaxed_domain_match(sig.domain, *from_domain)) {
		return not_authentic("matching From is not authentic");
	}

	/* A subdomain signs for its parent: needs the Domain Policy Record */
	auto policy_name = fmt::format("_domainkey.{}", *from_domain);

	if (policy_name.size() > DKIM2_MAX_DNS_NAME) {
		return not_authentic("matching From is not authentic");
	}

	chain->policies.try_emplace(policy_name);
	chain->from_checks.emplace_back(dkim2_from_check{
		sig.i,
		std::move(*from_domain),
		std::move(policy_name),
	});
}

/* The lowest numbered signature whose m= covers the instance */
static auto
dkim2_sig_for_instance(const rspamd_dkim2_chain_t *chain, std::size_t m) -> const sig_header_t &
{
	for (const auto &sig: chain->sigs) {
		if (sig.m >= m) {
			return sig;
		}
	}

	/* Not reachable: the last signature covers the latest instance */
	return chain->sigs.back();
}

/*
 * Verify the hashes of the older message instances by recreating them with
 * the recipes, from the latest instance backwards (Section 13), and check
 * that the From header fields seen on the way are Authentic. A message with
 * an instance that cannot be recreated is not a Fully Verified DKIM2 Message.
 */
static void
dkim2_check_instances(rspamd_dkim2_chain_t *chain, struct rspamd_task *task)
{
	recipe_limits_t limits;
	auto nmis = chain->mis.size();

	/*
	 * The first instance MAY have a recipe for what was done to the message
	 * before it was signed (Section 12.1). There is nothing to recreate with
	 * it, but it is still required to be a valid one (Section 14.2).
	 */
	if (const auto &first = chain->mis.front().parsed; first.has_recipe) {
		auto decoded = first.recipe_b64.size() > limits.max_recipe_len / 3 * 4 + 4 ? std::nullopt : b64_decode(first.recipe_b64);
		auto recipe = decoded ? parse_recipe(*decoded, limits) : tl::make_unexpected(recipe_error_t{recipe_error_kind::invalid_json, "invalid base64"});

		if (!recipe) {
			auto reason = recipe.error().kind == recipe_error_kind::invalid_recipe
							  ? fmt::format("Message-Instance m=1 recipe {} is invalid",
											dkim2_quote(recipe.error().what))
							  : std::string{"Message-Instance m=1 contains invalid JSON"};

			msg_info_dkim2("DKIM2 instances are not verified: %s", reason.c_str());
			chain->merge_prelim(RSPAMD_DKIM2_PERMERROR, std::move(reason));

			return;
		}
	}

	if (nmis == 1) {
		/* Nothing to recreate; the only From was placed by the Originator */
		std::vector<std::string_view> from_values;

		for (const auto &hdr: chain->headers) {
			if (eq_icase(hdr.name, "from")) {
				from_values.emplace_back(hdr.value);
			}
		}

		dkim2_check_from(chain, task, from_values, chain->sigs.front());

		return;
	}

	auto work_budget = dkim2_bounded_budget(task->msg.len,
											DKIM2_RECIPE_BUDGET_FACTOR,
											DKIM2_RECIPE_MIN_BUDGET,
											DKIM2_RECIPE_MAX_BUDGET);

	auto stop = [&](enum rspamd_dkim2_result_code rcode, std::string reason) {
		msg_info_dkim2("DKIM2 instances are not verified: %s", reason.c_str());
		chain->merge_prelim(rcode, std::move(reason));
	};

	auto recipe_error = [&](std::size_t m, const recipe_error_t &rerr) {
		switch (rerr.kind) {
		case recipe_error_kind::invalid_json:
			msg_info_dkim2("invalid JSON in the recipe of instance m=%z: %s",
						   m, rerr.what.c_str());
			return fmt::format("Message-Instance m={} contains invalid JSON", m);
		case recipe_error_kind::invalid_recipe:
			return fmt::format("Message-Instance m={} recipe {} is invalid",
							   m, dkim2_quote(rerr.what));
		case recipe_error_kind::too_complex:
			break;
		}

		msg_info_dkim2("recipe of instance m=%z is over the limits: %s",
					   m, rerr.what.c_str());

		return fmt::format("Message-Instance m={} JSON is unacceptably complex", m);
	};

	dkim2_msg_state state;

	if (!dkim2_build_current_state(chain, task, limits, state)) {
		return stop(RSPAMD_DKIM2_PERMERROR,
					fmt::format("Message-Instance m={} JSON is unacceptably complex", nmis));
	}

	auto state_from = [&]() -> std::vector<std::string_view> {
		auto it = state.headers.find("from");

		return it == state.headers.end() ? std::vector<std::string_view>{} : it->second;
	};

	/* Reconstructed states reference recipe data, keep all recipes alive */
	std::vector<recipe_t> recipes;
	recipes.reserve(nmis - 1);

	for (auto m = nmis; m >= 2; m--) {
		const auto &mi = chain->mis[m - 1].parsed;
		const recipe_t *r = nullptr;

		if (mi.has_recipe) {
			if (mi.recipe_b64.size() > limits.max_recipe_len / 3 * 4 + 4) {
				return stop(RSPAMD_DKIM2_PERMERROR,
							fmt::format("Message-Instance m={} JSON is unacceptably complex", m));
			}

			auto decoded = b64_decode(mi.recipe_b64);

			if (!decoded) {
				return stop(RSPAMD_DKIM2_PERMERROR,
							fmt::format("Message-Instance m={} contains invalid JSON", m));
			}

			auto recipe = parse_recipe(*decoded, limits);

			if (!recipe) {
				return stop(RSPAMD_DKIM2_PERMERROR, recipe_error(m, recipe.error()));
			}

			recipes.emplace_back(std::move(*recipe));
			r = &recipes.back();
		}

		if (r != nullptr && r->find_header("from") != nullptr) {
			/* This instance has a From that its Reviser has placed */
			auto from_values = state_from();
			dkim2_check_from(chain, task, from_values, dkim2_sig_for_instance(chain, m));
		}

		/* Without a recipe the instance has changed nothing */
		if (r != nullptr) {
			if (r->body_null) {
				return stop(RSPAMD_DKIM2_PERMERROR,
							fmt::format("Message-Instance m={} has a null recipe", m));
			}

			for (const auto &[name, steps]: r->headers) {
				auto &vec = state.headers[name];
				auto out = apply_recipe_steps(vec, steps,
											  limits.max_header_instances, work_budget);

				if (!out) {
					return stop(RSPAMD_DKIM2_PERMERROR, recipe_error(m, out.error()));
				}

				vec = std::move(*out);
			}

			if (r->has_body) {
				auto out = apply_recipe_steps(state.body_lines, r->body,
											  limits.max_body_lines, work_budget);

				if (!out) {
					return stop(RSPAMD_DKIM2_PERMERROR, recipe_error(m, out.error()));
				}

				state.body_lines = std::move(*out);
			}
		}

		/* The state is now instance m-1; verify its hashes */
		const auto &prev_mi = chain->mis[m - 2].parsed;
		bool no_digests = false;
		auto [res, reason] = dkim2_eval_hashes(
			prev_mi,
			[&](const EVP_MD *md) {
				return dkim2_hash_state(state, md, work_budget);
			},
			no_digests);

		if (no_digests) {
			return stop(RSPAMD_DKIM2_PERMERROR,
						fmt::format("Message-Instance m={} JSON is unacceptably complex", m));
		}

		if (res != result_t::pass) {
			return stop(to_rcode(res), std::move(reason));
		}

		chain->verified_instances++;
		msg_debug_dkim2("verified reconstructed instance m=%z, work budget left %z",
						m - 1, work_budget);
	}

	/* The state is the original message: its From was placed by the Originator */
	auto from_values = state_from();
	dkim2_check_from(chain, task, from_values, chain->sigs.front());
}

/* Comparison key of an SMTP envelope address: domains go as A-labels (Section 18) */
static auto
dkim2_envelope_key(struct rspamd_task *task, std::string_view addr) -> std::string
{
	auto key = smtp_addr_key(addr);
	auto at_pos = key.rfind('@');

	if (at_pos != std::string::npos) {
		auto alabel = dkim2_alabel(task, std::string_view{key}.substr(at_pos + 1));

		if (alabel) {
			key.replace(at_pos + 1, std::string::npos, *alabel);
		}
	}

	return key;
}

/*
 * The SMTP envelope against the highest numbered signature (Section 14.4):
 * an exact match of MAIL FROM, and every RCPT TO must be listed in rt=
 */
static void
dkim2_check_envelope(rspamd_dkim2_chain_t *chain, struct rspamd_task *task)
{
	const auto &last = chain->sigs.back();
	const auto &params = chain->params;

	if (last.has_nd) {
		/* A trailing nd= is reported by the Chain of Custody check */
		return;
	}

	bool mail_from_ok = false, rcpt_ok = false;

	/*
	 * The two halves are checked independently, each one only if the MTA has
	 * told us that value: an address that we could not parse is known, and
	 * it does not match anything.
	 */
	if (params.have_mail_from) {
		/* The sender as it was on the wire, before any alias rewriting */
		const auto *from = task->from_envelope_orig ? task->from_envelope_orig : task->from_envelope;
		std::string_view smtp_from;

		if (from != nullptr && from->addr != nullptr && from->addr_len > 0) {
			smtp_from = std::string_view{from->addr, from->addr_len};
		}

		if (from == nullptr ||
			dkim2_envelope_key(task, smtp_from) != smtp_addr_key(last.mf)) {
			msg_info_dkim2("MAIL FROM does not match mf= of the last DKIM2 signature");
			chain->merge_prelim(RSPAMD_DKIM2_FAIL,
								fmt::format("DKIM2-Signature i={} MAIL FROM {} did not match",
											last.i, from ? dkim2_quote(smtp_from) : "?"));
		}
		else {
			mail_from_ok = true;
		}
	}

	if (params.have_rcpt) {
		ankerl::unordered_dense::set<std::string> rt_index;
		rt_index.reserve(last.rt.size());

		for (const auto &rt: last.rt) {
			rt_index.emplace(smtp_addr_key(rt));
		}

		unsigned int i, nchecked = 0;
		struct rspamd_email_address *rcpt;
		bool has_original = false;

		rcpt_ok = true;

		if (task->rcpt_envelope != nullptr) {
			/* Recipients as they were on the wire, if aliases have added more */
			PTR_ARRAY_FOREACH(task->rcpt_envelope, i, rcpt)
			{
				has_original = has_original || (rcpt->flags & RSPAMD_EMAIL_ADDR_ORIGINAL);
			}

			PTR_ARRAY_FOREACH(task->rcpt_envelope, i, rcpt)
			{
				if (rcpt->addr == nullptr ||
					(has_original && !(rcpt->flags & RSPAMD_EMAIL_ADDR_ORIGINAL))) {
					continue;
				}

				std::string_view rcpt_sv{rcpt->addr, rcpt->addr_len};

				nchecked++;

				if (!rt_index.contains(dkim2_envelope_key(task, rcpt_sv))) {
					msg_info_dkim2("RCPT TO <%*s> not found in rt= of the last DKIM2 signature",
								   (int) rcpt->addr_len, rcpt->addr);
					chain->merge_prelim(RSPAMD_DKIM2_FAIL,
										fmt::format("DKIM2-Signature i={} RCPT TO {} did not match",
													last.i, dkim2_quote(rcpt_sv)));
					rcpt_ok = false;
					break;
				}
			}
		}

		if (rcpt_ok && nchecked == 0) {
			/*
			 * There were recipients, but none of them could be parsed and
			 * all were dropped: they cannot be in rt= either
			 */
			msg_info_dkim2("RCPT TO values of the message cannot be matched with rt=");
			chain->merge_prelim(RSPAMD_DKIM2_FAIL,
								fmt::format("DKIM2-Signature i={} RCPT TO ? did not match",
											last.i));
			rcpt_ok = false;
		}
	}

	chain->envelope_ok = mail_from_ok && rcpt_ok;
}

/*
 * Section 14.3: no signature may be older than 14 days or come from more
 * than a day ahead of the moment the message was accepted
 */
static void
dkim2_check_timestamps(rspamd_dkim2_chain_t *chain, struct rspamd_task *task)
{
	auto now = static_cast<std::uint64_t>(task->task_timestamp > 0 ? task->task_timestamp : time(nullptr));
	std::uint64_t max_age = chain->params.max_age ? chain->params.max_age : DKIM2_DEFAULT_MAX_AGE;
	std::uint64_t max_future = chain->params.time_jitter ? chain->params.time_jitter : DKIM2_DEFAULT_MAX_FUTURE;

	for (const auto &sig: chain->sigs) {
		if (sig.t > now && sig.t - now > max_future) {
			chain->merge_prelim(RSPAMD_DKIM2_FAIL,
								fmt::format("DKIM2-Signature i={} signature is from the future",
											sig.i));
			break;
		}
		if (sig.t < now && now - sig.t > max_age) {
			chain->merge_prelim(RSPAMD_DKIM2_FAIL,
								fmt::format("DKIM2-Signature i={} signature expired", sig.i));
			break;
		}
	}
}

#ifdef DKIM2_HAVE_MLDSA
/* Pure ML-DSA-44 over the signature input with the "DKIM2" context (Section 3.4) */
static auto
dkim2_verify_mldsa44(std::string_view pk, std::string_view sig, std::string_view input) -> result_t
{
	static const unsigned char ctx_string[] = {'D', 'K', 'I', 'M', '2'};
	auto res = result_t::permerror;
	auto *pkey = EVP_PKEY_new_raw_public_key_ex(nullptr, "ML-DSA-44", nullptr,
												reinterpret_cast<const unsigned char *>(pk.data()),
												pk.size());
	auto *md_ctx = EVP_MD_CTX_new();

	if (pkey != nullptr && md_ctx != nullptr) {
		OSSL_PARAM params[] = {
			OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
											  const_cast<unsigned char *>(ctx_string),
											  sizeof(ctx_string)),
			OSSL_PARAM_construct_end(),
		};

		if (EVP_DigestVerifyInit_ex(md_ctx, nullptr, nullptr, nullptr, nullptr,
									pkey, params) == 1) {
			auto rc = EVP_DigestVerify(md_ctx,
									   reinterpret_cast<const unsigned char *>(sig.data()),
									   sig.size(),
									   reinterpret_cast<const unsigned char *>(input.data()),
									   input.size());
			res = rc == 1 ? result_t::pass : result_t::fail;
		}
	}

	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(pkey);
	ERR_clear_error();

	return res;
}
#endif

/*
 * Check one signature of a hop (Section 14.6 steps 3 and 4): the result and,
 * unless it is a pass, the human-readable reason
 */
static auto
dkim2_verify_sig_set(rspamd_dkim2_chain_t *chain,
					 const sig_header_t &sig,
					 const sig_set_t &ss,
					 const unsigned char *sha256_digest,
					 std::string_view raw_input) -> std::pair<result_t, std::string>
{
	struct rspamd_task *task = chain->task;
	auto key_type = sig_alg_key_type(ss.alg);

#ifndef DKIM2_HAVE_MLDSA
	if (ss.alg == mldsa44_alg_name) {
		/* Not implemented by the crypto library in use */
		key_type = {};
	}
#endif

	if (key_type.empty()) {
		return {result_t::permerror,
				fmt::format("DKIM2-Signature i={} selector {} algorithm unknown",
							sig.i, ss.selector)};
	}

	auto slot_it = chain->keys.find(lc_string(fmt::format("{}._domainkey.{}",
														  ss.selector, sig.domain)));

	if (slot_it == chain->keys.end()) {
		/* Should not happen: all names are inserted in chain_verify */
		return {result_t::permerror,
				fmt::format("DKIM2-Signature i={} public key {} does not exist",
							sig.i, ss.selector)};
	}

	const auto &slot = slot_it->second;

	if (slot.rcode != RSPAMD_DKIM2_PASS) {
		return {from_rcode(slot.rcode),
				fmt::format("DKIM2-Signature i={} public key {} {}",
							sig.i, ss.selector, slot.problem)};
	}

	if (slot.k != key_type) {
		return {result_t::permerror,
				fmt::format("DKIM2-Signature i={} public key {} algorithm mismatch",
							sig.i, ss.selector)};
	}

	auto incorrect = [&]() -> std::pair<result_t, std::string> {
		msg_info_dkim2("DKIM2 signature i=%d did not verify; d=%s, selector=%s, alg=%s",
					   sig.i, sig.domain.c_str(), ss.selector.c_str(), ss.alg.c_str());

		return {result_t::fail,
				fmt::format("DKIM2-Signature i={} selector {} incorrect signature",
							sig.i, ss.selector)};
	};

	if (ss.alg == rsa_alg_name) {
		GError *err = nullptr;

		if (!rspamd_cryptobox_verify_evp_rsa(NID_sha256,
											 reinterpret_cast<const unsigned char *>(ss.sig.data()),
											 ss.sig.size(),
											 sha256_digest, 32,
											 static_cast<EVP_PKEY *>(rspamd_dkim_key_evp(slot.key)),
											 &err)) {
			ERR_clear_error();

			if (err != nullptr) {
				auto reason = fmt::format("DKIM2-Signature i={} selector {} cannot be verified: {}",
										  sig.i, ss.selector, err->message);
				g_error_free(err);

				return {result_t::permerror, std::move(reason)};
			}

			return incorrect();
		}
	}
	else if (ss.alg == ed25519_alg_name) {
		gsize pklen = 0;
		const unsigned char *pk = rspamd_dkim_key_eddsa(slot.key, &pklen);

		if (pk == nullptr || pklen != crypto_sign_publickeybytes()) {
			return {result_t::permerror,
					fmt::format("DKIM2-Signature i={} public key {} is malformed",
								sig.i, ss.selector)};
		}

		if (ss.sig.size() != crypto_sign_bytes() ||
			!rspamd_cryptobox_verify(reinterpret_cast<const unsigned char *>(ss.sig.data()),
									 ss.sig.size(),
									 sha256_digest, 32,
									 pk)) {
			return incorrect();
		}
	}
	else {
#ifdef DKIM2_HAVE_MLDSA
		if (ss.sig.size() != DKIM2_MLDSA44_SIG_LEN) {
			return incorrect();
		}

		/* The whole input is hashed again for every such signature */
		if (raw_input.size() > chain->signature_work_budget) {
			return {result_t::permerror,
					fmt::format("DKIM2-Signature i={} signature input is too large", sig.i)};
		}

		chain->signature_work_budget -= raw_input.size();

		auto res = dkim2_verify_mldsa44(slot.raw_pk, ss.sig, raw_input);

		if (res == result_t::fail) {
			return incorrect();
		}
		if (res != result_t::pass) {
			return {res,
					fmt::format("DKIM2-Signature i={} public key {} is malformed",
								sig.i, ss.selector)};
		}
#else
		(void) raw_input;
#endif
	}

	return {result_t::pass, {}};
}

static void
dkim2_verify_one_hop(rspamd_dkim2_chain_t *chain,
					 std::size_t hop_idx,
					 struct rspamd_dkim2_hop_result *hop)
{
	struct rspamd_task *task = chain->task;
	const auto &sig = chain->sigs[hop_idx];
	unsigned char digest[EVP_MAX_MD_SIZE];

	auto set_hop = [&](result_t res, std::string_view reason) {
		hop->rcode = to_rcode(res);
		hop->fail_reason = res == result_t::pass ? nullptr : rspamd_mempool_strdup(task->task_pool, std::string{reason}.c_str());
	};

	hop->rcode = RSPAMD_DKIM2_PASS;
	hop->fail_reason = nullptr;
	hop->idx = sig.i;
	hop->domain = rspamd_mempool_strdup(task->task_pool, sig.domain.c_str());
	hop->selector = rspamd_mempool_strdup(task->task_pool,
										  sig.sig_groups.front().front().selector.c_str());

	/*
	 * The signature input: the instances up to m=, the signatures below i=
	 * and this field with the signature values blanked (Section 14.6). The
	 * input of every hop repeats the previous ones, so the octets are charged
	 * to a budget shared by the whole chain.
	 */
	bool need_raw = false;

#ifdef DKIM2_HAVE_MLDSA
	/* ML-DSA signs the input itself, not its hash */
	for (const auto &group: sig.sig_groups) {
		for (const auto &ss: group) {
			need_raw = need_raw || ss.alg == mldsa44_alg_name;
		}
	}
#endif

	auto *md_ctx = EVP_MD_CTX_new();
	std::string raw_input;
	std::size_t input_size = 0;
	bool budget_exceeded = false;
	bool digest_ok = md_ctx != nullptr &&
					 EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) == 1;

	auto update_digest = [&](std::string_view data) {
		if (!digest_ok) {
			return;
		}

		if (data.size() > chain->signature_work_budget) {
			budget_exceeded = true;
			digest_ok = false;
			return;
		}

		chain->signature_work_budget -= data.size();
		input_size += data.size();

		if (need_raw) {
			raw_input.append(data);
		}

		digest_ok = EVP_DigestUpdate(md_ctx, data.data(), data.size()) == 1;
	};

	for (std::size_t k = 0; k < sig.m; k++) {
		update_digest(chain->mis[k].canon_line);
	}
	for (std::size_t k = 0; k < hop_idx; k++) {
		update_digest(chain->sig_lines[k]);
	}

	update_digest(blank_sig_values(chain->sig_lines[hop_idx]));

	unsigned int digest_len = 0;

	digest_ok = digest_ok && EVP_DigestFinal_ex(md_ctx, digest, &digest_len) == 1 &&
				digest_len == 32;
	EVP_MD_CTX_free(md_ctx);

	if (!digest_ok) {
		ERR_clear_error();
		set_hop(result_t::permerror,
				budget_exceeded
					? fmt::format("DKIM2-Signature i={} signature input is too large", sig.i)
					: fmt::format("DKIM2-Signature i={} signature input cannot be hashed", sig.i));
		return;
	}

	msg_debug_dkim2("hop i=%d: signature input is %z bytes; work budget left %z",
					sig.i, input_size, chain->signature_work_budget);

	/* Section 14.6 steps 5-7: `,` lists first, then the `|` groups */
	std::vector<result_t> group_results;
	std::vector<std::pair<result_t, std::string>> set_results;

	for (const auto &group: sig.sig_groups) {
		std::vector<result_t> results;

		for (const auto &ss: group) {
			auto set_res = dkim2_verify_sig_set(chain, sig, ss, digest, raw_input);

			results.push_back(set_res.first);
			set_results.emplace_back(std::move(set_res));
		}

		group_results.push_back(combine_all(results));
	}

	auto overall = combine_any(group_results);

	if (overall == result_t::pass) {
		return;
	}

	if (overall == result_t::fail && group_results.size() > 1) {
		set_hop(overall, fmt::format("DKIM2-Signature i={} no group of signatures passed", sig.i));
		return;
	}

	for (const auto &[res, reason]: set_results) {
		if (res == overall) {
			set_hop(overall, reason);
			return;
		}
	}

	set_hop(overall, fmt::format("DKIM2-Signature i={} no group of signatures passed", sig.i));
}

static void
dkim2_finalize(rspamd_dkim2_chain_t *chain)
{
	struct rspamd_task *task = chain->task;
	auto nhops = chain->sigs.size();

	if (chain->finalized) {
		return;
	}

	chain->finalized = true;

	auto *hops = rspamd_mempool_alloc_array_type(task->task_pool, nhops,
												 struct rspamd_dkim2_hop_result);
	auto *res = rspamd_mempool_alloc0_type(task->task_pool,
										   struct rspamd_dkim2_verify_result);

	for (std::size_t k = 0; k < nhops; k++) {
		if (chain->last_hop_only && k + 1 != nhops) {
			/* The outcome is known already, see rspamd_dkim2_chain_verify */
			hops[k].rcode = RSPAMD_DKIM2_NONE;
			hops[k].fail_reason = nullptr;
			hops[k].idx = chain->sigs[k].i;
			hops[k].domain = rspamd_mempool_strdup(task->task_pool,
												   chain->sigs[k].domain.c_str());
			hops[k].selector = nullptr;
			continue;
		}

		dkim2_verify_one_hop(chain, k, &hops[k]);

		if (hops[k].rcode != RSPAMD_DKIM2_PASS) {
			chain->merge_prelim(hops[k].rcode,
								hops[k].fail_reason ? hops[k].fail_reason : "");
		}
	}

	/* The From fields that depend on the Domain Policy Records (Section 14.8) */
	for (const auto &check: chain->from_checks) {
		auto slot_it = chain->policies.find(check.policy_name);

		if (slot_it == chain->policies.end()) {
			/* Cannot happen, but must never mean that the From is fine */
			chain->merge_prelim(RSPAMD_DKIM2_TEMPERROR,
								fmt::format("DKIM2-Signature i={} policy for {} unavailable",
											check.sig_i, check.from_domain));
			continue;
		}

		const auto &slot = slot_it->second;

		if (slot.rcode == RSPAMD_DKIM2_TEMPERROR) {
			chain->merge_prelim(RSPAMD_DKIM2_TEMPERROR,
								fmt::format("DKIM2-Signature i={} policy for {} {}",
											check.sig_i, check.from_domain, slot.problem));
		}
		else if (slot.rcode != RSPAMD_DKIM2_PASS) {
			chain->merge_prelim(RSPAMD_DKIM2_PERMERROR,
								fmt::format("DKIM2-Signature i={} {} for {} policy",
											check.sig_i, slot.problem, check.from_domain));
		}
		else if (slot.strict) {
			chain->merge_prelim(RSPAMD_DKIM2_FAIL,
								fmt::format("DKIM2-Signature i={} From {} forbids subdomain signing",
											check.sig_i, check.from_domain));
		}
	}

	const auto &last = chain->sigs.back();

	res->rcode = chain->prelim_rcode;
	res->fail_reason = chain->prelim_reason.empty() ? nullptr : rspamd_mempool_strdup(task->task_pool, chain->prelim_reason.c_str());
	res->nhops = nhops;
	res->hops = hops;
	res->ninstances = chain->ninstances;
	res->verified_instances = chain->verified_instances;
	/* Section 13.2 */
	res->provisional = chain->latest_hashes_ok && chain->envelope_ok &&
					   hops[nhops - 1].rcode == RSPAMD_DKIM2_PASS && !last.has_nd &&
					   (smtp_addr_is_null(last.mf) ||
						relaxed_domain_match(smtp_addr_domain(last.mf), last.domain));

	msg_debug_dkim2("DKIM2 chain verification finished: rcode=%d, %z hops",
					(int) res->rcode, nhops);

	chain->cb(task, res, chain->ud);
}

/*
 * Signers MUST use the public exponent 65537 (Section 3.2); a key with
 * another one is not a DKIM2 key, and a huge exponent makes a verification
 * as expensive as signing
 */
static auto
dkim2_rsa_exponent_ok(EVP_PKEY *pkey) -> bool
{
	bool ok = false;

	if (pkey == nullptr) {
		return false;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	BIGNUM *e = nullptr;

	if (EVP_PKEY_get_bn_param(pkey, "e", &e) == 1 && e != nullptr) {
		ok = BN_is_word(e, RSA_F4);
	}

	BN_free(e);
#else
	const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
	const BIGNUM *e = nullptr;

	if (rsa != nullptr) {
		RSA_get0_key(rsa, nullptr, &e, nullptr);
		ok = e != nullptr && BN_is_word(e, RSA_F4);
	}
#endif

	ERR_clear_error();

	return ok;
}

static void
dkim2_key_reply(struct rdns_reply *reply, dkim2_key_slot &slot)
{
	if (reply->code == RDNS_RC_NXDOMAIN || reply->code == RDNS_RC_NOREC) {
		slot.rcode = RSPAMD_DKIM2_PERMERROR;
		slot.problem = "does not exist";
		return;
	}

	if (reply->code != RDNS_RC_NOERROR) {
		slot.rcode = RSPAMD_DKIM2_TEMPERROR;
		slot.problem = "could not be fetched";
		return;
	}

	/* Records that are not DKIM1 ones are ignored; just one may remain (Section 3.7) */
	struct rdns_reply_entry *elt;
	const char *txt = nullptr;
	key_record_t record;
	auto status = record_status::ok;
	unsigned int nrecords = 0;

	slot.rcode = RSPAMD_DKIM2_PERMERROR;

	LL_FOREACH(reply->entries, elt)
	{
		if (elt->type != RDNS_REQUEST_TXT || elt->content.txt.data == nullptr) {
			continue;
		}

		if (txt != nullptr && strcmp(txt, elt->content.txt.data) == 0) {
			/* An RRset has no duplicates, but a test resolver can give them */
			continue;
		}

		key_record_t cur_record;
		auto cur_status = parse_key_record(elt->content.txt.data, cur_record);

		if (cur_status == record_status::ignored) {
			continue;
		}

		if (++nrecords > 1) {
			slot.problem = "has multiple records";
			return;
		}

		txt = elt->content.txt.data;
		record = std::move(cur_record);
		status = cur_status;
	}

	if (nrecords == 0) {
		slot.problem = "does not exist";
		return;
	}
	if (status != record_status::ok) {
		slot.problem = "has a syntax error";
		return;
	}
	if (record.revoked) {
		slot.problem = "has been revoked";
		return;
	}

	slot.k = record.k;
	slot.problem = "is malformed";

	if (record.k == "rsa" || record.k == "ed25519") {
		GError *err = nullptr;
		std::size_t keylen = 0;

		slot.key = rspamd_dkim_parse_key(txt, &keylen, &err);

		if (err != nullptr) {
			g_error_free(err);
		}

		auto expected = record.k == "rsa" ? RSPAMD_DKIM_KEY_RSA : RSPAMD_DKIM_KEY_EDDSA;

		if (slot.key == nullptr || rspamd_dkim_key_get_type(slot.key) != expected) {
			return;
		}

		if (expected == RSPAMD_DKIM_KEY_RSA &&
			!dkim2_rsa_exponent_ok(static_cast<EVP_PKEY *>(rspamd_dkim_key_evp(slot.key)))) {
			return;
		}
	}
	else if (record.k == "mldsa44") {
		auto pk = b64_decode(record.p);

		if (!pk || pk->size() != DKIM2_MLDSA44_PK_LEN) {
			return;
		}

		slot.raw_pk = std::move(*pk);
	}
	/* Any other key type cannot match a signature algorithm that we know */

	slot.rcode = RSPAMD_DKIM2_PASS;
	slot.problem = "";
}

static void
dkim2_policy_reply(struct rdns_reply *reply, dkim2_policy_slot &slot)
{
	if (reply->code == RDNS_RC_NXDOMAIN || reply->code == RDNS_RC_NOREC) {
		/* No Domain Policy Record: subdomains are authorized */
		slot.rcode = RSPAMD_DKIM2_PASS;
		return;
	}

	if (reply->code != RDNS_RC_NOERROR) {
		slot.rcode = RSPAMD_DKIM2_TEMPERROR;
		slot.problem = "unavailable";
		return;
	}

	struct rdns_reply_entry *elt;
	const char *txt = nullptr;
	unsigned int nrecords = 0;

	slot.rcode = RSPAMD_DKIM2_PASS;

	LL_FOREACH(reply->entries, elt)
	{
		if (elt->type != RDNS_REQUEST_TXT || elt->content.txt.data == nullptr) {
			continue;
		}

		if (txt != nullptr && strcmp(txt, elt->content.txt.data) == 0) {
			/* See dkim2_key_reply */
			continue;
		}

		policy_record_t record;
		auto status = parse_policy_record(elt->content.txt.data, record);

		if (status == record_status::ignored) {
			continue;
		}

		txt = elt->content.txt.data;

		if (++nrecords > 1) {
			slot.rcode = RSPAMD_DKIM2_PERMERROR;
			slot.problem = "multiple records";
			return;
		}

		if (status != record_status::ok) {
			slot.rcode = RSPAMD_DKIM2_PERMERROR;
			slot.problem = "invalid record";
		}

		slot.strict = record.strict;
	}
}

static void
dkim2_dns_cb(struct rdns_reply *reply, void *arg)
{
	auto *cbd = static_cast<dkim2_dns_cbdata *>(arg);
	auto *chain = cbd->chain;
	struct rspamd_task *task = chain->task;

	if (cbd->is_policy) {
		auto slot_it = chain->policies.find(cbd->dns_name);

		if (slot_it != chain->policies.end()) {
			dkim2_policy_reply(reply, slot_it->second);
			msg_debug_dkim2("DKIM2 policy %s: rcode=%d, strict=%d", cbd->dns_name,
							(int) slot_it->second.rcode, (int) slot_it->second.strict);
		}
	}
	else {
		auto slot_it = chain->keys.find(cbd->dns_name);

		if (slot_it != chain->keys.end()) {
			dkim2_key_reply(reply, slot_it->second);
			msg_debug_dkim2("DKIM2 key %s: %s", cbd->dns_name,
							slot_it->second.rcode == RSPAMD_DKIM2_PASS ? "fetched" : slot_it->second.problem);
		}
	}

	if (chain->pending > 0 && --chain->pending == 0) {
		dkim2_finalize(chain);
	}
}

bool rspamd_dkim2_chain_verify(rspamd_dkim2_chain_t *chain,
							   struct rspamd_task *task,
							   const struct rspamd_dkim2_verify_params *params,
							   rspamd_dkim2_verify_cb cb,
							   void *ud)
{
	if (chain == nullptr || cb == nullptr || task->message == nullptr ||
		chain->cb != nullptr) {
		/* Nothing to verify, or the chain has been already used */
		return false;
	}

	chain->task = task;
	chain->cb = cb;
	chain->ud = ud;
	chain->signature_work_budget = dkim2_bounded_budget(task->msg.len,
														DKIM2_SIGNATURE_BUDGET_FACTOR,
														DKIM2_SIGNATURE_MIN_BUDGET,
														DKIM2_SIGNATURE_MAX_BUDGET);

	if (params != nullptr) {
		chain->params = *params;
	}

	/* Synchronous checks first */
	chain->ninstances = chain->mis.size();

	bool no_digests = false;
	auto [latest_res, latest_reason] = dkim2_eval_hashes(
		chain->mis.back().parsed,
		[&](const EVP_MD *md) {
			return dkim2_hash_current(chain, task, md);
		},
		no_digests);

	if (latest_res == result_t::pass) {
		chain->latest_hashes_ok = true;
		chain->verified_instances = 1;
		/* Recreate and verify the older instances, check the From fields */
		dkim2_check_instances(chain, task);
	}
	else {
		msg_info_dkim2("DKIM2 hashes of the message do not verify: %s",
					   latest_reason.c_str());
		chain->merge_prelim(to_rcode(latest_res), std::move(latest_reason));
	}

	dkim2_check_timestamps(chain, task);
	dkim2_check_envelope(chain, task);

	if (auto broken = check_custody(chain->sigs)) {
		msg_info_dkim2("DKIM2 chain of custody is broken: %s", broken->c_str());
		chain->merge_prelim(RSPAMD_DKIM2_FAIL, std::move(*broken));
	}

	if (chain->prelim_rcode == RSPAMD_DKIM2_FAIL) {
		/*
		 * Nothing can turn a FAIL into another result, and a Verifier MAY
		 * cease verifying once the outcome is known (Section 14.1): do not
		 * spend DNS requests and signature checks on such a message. Only the
		 * last signature is still verified, as it tells if the message is
		 * Provisionally Verified.
		 */
		chain->last_hop_only = true;
		chain->policies.clear();
		chain->from_checks.clear();
	}

	/* Collect all unique key names */
	for (const auto &sig: chain->sigs) {
		if (chain->last_hop_only && &sig != &chain->sigs.back()) {
			continue;
		}

		for (const auto &group: sig.sig_groups) {
			for (const auto &ss: group) {
				if (sig_alg_key_type(ss.alg).empty()) {
					/* Do not fetch keys for unknown algorithms */
					continue;
				}

				auto dns_name = lc_string(fmt::format("{}._domainkey.{}",
													  ss.selector, sig.domain));
				auto [slot_it, inserted] = chain->keys.try_emplace(std::move(dns_name));

				if (inserted && slot_it->first.size() > DKIM2_MAX_DNS_NAME) {
					/* Not a name that can exist in DNS */
					slot_it->second.rcode = RSPAMD_DKIM2_PERMERROR;
					slot_it->second.problem = "does not exist";
				}
			}
		}
	}

	/*
	 * The extra reference keeps the chain from being finalized by a reply
	 * that arrives while the requests are still being made
	 */
	chain->pending = 1;

	auto make_request = [&](const std::string &name, bool is_policy) -> bool {
		auto *cbd = rspamd_mempool_alloc_type(task->task_pool, struct dkim2_dns_cbdata);

		cbd->chain = chain;
		cbd->dns_name = rspamd_mempool_strdup(task->task_pool, name.c_str());
		cbd->is_policy = is_policy;
		chain->pending++;

		if (!rspamd_dns_resolver_request_task(task, dkim2_dns_cb, cbd,
											  RDNS_REQUEST_TXT, cbd->dns_name)) {
			chain->pending--;
			return false;
		}

		return true;
	};

	for (auto &kv: chain->keys) {
		if (kv.second.rcode == RSPAMD_DKIM2_PERMERROR) {
			continue;
		}

		if (!make_request(kv.first, false)) {
			kv.second.rcode = RSPAMD_DKIM2_TEMPERROR;
			kv.second.problem = "could not be fetched";
		}
	}

	for (auto &kv: chain->policies) {
		if (!make_request(kv.first, true)) {
			kv.second.rcode = RSPAMD_DKIM2_TEMPERROR;
			kv.second.problem = "unavailable";
		}
	}

	if (--chain->pending == 0) {
		/* No DNS requests are in flight: finalize synchronously */
		dkim2_finalize(chain);
	}

	return true;
}
