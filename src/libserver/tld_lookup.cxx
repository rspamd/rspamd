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

#include "config.h"
#include "tld_lookup.h"
#include "logger.h"
#include "libutil/str_util.h"
#include "libutil/cxx/hash_util.hxx"

#include "contrib/ankerl/unordered_dense.h"

#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr std::uint8_t FL_EXACT = 0x1;
/* Set on the parent key `foo` of a `*.foo` rule */
constexpr std::uint8_t FL_WILDCARD = 0x2;
constexpr std::uint8_t FL_EXCEPTION = 0x4;
constexpr std::uint8_t FL_PRIVATE = 0x8;

using rules_map = ankerl::unordered_dense::map<std::string, std::uint8_t,
											   rspamd::smart_str_hash, rspamd::smart_str_equal>;
using labels_set = ankerl::unordered_dense::set<std::string,
												rspamd::smart_str_hash, rspamd::smart_str_equal>;

/* Suffix rules never exceed 6 labels, +1 for a wildcard child */
constexpr unsigned int max_suffix_labels = 7;

/*
 * A lookup result in terms of labels counted from the right: label 0 is the
 * rightmost one. Case folding may change byte offsets but never the label
 * structure, so labels are the safe currency between the folded copy used
 * for probing and the original host used for the output tokens.
 */
struct lookup_result {
	unsigned int suffix_label;
	unsigned int reg_label;
	unsigned int flags;
};

/*
 * Lowercased copy of a host for probing: rules are stored folded with
 * rspamd_str_lc_utf8, which never grows a string (length-increasing case
 * mappings are kept as is), so the copy always fits the original size and
 * ordinary hosts stay on the stack.
 */
struct folded_host {
	explicit folded_host(std::string_view host)
	{
		char *dst = stack_buf.data();

		if (host.size() > stack_buf.size()) {
			heap_buf.resize(host.size());
			dst = heap_buf.data();
		}

		memcpy(dst, host.data(), host.size());

		/* The ICU based folding costs a per-codepoint function call, so keep
		 * the dominant all-ASCII case on the table based path */
		unsigned int len;
		if (!rspamd_str_has_8bit((const unsigned char *) dst, host.size())) {
			len = rspamd_str_lc(dst, (unsigned int) host.size());
		}
		else {
			len = rspamd_str_lc_utf8(dst, (unsigned int) host.size());
		}

		folded = std::string_view{dst, len};
	}

	std::string_view folded;

private:
	std::array<char, 256> stack_buf;
	std::string heap_buf;
};

/* Byte offset of the label `nright` positions from the right (0 = last) */
auto right_label_offset(std::string_view host, unsigned int nright) -> std::size_t
{
	auto search_end = host.size();

	for (unsigned int i = 0;; i++) {
		auto dot = search_end == 0 ? std::string_view::npos
								   : host.rfind('.', search_end - 1);

		if (dot == std::string_view::npos) {
			return 0;
		}
		if (i == nright) {
			return dot + 1;
		}

		search_end = dot;
	}
}

} /* anonymous namespace */

struct rspamd_tld_lookup {
	rules_map rules;
	labels_set final_labels;
	unsigned int nrules = 0;

	auto add_rule(std::string_view rule, bool in_private) -> void
	{
		auto flags_of = [in_private](std::uint8_t fl) -> std::uint8_t {
			return in_private ? (fl | FL_PRIVATE) : fl;
		};

		if (rule.empty()) {
			return;
		}

		if (rule.front() == '!') {
			rule.remove_prefix(1);
			if (rule.empty()) {
				return;
			}
			rules[std::string{rule}] |= flags_of(FL_EXCEPTION);
		}
		else if (rule.front() == '*') {
			auto dot = rule.find('.');
			if (dot == std::string_view::npos || dot + 1 == rule.size()) {
				msg_err("got bad star suffix rule, skip it: %*s",
						(int) rule.size(), rule.data());
				return;
			}
			rule.remove_prefix(dot + 1);
			rules[std::string{rule}] |= flags_of(FL_WILDCARD);
		}
		else {
			rules[std::string{rule}] |= flags_of(FL_EXACT);
		}

		auto last_dot = rule.rfind('.');
		auto label = last_dot == std::string_view::npos ? rule : rule.substr(last_dot + 1);
		if (!label.empty()) {
			final_labels.emplace(label);
		}

		nrules++;
	}

	auto lookup(std::string_view host) const -> std::optional<lookup_result>
	{
		/* Start offsets of the rightmost labels, rightmost first; one extra
		 * entry past the deepest possible suffix for the registrable label */
		std::array<std::size_t, max_suffix_labels + 2> starts;
		unsigned int nl = 0;
		auto search_end = host.size();

		while (nl < starts.size()) {
			auto dot = search_end == 0 ? std::string_view::npos
									   : host.rfind('.', search_end - 1);

			if (dot == std::string_view::npos) {
				starts[nl++] = 0;
				break;
			}

			starts[nl++] = dot + 1;
			search_end = dot;
		}

		std::uint8_t prev_flags = 0;
		int ps_r = -1, exc_r = -1;
		unsigned int ps_flags = 0, exc_flags = 0;
		auto nprobe = std::min(nl, max_suffix_labels);

		for (unsigned int r = 0; r < nprobe; r++) {
			std::uint8_t fl = 0;

			if (auto it = rules.find(host.substr(starts[r])); it != rules.end()) {
				fl = it->second;
			}

			if (fl & FL_EXCEPTION) {
				exc_r = r;
				exc_flags = RSPAMD_TLD_SUFFIX_EXCEPTION |
							((fl & FL_PRIVATE) ? RSPAMD_TLD_SUFFIX_PRIVATE : 0);
			}

			if (fl & FL_EXACT) {
				ps_r = r;
				ps_flags = (fl & FL_PRIVATE) ? RSPAMD_TLD_SUFFIX_PRIVATE : 0;
			}
			else if (prev_flags & FL_WILDCARD) {
				ps_r = r;
				ps_flags = RSPAMD_TLD_SUFFIX_WILDCARD |
						   ((prev_flags & FL_PRIVATE) ? RSPAMD_TLD_SUFFIX_PRIVATE : 0);
			}

			prev_flags = fl;
		}

		/* An exception rule prevails: the matched host part is registrable
		 * and the public suffix is the rule minus its leftmost label */
		if (exc_r >= 1) {
			return lookup_result{(unsigned int) exc_r - 1, (unsigned int) exc_r, exc_flags};
		}

		if (ps_r >= 0) {
			/* Registrable domain is one label to the left of the public
			 * suffix; a host that is itself a public suffix is clamped to
			 * the whole host */
			auto reg_r = (unsigned int) ps_r + 1 < nl ? (unsigned int) ps_r + 1
													  : (unsigned int) ps_r;
			return lookup_result{(unsigned int) ps_r, reg_r, ps_flags};
		}

		return std::nullopt;
	}
};

namespace {

auto tld_lookup_run(const struct rspamd_tld_lookup *lookup,
					std::string_view &host) -> std::optional<lookup_result>
{
	/* Ignore a single trailing dot (FQDN form) */
	if (!host.empty() && host.back() == '.') {
		host.remove_suffix(1);
	}

	if (host.empty()) {
		return std::nullopt;
	}

	folded_host fh{host};

	return lookup->lookup(fh.folded);
}

} /* anonymous namespace */

struct rspamd_tld_lookup *
rspamd_tld_lookup_new(const char *tld_file)
{
	FILE *f = fopen(tld_file, "r");

	if (f == nullptr) {
		return nullptr;
	}

	auto *lookup = new rspamd_tld_lookup;
	char *linebuf = nullptr;
	gsize buflen = 0;
	gssize r;
	bool in_private = false;

	while ((r = rspamd_getline(&linebuf, &buflen, f)) > 0) {
		auto line = std::string_view{linebuf, (std::size_t) r};

		while (!line.empty() && g_ascii_isspace(line.back())) {
			line.remove_suffix(1);
		}

		if (line.empty() || g_ascii_isspace(line.front())) {
			continue;
		}

		if (line.front() == '/') {
			if (line.find("===BEGIN PRIVATE DOMAINS===") != std::string_view::npos) {
				in_private = true;
			}
			else if (line.find("===END PRIVATE DOMAINS===") != std::string_view::npos) {
				in_private = false;
			}
			continue;
		}

		/* Rules are matched against folded hosts, so fold them the same way */
		auto flen = rspamd_str_lc_utf8(linebuf, (unsigned int) line.size());
		lookup->add_rule(std::string_view{linebuf, flen}, in_private);
	}

	rspamd_getline_free(linebuf);
	fclose(f);

	if (lookup->nrules == 0) {
		delete lookup;
		return nullptr;
	}

	return lookup;
}

void rspamd_tld_lookup_destroy(struct rspamd_tld_lookup *lookup)
{
	delete lookup;
}

unsigned int rspamd_tld_lookup_nrules(const struct rspamd_tld_lookup *lookup)
{
	return lookup ? lookup->nrules : 0;
}

gboolean
rspamd_tld_lookup_registrable(const struct rspamd_tld_lookup *lookup,
							  const char *host, gsize len,
							  rspamd_ftok_t *out)
{
	if (lookup == nullptr || host == nullptr) {
		return FALSE;
	}

	auto hv = std::string_view{host, len};
	auto res = tld_lookup_run(lookup, hv);

	if (!res) {
		return FALSE;
	}

	if (out != nullptr) {
		auto off = right_label_offset(hv, res->reg_label);
		out->begin = hv.data() + off;
		out->len = hv.size() - off;
	}

	return TRUE;
}

gboolean
rspamd_tld_lookup_suffix(const struct rspamd_tld_lookup *lookup,
						 const char *host, gsize len,
						 rspamd_ftok_t *out, unsigned int *flags)
{
	if (lookup == nullptr || host == nullptr) {
		return FALSE;
	}

	auto hv = std::string_view{host, len};
	auto res = tld_lookup_run(lookup, hv);

	if (!res) {
		return FALSE;
	}

	if (out != nullptr) {
		auto off = right_label_offset(hv, res->suffix_label);
		out->begin = hv.data() + off;
		out->len = hv.size() - off;
	}

	if (flags != nullptr) {
		*flags = res->flags;
	}

	return TRUE;
}

gboolean
rspamd_tld_lookup_is_final_label(const struct rspamd_tld_lookup *lookup,
								 const char *label, gsize len)
{
	if (lookup == nullptr || label == nullptr || len == 0 || len > 63) {
		return FALSE;
	}

	char buf[64];
	unsigned int flen;

	memcpy(buf, label, len);

	if (!rspamd_str_has_8bit((const unsigned char *) buf, len)) {
		flen = rspamd_str_lc(buf, (unsigned int) len);
	}
	else {
		flen = rspamd_str_lc_utf8(buf, (unsigned int) len);
	}

	return lookup->final_labels.contains(std::string_view{buf, flen}) ? TRUE : FALSE;
}
