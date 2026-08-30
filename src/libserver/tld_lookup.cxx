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

#include "contrib/ankerl/unordered_dense.h"

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

struct sv_hash {
	using is_transparent = void;
	using is_avalanching = void;
	auto operator()(std::string_view v) const noexcept -> std::uint64_t
	{
		return ankerl::unordered_dense::hash<std::string_view>{}(v);
	}
};

using rules_map = ankerl::unordered_dense::map<std::string, std::uint8_t,
											   sv_hash, std::equal_to<>>;
using labels_set = ankerl::unordered_dense::set<std::string,
												sv_hash, std::equal_to<>>;

/* Suffix rules never exceed 6 labels, +1 for a wildcard child */
constexpr int max_suffix_labels = 7;
constexpr std::size_t max_labels = 256;

struct lookup_result {
	std::size_t suffix_off;
	std::size_t reg_off;
	unsigned int flags;
};

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
		std::size_t starts[max_labels];
		std::size_t nl = 0;

		starts[nl++] = 0;
		for (std::size_t i = 0; i < host.size() && nl < max_labels; i++) {
			if (host[i] == '.') {
				starts[nl++] = i + 1;
			}
		}

		auto lo = nl > max_suffix_labels ? nl - max_suffix_labels : 0;
		std::uint8_t prev_flags = 0;
		int ps_i = -1, exc_i = -1;
		unsigned int ps_flags = 0, exc_flags = 0;

		for (auto i = (int) nl - 1; i >= (int) lo; i--) {
			std::uint8_t fl = 0;

			if (auto it = rules.find(host.substr(starts[i])); it != rules.end()) {
				fl = it->second;
			}

			if (fl & FL_EXCEPTION) {
				exc_i = i;
				exc_flags = RSPAMD_TLD_SUFFIX_EXCEPTION |
							((fl & FL_PRIVATE) ? RSPAMD_TLD_SUFFIX_PRIVATE : 0);
			}

			if (fl & FL_EXACT) {
				ps_i = i;
				ps_flags = (fl & FL_PRIVATE) ? RSPAMD_TLD_SUFFIX_PRIVATE : 0;
			}
			else if (prev_flags & FL_WILDCARD) {
				ps_i = i;
				ps_flags = RSPAMD_TLD_SUFFIX_WILDCARD |
						   ((prev_flags & FL_PRIVATE) ? RSPAMD_TLD_SUFFIX_PRIVATE : 0);
			}

			prev_flags = fl;
		}

		/* An exception rule prevails: the matched host part is registrable and
		 * the public suffix is the rule minus its leftmost label */
		if (exc_i >= 0 && (std::size_t) exc_i + 1 < nl) {
			return lookup_result{starts[exc_i + 1], starts[exc_i], exc_flags};
		}

		if (ps_i >= 0) {
			/* Registrable domain is one label to the left of the public
			 * suffix; a host that is itself a public suffix is clamped to
			 * the whole host */
			auto reg_off = ps_i > 0 ? starts[ps_i - 1] : starts[0];
			return lookup_result{starts[ps_i], reg_off, ps_flags};
		}

		return std::nullopt;
	}
};

namespace {

auto lookup_prepared(const struct rspamd_tld_lookup *lookup,
					 const char *host, gsize len) -> std::optional<lookup_result>
{
	if (len == 0) {
		return std::nullopt;
	}

	/* Ignore a single trailing dot (FQDN form) */
	if (host[len - 1] == '.') {
		len--;
		if (len == 0) {
			return std::nullopt;
		}
	}

	/* Rules are stored lowercase; fold the host before probing */
	char buf[512];
	std::string long_buf;
	char *dst = buf;

	if (len > sizeof(buf)) {
		long_buf.resize(len);
		dst = long_buf.data();
	}

	for (gsize i = 0; i < len; i++) {
		dst[i] = (char) g_ascii_tolower(host[i]);
	}

	return lookup->lookup(std::string_view{dst, len});
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
	char linebuf[512];
	bool in_private = false;

	while (fgets(linebuf, sizeof(linebuf), f) != nullptr) {
		auto len = strlen(linebuf);
		bool truncated = len > 0 && linebuf[len - 1] != '\n' && !feof(f);

		while (len > 0 && g_ascii_isspace(linebuf[len - 1])) {
			linebuf[--len] = '\0';
		}

		if (truncated) {
			/* Drop the tail of an oversized line */
			int c;
			while ((c = fgetc(f)) != EOF && c != '\n') {}
			continue;
		}

		if (len == 0 || g_ascii_isspace(linebuf[0])) {
			continue;
		}

		if (linebuf[0] == '/') {
			if (strstr(linebuf, "===BEGIN PRIVATE DOMAINS===") != nullptr) {
				in_private = true;
			}
			else if (strstr(linebuf, "===END PRIVATE DOMAINS===") != nullptr) {
				in_private = false;
			}
			continue;
		}

		for (gsize i = 0; i < len; i++) {
			linebuf[i] = (char) g_ascii_tolower(linebuf[i]);
		}

		lookup->add_rule(std::string_view{linebuf, len}, in_private);
	}

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

	auto res = lookup_prepared(lookup, host, len);

	if (!res) {
		return FALSE;
	}

	if (out != nullptr) {
		gsize eff_len = (len > 0 && host[len - 1] == '.') ? len - 1 : len;
		out->begin = host + res->reg_off;
		out->len = eff_len - res->reg_off;
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

	auto res = lookup_prepared(lookup, host, len);

	if (!res) {
		return FALSE;
	}

	if (out != nullptr) {
		gsize eff_len = (len > 0 && host[len - 1] == '.') ? len - 1 : len;
		out->begin = host + res->suffix_off;
		out->len = eff_len - res->suffix_off;
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

	for (gsize i = 0; i < len; i++) {
		buf[i] = (char) g_ascii_tolower(label[i]);
	}

	return lookup->final_labels.contains(std::string_view{buf, len}) ? TRUE : FALSE;
}
