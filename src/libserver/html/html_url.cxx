/*-
 * Copyright 2021 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "html_url.hxx"
#include "libutil/str_util.h"
#include "libserver/url.h"
#include "libserver/logger.h"

#include <unicode/idna.h>

namespace rspamd::html {

static auto
rspamd_url_is_subdomain(std::string_view t1, std::string_view t2) -> bool
{
	const auto *p1 = t1.data() + t1.size() - 1;
	const auto *p2 = t2.data() + t2.size() - 1;

	/* Skip trailing dots */
	while (p1 > t1.data()) {
		if (*p1 != '.') {
			break;
		}

		p1--;
	}

	while (p2 > t2.data()) {
		if (*p2 != '.') {
			break;
		}

		p2--;
	}

	while (p1 > t1.data() && p2 > t2.data()) {
		if (*p1 != *p2) {
			break;
		}

		p1--;
		p2--;
	}

	if (p2 == t2.data()) {
		/* p2 can be subdomain of p1 if *p1 is '.' */
		if (p1 != t1.data() && *(p1 - 1) == '.') {
			return true;
		}
	}
	else if (p1 == t1.data()) {
		if (p2 != t2.data() && *(p2 - 1) == '.') {
			return true;
		}
	}

	return false;
}


static auto
get_icu_idna_instance(void) -> auto
{
	auto uc_err = U_ZERO_ERROR;
	static auto *udn = icu::IDNA::createUTS46Instance(UIDNA_DEFAULT, uc_err);

	return udn;
}

static auto
convert_idna_hostname_maybe(rspamd_mempool_t *pool, struct rspamd_url *url, bool use_tld)
		-> std::string_view
{
	std::string_view ret = use_tld ?
			std::string_view{rspamd_url_tld_unsafe (url), url->tldlen} :
			std::string_view {rspamd_url_host_unsafe (url), url->hostlen};

	/* Handle IDN url's */
	if (ret.size() > 4 &&
		rspamd_substring_search_caseless(ret.data(), ret.size(), "xn--", 4) != -1) {
		const auto buf_capacity = ret.size() * 2 + 1;
		auto *idn_hbuf = (char *)rspamd_mempool_alloc (pool, buf_capacity);
		icu::CheckedArrayByteSink byte_sink{idn_hbuf, (int)buf_capacity};
		/* We need to convert it to the normal value first */
		icu::IDNAInfo info;
		auto uc_err = U_ZERO_ERROR;
		auto *udn = get_icu_idna_instance();
		udn->nameToASCII_UTF8(ret,byte_sink, info, uc_err);

		if (uc_err == U_ZERO_ERROR && !info.hasErrors()) {
			ret = std::string_view{idn_hbuf, (std::size_t)byte_sink.NumberOfBytesWritten()};
		}
		else {
			msg_err_pool ("cannot convert to IDN: %s (0x%xd)",
					u_errorName(uc_err), info.getErrors());
		}
	}

	return ret;
};

constexpr auto sv_equals(std::string_view s1, std::string_view s2) -> auto {
	return (s1.size() == s2.size()) &&
		std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(),
				[](const auto c1, const auto c2) {
					return g_ascii_tolower(c1) == g_ascii_tolower(c2);
		});
}

auto
html_url_is_phished(rspamd_mempool_t *pool,
					struct rspamd_url *href_url,
					std::string_view text_data) -> std::optional<rspamd_url *>
{
	struct rspamd_url *text_url;
	std::string_view disp_tok, href_tok;
	goffset url_pos;
	gchar *url_str = NULL;

	auto sz = text_data.size();
	const auto *trimmed = rspamd_string_unicode_trim_inplace(text_data.data(), &sz);
	text_data = std::string_view(trimmed, sz);

	if (text_data.size() > 4 &&
		rspamd_url_find(pool, text_data.data(), text_data.size(), &url_str,
				RSPAMD_URL_FIND_ALL,
				&url_pos, NULL) && url_str != NULL) {

		text_url = rspamd_mempool_alloc0_type (pool, struct rspamd_url);
		auto rc = rspamd_url_parse(text_url, url_str, strlen(url_str), pool,
				RSPAMD_URL_PARSE_TEXT);

		if (rc == URI_ERRNO_OK) {
			disp_tok = convert_idna_hostname_maybe(pool, text_url, false);
			href_tok = convert_idna_hostname_maybe(pool, href_url, false);

			if (!sv_equals(disp_tok, href_tok) &&
				text_url->tldlen > 0 && href_url->tldlen > 0) {

				/* Apply the same logic for TLD */
				disp_tok = convert_idna_hostname_maybe(pool, text_url, true);
				href_tok = convert_idna_hostname_maybe(pool, href_url, true);

				if (!sv_equals(disp_tok, href_tok)) {
					/* Check if one url is a subdomain for another */

					if (!rspamd_url_is_subdomain(disp_tok, href_tok)) {
						href_url->flags |= RSPAMD_URL_FLAG_PHISHED;
						href_url->linked_url = text_url;
						text_url->flags |= RSPAMD_URL_FLAG_HTML_DISPLAYED;
					}
				}
			}

			return text_url;
		}
		else {
			/*
			 * We have found something that looks like an url but it was
			 * not parsed correctly.
			 * Sometimes it means an obfuscation attempt, so we have to check
			 * what's inside of the text
			 */
			gboolean obfuscation_found = FALSE;

			if (text_data.size() > 4
				&& g_ascii_strncasecmp(text_data.begin(), "http", 4) == 0 &&
				rspamd_substring_search(text_data.begin(), text_data.size(), "://", 3) != -1) {
				/* Clearly an obfuscation attempt */
				obfuscation_found = TRUE;
			}

			msg_info_pool ("extract of url '%s' failed: %s; obfuscation detected: %s",
					url_str,
					rspamd_url_strerror(rc),
					obfuscation_found ? "yes" : "no");

			if (obfuscation_found) {
				href_url->flags |= RSPAMD_URL_FLAG_PHISHED | RSPAMD_URL_FLAG_OBSCURED;
			}
		}
	}

	return std::nullopt;
}

}