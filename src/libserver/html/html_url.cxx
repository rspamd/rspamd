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
#include "rspamd.h"

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
		udn->nameToASCII_UTF8(icu::StringPiece(ret.data(), ret.size()),
				byte_sink, info, uc_err);

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

constexpr auto
is_transfer_proto(struct rspamd_url *u) -> bool
{
	return (u->protocol & (PROTOCOL_HTTP|PROTOCOL_HTTPS|PROTOCOL_FTP)) != 0;
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
				&url_pos, NULL) && url_str != nullptr) {

		if (url_pos > 0) {
			/*
			 * We have some url at some offset, so we need to check what is
			 * at the start of the text
			 */
			return std::nullopt;
		}

		text_url = rspamd_mempool_alloc0_type (pool, struct rspamd_url);
		auto rc = rspamd_url_parse(text_url, url_str, strlen(url_str), pool,
				RSPAMD_URL_PARSE_TEXT);

		if (rc == URI_ERRNO_OK) {
			text_url->flags |= RSPAMD_URL_FLAG_HTML_DISPLAYED;
			href_url->flags |= RSPAMD_URL_FLAG_DISPLAY_URL;

			/* Check for phishing */
			if (is_transfer_proto(text_url) == is_transfer_proto(href_url)) {
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

void
html_check_displayed_url(rspamd_mempool_t *pool,
						 GList **exceptions,
						 void *url_set,
						 std::string_view visible_part,
						 goffset href_offset,
						 struct rspamd_url *url)
{
	struct rspamd_url *displayed_url = nullptr;
	struct rspamd_url *turl;
	struct rspamd_process_exception *ex;
	guint saved_flags = 0;
	gsize dlen;

	if (visible_part.empty()) {
		/* No dispalyed url, just some text within <a> tag */
		return;
	}

	url->visible_part = rspamd_mempool_alloc_buffer(pool, visible_part.size() + 1);
	rspamd_strlcpy(url->visible_part,
			visible_part.data(),
			visible_part.size() + 1);
	dlen = visible_part.size();

	/* Strip unicode spaces from the start and the end */
	url->visible_part = const_cast<char *>(
			rspamd_string_unicode_trim_inplace(url->visible_part,
			&dlen));
	auto maybe_url = html_url_is_phished(pool, url,
			{url->visible_part, dlen});

	if (maybe_url) {
		url->flags |= saved_flags;
		displayed_url = maybe_url.value();
	}

	if (exceptions && displayed_url != nullptr) {
		ex = rspamd_mempool_alloc_type (pool,struct rspamd_process_exception);
		ex->pos = href_offset;
		ex->len = dlen;
		ex->type = RSPAMD_EXCEPTION_URL;
		ex->ptr = url;

		*exceptions = g_list_prepend(*exceptions, ex);
	}

	if (displayed_url && url_set) {
		turl = rspamd_url_set_add_or_return((khash_t (rspamd_url_hash) *)url_set, displayed_url);

		if (turl != nullptr) {
			/* Here, we assume the following:
			 * if we have a URL in the text part which
			 * is the same as displayed URL in the
			 * HTML part, we assume that it is also
			 * hint only.
			 */
			if (turl->flags &
				RSPAMD_URL_FLAG_FROM_TEXT) {
				turl->flags |= displayed_url->flags;
				turl->flags &= ~RSPAMD_URL_FLAG_FROM_TEXT;
			}

			turl->count++;
		}
		else {
			/* Already inserted by `rspamd_url_set_add_or_return` */
		}
	}

	rspamd_normalise_unicode_inplace(url->visible_part, &dlen);
}

auto
html_process_url(rspamd_mempool_t *pool, std::string_view &input)
	-> std::optional<struct rspamd_url *>
{
	struct rspamd_url *url;
	guint saved_flags = 0;
	gint rc;
	const gchar *s, *prefix = "http://";
	gchar *d;
	gsize dlen;
	gboolean has_bad_chars = FALSE, no_prefix = FALSE;
	static const gchar hexdigests[] = "0123456789abcdef";

	auto sz = input.length();
	const auto *trimmed = rspamd_string_unicode_trim_inplace(input.data(), &sz);
	input = {trimmed, sz};

	const auto *start = input.data();
	s = start;
	dlen = 0;

	for (auto i = 0; i < sz; i++) {
		if (G_UNLIKELY (((guint) s[i]) < 0x80 && !g_ascii_isgraph(s[i]))) {
			dlen += 3;
		}
		else {
			dlen++;
		}
	}

	if (rspamd_substring_search(start, sz, "://", 3) == -1) {
		if (sz >= sizeof("mailto:") &&
			(memcmp(start, "mailto:", sizeof("mailto:") - 1) == 0 ||
			 memcmp(start, "tel:", sizeof("tel:") - 1) == 0 ||
			 memcmp(start, "callto:", sizeof("callto:") - 1) == 0)) {
			/* Exclusion, has valid but 'strange' prefix */
		}
		else {
			for (auto i = 0; i < sz; i++) {
				if (!((s[i] & 0x80) || g_ascii_isalnum (s[i]))) {
					if (i == 0 && sz > 2 && s[i] == '/' && s[i + 1] == '/') {
						prefix = "http:";
						dlen += sizeof("http:") - 1;
						no_prefix = TRUE;
					}
					else if (s[i] == '@') {
						/* Likely email prefix */
						prefix = "mailto://";
						dlen += sizeof("mailto://") - 1;
						no_prefix = TRUE;
					}
					else if (s[i] == ':' && i != 0) {
						/* Special case */
						no_prefix = FALSE;
					}
					else {
						if (i == 0) {
							/* No valid data */
							return std::nullopt;
						}
						else {
							no_prefix = TRUE;
							dlen += strlen(prefix);
						}
					}

					break;
				}
			}
		}
	}

	auto *decoded = rspamd_mempool_alloc_buffer(pool, dlen + 1);
	d = decoded;

	if (no_prefix) {
		gsize plen = strlen(prefix);
		memcpy(d, prefix, plen);
		d += plen;
	}

	/*
	 * We also need to remove all internal newlines, spaces
	 * and encode unsafe characters
	 * Another obfuscation find in the wild was encoding of the SAFE url characters,
	 * including essential ones
	 */
	for (auto i = 0; i < sz; i++) {
		if (G_UNLIKELY (g_ascii_isspace(s[i]))) {
			continue;
		}
		else if (G_UNLIKELY (((guint) s[i]) < 0x80 && !g_ascii_isgraph(s[i]))) {
			/* URL encode */
			*d++ = '%';
			*d++ = hexdigests[(s[i] >> 4) & 0xf];
			*d++ = hexdigests[s[i] & 0xf];
			has_bad_chars = TRUE;
		}
		else if (G_UNLIKELY (s[i] == '%')) {
			if (i + 2 < sz) {
				auto c1 = s[i + 1];
				auto c2 = s[i + 2];

				if (g_ascii_isxdigit(c1) && g_ascii_isxdigit(c2)) {
					auto codepoint = 0;

					if      (c1 >= '0' && c1 <= '9') codepoint = c1 - '0';
					else if (c1 >= 'A' && c1 <= 'F') codepoint = c1 - 'A' + 10;
					else if (c1 >= 'a' && c1 <= 'f') codepoint = c1 - 'a' + 10;

					codepoint <<= 4;

					if      (c2 >= '0' && c2 <= '9') codepoint += c2 - '0';
					else if (c2 >= 'A' && c2 <= 'F') codepoint += c2 - 'A' + 10;
					else if (c2 >= 'a' && c2 <= 'f') codepoint += c2 - 'a' + 10;

					/* Now check for 'interesting' codepoints */
					if (codepoint == '@' || codepoint == ':' || codepoint == '|' ||
						codepoint == '?' || codepoint == '\\' || codepoint == '/') {
						/* Replace it back */
						*d++ = (char)(codepoint & 0xff);
						i += 2;
					}
					else {
						*d++ = s[i];
					}
				}
				else {
					*d++ = s[i];
				}
			}
			else {
				*d++ = s[i];
			}
		}
		else {
			*d++ = s[i];
		}
	}

	*d = '\0';
	dlen = d - decoded;

	url = rspamd_mempool_alloc0_type(pool, struct rspamd_url);
	rspamd_url_normalise_propagate_flags (pool, decoded, &dlen, saved_flags);
	rc = rspamd_url_parse(url, decoded, dlen, pool, RSPAMD_URL_PARSE_HREF);

	/* Filter some completely damaged urls */
	if (rc == URI_ERRNO_OK && url->hostlen > 0 &&
		!((url->protocol & PROTOCOL_UNKNOWN))) {
		url->flags |= saved_flags;

		if (has_bad_chars) {
			url->flags |= RSPAMD_URL_FLAG_OBSCURED;
		}

		if (no_prefix) {
			url->flags |= RSPAMD_URL_FLAG_SCHEMALESS;

			if (url->tldlen == 0 || (url->flags & RSPAMD_URL_FLAG_NO_TLD)) {
				/* Ignore urls with both no schema and no tld */
				return std::nullopt;
			}
		}

		decoded = url->string;

		input = {decoded, url->urllen};

		/* Spaces in href usually mean an attempt to obfuscate URL */
		/* See https://github.com/vstakhov/rspamd/issues/593 */
#if 0
		if (has_spaces) {
			url->flags |= RSPAMD_URL_FLAG_OBSCURED;
		}
#endif

		return url;
	}

	return std::nullopt;
}

}