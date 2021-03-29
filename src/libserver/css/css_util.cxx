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

#include "css_util.hxx"
#include "css.hxx"
#include <unicode/utf8.h>

namespace rspamd::css {

std::string_view unescape_css(rspamd_mempool_t *pool,
							  const std::string_view &sv)
{
	auto *nspace = reinterpret_cast<char *>(rspamd_mempool_alloc(pool, sv.length()));
	auto *d = nspace;
	auto nleft = sv.length ();

	enum {
		normal = 0,
		quoted,
		escape,
		skip_spaces,
	} state = normal;

	char quote_char, prev_c = 0;
	auto escape_offset = 0, i = 0;

#define MAYBE_CONSUME_CHAR(c) do { \
    if ((c) == '"' || (c) == '\'') { \
        state = quoted; \
        quote_char = (c); \
        nleft--; \
        *d++ = (c); \
    } \
    else if ((c) == '\\') { \
        escape_offset = i; \
        state = escape; \
    } \
    else { \
        state = normal; \
        nleft--; \
        *d++ = g_ascii_tolower(c); \
    } \
} while (0)

	for (const auto c : sv) {
		if (nleft == 0) {
			msg_err_css("cannot unescape css: truncated buffer of size %d",
					(int)sv.length());
			break;
		}
		switch (state) {
		case normal:
			MAYBE_CONSUME_CHAR(c);
			break;
		case quoted:
			if (c == quote_char) {
				if (prev_c != '\\') {
					state = normal;
				}
			}
			prev_c = c;
			nleft --;
			*d++ = c;
			break;
		case escape:
			if (!g_ascii_isxdigit(c)) {
				if (i > escape_offset + 1) {
					/* Try to decode an escape */
					const auto *escape_start = &sv[escape_offset + 1];
					unsigned long val;

					if (!rspamd_xstrtoul(escape_start, i - escape_offset - 1, &val)) {
						msg_debug_css("invalid broken escape found at pos %d",
								escape_offset);
					}
					else {
						if (val < 0x80) {
							/* Trivial case: ascii character */
							*d++ = (unsigned char)g_ascii_tolower(val);
							nleft --;
						}
						else {
							UChar32 uc = val;
							auto off = 0;
							UTF8_APPEND_CHAR_SAFE((uint8_t *) d, off,
									sv.length (), u_tolower(uc));
							d += off;
							nleft -= off;
						}
					}
				}
				else {
					/* Empty escape, ignore it */
					msg_debug_css("invalid empty escape found at pos %d",
							escape_offset);
				}

				if (nleft <= 0) {
					msg_err_css("cannot unescape css: truncated buffer of size %d",
							(int)sv.length());
				}
				else {
					/* Escape is done, advance forward */
					if (g_ascii_isspace (c)) {
						state = skip_spaces;
					}
					else {
						MAYBE_CONSUME_CHAR(c);
					}
				}
			}
			break;
		case skip_spaces:
			if (!g_ascii_isspace(c)) {
				MAYBE_CONSUME_CHAR(c);
			}
			/* Ignore spaces */
			break;
		}

		i ++;
	}

	return std::string_view{nspace, sv.size() - nleft};
}

}

/* C API */
const gchar *rspamd_css_unescape (rspamd_mempool_t *pool,
								  const guchar *begin,
								  gsize len,
								  gsize *outlen)
{
	auto sv = rspamd::css::unescape_css(pool, {(const char*)begin, len});
	const auto *v = sv.begin();

	if (outlen) {
		*outlen = sv.size();
	}

	return v;
}