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

#include "css_parser.hxx"
#include <unicode/utf8.h>


namespace rspamd::css {

class css_parser {
public:
	css_parser(void) = delete; /* Require mempool to be set for logging */
	explicit css_parser(rspamd_mempool_t *pool) : pool (pool) {}

	bool consume_input(const std::string_view &sv);

	auto get_object_maybe(void) -> tl::expected<std::unique_ptr<css_style_sheet>, css_parse_error> {
		if (state == parser_state::parse_done) {
			state = parser_state::initial_state;
			return std::move (style_object);
		}

		return tl::make_unexpected (error);
	}

	/* Public for unit tests */
	std::string_view unescape_css(const std::string_view &sv);

private:
	enum class parser_state {
		initial_state,
		skip_spaces,
		parse_selector,
		ignore_selector, /* e.g. media or namespace */
		parse_done,
	};
	parser_state state = parser_state::initial_state;
	std::unique_ptr<css_style_sheet> style_object;
	css_parse_error error;
	rspamd_mempool_t *pool;

	/* Helper parser methods */
	bool need_unescape(const std::string_view &sv);
};

/*
 * Find if we need to unescape css
 */
bool
css_parser::need_unescape(const std::string_view &sv)
{
	bool in_quote = false;
	char quote_char, prev_c = 0;

	for (const auto c : sv) {
		if (!in_quote) {
			if (c == '"' || c == '\'') {
				in_quote = true;
				quote_char = c;
			}
			else if (c == '\\') {
				return true;
			}
		}
		else {
			if (c == quote_char) {
				if (prev_c != '\\') {
					in_quote = false;
				}
			}
			prev_c = c;
		}
	}

	return false;
}

/*
 * Unescape css escapes
 * \20AC : must be followed by a space if the next character is one of a-f, A-F, 0-9
 * \0020AC : must be 6 digits long, no space needed (but can be included)
 */
std::string_view
css_parser::unescape_css(const std::string_view &sv)
{
	auto *nspace = reinterpret_cast<char *>(rspamd_mempool_alloc(pool, sv.length ()));
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
    if (c == '"' || c == '\'') { \
        state = quoted; \
        quote_char = c; \
        nleft--; \
        *d++ = c; \
    } \
    else if (c == '\\') { \
        escape_offset = i; \
        state = escape; \
    } \
    else { \
        state = normal; \
        nleft--; \
        *d++ = c; \
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

					if (!rspamd_xstrtoul (escape_start, i - escape_offset - 1, &val)) {
						msg_debug_css("invalid broken escape found at pos %d",
								escape_offset);
					}
					else {
						if (val < 0x1f) {
							/* Trivial case: ascii character */
							*d++ = (unsigned char)val;
							nleft --;
						}
						else {
							UChar32 uc = val;
							auto off = d - nspace;
							UTF8_APPEND_CHAR_SAFE((uint8_t *) d, off,
									sv.length (), uc);
							d = nspace + off;
							nleft = sv.length () - off;
						}
					}
				}
				else {
					/* Empty escape, ignore it */
					msg_debug_css("invalid empty escape found at pos %d",
							escape_offset);
				}

				if (nleft > 0) {
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
};

bool css_parser::consume_input(const std::string_view &sv)
{
	auto our_sv = sv;

	if (need_unescape(sv)) {
		our_sv = unescape_css(sv);
		msg_debug_css("unescaped css: input size %d, unescaped size %d",
				(int)sv.size(), (int)our_sv.size());
	}

	return true;
}

/*
 * Wrapper for the parser
 */
auto parse_css(rspamd_mempool_t *pool, const std::string_view &st) ->
	tl::expected<std::unique_ptr<css_style_sheet>,css_parse_error>
{
	css_parser parser(pool);

	parser.consume_input(st);

	return parser.get_object_maybe();
}

}

/* C API */
const gchar *rspamd_css_unescape (rspamd_mempool_t *pool,
							const guchar *begin,
							gsize len,
							gsize *outlen)
{
	rspamd::css::css_parser parser(pool);
	auto sv = parser.unescape_css({(const char*)begin, len});
	const auto *v = sv.begin();

	if (outlen) {
		*outlen = sv.size();
	}

	return v;
}
