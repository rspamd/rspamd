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


namespace {

constexpr auto is_css_newline(char c) -> bool
{
	return c == '\n' || c == '\r' || c == '\f';
}

/* Characters that can be part of an identifier */
constexpr auto is_css_name_char(unsigned char c) -> bool
{
	return (c & 0x80) || g_ascii_isalnum(c) || c == '-' || c == '_';
}

}// namespace

std::string_view unescape_css(rspamd_mempool_t *pool,
							  const std::string_view &sv,
							  bool in_string)
{
	const auto n = sv.size();
	/* Keeping an escape may add a separating space, one per at least 7 characters */
	auto *nspace = reinterpret_cast<char *>(rspamd_mempool_alloc(pool, n + n / 4 + 2));
	auto *d = nspace;
	auto *dend = nspace + n + n / 4 + 2;

	enum {
		normal = 0,
		quoted,
		comment,
	} state = normal;

	char quote_char = 0;

	auto put = [&](char c) {
		if (d < dend) {
			*d++ = c;
		}
	};

	/*
	 * Handles an escape that starts at sv[i] == '\\', returns the index of the
	 * first character after it. An escape never creates syntax: outside of
	 * strings it is decoded only when it yields a name character, otherwise
	 * it is kept in place for the tokeniser, which reads it as a part of an
	 * identifier.
	 */
	auto escape = [&](std::size_t i) -> std::size_t {
		auto j = i + 1;

		if (j >= n) {
			/* A lone backslash at the end of the input */
			if (!in_string) {
				put('\\');
			}

			return j;
		}

		auto c = sv[j];

		if (g_ascii_isxdigit(c)) {
			unsigned long val = 0;
			auto k = j;

			while (k < n && k - j < 6 && g_ascii_isxdigit(sv[k])) {
				val = val * 16 + g_ascii_xdigit_value(sv[k]);
				k++;
			}

			auto hex_end = k;
			auto had_space = false;

			if (k < n && g_ascii_isspace(sv[k])) {
				/* A single whitespace belongs to the escape, \r\n is one */
				had_space = true;
				if (sv[k] == '\r' && k + 1 < n && sv[k + 1] == '\n') {
					k++;
				}
				k++;
			}

			if (val == 0 && in_string) {
				return k;
			}

			if (val > 0x10FFFF || (val >= 0xD800 && val <= 0xDFFF)) {
				val = 0xFFFD;
			}

			if (val != 0 && (val >= 0x80 || in_string || is_css_name_char(val))) {
				if (val < 0x80) {
					put(g_ascii_tolower(val));
				}
				else {
					UChar32 uc = u_tolower(static_cast<UChar32>(val));
					auto off = 0;
					auto room = static_cast<int>(dend - d);

					UTF8_APPEND_CHAR_SAFE((uint8_t *) d, off, room, uc);
					d += off;
				}
			}
			else {
				/* Keep the escape, it must not become a syntax character */
				put('\\');
				for (auto m = j; m < hex_end; m++) {
					put(g_ascii_tolower(sv[m]));
				}
				if (had_space || (hex_end < n && g_ascii_isxdigit(sv[hex_end]))) {
					put(' ');
				}
			}

			return k;
		}

		if (is_css_newline(c)) {
			if (in_string) {
				/* Line continuation */
				if (c == '\r' && j + 1 < n && sv[j + 1] == '\n') {
					return j + 2;
				}

				return j + 1;
			}

			/* Not an escape: a backslash followed by a newline */
			put('\\');
			return j;
		}

		if (in_string || is_css_name_char(c)) {
			/* The escaped character itself; the rest of a multibyte one passes as it is */
			put((static_cast<unsigned char>(c) & 0x80) ? c : g_ascii_tolower(c));
		}
		else {
			put('\\');
			put(c);
		}

		return j + 1;
	};

	if (in_string) {
		for (std::size_t i = 0; i < n;) {
			if (sv[i] == '\\') {
				i = escape(i);
			}
			else {
				put(g_ascii_tolower(sv[i]));
				i++;
			}
		}

		return std::string_view{nspace, static_cast<std::size_t>(d - nspace)};
	}

	for (std::size_t i = 0; i < n;) {
		auto c = sv[i];

		switch (state) {
		case normal:
			if (c == '"' || c == '\'') {
				state = quoted;
				quote_char = c;
				put(c);
				i++;
			}
			else if (c == '/' && i + 1 < n && sv[i + 1] == '*') {
				state = comment;
				put('/');
				put('*');
				i += 2;
			}
			else if (c == '\\') {
				i = escape(i);
			}
			else {
				put(g_ascii_tolower(c));
				i++;
			}
			break;
		case quoted:
			/* Strings are kept as they are, the tokeniser unescapes them */
			if (c == '\\') {
				put(c);
				i++;

				if (i < n) {
					put(sv[i]);
					if (sv[i] == '\r' && i + 1 < n && sv[i + 1] == '\n') {
						i++;
						put('\n');
					}
					i++;
				}
			}
			else {
				if (c == quote_char || is_css_newline(c)) {
					state = normal;
				}
				put(c);
				i++;
			}
			break;
		case comment:
			put(c);
			if (c == '*' && i + 1 < n && sv[i + 1] == '/') {
				put('/');
				state = normal;
				i++;
			}
			i++;
			break;
		}
	}

	return std::string_view{nspace, static_cast<std::size_t>(d - nspace)};
}

bool css_has_escape(const std::string_view &sv)
{
	enum {
		normal,
		quoted,
		comment,
	} state = normal;
	char quote_char = 0;
	const auto n = sv.size();

	for (std::size_t i = 0; i < n; i++) {
		auto c = sv[i];

		switch (state) {
		case normal:
			if (c == '"' || c == '\'') {
				state = quoted;
				quote_char = c;
			}
			else if (c == '/' && i + 1 < n && sv[i + 1] == '*') {
				state = comment;
				i++;
			}
			else if (c == '\\') {
				return true;
			}
			break;
		case quoted:
			if (c == '\\') {
				if (i + 2 < n && sv[i + 1] == '\r' && sv[i + 2] == '\n') {
					i++;
				}
				i++;
			}
			else if (c == quote_char || is_css_newline(c)) {
				state = normal;
			}
			break;
		case comment:
			if (c == '*' && i + 1 < n && sv[i + 1] == '/') {
				state = normal;
				i++;
			}
			break;
		}
	}

	return false;
}

}// namespace rspamd::css

/* C API */
const char *rspamd_css_unescape(rspamd_mempool_t *pool,
								const unsigned char *begin,
								gsize len,
								gsize *outlen)
{
	auto sv = rspamd::css::unescape_css(pool, {(const char *) begin, len});
	const auto *v = sv.data();

	if (outlen) {
		*outlen = sv.size();
	}

	return v;
}