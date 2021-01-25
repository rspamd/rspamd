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

#include "css_tokeniser.hxx"
#include "css_util.hxx"

namespace rspamd::css {


auto css_tokeniser::next_token (void) -> std::pair<css_parser_token, std::string_view>
{
	/* Helpers */

	/*
	 * This lambda eats comment handling nested comments;
	 * offset is set to the next character after a comment (or eof)
	 * Nothing is returned
	 */
	auto consume_comment = [this] () {
		auto i = offset;
		auto nested = 0;

		/* We handle nested comments just because they can exist... */
		while (i < input.size () - 1) {
			auto c = input[i];
			if (c == '*' && input[i + 1] == '/') {
				if (nested == 0) {
					offset = i + 2;
					return;
				}
				else {
					nested--;
					i += 2;
					continue;
				}
			}
			else if (c == '/' && input[i + 1] == '*') {
				nested++;
				i += 2;
				continue;
			}

			i++;
		}

		offset = i;
	};

	/*
	 * Consume quoted string, returns a string_view over a string, offset
	 * is set one character after the string. Css unescaping is done automatically
	 * Accepts a quote char to find end of string
	 */
	auto consume_string = [this] (auto quote_char) -> auto {
		auto i = offset;
		bool need_unescape = false;

		while (i < input.size ()) {
			auto c = input[i];

			if (c == '\\') {
				if (i + 1 < input.size ()) {
					need_unescape = true;
				}
				else {
					/* \ at the end -> ignore */

				}
			}
			else if (c == quote_char) {
				/* End of string */
				std::string_view res{&input[offset], i - offset};

				if (need_unescape) {
					res = rspamd::css::unescape_css(pool, res);
				}

				offset = i + 1;

				return res;
			}
			else if (c == '\n') {
				/* Should be a error, but we ignore it for now */
			}
		}

		/* EOF with no quote character, consider it fine */
		std::string_view res{&input[offset], i - offset};

		if (need_unescape) {
			res = rspamd::css::unescape_css(pool, res);
		}

		offset = i;

		return res;
	};

	/* Main tokenisation loop */
	for (auto i = offset; i < input.size (); ++i) {
		auto c = input[i];

		switch (c) {
		case '/':
			if (i + 1 < input.size () && input[i + 1] == '*') {
				offset = i + 2;
				consume_comment (); /* Consume comment and go forward */
				return next_token (); /* Tail call */
			}
			else {
				offset = i + 1;
				return std::make_pair (css_parser_token::delim_token,
						std::string_view (&input[offset - 1], 1));
			}
			break;
		case ' ':
		case '\t':
		case '\n':
		case '\r':
		case '\v': {
			/* Consume as much space as we can */
			do {
				c = input[++i];
			} while (i < input.size () && g_ascii_isspace (c));

			auto ret = std::make_pair (css_parser_token::whitespace_token,
					std::string_view (&input[offset], i - offset));
			offset = i;
			return ret;
		}
		case '"':
		case '\'':
			offset = i + 1;
			return std::make_pair (css_parser_token::string_token,
					consume_string (c));
		case '(':
			offset = i + 1;
			return std::make_pair (css_parser_token::obrace_token,
					std::string_view (&input[offset - 1], 1));
		case ')':
			offset = i + 1;
			return std::make_pair (css_parser_token::ebrace_token,
					std::string_view (&input[offset - 1], 1));
		case ',':
			offset = i + 1;
			return std::make_pair (css_parser_token::comma_token,
					std::string_view (&input[offset - 1], 1));
		case '<':
			/* Maybe an xml like comment */
			if (i + 3 < input.size () && input[i + 1] == '!'
				&& input[i + 2] == '-' && input[i + 3] == '-') {
				offset += 3;

				return std::make_pair (css_parser_token::cdo_token,
						std::string_view (&input[offset - 3], 3));
			}
			else {
				offset = i + 1;
				return std::make_pair (css_parser_token::delim_token,
						std::string_view (&input[offset - 1], 1));
			}
			break;
		}

	}

	return std::make_pair (css_parser_token::eof_token, std::string_view ());
}

}