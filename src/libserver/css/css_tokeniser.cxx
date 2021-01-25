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

/* Helpers to create tokens */

/*
 * This helper is intended to create tokens either with a tag and value
 * or with just a tag.
 */
template<css_parser_token::token_type T, typename ...Args>
auto make_token(const Args&... args) -> css_parser_token;

template<>
auto make_token<css_parser_token::token_type::string_token, std::string_view>(const std::string_view &s)
        -> css_parser_token
{
	return css_parser_token{css_parser_token::token_type::string_token, s};
}

template<>
auto make_token<css_parser_token::token_type::whitespace_token, std::string_view>(const std::string_view &s)
        -> css_parser_token
{
	return css_parser_token{css_parser_token::token_type::whitespace_token, s};
}

template<>
auto make_token<css_parser_token::token_type::delim_token, char>(const char &c)
        -> css_parser_token
{
	return css_parser_token{css_parser_token::token_type::delim_token, c};
}

/*
 * Generic tokens with no value (non-terminals)
 */
template<css_parser_token::token_type T>
auto make_token(void) -> css_parser_token
{
	return css_parser_token{T, css_parser_token_placeholder()};
}

auto css_tokeniser::next_token(void) -> struct css_parser_token
{
	/* Helpers */

	/*
	 * This lambda eats comment handling nested comments;
	 * offset is set to the next character after a comment (or eof)
	 * Nothing is returned
	 */
	auto consume_comment = [this]() {
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
	auto consume_string = [this](auto quote_char) -> auto {
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
				return make_token<css_parser_token::token_type::delim_token>(c);
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

			auto ret = make_token<css_parser_token::token_type::whitespace_token>(
					std::string_view(&input[offset], i - offset));
			offset = i;
			return ret;
		}
		case '"':
		case '\'':
			offset = i + 1;
			return make_token<css_parser_token::token_type::string_token>(consume_string(c));
		case '(':
			offset = i + 1;
			return make_token<css_parser_token::token_type::obrace_token>();
		case ')':
			offset = i + 1;
			return make_token<css_parser_token::token_type::ebrace_token>();
		case ',':
			return make_token<css_parser_token::token_type::comma_token>();
		case '<':
			/* Maybe an xml like comment */
			if (i + 3 < input.size () && input[i + 1] == '!'
				&& input[i + 2] == '-' && input[i + 3] == '-') {
				offset += 3;

				return make_token<css_parser_token::token_type::cdo_token>();
			}
			else {
				offset = i + 1;
				return make_token<css_parser_token::token_type::delim_token>(c);
			}
			break;
		}

	}

	return make_token<css_parser_token::token_type::eof_token>();
}

}