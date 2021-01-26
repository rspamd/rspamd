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
#include "css.hxx"
#include <charconv>
#include <string>

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
auto make_token<css_parser_token::token_type::ident_token, std::string_view>(const std::string_view &s)
-> css_parser_token
{
	return css_parser_token{css_parser_token::token_type::ident_token, s};
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

template<>
auto make_token<css_parser_token::token_type::number_token, double>(const double &d)
-> css_parser_token
{
	return css_parser_token{css_parser_token::token_type::number_token, d};
}

/*
 * Generic tokens with no value (non-terminals)
 */
template<css_parser_token::token_type T>
auto make_token(void) -> css_parser_token
{
	return css_parser_token{T, css_parser_token_placeholder()};
}

static constexpr inline auto is_plain_ident(char c) -> bool
{
	if ((c & 0x80) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
		return true;
	}

	return false;
};

auto
css_parser_token::adjust_dim(const css_parser_token &dim_token) -> bool
{
	if (!std::holds_alternative<double>(value) ||
	        !std::holds_alternative<std::string_view>(dim_token.value)) {
		/* Invalid tokens */
		return false;
	}

	auto num = std::get<double>(value);
	auto sv = std::get<std::string_view>(dim_token.value);

	if (sv == "px") {
		dim_type = css_parser_token::dim_type::dim_px;
		flags |= css_parser_token::number_dimension;
		num = (unsigned)num; /* Round to number */
	}
	else if (sv == "em") {
		dim_type = css_parser_token::dim_type::dim_em;
		flags |= css_parser_token::number_dimension;
		/* EM is 16 px, so multiply and round */
		num = (unsigned)(num * 16.0);
	}
	else if (sv == "rem") {
		/* equal to EM in our case */
		dim_type = css_parser_token::dim_type::dim_rem;
		flags |= css_parser_token::number_dimension;
		num = (unsigned)(num * 16.0);
	}
	else if (sv == "ex") {
		/*
		 * Represents the x-height of the element's font.
		 * On fonts with the "x" letter, this is generally the height
		 * of lowercase letters in the font; 1ex = 0.5em in many fonts.
		 */
		dim_type = css_parser_token::dim_type::dim_ex;
		flags |= css_parser_token::number_dimension;
		num = (unsigned)(num * 8.0);
	}
	else if (sv == "wv") {
		/*
		 * Vewport width in percentages:
		 * we assume 1% of viewport width as 8px
		 */
		dim_type = css_parser_token::dim_type::dim_wv;
		flags |= css_parser_token::number_dimension;
		num = (unsigned)(num * 8.0);
	}
	else if (sv == "wh") {
		/*
		 * Vewport height in percentages
		 * we assume 1% of viewport width as 6px
		 */
		dim_type = css_parser_token::dim_type::dim_wh;
		flags |= css_parser_token::number_dimension;
		num = (unsigned)(num * 6.0);
	}
	else if (sv == "vmax") {
		/*
		 * Vewport width in percentages
		 * we assume 1% of viewport width as 6px
		 */
		dim_type = css_parser_token::dim_type::dim_vmax;
		flags |= css_parser_token::number_dimension;
		num = (unsigned)(num * 8.0);
	}
	else if (sv == "vmin") {
		/*
		 * Vewport height in percentages
		 * we assume 1% of viewport width as 6px
		 */
		dim_type = css_parser_token::dim_type::dim_vmin;
		flags |= css_parser_token::number_dimension;
		num = (unsigned)(num * 6.0);
	}
	else if (sv == "pt") {
		dim_type = css_parser_token::dim_type::dim_pt;
		flags |= css_parser_token::number_dimension;
		num = (num * 96.0 / 72.0); /* One point. 1pt = 1/72nd of 1in */
	}
	else if (sv == "cm") {
		dim_type = css_parser_token::dim_type::dim_cm;
		flags |= css_parser_token::number_dimension;
		num = (num * 96.0 / 2.54); /* 96px/2.54 */
	}
	else if (sv == "mm") {
		dim_type = css_parser_token::dim_type::dim_mm;
		flags |= css_parser_token::number_dimension;
		num = (num * 9.6 / 2.54); /* 9.6px/2.54 */
	}
	else if (sv == "in") {
		dim_type = css_parser_token::dim_type::dim_in;
		flags |= css_parser_token::number_dimension;
		num = (num * 96.0); /* 96px */
	}
	else if (sv == "pc") {
		dim_type = css_parser_token::dim_type::dim_pc;
		flags |= css_parser_token::number_dimension;
		num = (num * 96.0 / 6.0); /* 1pc = 12pt = 1/6th of 1in. */
	}
	else {
		flags |= css_parser_token::flag_bad_dimension;

		return false;
	}

	value = num;

	return true;
}


/*
 * Consume functions: return a token and advance lexer offset
 */
auto css_tokeniser::consume_ident() -> struct css_parser_token
{
	auto i = offset;
	auto need_escape = false;

	/* Ident token can start from `-` or `--` */
	if (input[i] == '-') {
		i ++;

		if (i < input.size() && input[i] == '-') {
			i ++;
		}
	}

	while (i < input.size()) {
		auto c = input[i];

		if (!is_plain_ident(c)) {
			if (c == '\\' && i + 1 < input.size ()) {
				need_escape = true;
				auto nhex = 0;

				/* Need to find an escape end */
				do {
					c = input[++i];
					if (g_ascii_isxdigit(c)) {
						nhex++;

						if (nhex > 6) {
							/* End of the escape */
							break;
						}
					}
					else if (nhex > 0 && c == ' ') {
						/* \[hex]{1,6} */
						i++; /* Skip one space */
						break;
					}
					else {
						/* Single \ + char */
						break;
					}
				} while (i < input.size ());
			}
			else {
				i --; /* Push token back */
				break; /* Not an ident token */
			}
		} /* !plain ident */

		i ++;
	}

	if (need_escape) {
		auto escaped = rspamd::css::unescape_css(pool, {&input[offset], i - offset});
		offset = i;

		return make_token<css_parser_token::token_type::ident_token>(escaped);
	}

	auto result = std::string_view{&input[offset], i - offset};
	offset = i;

	return make_token<css_parser_token::token_type::ident_token>(result);
}

auto css_tokeniser::consume_number() -> struct css_parser_token
{
	auto i = offset;
	auto seen_dot = false, seen_exp = false;

	if (input[i] == '-') {
		i ++;
	}
	if (input[i] == '.' && i < input.size()) {
		seen_dot = true;
		i ++;
	}

	while (i < input.size()) {
		auto c = input[i];

		if (!g_ascii_isdigit(c)) {
			if (c == '.') {
				if (!seen_dot) {
					seen_dot = true;
				}
				else {
					i --; /* Push back */
					break;
				}
			}
			else if (c == 'e' || c == 'E') {
				if (!seen_exp) {
					seen_exp = true;
					seen_dot = true; /* dots are not allowed after e */

					if (i + 1 < input.size()) {
						auto next_c = input[i + 1];
						if (next_c == '+' || next_c == '-') {
							i ++;
						}
					}
				}
				else {
					i --; /* Push back */
					break;
				}
			}
		}

		i ++;
	}

	if (i > offset) {
		double num;

		/* I wish it was supported properly */
		//auto conv_res = std::from_chars(&input[offset], &input[i], num);
		std::string numbuf{&input[offset], (i - offset)};
		num = std::stod(numbuf);

		auto ret = make_token<css_parser_token::token_type::number_token>(num);

		if (i < input.size()) {
			if (input[i] == '%') {
				ret.flags |= css_parser_token::number_percent;
				i ++;
			}
			else if (is_plain_ident(input[i])) {
				auto dim_token = consume_ident();

				if (dim_token.type == css_parser_token::token_type::ident_token) {
					if (!dim_token.adjust_dim(dim_token)) {
						auto sv = std::get<std::string_view>(dim_token.value);
						msg_debug_css("cannot apply dimension from the token %*s; number value = %.1f",
								(int)sv.size(), sv.begin(), num);
					}
				}
			}
		}

		return ret;
	}
	else {
		msg_err_css("internal error: invalid number, empty token");
		i ++;
	}

	offset = i;
	/* Should not happen */
	return make_token<css_parser_token::token_type::delim_token>(input[i - 1]);
}

/*
 * Main routine to produce lexer tokens
 */
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
		while (i < input.size() - 1) {
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

		while (i < input.size()) {
			auto c = input[i];

			if (c == '\\') {
				if (i + 1 < input.size()) {
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

			i ++;
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
	for (auto i = offset; i < input.size(); ++i) {
		auto c = input[i];

		switch (c) {
		case '/':
			if (i + 1 < input.size() && input[i + 1] == '*') {
				offset = i + 2;
				consume_comment(); /* Consume comment and go forward */
				return next_token(); /* Tail call */
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
			} while (i < input.size() && g_ascii_isspace(c));

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
		case '[':
			offset = i + 1;
			return make_token<css_parser_token::token_type::osqbrace_token>();
		case ']':
			offset = i + 1;
			return make_token<css_parser_token::token_type::esqbrace_token>();
		case '{':
			offset = i + 1;
			return make_token<css_parser_token::token_type::ocurlbrace_token>();
		case '}':
			offset = i + 1;
			return make_token<css_parser_token::token_type::ecurlbrace_token>();
		case ',':
			return make_token<css_parser_token::token_type::comma_token>();
		case ';':
			return make_token<css_parser_token::token_type::semicolon_token>();
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
		case '-':
			if (i + 1 < input.size()) {
				auto next_c = input[i + 1];

				if (g_ascii_isdigit(next_c)) {
					/* negative number */
					return consume_number();
				}
				else if (next_c == '-') {
					if (i + 2 < input.size() && input[i + 2] == '>') {
						/* XML like comment */
						return make_token<css_parser_token::token_type::cdc_token>();
					}
				}
			}
			/* No other options, a delimiter - */
			offset = i + 1;
			return make_token<css_parser_token::token_type::delim_token>(c);

			break;
		case '+':
		case '.':
			/* Maybe number */
			if (i + 1 < input.size()) {
				auto next_c = input[i + 1];

				if (g_ascii_isdigit(next_c)) {
					/* Numeric token */
					return consume_number();
				}
			}
			/* No other options, a delimiter - */
			offset = i + 1;
			return make_token<css_parser_token::token_type::delim_token>(c);

			break;
		}

	}

	return make_token<css_parser_token::token_type::eof_token>();
}

}