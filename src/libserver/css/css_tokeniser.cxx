/*
 * Copyright 2025 Vsevolod Stakhov
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

#include "css_tokeniser.hxx"
#include "css_util.hxx"
#include "css.hxx"
#include "frozen/unordered_map.h"
#include "frozen/string.h"
#include <string>
#include <cmath>

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

namespace rspamd::css {

/* Helpers to create tokens */

/*
 * This helper is intended to create tokens either with a tag and value
 * or with just a tag.
 */
template<css_parser_token::token_type T, class Arg>
auto make_token(const Arg &arg) -> css_parser_token;

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
auto make_token<css_parser_token::token_type::function_token, std::string_view>(const std::string_view &s)
	-> css_parser_token
{
	return css_parser_token{css_parser_token::token_type::function_token, s};
}

template<>
auto make_token<css_parser_token::token_type::url_token, std::string_view>(const std::string_view &s)
	-> css_parser_token
{
	return css_parser_token{css_parser_token::token_type::url_token, s};
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
auto make_token<css_parser_token::token_type::number_token, float>(const float &d)
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

static constexpr inline auto is_plain_ident_start(char c) -> bool
{
	/* NUL is replaced with U+FFFD by the preprocessing step, an ident char */
	if ((c & 0x80) || g_ascii_isalpha(c) || c == '_' || c == '\0') {
		return true;
	}

	return false;
};

static constexpr inline auto is_plain_ident(char c) -> bool
{
	if (is_plain_ident_start(c) || c == '-' || g_ascii_isdigit(c)) {
		return true;
	}

	return false;
};

struct css_dimension_data {
	css_parser_token::dim_type dtype;
	double mult;
};

/*
 * Maps from css dimensions to the multipliers that look reasonable in email
 */
constexpr const auto max_dims = static_cast<int>(css_parser_token::dim_type::dim_max);
constexpr frozen::unordered_map<frozen::string, css_dimension_data, max_dims> dimensions_map{
	{"px", {css_parser_token::dim_type::dim_px, 1.0}},
	/* EM/REM are 16 px, so multiply and round */
	{"em", {css_parser_token::dim_type::dim_em, 16.0}},
	{"rem", {css_parser_token::dim_type::dim_rem, 16.0}},
	/*
		 * Represents the x-height of the element's font.
		 * On fonts with the "x" letter, this is generally the height
		 * of lowercase letters in the font; 1ex = 0.5em in many fonts.
		 */
	{"ex", {css_parser_token::dim_type::dim_ex, 8.0}},
	/* The advance of the "0" glyph, roughly 0.5em in many fonts */
	{"ch", {css_parser_token::dim_type::dim_ch, 8.0}},
	/* The line height of the element, roughly the font size */
	{"lh", {css_parser_token::dim_type::dim_lh, 16.0}},
	/* The rarer font-relative units of the same scale */
	{"cap", {css_parser_token::dim_type::dim_cap, 10.0}},
	{"ic", {css_parser_token::dim_type::dim_ic, 16.0}},
	{"rlh", {css_parser_token::dim_type::dim_rlh, 16.0}},
	/* 1% of a viewport that a mail client is likely to use */
	{"vw", {css_parser_token::dim_type::dim_vw, 8.0}},
	{"vh", {css_parser_token::dim_type::dim_vh, 6.0}},
	{"vmax", {css_parser_token::dim_type::dim_vmax, 8.0}},
	{"vmin", {css_parser_token::dim_type::dim_vmin, 6.0}},
	/* The inline and block axes of a viewport, of the vmin scale */
	{"vi", {css_parser_token::dim_type::dim_vi, 6.0}},
	{"vb", {css_parser_token::dim_type::dim_vb, 6.0}},
	/*
	 * Small, large and dynamic viewport units: a mail client window
	 * is small, so the multipliers of the base ones apply
	 */
	{"svw", {css_parser_token::dim_type::dim_svw, 8.0}},
	{"lvw", {css_parser_token::dim_type::dim_lvw, 8.0}},
	{"dvw", {css_parser_token::dim_type::dim_dvw, 8.0}},
	{"svh", {css_parser_token::dim_type::dim_svh, 6.0}},
	{"lvh", {css_parser_token::dim_type::dim_lvh, 6.0}},
	{"dvh", {css_parser_token::dim_type::dim_dvh, 6.0}},
	{"svi", {css_parser_token::dim_type::dim_svi, 6.0}},
	{"lvi", {css_parser_token::dim_type::dim_lvi, 6.0}},
	{"dvi", {css_parser_token::dim_type::dim_dvi, 6.0}},
	{"svb", {css_parser_token::dim_type::dim_svb, 6.0}},
	{"lvb", {css_parser_token::dim_type::dim_lvb, 6.0}},
	{"dvb", {css_parser_token::dim_type::dim_dvb, 6.0}},
	{"svmin", {css_parser_token::dim_type::dim_svmin, 6.0}},
	{"lvmin", {css_parser_token::dim_type::dim_lvmin, 6.0}},
	{"dvmin", {css_parser_token::dim_type::dim_dvmin, 6.0}},
	{"svmax", {css_parser_token::dim_type::dim_svmax, 8.0}},
	{"lvmax", {css_parser_token::dim_type::dim_lvmax, 8.0}},
	{"dvmax", {css_parser_token::dim_type::dim_dvmax, 8.0}},
	/* Container query units, of the viewport scale */
	{"cqw", {css_parser_token::dim_type::dim_cqw, 8.0}},
	{"cqh", {css_parser_token::dim_type::dim_cqh, 6.0}},
	{"cqi", {css_parser_token::dim_type::dim_cqi, 6.0}},
	{"cqb", {css_parser_token::dim_type::dim_cqb, 6.0}},
	{"cqmin", {css_parser_token::dim_type::dim_cqmin, 6.0}},
	{"cqmax", {css_parser_token::dim_type::dim_cqmax, 8.0}},
	/* One point. 1pt = 1/72nd of 1in */
	{"pt", {css_parser_token::dim_type::dim_pt, 96.0 / 72.0}},
	/* 96px/2.54 */
	{"cm", {css_parser_token::dim_type::dim_cm, 96.0 / 2.54}},
	{"mm", {css_parser_token::dim_type::dim_mm, 9.60 / 2.54}},
	/* A quarter of a millimetre */
	{"q", {css_parser_token::dim_type::dim_q, 9.60 / 2.54 / 4}},
	{"in", {css_parser_token::dim_type::dim_in, 96.0}},
	/* 1pc = 12pt = 1/6th of 1in. */
	{"pc", {css_parser_token::dim_type::dim_pc, 96.0 / 6.0}}};

auto css_parser_token::adjust_dim(const css_parser_token &dim_token) -> bool
{
	if (!std::holds_alternative<float>(value) ||
		!std::holds_alternative<std::string_view>(dim_token.value)) {
		/* Invalid tokens */
		return false;
	}

	/* The multiplication is done in double to keep a huge number finite */
	double num = std::get<float>(value);
	auto sv = std::get<std::string_view>(dim_token.value);

	/* CSS units are case-insensitive */
	char lower_buf[8];

	if (sv.size() > sizeof(lower_buf) - 1) {
		/* Longer than any known unit */
		flags |= css_parser_token::flag_bad_dimension;

		return false;
	}

	auto unit_len = sv.size();

	for (auto i = 0; i < unit_len; i++) {
		lower_buf[i] = g_ascii_tolower(sv[i]);
	}

	auto dim_found = find_map(dimensions_map,
							  std::string_view{lower_buf, unit_len});

	if (dim_found) {
		auto dim_elt = dim_found.value().get();
		dimension_type = dim_elt.dtype;
		flags |= css_parser_token::number_dimension;
		num *= dim_elt.mult;
	}
	else {
		flags |= css_parser_token::flag_bad_dimension;

		return false;
	}

	/* A huge number multiplied by a unit stays finite */
	if (num > G_MAXFLOAT) {
		num = G_MAXFLOAT;
	}
	else if (num < -G_MAXFLOAT) {
		num = -G_MAXFLOAT;
	}

	value = static_cast<float>(num);

	return true;
}

/*
 * Consume functions: return a token and advance lexer offset
 */
auto css_tokeniser::consume_ident(bool allow_number) -> struct css_parser_token {
	auto i = offset;
	auto need_escape = false;
	auto allow_middle_minus = false;

	auto maybe_escape_sv = [&](auto cur_pos, auto tok_type) -> auto {
		if (need_escape) {
			auto escaped = rspamd::css::unescape_css(pool, {&input[offset],
															cur_pos - offset});
			offset = cur_pos;

			return css_parser_token{tok_type, escaped};
		}

		auto result = std::string_view{&input[offset], cur_pos - offset};
		offset = cur_pos;

		return css_parser_token{tok_type, result};
	};

	/* Ident token can start from `-` or `--` */
	if (input[i] == '-') {
		i++;

		if (i < input.size() && input[i] == '-') {
			i++;
			allow_middle_minus = true;
		}
	}

	while (i < input.size()) {
		auto c = input[i];

		auto is_plain_c = (allow_number || allow_middle_minus) ? is_plain_ident(c) : is_plain_ident_start(c);
		if (!is_plain_c) {
			if (c == '\\' && i + 1 < input.size() &&
				input[i + 1] != '\n' && input[i + 1] != '\r' && input[i + 1] != '\f') {
				/* Escape token */
				need_escape = true;
				auto j = i + 1;

				if (g_ascii_isxdigit(input[j])) {
					/*
					 * \[hex]{1,6}, optionally followed by a single whitespace
					 * that belongs to the escape
					 */
					auto nhex = 0;

					while (j < input.size() && nhex < 6 && g_ascii_isxdigit(input[j])) {
						j++;
						nhex++;
					}

					if (j < input.size() && g_ascii_isspace(input[j])) {
						if (input[j] == '\r' && j + 1 < input.size() && input[j + 1] == '\n') {
							j++;
						}
						j++;
					}
				}
				else {
					/* Single \ + char */
					j++;
				}

				i = j;
				allow_middle_minus = true;
				continue;
			}
			else if (c == '(') {
				/* Function or url token */
				auto j = i + 1;

				while (j < input.size() && g_ascii_isspace(input[j])) {
					j++;
				}

				if (!need_escape && i - offset == 3 &&
					g_ascii_strncasecmp(&input[offset], "url", 3) == 0) {
					if (j < input.size() && (input[j] == '"' || input[j] == '\'')) {
						/* Function token */
						auto ret = maybe_escape_sv(i,
												   css_parser_token::token_type::function_token);
						/* The function token owns its opening parenthesis */
						offset = i + 1;
						return ret;
					}
					else {
						/* Consume URL token */
						while (j < input.size() && input[j] != ')') {
							j++;
						}

						if (j < input.size() && input[j] == ')') {
							/* Valid url token */
							auto ret = maybe_escape_sv(j + 1,
													   css_parser_token::token_type::url_token);
							return ret;
						}
						else {
							/* Incomplete url token */
							auto ret = maybe_escape_sv(j,
													   css_parser_token::token_type::url_token);

							ret.flags |= css_parser_token::flag_bad_string;
							return ret;
						}
					}
				}
				else {
					auto ret = maybe_escape_sv(i,
											   css_parser_token::token_type::function_token);
					/* The function token owns its opening parenthesis */
					offset = i + 1;
					return ret;
				}
			}
			else if (c == '-' && allow_middle_minus) {
				i++;
				continue;
			}
			else {
				break; /* Not an ident token */
			}
		} /* !plain ident */
		else {
			allow_middle_minus = true;
		}

		i++;
	}

	return maybe_escape_sv(i, css_parser_token::token_type::ident_token);
}

auto
css_tokeniser::consume_number() -> struct css_parser_token {
	/*
	 * The extent of the number is found as the CSS syntax defines it:
	 * [sign] digits [. digits] [(e|E) [sign] digits]; a dot or an exponent
	 * mark that is not followed by a digit does not belong to the number
	 */
	auto i = offset;
	const auto n = input.size();

	if (i < n && (input[i] == '-' || input[i] == '+')) {
		i++;
	}

	while (i < n && g_ascii_isdigit(input[i])) {
		i++;
	}

	if (i + 1 < n && input[i] == '.' && g_ascii_isdigit(input[i + 1])) {
		i += 2;

		while (i < n && g_ascii_isdigit(input[i])) {
			i++;
		}
	}

	if (i < n && (input[i] == 'e' || input[i] == 'E')) {
		auto j = i + 1;

		if (j < n && (input[j] == '-' || input[j] == '+')) {
			j++;
		}

		if (j < n && g_ascii_isdigit(input[j])) {
			while (j < n && g_ascii_isdigit(input[j])) {
				j++;
			}

			i = j;
		}
	}

	if (i == offset) {
		/* Not a number at all, cannot happen for a checked start */
		msg_err_css("internal error: invalid number, empty token");
		offset++;

		return make_token<css_parser_token::token_type::delim_token>(input[offset - 1]);
	}

	/*
	 * g_ascii_strtod needs a NUL terminated string: use the stack for
	 * the usual numbers, and the heap for a long run of digits, so the
	 * value is never taken from a truncated copy
	 */
	char numbuf[64];
	std::string long_num;
	const char *numstr;
	auto len = i - offset;

	if (len < sizeof(numbuf)) {
		memcpy(numbuf, &input[offset], len);
		numbuf[len] = '\0';
		numstr = numbuf;
	}
	else {
		long_num.assign(&input[offset], len);
		numstr = long_num.c_str();
	}

	auto num = g_ascii_strtod(numstr, nullptr);
	offset = i;

	/* Out of the float range numbers are clamped, not dropped */
	if (std::isnan(num)) {
		num = 0;
	}
	else if (num > G_MAXFLOAT) {
		num = G_MAXFLOAT;
	}
	else if (num < -G_MAXFLOAT) {
		num = -G_MAXFLOAT;
	}

	auto ret = make_token<css_parser_token::token_type::number_token>(static_cast<float>(num));

	if (i < n) {
		if (input[i] == '%') {
			ret.flags |= css_parser_token::number_percent;
			offset = i + 1;
		}
		else if (is_plain_ident_start(input[i])) {
			auto dim_token = consume_ident();

			if (dim_token.type == css_parser_token::token_type::ident_token) {
				if (!ret.adjust_dim(dim_token)) {
					auto sv = std::get<std::string_view>(dim_token.value);
					msg_debug_css("cannot apply dimension from the token %*s; number value = %.1f",
								  (int) sv.size(), sv.begin(), num);
					/* Unconsume ident */
					offset = i;
				}
			}
			else {
				/* We have no option but to uncosume ident token in this case */
				msg_debug_css("got invalid ident like token after number, unconsume it");
				offset = i;
			}
		}
	}

	return ret;
}

/*
 * Main routine to produce lexer tokens
 */
auto
css_tokeniser::next_token(void) -> struct css_parser_token {
	/* Check pushback queue */
	if (!backlog.empty()) {
		auto tok = backlog.front();
		backlog.pop_front();

		return tok;
	}
	/* Helpers */

	/*
	 * This lambda eats a comment, which ends at the first closing sequence:
	 * comments do not nest. Offset is set to the next character after a comment, or to
	 * the end of the input for an unterminated one. Nothing is returned
	 */
	auto consume_comment = [this]() {
		auto i = offset;

		while (i + 1 < input.size()) {
			if (input[i] == '*' && input[i + 1] == '/') {
				offset = i + 2;
				return;
			}

			i++;
		}

		offset = input.size();
	};

	/*
	 * Consume quoted string, returns a string token, offset is set one
	 * character after the string. Css unescaping is done automatically.
	 * Accepts a quote char to find end of string. A backslash escapes the next
	 * character, so an escaped quote does not end the string. A newline that is
	 * not escaped ends the string as a bad one: the newline is left in the
	 * input and the token is flagged
	 */
	auto consume_string = [this](auto quote_char) -> css_parser_token {
		auto i = offset;
		bool need_unescape = false;

		auto make_result = [&](std::size_t end, bool bad) -> css_parser_token {
			std::string_view res{&input[offset], end - offset};

			if (need_unescape) {
				res = rspamd::css::unescape_css(pool, res, true);
			}

			auto tok = make_token<css_parser_token::token_type::string_token>(res);

			if (bad) {
				tok.flags |= css_parser_token::flag_bad_string;
			}

			return tok;
		};

		while (i < input.size()) {
			auto c = input[i];

			if (c == '\\') {
				if (i + 1 < input.size()) {
					need_unescape = true;

					if (input[i + 1] == '\r' && i + 2 < input.size() && input[i + 2] == '\n') {
						i++;
					}

					/* Skip the escaped character, it cannot end the string */
					i += 2;
					continue;
				}
				/* \ at the end -> ignore */
			}
			else if (c == quote_char) {
				/* End of string */
				auto ret = make_result(i, false);

				offset = i + 1;

				return ret;
			}
			else if (c == '\n' || c == '\r' || c == '\f') {
				auto ret = make_result(i, true);

				offset = i;

				return ret;
			}

			i++;
		}

		/* EOF with no quote character, consider it fine */
		auto ret = make_result(i, false);

		offset = i;

		return ret;
	};

	/* Whether an identifier can start at the position */
	auto would_start_ident = [this](std::size_t pos) -> bool {
		if (pos >= input.size()) {
			return false;
		}

		auto c = input[pos];

		if (is_plain_ident_start(c)) {
			return true;
		}

		if (c == '-') {
			if (pos + 1 >= input.size()) {
				return false;
			}

			auto next_c = input[pos + 1];

			return next_c == '-' || is_plain_ident_start(next_c) ||
				   (next_c == '\\' && pos + 2 < input.size() &&
					input[pos + 2] != '\n' && input[pos + 2] != '\r' &&
					input[pos + 2] != '\f');
		}

		return c == '\\' && pos + 1 < input.size() && input[pos + 1] != '\n' &&
			   input[pos + 1] != '\r' && input[pos + 1] != '\f';
	};

	/* Whether a number can start at the position */
	auto would_start_number = [this](std::size_t pos) -> bool {
		if (pos >= input.size()) {
			return false;
		}

		auto c = input[pos];

		if (c == '-' || c == '+') {
			pos++;

			if (pos >= input.size()) {
				return false;
			}

			c = input[pos];
		}

		if (c == '.') {
			return pos + 1 < input.size() && g_ascii_isdigit(input[pos + 1]);
		}

		return g_ascii_isdigit(c);
	};

	/*
	 * Main tokenisation loop
	 *
	 * Every branch below either returns a token or, for comments, moves `i`
	 * past the comment and continues. Recursing on comments would consume
	 * stack proportionally to their count in the input.
	 */
	auto i = offset;

	while (i < input.size()) {
		auto c = input[i];

		switch (c) {
		case '/':
			if (i + 1 < input.size() && input[i + 1] == '*') {
				offset = i + 2;
				consume_comment(); /* Consume comment and restart from the new offset */
				/* consume_comment never moves offset backwards, so this always progresses */
				i = offset;
				continue;
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
		case '\f': {
			/* Consume as much space as we can */
			while (i < input.size() &&
				   (input[i] == ' ' || input[i] == '\t' || input[i] == '\n' ||
					input[i] == '\r' || input[i] == '\f')) {
				i++;
			}

			auto ret = make_token<css_parser_token::token_type::whitespace_token>(
				std::string_view(&input[offset], i - offset));
			offset = i;
			return ret;
		}
		case '"':
		case '\'':
			offset = i + 1;
			if (offset < input.size()) {
				return consume_string(c);
			}
			else {
				/* Unpaired quote at the end of the rule */
				return make_token<css_parser_token::token_type::delim_token>(c);
			}
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
			offset = i + 1;
			return make_token<css_parser_token::token_type::comma_token>();
		case ';':
			offset = i + 1;
			return make_token<css_parser_token::token_type::semicolon_token>();
		case ':':
			offset = i + 1;
			return make_token<css_parser_token::token_type::colon_token>();
		case '<':
			/* Maybe an xml like comment */
			if (i + 3 < input.size() && input[i + 1] == '!' && input[i + 2] == '-' && input[i + 3] == '-') {
				offset = i + 4;

				return make_token<css_parser_token::token_type::cdo_token>();
			}
			else {
				offset = i + 1;
				return make_token<css_parser_token::token_type::delim_token>(c);
			}
			break;
		case '-':
		case '+':
		case '.':
			if (would_start_number(i)) {
				return consume_number();
			}

			if (c == '-') {
				if (i + 2 < input.size() && input[i + 1] == '-' && input[i + 2] == '>') {
					/* XML like comment */
					offset = i + 3;

					return make_token<css_parser_token::token_type::cdc_token>();
				}

				if (would_start_ident(i)) {
					return consume_ident();
				}
			}

			/* No other options, a delimiter */
			offset = i + 1;
			return make_token<css_parser_token::token_type::delim_token>(c);
		case '\\':
			if (i + 1 < input.size()) {
				if (input[i + 1] == '\n' || input[i + 1] == '\r') {
					offset = i + 1;
					return make_token<css_parser_token::token_type::delim_token>(c);
				}
				else {
					/* Valid escape, assume ident */
					return consume_ident();
				}
			}
			else {
				offset = i + 1;
				return make_token<css_parser_token::token_type::delim_token>(c);
			}
			break;
		case '@':
			if (would_start_ident(i + 1)) {
				offset = i + 1;
				auto ident_token = consume_ident();

				if (ident_token.type == css_parser_token::token_type::ident_token) {
					/* Update type */
					ident_token.type = css_parser_token::token_type::at_keyword_token;
				}
				else if (ident_token.type == css_parser_token::token_type::function_token) {
					/* An at-keyword is never a function: leave the parenthesis alone */
					ident_token.type = css_parser_token::token_type::at_keyword_token;
					offset--;
				}

				return ident_token;
			}
			else {
				offset = i + 1;
				return make_token<css_parser_token::token_type::delim_token>(c);
			}
			break;
		case '#':
			/* TODO: make it more conformant */
			if (i + 2 < input.size()) {
				auto next_c = input[i + 1], next_next_c = input[i + 2];
				if ((is_plain_ident(next_c) || next_c == '-') &&
					(is_plain_ident(next_next_c) || next_next_c == '-')) {
					offset = i + 1;
					/* We consume indent, but we allow numbers there */
					auto ident_token = consume_ident(true);

					if (ident_token.type == css_parser_token::token_type::ident_token) {
						/* Update type */
						ident_token.type = css_parser_token::token_type::hash_token;
					}

					return ident_token;
				}
				else {
					offset = i + 1;
					return make_token<css_parser_token::token_type::delim_token>(c);
				}
			}
			else {
				offset = i + 1;
				return make_token<css_parser_token::token_type::delim_token>(c);
			}
			break;
		default:
			/* Generic parsing code */

			if (g_ascii_isdigit(c)) {
				return consume_number();
			}
			else if (is_plain_ident_start(c)) {
				return consume_ident();
			}
			else {
				offset = i + 1;
				return make_token<css_parser_token::token_type::delim_token>(c);
			}
			break;
		}

		/* Not reached: all cases above either return or continue */
		break;
	}

	return make_token<css_parser_token::token_type::eof_token>();
}

constexpr auto
css_parser_token::get_token_type() -> const char *
{
	const char *ret = "unknown";

	switch (type) {
	case token_type::whitespace_token:
		ret = "whitespace";
		break;
	case token_type::ident_token:
		ret = "ident";
		break;
	case token_type::function_token:
		ret = "function";
		break;
	case token_type::at_keyword_token:
		ret = "atkeyword";
		break;
	case token_type::hash_token:
		ret = "hash";
		break;
	case token_type::string_token:
		ret = "string";
		break;
	case token_type::number_token:
		ret = "number";
		break;
	case token_type::url_token:
		ret = "url";
		break;
	case token_type::cdo_token: /* xml open comment */
		ret = "cdo";
		break;
	case token_type::cdc_token: /* xml close comment */
		ret = "cdc";
		break;
	case token_type::delim_token:
		ret = "delim";
		break;
	case token_type::obrace_token: /* ( */
		ret = "obrace";
		break;
	case token_type::ebrace_token: /* ) */
		ret = "ebrace";
		break;
	case token_type::osqbrace_token: /* [ */
		ret = "osqbrace";
		break;
	case token_type::esqbrace_token: /* ] */
		ret = "esqbrace";
		break;
	case token_type::ocurlbrace_token: /* { */
		ret = "ocurlbrace";
		break;
	case token_type::ecurlbrace_token: /* } */
		ret = "ecurlbrace";
		break;
	case token_type::comma_token:
		ret = "comma";
		break;
	case token_type::colon_token:
		ret = "colon";
		break;
	case token_type::semicolon_token:
		ret = "semicolon";
		break;
	case token_type::eof_token:
		ret = "eof";
		break;
	}

	return ret;
}


auto css_parser_token::debug_token_str() -> std::string
{
	const auto *token_type_str = get_token_type();
	std::string ret = token_type_str;

	std::visit([&](auto arg) -> auto {
		using T = std::decay_t<decltype(arg)>;

		if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, char>) {
			ret += "; value=";
			ret += arg;
		}
		else if constexpr (std::is_same_v<T, double>) {
			ret += "; value=";
			ret += std::to_string(arg);
		}
	},
			   value);

	if ((flags & (~number_dimension)) != default_flags) {
		ret += "; flags=" + std::to_string(flags);
	}

	if (flags & number_dimension) {
		ret += "; dim=" + std::to_string(static_cast<int>(dimension_type));
	}

	return ret; /* Copy elision */
}

TEST_SUITE("css")
{
	TEST_CASE("comments are skipped")
	{
		using tt = css_parser_token::token_type;
		const std::vector<std::pair<const char *, std::vector<tt>>> cases{
			{"/**/", {tt::eof_token}},
			/* An unterminated comment runs to the end of the input */
			{"/* unterminated", {tt::eof_token}},
			{"/*/", {tt::eof_token}},
			{"/* a /* b */ c", {tt::whitespace_token, tt::ident_token, tt::eof_token}},
			{"/", {tt::delim_token, tt::eof_token}},
			{"/*a*/b", {tt::ident_token, tt::eof_token}},
			{"a/*b*/c", {tt::ident_token, tt::ident_token, tt::eof_token}},
			{"/*a*//*b*//*c*/d", {tt::ident_token, tt::eof_token}},
			/* Comments do not nest: the first closing sequence ends the comment */
			{"/* /* nested */ still */e",
			 {tt::whitespace_token, tt::ident_token, tt::whitespace_token, tt::delim_token,
			  tt::delim_token, tt::ident_token, tt::eof_token}},
			{"/*a*/ /*b*/\n/*c*/f", {tt::whitespace_token, tt::whitespace_token, tt::ident_token, tt::eof_token}},
			{"p/*x*/{/*y*/color/*z*/:red}",
			 {tt::ident_token, tt::ocurlbrace_token, tt::ident_token, tt::colon_token, tt::ident_token,
			  tt::ecurlbrace_token, tt::eof_token}},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		for (const auto &c: cases) {
			css_tokeniser tok{pool, c.first};

			for (auto expected: c.second) {
				auto t = tok.next_token();
				CHECK_MESSAGE(t.type == expected, std::string{c.first});
			}
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("hex escape consumes exactly one trailing space")
	{
		using tt = css_parser_token::token_type;
		/* The escaped ident is followed by `{`, which is not part of it */
		const std::string_view full{"a\\41 {"};
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		for (auto input: {full, full.substr(0, full.size() - 1)}) {
			css_tokeniser tok{pool, input};

			auto t = tok.next_token();
			REQUIRE(t.type == tt::ident_token);
			CHECK(std::get<std::string_view>(t.value) == "aa");

			if (input.size() == full.size()) {
				CHECK(tok.next_token().type == tt::ocurlbrace_token);
			}

			CHECK(tok.next_token().type == tt::eof_token);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("strings end at the unescaped quote")
	{
		using tt = css_parser_token::token_type;
		struct str_case {
			std::string_view input;
			std::string_view value;
			bool bad;
			tt next;
		};
		const std::vector<str_case> cases{
			{R"x("abc")x", "abc", false, tt::eof_token},
			{R"x("a\"b"x)x", R"x(a"b)x", false, tt::ident_token},
			{R"x('a\'b'x)x", "a'b", false, tt::ident_token},
			/* An escaped backslash does not escape the quote */
			{R"x("a\\"x)x", R"x(a\)x", false, tt::ident_token},
			/* A backslash before a newline continues the string */
			{"\"a\\\nb\"x", "ab", false, tt::ident_token},
			{"\"a\\\r\nb\"x", "ab", false, tt::ident_token},
			/* A raw newline ends the string as a bad one */
			{"\"a\nb", "a", true, tt::whitespace_token},
			{"\"a\rb", "a", true, tt::whitespace_token},
			{"\"a\fb", "a", true, tt::whitespace_token},
			/* An unterminated string at the end of the input is fine */
			{R"x("abc)x", "abc", false, tt::eof_token},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		for (const auto &c: cases) {
			css_tokeniser tok{pool, c.input};
			auto t = tok.next_token();

			REQUIRE_MESSAGE(t.type == tt::string_token, std::string{c.input});
			CHECK_MESSAGE(std::get<std::string_view>(t.value) == c.value, std::string{c.input});
			CHECK_MESSAGE(((t.flags & css_parser_token::flag_bad_string) != 0) == c.bad,
						  std::string{c.input});
			CHECK_MESSAGE(tok.next_token().type == c.next, std::string{c.input});
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("escapes do not create syntax")
	{
		using tt = css_parser_token::token_type;
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		/* Name characters are decoded, so that class names still match */
		CHECK(unescape_css(pool, R"x(\68 ide)x") == "hide");
		CHECK(unescape_css(pool, R"x(\68ide)x") == "hide");
		CHECK(unescape_css(pool, R"x(\48 IDE)x") == "hide");
		CHECK(unescape_css(pool, R"x(a\2d b)x") == "a-b");
		CHECK(unescape_css(pool, R"x(\68\69)x") == "hi");
		CHECK(unescape_css(pool, R"x(\e9 t)x") == "\xc3\xa9t");
		/* At most six digits belong to an escape */
		CHECK(unescape_css(pool, R"x(\000041b)x") == "ab");

		/* Anything else stays an escape and never turns into a syntax character */
		for (const auto *in: {R"x(\7b)x", R"x(\7d)x", R"x(\3a)x", R"x(\3b)x", R"x(\7B )x",
							  R"x(\22 )x", R"x(\27)x", R"x(\5c)x", R"x(\0)x", R"x(\2f)x", R"x(\2a)x"}) {
			auto out = unescape_css(pool, in);
			CHECK_MESSAGE(out.find_first_of(R"x({};:"'/*)x") == std::string_view::npos,
						  std::string{in});
			/* Unescaping the result once more changes nothing */
			CHECK_MESSAGE(unescape_css(pool, out) == out, std::string{in});
		}

		/* An escaped character that is not a name character keeps its backslash */
		for (const auto *in: {R"x(\{)x", R"x(\;)x", R"x(\})x", R"x(\:)x", R"x(\")x", R"x(\')x",
							  R"x(\/)x", R"x(\*)x", R"x(\()x", R"x(\!)x"}) {
			CHECK_MESSAGE(unescape_css(pool, in) == in, std::string{in});
		}

		CHECK(unescape_css(pool, R"x(.\7b x{a:b})x") == R"x(.\7b x{a:b})x");
		CHECK(unescape_css(pool, R"x(.a\3b{})x") == R"x(.a\3b{})x");
		CHECK(unescape_css(pool, R"x(\7b{)x") == R"x(\7b{)x");
		CHECK(unescape_css(pool, R"x(\7b a)x") == R"x(\7b a)x");
		CHECK(unescape_css(pool, R"x(\00007b a)x") == R"x(\00007b a)x");
		CHECK(unescape_css(pool, R"x(\00007b1)x") == R"x(\00007b 1)x");
		/* A lone backslash and a backslash before a newline are not escapes */
		CHECK(unescape_css(pool, "a\\") == "a\\");
		CHECK(unescape_css(pool, "a\\\nb") == "a\\\nb");
		/* Strings and comments are copied, only the rest is lowercased */
		CHECK(unescape_css(pool, R"x(A"B\7b"C)x") == R"x(a"B\7b"c)x");
		CHECK(unescape_css(pool, R"x(A/* B " */C)x") == R"x(a/* B " */c)x");
		CHECK(unescape_css(pool, "A\"b\nC") == "a\"b\nc");
		CHECK(unescape_css(pool, R"x("\\"\68 IDE)x") == R"x("\\"hide)x");
		/* The content of a string gets all escapes decoded */
		CHECK(unescape_css(pool, "a\\\"b\\7b\\\nc", true) == "a\"b{c");

		/* The tokeniser reads a kept escape as a part of an identifier */
		css_tokeniser tok{pool, R"x(.a\7b x{})x"};
		CHECK(tok.next_token().type == tt::delim_token);
		CHECK(tok.next_token().type == tt::ident_token);
		CHECK(tok.next_token().type == tt::ocurlbrace_token);
		CHECK(tok.next_token().type == tt::ecurlbrace_token);

		for (const auto *in: {R"x(a\;b)x", R"x(\{a)x", R"x(a\7d{)x"}) {
			css_tokeniser t2{pool, in};

			CHECK_MESSAGE(t2.next_token().type == tt::ident_token, std::string{in});
			CHECK_MESSAGE(css_has_escape(in), std::string{in});
		}

		/* The escape ends before the character that follows its digits */
		css_tokeniser t3{pool, R"x(a\7d{)x"};
		CHECK(t3.next_token().type == tt::ident_token);
		CHECK(t3.next_token().type == tt::ocurlbrace_token);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("escapes are looked for outside of strings and comments")
	{
		CHECK(css_has_escape(R"x(a\b)x"));
		CHECK(css_has_escape(R"x("a" \68 ide)x"));
		CHECK(!css_has_escape(R"x("a\"b")x"));
		/* An escaped backslash does not escape the closing quote */
		CHECK(css_has_escape(R"x("\\" \68 ide)x"));
		CHECK(!css_has_escape(R"x(/* \ */ a)x"));
		/* A quote in a comment does not open a string */
		CHECK(css_has_escape(R"x(/* it's */ \68 ide)x"));
		/* A newline ends a string */
		CHECK(css_has_escape("\"a\n\\68 ide"));
		CHECK(!css_has_escape("\"a\\\nb\\68 ide\""));
	}

	TEST_CASE("number tokens follow the CSS syntax")
	{
		using tt = css_parser_token::token_type;
		struct num_case {
			std::string input;
			float value;
			bool dimension;
			bool percent;
			std::vector<tt> rest; /* the tokens that follow the number */
		};
		const std::vector<num_case> cases{
			{"1e2px", 100, true, false, {}},
			{"1E2px", 100, true, false, {}},
			{"1e+2px", 100, true, false, {}},
			{"1.5e-1px", 0.15f, true, false, {}},
			{"1e2", 100, false, false, {}},
			{"1em", 16, true, false, {}},
			{"1ex", 8, true, false, {}},
			{"+1px", 1, true, false, {}},
			{"-1px", -1, true, false, {}},
			{".5px", 0.5f, true, false, {}},
			{"+.5px", 0.5f, true, false, {}},
			{"-.5px", -0.5f, true, false, {}},
			{"50%", 50, false, true, {}},
			{"1PX", 1, true, false, {}},
			{"1.px", 1, false, false, {tt::delim_token, tt::ident_token}},
			{"1e+px", 1, false, false, {tt::ident_token, tt::delim_token, tt::ident_token}},
			{"1.5.5", 1.5f, false, false, {tt::number_token}},
			{"1e2e2", 100, false, false, {tt::ident_token}},
			{std::string(40, '0') + "100px", 100, true, false, {}},
			{std::string(300, '0') + "100px", 100, true, false, {}},
			{"0." + std::string(200, '0') + "1", 0, false, false, {}},
			{"1" + std::string(300, '0'), G_MAXFLOAT, false, false, {}},
			{"-1" + std::string(300, '0'), -G_MAXFLOAT, false, false, {}},
			{"1e999", G_MAXFLOAT, false, false, {}},
			{"3e38in", G_MAXFLOAT, true, false, {}},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		for (const auto &c: cases) {
			css_tokeniser tok{pool, c.input};
			auto t = tok.next_token();
			auto label = c.input.substr(0, 40);

			REQUIRE_MESSAGE(t.type == tt::number_token, label);
			CHECK_MESSAGE(std::get<float>(t.value) == doctest::Approx(c.value).epsilon(1e-5), label);
			CHECK_MESSAGE(bool(t.flags & css_parser_token::number_dimension) == c.dimension, label);
			CHECK_MESSAGE(bool(t.flags & css_parser_token::number_percent) == c.percent, label);

			for (auto expected: c.rest) {
				CHECK_MESSAGE(tok.next_token().type == expected, label);
			}

			CHECK_MESSAGE(tok.next_token().type == tt::eof_token, label);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("idents strings urls and at-keywords")
	{
		using tt = css_parser_token::token_type;
		struct tok_case {
			std::string input;
			std::vector<std::pair<tt, std::string>> toks;
		};
		const std::vector<tok_case> cases{
			{"-webkit-x", {{tt::ident_token, "-webkit-x"}}},
			{"--x", {{tt::ident_token, "--x"}}},
			{"--", {{tt::ident_token, "--"}}},
			{"-", {{tt::delim_token, "-"}}},
			{"- x", {{tt::delim_token, "-"}, {tt::whitespace_token, " "}, {tt::ident_token, "x"}}},
			{"-->", {{tt::cdc_token, ""}}},
			{"<!--x", {{tt::cdo_token, ""}, {tt::ident_token, "x"}}},
			{"\"a\\\"b\"", {{tt::string_token, "a\"b"}}},
			{"'a\\'b'", {{tt::string_token, "a'b"}}},
			{"\"a\nb", {{tt::string_token, "a"}, {tt::whitespace_token, "\n"}, {tt::ident_token, "b"}}},
			{"\"a;b", {{tt::string_token, "a;b"}}},
			{"urlx(a;b)", {{tt::function_token, "urlx"}, {tt::ident_token, "a"}, {tt::semicolon_token, ""}, {tt::ident_token, "b"}, {tt::ebrace_token, ""}}},
			{"url(a;b)", {{tt::url_token, "url(a;b)"}}},
			{"URL(a)", {{tt::url_token, "URL(a)"}}},
			{"calc(1)", {{tt::function_token, "calc"}, {tt::number_token, ""}, {tt::ebrace_token, ""}}},
			{"@media{", {{tt::at_keyword_token, "media"}, {tt::ocurlbrace_token, ""}}},
			{"@x(", {{tt::at_keyword_token, "x"}, {tt::obrace_token, ""}}},
			{"@", {{tt::delim_token, "@"}}},
			{"a\v", {{tt::ident_token, "a"}, {tt::delim_token, "\v"}}},
			{"a /* x */\tb", {{tt::ident_token, "a"}, {tt::whitespace_token, " "}, {tt::whitespace_token, "\t"}, {tt::ident_token, "b"}}},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		for (const auto &c: cases) {
			css_tokeniser tok{pool, c.input};

			for (const auto &[type, text]: c.toks) {
				auto t = tok.next_token();

				CHECK_MESSAGE(t.type == type, c.input);

				if (!text.empty() && t.type != tt::number_token) {
					CHECK_MESSAGE(t.get_string_or_default("") == text, c.input);
				}
			}

			CHECK_MESSAGE(tok.next_token().type == tt::eof_token, c.input);
		}

		/* The raw newline ends a string as a bad one */
		css_tokeniser bad{pool, "\"a\nb"};
		CHECK(bool(bad.next_token().flags & css_parser_token::flag_bad_string));

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("css escapes")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);
		const std::vector<std::pair<std::string, std::string>> cases{
			{"w\\69 dth", "width"},
			{"w\\69dth", "w\xDA\x9Dth"}, /* U+069D: the escape takes all the hex digits */
			{"w\\69", "wi"},             /* cut by the end of the input */
			{"\\000041", "a"},
			{"\\0000411", "a1"}, /* at most six hex digits */
			{"\\i", "i"},
			{"\\110000 x", "\xEF\xBF\xBDx"},
			{"\\d800 x", "\xEF\xBF\xBDx"},
		};

		for (const auto &c: cases) {
			auto res = unescape_css(pool, c.first);

			CHECK_MESSAGE(std::string{res} == c.second, c.first);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("many sequential comments do not exhaust stack")
	{
		constexpr auto ncomments = 100000;
		std::string input;

		input.reserve(ncomments * 4 + 4);

		for (auto i = 0; i < ncomments; i++) {
			input += "/**/";
		}

		input += "end";

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);
		css_tokeniser tok{pool, input};

		CHECK(tok.next_token().type == css_parser_token::token_type::ident_token);
		CHECK(tok.next_token().type == css_parser_token::token_type::eof_token);

		rspamd_mempool_delete(pool);
	}
}

}// namespace rspamd::css