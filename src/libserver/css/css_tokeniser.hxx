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

#pragma once

#ifndef RSPAMD_CSS_TOKENISER_HXX
#define RSPAMD_CSS_TOKENISER_HXX

#include <string_view>
#include <utility>
#include <variant>
#include <list>
#include <functional>
#include <cstdint>
#include "mem_pool.h"

namespace rspamd::css {

struct css_parser_token_placeholder {}; /* For empty tokens */

struct css_parser_token {

	enum class token_type : std::uint8_t {
		whitespace_token,
		ident_token,
		function_token,
		at_keyword_token,
		hash_token,
		string_token,
		number_token,
		url_token,
		cdo_token, /* xml open comment */
		cdc_token, /* xml close comment */
		delim_token,
		obrace_token,     /* ( */
		ebrace_token,     /* ) */
		osqbrace_token,   /* [ */
		esqbrace_token,   /* ] */
		ocurlbrace_token, /* { */
		ecurlbrace_token, /* } */
		comma_token,
		colon_token,
		semicolon_token,
		eof_token,
	};

	enum class dim_type : std::uint8_t {
		dim_px = 0,
		dim_em,
		dim_rem,
		dim_ex,
		dim_ch,
		dim_lh,
		dim_cap,
		dim_ic,
		dim_rlh,
		dim_vw,
		dim_vh,
		dim_vmax,
		dim_vmin,
		dim_svw,
		dim_svh,
		dim_svi,
		dim_svb,
		dim_svmin,
		dim_svmax,
		dim_lvw,
		dim_lvh,
		dim_lvi,
		dim_lvb,
		dim_lvmin,
		dim_lvmax,
		dim_dvw,
		dim_dvh,
		dim_dvi,
		dim_dvb,
		dim_dvmin,
		dim_dvmax,
		dim_vi,
		dim_vb,
		dim_cqw,
		dim_cqh,
		dim_cqi,
		dim_cqb,
		dim_cqmin,
		dim_cqmax,
		dim_pt,
		dim_cm,
		dim_mm,
		dim_q,
		dim_in,
		dim_pc,
		dim_max,
	};

	static const std::uint8_t default_flags = 0;
	static const std::uint8_t flag_bad_string = (1u << 0u);
	static const std::uint8_t number_dimension = (1u << 1u);
	static const std::uint8_t number_percent = (1u << 2u);
	static const std::uint8_t flag_bad_dimension = (1u << 3u);

	using value_type = std::variant<std::string_view,            /* For strings and string like tokens */
									char,                        /* For delimiters (might need to move to unicode point) */
									float,                       /* For numeric stuff */
									css_parser_token_placeholder /* For general no token stuff */
									>;

	/* Typed storage */
	value_type value;

	int lineno;

	token_type type;
	std::uint8_t flags = default_flags;
	dim_type dimension_type;

	css_parser_token() = delete;
	explicit css_parser_token(token_type type, const value_type &value)
		: value(value), type(type)
	{
	}
	css_parser_token(css_parser_token &&other) = default;
	css_parser_token(const css_parser_token &token) = default;
	auto operator=(css_parser_token &&other) -> css_parser_token & = default;
	auto adjust_dim(const css_parser_token &dim_token) -> bool;

	auto get_string_or_default(const std::string_view &def) const -> std::string_view
	{
		if (std::holds_alternative<std::string_view>(value)) {
			return std::get<std::string_view>(value);
		}
		else if (std::holds_alternative<char>(value)) {
			return std::string_view(&std::get<char>(value), 1);
		}

		return def;
	}

	auto get_delim() const -> char
	{
		if (std::holds_alternative<char>(value)) {
			return std::get<char>(value);
		}

		return (char) -1;
	}

	auto get_number_or_default(float def) const -> float
	{
		if (std::holds_alternative<float>(value)) {
			auto dbl = std::get<float>(value);

			if (flags & css_parser_token::number_percent) {
				dbl /= 100.0;
			}

			return dbl;
		}

		return def;
	}

	auto get_normal_number_or_default(float def) const -> float
	{
		if (std::holds_alternative<float>(value)) {
			auto dbl = std::get<float>(value);

			if (flags & css_parser_token::number_percent) {
				dbl /= 100.0;
			}

			if (dbl < 0) {
				return 0.0;
			}
			else if (dbl > 1.0) {
				return 1.0;
			}

			return dbl;
		}

		return def;
	}

	/*
	 * Font-relative and viewport dimensions resolve against the
	 * environment rather than a fixed pixel multiplier
	 */
	auto is_relative_dimension(void) const -> bool
	{
		if (!(flags & css_parser_token::number_dimension)) {
			return false;
		}

		return dimension_type == dim_type::dim_em ||
			   dimension_type == dim_type::dim_rem ||
			   dimension_type == dim_type::dim_ex ||
			   dimension_type == dim_type::dim_ch ||
			   dimension_type == dim_type::dim_lh ||
			   dimension_type == dim_type::dim_cap ||
			   dimension_type == dim_type::dim_ic ||
			   dimension_type == dim_type::dim_rlh ||
			   dimension_type == dim_type::dim_vw ||
			   dimension_type == dim_type::dim_vh ||
			   dimension_type == dim_type::dim_vmax ||
			   dimension_type == dim_type::dim_vmin ||
			   dimension_type == dim_type::dim_svw ||
			   dimension_type == dim_type::dim_svh ||
			   dimension_type == dim_type::dim_svi ||
			   dimension_type == dim_type::dim_svb ||
			   dimension_type == dim_type::dim_svmin ||
			   dimension_type == dim_type::dim_svmax ||
			   dimension_type == dim_type::dim_lvw ||
			   dimension_type == dim_type::dim_lvh ||
			   dimension_type == dim_type::dim_lvi ||
			   dimension_type == dim_type::dim_lvb ||
			   dimension_type == dim_type::dim_lvmin ||
			   dimension_type == dim_type::dim_lvmax ||
			   dimension_type == dim_type::dim_dvw ||
			   dimension_type == dim_type::dim_dvh ||
			   dimension_type == dim_type::dim_dvi ||
			   dimension_type == dim_type::dim_dvb ||
			   dimension_type == dim_type::dim_dvmin ||
			   dimension_type == dim_type::dim_dvmax ||
			   dimension_type == dim_type::dim_vi ||
			   dimension_type == dim_type::dim_vb ||
			   dimension_type == dim_type::dim_cqw ||
			   dimension_type == dim_type::dim_cqh ||
			   dimension_type == dim_type::dim_cqi ||
			   dimension_type == dim_type::dim_cqb ||
			   dimension_type == dim_type::dim_cqmin ||
			   dimension_type == dim_type::dim_cqmax;
	}

	/* Debugging routines */
	constexpr auto get_token_type() -> const char *;
	/* This function might be slow */
	auto debug_token_str() -> std::string;
};

static auto css_parser_eof_token(void) -> const css_parser_token &
{
	static css_parser_token eof_tok{
		css_parser_token::token_type::eof_token,
		css_parser_token_placeholder()};

	return eof_tok;
}

/*
 * Whether a unit name is a known CSS length unit; the lookup is
 * case-insensitive, as CSS units are
 */
auto css_is_known_unit(std::string_view unit) -> bool;

/* Ensure that parser tokens are simple enough */
/*
 * compiler must implement P0602 "variant and optional should propagate copy/move triviality"
 * This is broken on gcc < 8!
 */
static_assert(std::is_trivially_copyable_v<css_parser_token>);

class css_tokeniser {
public:
	css_tokeniser() = delete;
	css_tokeniser(rspamd_mempool_t *pool, const std::string_view &sv)
		: input(sv), offset(0), pool(pool)
	{
	}

	auto next_token(void) -> struct css_parser_token;
	auto pushback_token(const struct css_parser_token &t) const -> void
	{
		backlog.push_back(t);
	}

	/* Position of the next token in the input, valid while nothing is pushed back */
	auto get_offset() const -> std::size_t
	{
		return offset;
	}

	/* Continue from the given position, dropping the pushed back tokens */
	auto seek(std::size_t pos) -> void
	{
		offset = std::min(pos, input.size());
		backlog.clear();
	}

private:
	std::string_view input;
	std::size_t offset;
	rspamd_mempool_t *pool;
	mutable std::list<css_parser_token> backlog;

	auto consume_number() -> struct css_parser_token;
	auto consume_ident(bool allow_number = false) -> struct css_parser_token;
};

}// namespace rspamd::css


#endif//RSPAMD_CSS_TOKENISER_HXX
