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
		obrace_token, /* ( */
		ebrace_token, /* ) */
		osqbrace_token, /* [ */
		esqbrace_token, /* ] */
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
		dim_wv,
		dim_wh,
		dim_vmax,
		dim_vmin,
		dim_pt,
		dim_cm,
		dim_mm,
		dim_in,
		dim_pc,
		dim_max,
	};

	static const std::uint8_t default_flags = 0;
	static const std::uint8_t flag_bad_string = (1u << 0u);
	static const std::uint8_t number_dimension = (1u << 1u);
	static const std::uint8_t number_percent = (1u << 2u);
	static const std::uint8_t flag_bad_dimension = (1u << 3u);

	using value_type = std::variant<std::string_view, /* For strings and string like tokens */
			char, /* For delimiters (might need to move to unicode point) */
			float, /* For numeric stuff */
			css_parser_token_placeholder /* For general no token stuff */
	>;

	/* Typed storage */
	value_type value;

	int lineno;

	token_type type;
	std::uint8_t flags = default_flags;
	dim_type dimension_type;

	css_parser_token() = delete;
	explicit css_parser_token(token_type type, const value_type &value) :
			value(value), type(type) {}
	css_parser_token(css_parser_token &&other) = default;
	css_parser_token(const css_parser_token &token) = default;
	auto operator=(css_parser_token &&other) -> css_parser_token& = default;
	auto adjust_dim(const css_parser_token &dim_token) -> bool;

	auto get_string_or_default(const std::string_view &def) const -> std::string_view {
		if (std::holds_alternative<std::string_view>(value)) {
			return std::get<std::string_view>(value);
		}
		else if (std::holds_alternative<char>(value)) {
			return std::string_view(&std::get<char>(value), 1);
		}

		return def;
	}

	auto get_delim() const -> char {
		if (std::holds_alternative<char>(value)) {
			return std::get<char>(value);
		}

		return (char)-1;
	}

	auto get_number_or_default(float def) const -> float {
		if (std::holds_alternative<float>(value)) {
			auto dbl = std::get<float>(value);

			if (flags & css_parser_token::number_percent) {
				dbl /= 100.0;
			}

			return dbl;
		}

		return def;
	}

	auto get_normal_number_or_default(float def) const -> float {
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

	/* Debugging routines */
	constexpr auto get_token_type() -> const char *;
	/* This function might be slow */
	auto debug_token_str() -> std::string;
};

static auto css_parser_eof_token(void) -> const css_parser_token & {
	static css_parser_token eof_tok {
		css_parser_token::token_type::eof_token,
				css_parser_token_placeholder()
	};

	return eof_tok;
}

/* Ensure that parser tokens are simple enough */
/*
 * compiler must implement P0602 "variant and optional should propagate copy/move triviality"
 * This is broken on gcc < 8!
 */
static_assert(std::is_trivially_copyable_v<css_parser_token>);

class css_tokeniser {
public:
	css_tokeniser() = delete;
	css_tokeniser(rspamd_mempool_t *pool, const std::string_view &sv) :
			input(sv), offset(0), pool(pool) {}

	auto next_token(void) -> struct css_parser_token;
	auto get_offset(void) const { return offset; }
	auto pushback_token(const struct css_parser_token &t) const -> void {
		backlog.push_back(t);
	}
private:
	std::string_view input;
	std::size_t offset;
	rspamd_mempool_t *pool;
	mutable std::list<css_parser_token> backlog;

	auto consume_number() -> struct css_parser_token;
	auto consume_ident(bool allow_number = false) -> struct css_parser_token;
};

}


#endif //RSPAMD_CSS_TOKENISER_HXX
