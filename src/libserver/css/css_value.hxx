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

#ifndef RSPAMD_CSS_VALUE_HXX
#define RSPAMD_CSS_VALUE_HXX

#include <string>
#include <variant>
#include <optional>
#include <vector>
#include <iosfwd>
#include "parse_error.hxx"
#include "css_parser.hxx"
#include "contrib/expected/expected.hpp"

namespace rspamd::css {

struct alignas(int) css_color {
	std::uint8_t r;
	std::uint8_t g;
	std::uint8_t b;

	std::uint8_t alpha;

	css_color(std::uint8_t _r, std::uint8_t _g, std::uint8_t _b, std::uint8_t _alpha = 255) :
	 	r(_r), g(_g), b(_b), alpha(_alpha) {}
	css_color() = default;
	constexpr auto to_number() const -> std::uint32_t {
		return (std::uint32_t)alpha << 24 |
				(std::uint32_t)r << 16 |
				(std::uint32_t)g << 8 |
				(std::uint32_t)b << 0;
	}
	friend bool operator==(const css_color& l, const css_color& r) {
		return (memcmp(&l, &r, sizeof(css_color)) == 0);
	}
};

struct css_dimension {
	float dim;
	bool is_percent;
};

/*
 * Simple enum class for display stuff
 */
enum class css_display_value {
	DISPLAY_NORMAL,
	DISPLAY_HIDDEN
};

/*
 * Value handler, uses std::variant instead of polymorphic classes for now
 * for simplicity
 */
struct css_value {
	/* Bitset of known types */
	enum class css_value_type {
		CSS_VALUE_COLOR = 1 << 0,
		CSS_VALUE_NUMBER = 1 << 1,
		CSS_VALUE_DISPLAY = 1 << 2,
		CSS_VALUE_DIMENSION = 1 << 3,
		CSS_VALUE_NYI = 1 << 4,
	};

	css_value_type type;
	std::variant<css_color,
			double,
			css_display_value,
			css_dimension,
			std::monostate> value;

	css_value() : type(css_value_type::CSS_VALUE_NYI) {}
	css_value(const css_color &color) :
			type(css_value_type::CSS_VALUE_COLOR), value(color) {}
	css_value(double num) :
			type(css_value_type::CSS_VALUE_NUMBER), value(num) {}
	css_value(css_dimension dim) :
			type(css_value_type::CSS_VALUE_DIMENSION), value(dim) {}
	css_value(css_display_value d) :
			type(css_value_type::CSS_VALUE_DISPLAY), value(d) {}

	auto to_color(void) const -> std::optional<css_color> {
		if (type == css_value_type::CSS_VALUE_COLOR) {
			return std::get<css_color>(value);
		}

		return std::nullopt;
	}

	auto to_number(void) const -> std::optional<double> {
		if (type == css_value_type::CSS_VALUE_NUMBER) {
			return std::get<double>(value);
		}

		return std::nullopt;
	}

	auto to_dimension(void) const -> std::optional<css_dimension> {
		if (type == css_value_type::CSS_VALUE_DIMENSION) {
			return std::get<css_dimension>(value);
		}

		return std::nullopt;
	}

	auto to_display(void) const -> std::optional<css_display_value> {
		if (type == css_value_type::CSS_VALUE_DISPLAY) {
			return std::get<css_display_value>(value);
		}

		return std::nullopt;
	}

	auto is_valid(void) const -> bool {
		return (type != css_value_type::CSS_VALUE_NYI);
	}

	auto debug_str() const -> std::string;

	static auto maybe_color_from_string(const std::string_view &input)
		-> std::optional<css_value>;
	static auto maybe_color_from_hex(const std::string_view &input)
		-> std::optional<css_value>;
	static auto maybe_color_from_function(const css_consumed_block::css_function_block &func)
		-> std::optional<css_value>;
	static auto maybe_dimension_from_number(const css_parser_token &tok)
		-> std::optional<css_value>;
	static auto maybe_display_from_string(const std::string_view &input)
		-> std::optional<css_value>;
};

}


#endif //RSPAMD_CSS_VALUE_HXX
