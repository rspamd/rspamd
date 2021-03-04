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
};

/*
 * Simple enum class for display stuff
 */
enum class css_display_value {
	DISPLAY_NORMAL,
	DISPLAY_HIDDEN
};

/*
 * CSS flags
 */
enum class css_flag_value {
	FLAG_INHERIT,
	FLAG_IMPORTANT,
	FLAG_NOTIMPORTANT
};

/*
 * Value handler, uses std::variant instead of polymorphic classes for now
 * for simplicity
 */
struct css_value {
	enum class css_value_type {
		CSS_VALUE_COLOR,
		CSS_VALUE_SIZE,
		CSS_VALUE_DISPLAY,
		CSS_VALUE_FLAG,
		CSS_VALUE_NYI,
	} type;

	std::variant<css_color,
			double,
			css_display_value,
			css_flag_value,
			std::monostate> value;

	css_value(const css_color &color) :
			type(css_value_type::CSS_VALUE_COLOR), value(color) {}
	css_value(double sz) :
			type(css_value_type::CSS_VALUE_SIZE), value(sz) {}

	constexpr std::optional<css_color> to_color(void) const {
		if (type == css_value_type::CSS_VALUE_COLOR) {
			return std::get<css_color>(value);
		}

		return std::nullopt;
	}

	constexpr std::optional<double> to_size(void) const {
		if (type == css_value_type::CSS_VALUE_SIZE) {
			return std::get<double>(value);
		}

		return std::nullopt;
	}

	constexpr std::optional<css_display_value> to_display(void) const {
		if (type == css_value_type::CSS_VALUE_DISPLAY) {
			return std::get<css_display_value>(value);
		}

		return std::nullopt;
	}

	constexpr std::optional<css_flag_value> to_flag(void) const {
		if (type == css_value_type::CSS_VALUE_FLAG) {
			return std::get<css_flag_value>(value);
		}

		return std::nullopt;
	}

	constexpr bool is_valid(void) const {
		return (type != css_value_type::CSS_VALUE_NYI);
	}

	auto debug_str() const -> std::string;

	static auto from_css_block(const css_consumed_block &bl) -> tl::expected<css_value, css_parse_error>;

	static auto maybe_color_from_string(const std::string_view &input)
		-> std::optional<css_value>;
	static auto maybe_color_from_hex(const std::string_view &input)
		-> std::optional<css_value>;
	static auto maybe_color_from_function(const css_consumed_block::css_function_block &func)
		-> std::optional<css_value>;
};

}

#endif //RSPAMD_CSS_VALUE_HXX
