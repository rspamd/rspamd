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

	constexpr auto to_rgb() const -> std::uint32_t {
		return (std::uint32_t)r << 16 |
			   (std::uint32_t)g << 8 |
			   (std::uint32_t)b << 0;
	}
	friend bool operator==(const css_color& l, const css_color& r) {
		return (memcmp(&l, &r, sizeof(css_color)) == 0);
	}

	static auto white() -> css_color {
		return css_color{255, 255, 255};
	}
	static auto black() -> css_color {
		return css_color{0, 0, 0};
	}
};

struct css_dimension {
	float dim;
	bool is_percent;
};

/*
 * Simple enum class for display stuff
 */
enum class css_display_value : std::uint8_t {
	DISPLAY_INLINE,
	DISPLAY_BLOCK,
	DISPLAY_TABLE_ROW,
	DISPLAY_HIDDEN
};

/*
 * Value handler, uses std::variant instead of polymorphic classes for now
 * for simplicity
 */
struct css_value {
	std::variant<css_color,
			float,
			css_display_value,
			css_dimension,
			std::monostate> value;

	css_value() {}
	css_value(const css_color &color) :
			value(color) {}
	css_value(float num) :
			value(num) {}
	css_value(css_dimension dim) :
			value(dim) {}
	css_value(css_display_value d) :
			value(d) {}

	auto to_color(void) const -> std::optional<css_color> {
		return extract_value_maybe<css_color>();
	}

	auto to_number(void) const -> std::optional<float> {
		return extract_value_maybe<float>();
	}

	auto to_dimension(void) const -> std::optional<css_dimension> {
		return extract_value_maybe<css_dimension>();
	}

	auto to_display(void) const -> std::optional<css_display_value> {
		return extract_value_maybe<css_display_value>();
	}

	auto is_valid(void) const -> bool {
		return !(std::holds_alternative<std::monostate>(value));
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
private:
	template<typename T>
	auto extract_value_maybe(void) const -> std::optional<T> {
		if (std::holds_alternative<T>(value)) {
			return std::get<T>(value);
		}

		return std::nullopt;
	}
};

}


#endif //RSPAMD_CSS_VALUE_HXX
