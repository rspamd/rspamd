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

#include "libserver/html.h"
#include <string>
#include <variant>
#include <optional>
#include "parse_error.hxx"
#include "css_parser.hxx"
#include "contrib/expected/expected.hpp"

namespace rspamd::css {

/*
 * Simple enum class for display stuff
 */
enum class css_display_value {
	DISPLAY_NORMAL,
	DISPLAY_
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
		CSS_VALUE_STRING,
		CSS_VALUE_DISPLAY,
		CSS_VALUE_FLAG,
		CSS_VALUE_NYI,
	} type;

	std::variant<struct html_color,
			double,
			std::string,
			css_display_value,
			css_flag_value> value;

	constexpr std::optional<struct html_color> to_color (void) const {
		if (type == css_value_type::CSS_VALUE_COLOR) {
			return std::get<struct html_color>(value);
		}

		return std::nullopt;
	}

	constexpr std::optional<double> to_size (void) const {
		if (type == css_value_type::CSS_VALUE_SIZE) {
			return std::get<double>(value);
		}

		return std::nullopt;
	}

	constexpr std::optional<css_display_value> to_display (void) const {
		if (type == css_value_type::CSS_VALUE_DISPLAY) {
			return std::get<css_display_value>(value);
		}

		return std::nullopt;
	}

	constexpr std::optional<css_flag_value> to_flag (void) const {
		if (type == css_value_type::CSS_VALUE_FLAG) {
			return std::get<css_flag_value>(value);
		}

		return std::nullopt;
	}

	constexpr std::optional<std::string_view> to_string (void) const {
		if (type == css_value_type::CSS_VALUE_STRING) {
			return std::string_view(std::get<std::string>(value));
		}

		return std::nullopt;
	}

	constexpr bool is_valid (void) const {
		return (type != css_value_type::CSS_VALUE_NYI);
	}

	static tl::expected<css_value,css_parse_error> from_css_block(const css_consumed_block &bl);
};

}

#endif //RSPAMD_CSS_VALUE_HXX
