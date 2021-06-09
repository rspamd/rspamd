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

#ifndef RSPAMD_CSS_PROPERTY_HXX
#define RSPAMD_CSS_PROPERTY_HXX

#include <string>
#include "css_tokeniser.hxx"
#include "parse_error.hxx"
#include "contrib/expected/expected.hpp"

namespace rspamd::css {

/*
 * To be extended with properties that are interesting from the email
 * point of view
 */
enum class css_property_type : std::uint16_t {
	PROPERTY_FONT = 0,
	PROPERTY_FONT_COLOR,
	PROPERTY_FONT_SIZE,
	PROPERTY_COLOR,
	PROPERTY_BGCOLOR,
	PROPERTY_BACKGROUND,
	PROPERTY_HEIGHT,
	PROPERTY_WIDTH,
	PROPERTY_DISPLAY,
	PROPERTY_VISIBILITY,
	PROPERTY_OPACITY,
	PROPERTY_NYI,
};

enum class css_property_flag : std::uint16_t {
	FLAG_NORMAL,
	FLAG_IMPORTANT,
	FLAG_NOT_IMPORTANT
};

struct alignas(int) css_property {
	css_property_type type;
	css_property_flag flag;

	css_property(css_property_type t, css_property_flag fl = css_property_flag::FLAG_NORMAL) :
			type(t), flag(fl) {}
	static tl::expected<css_property,css_parse_error> from_token(
			const css_parser_token &tok);

	constexpr auto to_string(void) const -> const char * {
		const char *ret = "nyi";

		switch(type) {
		case css_property_type::PROPERTY_FONT:
			ret = "font";
			break;
		case css_property_type::PROPERTY_FONT_COLOR:
			ret = "font-color";
			break;
		case css_property_type::PROPERTY_FONT_SIZE:
			ret = "font-size";
			break;
		case css_property_type::PROPERTY_COLOR:
			ret = "color";
			break;
		case css_property_type::PROPERTY_BGCOLOR:
			ret = "bgcolor";
			break;
		case css_property_type::PROPERTY_BACKGROUND:
			ret = "background";
			break;
		case css_property_type::PROPERTY_HEIGHT:
			ret = "height";
			break;
		case css_property_type::PROPERTY_WIDTH:
			ret = "width";
			break;
		case css_property_type::PROPERTY_DISPLAY:
			ret = "display";
			break;
		case css_property_type::PROPERTY_VISIBILITY:
			ret = "visibility";
			break;
		case css_property_type::PROPERTY_OPACITY:
			ret = "opacity";
			break;
		default:
			break;
		}

		return ret;
	}

	/* Helpers to define which values are valid for which properties */
	auto is_color(void) const -> bool {
		return type == css_property_type::PROPERTY_COLOR ||
				type == css_property_type::PROPERTY_BACKGROUND ||
				type == css_property_type::PROPERTY_BGCOLOR ||
				type == css_property_type::PROPERTY_FONT_COLOR ||
				type == css_property_type::PROPERTY_FONT;
	}
	auto is_dimension(void) const -> bool {
		return type == css_property_type::PROPERTY_HEIGHT ||
				type == css_property_type::PROPERTY_WIDTH ||
				type == css_property_type::PROPERTY_FONT_SIZE ||
				type == css_property_type::PROPERTY_FONT;
	}

	auto is_normal_number(void) const -> bool {
		return type == css_property_type::PROPERTY_OPACITY;
	}

	auto is_display(void) const -> bool {
		return type == css_property_type::PROPERTY_DISPLAY;
	}

	auto is_visibility(void) const -> bool {
		return type == css_property_type::PROPERTY_VISIBILITY;
	}

	auto operator==(const css_property &other) const { return type == other.type; }
};


}

/* Make properties hashable */
namespace std {
template<>
class hash<rspamd::css::css_property> {
public:
	/* Mix bits to provide slightly better distribution but being constexpr */
	constexpr size_t operator() (const rspamd::css::css_property &prop) const {
		std::size_t key = 0xdeadbeef ^static_cast<std::size_t>(prop.type);
		key = (~key) + (key << 21);
		key = key ^ (key >> 24);
		key = (key + (key << 3)) + (key << 8);
		key = key ^ (key >> 14);
		key = (key + (key << 2)) + (key << 4);
		key = key ^ (key >> 28);
		key = key + (key << 31);
		return key;
	}
};
}

#endif //RSPAMD_CSS_PROPERTY_HXX