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

#include "css_property.hxx"
#include "frozen/unordered_map.h"
#include "frozen/string.h"

namespace rspamd::css {

constexpr const auto type_map = frozen::make_unordered_map<frozen::string, css_property_type>({
		{"font", css_property_type::PROPERTY_FONT},
		{"font-color", css_property_type::PROPERTY_FONT_COLOR},
		{"color", css_property_type::PROPERTY_COLOR},
		{"bgcolor", css_property_type::PROPERTY_BGCOLOR},
		{"background", css_property_type::PROPERTY_BACKGROUND},
		{"height", css_property_type::PROPERTY_HEIGHT},
		{"width", css_property_type::PROPERTY_WIDTH},
		{"display", css_property_type::PROPERTY_DISPLAY},
		{"visibility", css_property_type::PROPERTY_VISIBILITY},
});

auto token_string_to_property(const std::string_view &inp)
	-> css_property_type
{

	css_property_type ret = css_property_type::PROPERTY_NYI;

	auto known_type = type_map.find(inp);

	if (known_type != type_map.end()) {
		ret = known_type->second;
	}

	return ret;
}

auto css_property::from_token(const css_parser_token &tok)
	-> tl::expected<css_property,css_parse_error>
{
	if (tok.type == css_parser_token::token_type::ident_token) {
		auto sv = tok.get_string_or_default("");

		return css_property{token_string_to_property(sv), css_property_flag::FLAG_NORMAL};
	}

	return tl::unexpected{css_parse_error(css_parse_error_type::PARSE_ERROR_NYI)};
}

}
