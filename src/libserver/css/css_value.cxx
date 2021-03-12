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

#include "css_value.hxx"
#include "css_colors_list.hxx"
#include "frozen/unordered_map.h"
#include "frozen/string.h"
#include "contrib/robin-hood/robin_hood.h"
#include "fmt/core.h"

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

/* Helper for unit test stringification */
namespace doctest {
template<> struct StringMaker<rspamd::css::css_color> {
	static String convert(const rspamd::css::css_color& value) {
		return fmt::format("r={};g={};b={};alpha={}",
				value.r, value.g, value.b, value.alpha).c_str();
	}
};

}

namespace rspamd::css {

auto css_value::maybe_color_from_string(const std::string_view &input)
-> std::optional<css_value> {
	auto found_it = css_colors_map.find(input);

	if (found_it != css_colors_map.end()) {
		return css_value{found_it->second};
	}

	return std::nullopt;
}

constexpr static inline auto hexpair_decode(char c1, char c2) -> std::uint8_t {
	std::uint8_t ret = 0;

	if (c1 >= '0' && c1 <= '9') ret = c1 - '0';
	else if (c1 >= 'A' && c1 <= 'F') ret = c1 - 'A' + 10;
	else if (c1 >= 'a' && c1 <= 'f') ret = c1 - 'a' + 10;

	ret *= 16;

	if (c2 >= '0' && c2 <= '9') ret += c2 - '0';
	else if (c2 >= 'A' && c2 <= 'F') ret += c2 - 'A' + 10;
	else if (c2 >= 'a' && c2 <= 'f') ret += c2 - 'a' + 10;

	return ret;
}

auto css_value::maybe_color_from_hex(const std::string_view &input)
-> std::optional<css_value> {
	if (input.length() == 6) {
		/* Plain RGB */
		css_color col(hexpair_decode(input[0], input[1]),
				hexpair_decode(input[2], input[3]),
				hexpair_decode(input[4], input[5]));
		return css_value(col);
	}
	else if (input.length() == 3) {
		/* Rgb as 3 hex digests */
		css_color col(hexpair_decode(input[0], input[0]),
				hexpair_decode(input[1], input[1]),
				hexpair_decode(input[2], input[2]));
		return css_value(col);
	}
	else if (input.length() == 8) {
		/* RGBA */
		css_color col(hexpair_decode(input[0], input[1]),
				hexpair_decode(input[2], input[3]),
				hexpair_decode(input[4], input[5]),
				hexpair_decode(input[6], input[7]));
		return css_value(col);
	}

	return std::nullopt;
}

constexpr static inline auto rgb_color_component_convert(const css_parser_token &tok)
-> std::uint8_t {
	std::uint8_t ret = 0;

	if (tok.type == css_parser_token::token_type::number_token) {
		auto dbl = std::get<double>(tok.value);

		if (tok.flags & css_parser_token::number_percent) {
			if (dbl > 100) {
				dbl = 100;
			}
			else if (dbl < 0) {
				dbl = 0;
			}
			ret = (std::uint8_t) (dbl / 100.0 * 255.0);
		}
		else {
			if (dbl > 1) {
				dbl = 1;
			}
			else if (dbl < 0) {
				dbl = 0;
			}

			ret = (std::uint8_t) (dbl * 255.0);
		}
	}

	return ret;
}

constexpr static inline auto alpha_component_convert(const css_parser_token &tok)
-> std::uint8_t {
	double ret = 1.0;

	if (tok.type == css_parser_token::token_type::number_token) {
		auto dbl = std::get<double>(tok.value);

		if (tok.flags & css_parser_token::number_percent) {
			if (dbl > 100) {
				dbl = 100;
			}
			else if (dbl < 0) {
				dbl = 0;
			}
			ret = (dbl / 100.0);
		}
		else {
			if (dbl > 255) {
				dbl = 255;
			}
			else if (dbl < 0) {
				dbl = 0;
			}

			ret = dbl / 255.0;
		}
	}

	return (std::uint8_t) (ret * 255.0);
}

constexpr static inline auto h_component_convert(const css_parser_token &tok)
-> double {
	double ret = 0.0;

	if (tok.type == css_parser_token::token_type::number_token) {
		auto dbl = std::get<double>(tok.value);

		if (tok.flags & css_parser_token::number_percent) {
			if (dbl > 100) {
				dbl = 100;
			}
			else if (dbl < 0) {
				dbl = 0;
			}
			ret = (dbl / 100.0);
		}
		else {
			dbl = ((((int) dbl % 360) + 360) % 360); /* Deal with rotations */
			ret = dbl / 360.0; /* Normalize to 0..1 */
		}
	}

	return ret;
}

constexpr static inline auto sl_component_convert(const css_parser_token &tok)
-> double {
	double ret = 0.0;

	if (tok.type == css_parser_token::token_type::number_token) {
		ret = tok.get_normal_number_or_default(ret);
	}

	return ret;
}

static inline auto hsl_to_rgb(double h, double s, double l)
-> css_color {
	css_color ret;

	constexpr auto hue2rgb = [](auto p, auto q, auto t) -> auto {
		if (t < 0.0) {
			t += 1.0;
		}
		if (t > 1.0) {
			t -= 1.0;
		}
		if (t * 6. < 1.0) {
			return p + (q - p) * 6.0 * t;
		}
		if (t * 2. < 1) {
			return q;
		}
		if (t * 3. < 2.) {
			return p + (q - p) * (2.0 / 3.0 - t) * 6.0;
		}
		return p;
	};

	if (s == 0) {
		/* Achromatic */
		ret.r = l;
		ret.g = l;
		ret.b = l;
	}
	else {
		auto q = l <= 0.5 ? l * (1.0 + s) : l + s - l * s;
		auto p = 2.0 * l - q;
		ret.r = (std::uint8_t) (hue2rgb(p, q, h + 1.0 / 3.0) * 255);
		ret.g = (std::uint8_t) (hue2rgb(p, q, h) * 255);
		ret.b = (std::uint8_t) (hue2rgb(p, q, h - 1.0 / 3.0) * 255);
	}

	ret.alpha = 255;

	return ret;
}

auto css_value::maybe_color_from_function(const css_consumed_block::css_function_block &func)
-> std::optional<css_value> {

	if (func.as_string() == "rgb" && func.args.size() == 3) {
		css_color col{rgb_color_component_convert(func.args[0]->get_token_or_empty()),
					  rgb_color_component_convert(func.args[1]->get_token_or_empty()),
					  rgb_color_component_convert(func.args[2]->get_token_or_empty())};

		return css_value(col);
	}
	else if (func.as_string() == "rgba" && func.args.size() == 4) {
		css_color col{rgb_color_component_convert(func.args[0]->get_token_or_empty()),
					  rgb_color_component_convert(func.args[1]->get_token_or_empty()),
					  rgb_color_component_convert(func.args[2]->get_token_or_empty()),
					  alpha_component_convert(func.args[3]->get_token_or_empty())};

		return css_value(col);
	}
	else if (func.as_string() == "hsl" && func.args.size() == 3) {
		auto h = h_component_convert(func.args[0]->get_token_or_empty());
		auto s = sl_component_convert(func.args[1]->get_token_or_empty());
		auto l = sl_component_convert(func.args[2]->get_token_or_empty());

		auto col = hsl_to_rgb(h, s, l);

		return css_value(col);
	}
	else if (func.as_string() == "hsla" && func.args.size() == 4) {
		auto h = h_component_convert(func.args[0]->get_token_or_empty());
		auto s = sl_component_convert(func.args[1]->get_token_or_empty());
		auto l = sl_component_convert(func.args[2]->get_token_or_empty());

		auto col = hsl_to_rgb(h, s, l);
		col.alpha = alpha_component_convert(func.args[3]->get_token_or_empty());

		return css_value(col);
	}

	return std::nullopt;
}

auto css_value::maybe_dimension_from_number(const css_parser_token &tok)
-> std::optional<css_value> {
	if (std::holds_alternative<double>(tok.value)) {
		auto dbl = std::get<double>(tok.value);
		css_dimension dim;

		dim.dim = dbl;

		if (tok.flags & css_parser_token::number_percent) {
			dim.is_percent = true;
		}
		else {
			dim.is_percent = false;
		}

		return css_value{dim};
	}

	return std::nullopt;
}

constexpr const auto display_names_map = frozen::make_unordered_map<frozen::string, css_display_value>({
		{"hidden",             css_display_value::DISPLAY_HIDDEN},
		{"none",               css_display_value::DISPLAY_HIDDEN},
		{"inline",             css_display_value::DISPLAY_NORMAL},
		{"block",              css_display_value::DISPLAY_NORMAL},
		{"content",            css_display_value::DISPLAY_NORMAL},
		{"flex",               css_display_value::DISPLAY_NORMAL},
		{"grid",               css_display_value::DISPLAY_NORMAL},
		{"inline-block",       css_display_value::DISPLAY_NORMAL},
		{"inline-flex",        css_display_value::DISPLAY_NORMAL},
		{"inline-grid",        css_display_value::DISPLAY_NORMAL},
		{"inline-table",       css_display_value::DISPLAY_NORMAL},
		{"list-item",          css_display_value::DISPLAY_NORMAL},
		{"run-in",             css_display_value::DISPLAY_NORMAL},
		{"table",              css_display_value::DISPLAY_NORMAL},
		{"table-caption",      css_display_value::DISPLAY_NORMAL},
		{"table-column-group", css_display_value::DISPLAY_NORMAL},
		{"table-header-group", css_display_value::DISPLAY_NORMAL},
		{"table-footer-group", css_display_value::DISPLAY_NORMAL},
		{"table-row-group",    css_display_value::DISPLAY_NORMAL},
		{"table-cell",         css_display_value::DISPLAY_NORMAL},
		{"table-column",       css_display_value::DISPLAY_NORMAL},
		{"table-row",          css_display_value::DISPLAY_NORMAL},
		{"initial",            css_display_value::DISPLAY_NORMAL},
});

auto css_value::maybe_display_from_string(const std::string_view &input)
-> std::optional<css_value> {
	auto f = display_names_map.find(input);

	if (f != display_names_map.end()) {
		return css_value{f->second};
	}

	return std::nullopt;
}


auto css_value::debug_str() const -> std::string {
	std::string ret;

	std::visit([&](const auto &arg) {
		using T = std::decay_t<decltype(arg)>;

		if constexpr (std::is_same_v<T, css_color>) {
			ret += "color: r=" + std::to_string(arg.r) +
				   "; g=" + std::to_string(arg.g) +
				   "; b=" + std::to_string(arg.b) +
				   "; a=" + std::to_string(arg.alpha);
		}
		else if constexpr (std::is_same_v<T, double>) {
			ret += "size: " + std::to_string(arg);
		}
		else if constexpr (std::is_same_v<T, css_dimension>) {
			ret += "dimension: " + std::to_string(arg.dim);
			if (arg.is_percent) {
				ret += "%";
			}
		}
		else if constexpr (std::is_same_v<T, css_display_value>) {
			ret += "display: ";
			ret += (arg == css_display_value::DISPLAY_HIDDEN ? "hidden" : "normal");
		}
		else if constexpr (std::is_integral_v<T>) {
			ret += "integral: " + std::to_string(static_cast<int>(arg));
		}
		else {
			ret += "nyi";
		}
	}, value);

	return ret;
}

TEST_SUITE("css values") {
	TEST_CASE("css hex colors") {
		const std::pair<const char*, css_color> hex_tests[] = {
				{"000", css_color(0, 0, 0)},
				{"000000", css_color(0, 0, 0)},
				{"f00", css_color(255, 0, 0)},
				{"FEDCBA", css_color(254, 220, 186)},
				{"234", css_color(34, 51, 68)},
		};

		for (const auto &p : hex_tests) {
			auto col_parsed = css_value::maybe_color_from_hex(p.first);
			//CHECK_UNARY(col_parsed);
			//CHECK_UNARY(col_parsed.value().to_color());
			auto final_col = col_parsed.value().to_color().value();
			CHECK(final_col == p.second);
		}
	}
};

}
