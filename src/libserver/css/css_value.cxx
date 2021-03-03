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
#include "contrib/robin-hood/robin_hood.h"

namespace rspamd::css {



tl::expected<css_value,css_parse_error>
css_value::from_css_block(const css_consumed_block &bl)
{
	return tl::unexpected{css_parse_error(css_parse_error_type::PARSE_ERROR_NYI)};
}

auto css_value::maybe_color_from_string(const std::string_view &input)
	-> std::optional<css_value>
{
	auto found_it = css_colors_map.find(input);

	if (found_it != css_colors_map.end()) {
		return css_value{found_it->second};
	}

	return std::nullopt;
}

constexpr static inline auto hexpair_decode(char c1, char c2) -> std::uint8_t
{
	std::uint8_t ret = 0;

	if      (c1 >= '0' && c1 <= '9') ret = c1 - '0';
	else if (c1 >= 'A' && c1 <= 'F') ret = c1 - 'A' + 10;
	else if (c1 >= 'a' && c1 <= 'f') ret = c1 - 'a' + 10;

	ret *= 16;

	if      (c2 >= '0' && c2 <= '9') ret += c2 - '0';
	else if (c2 >= 'A' && c2 <= 'F') ret += c2 - 'A' + 10;
	else if (c2 >= 'a' && c2 <= 'f') ret += c2 - 'a' + 10;

	return ret;
}

auto css_value::maybe_color_from_hex(const std::string_view &input)
	-> std::optional<css_value>
{
	if (input.length() == 6) {
		/* Plain RGB */
		css_color col(hexpair_decode(input[0], input[1]),
				hexpair_decode(input[2], input[3]),
				hexpair_decode(input[4], input[5]));
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
	-> std::uint8_t
{
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
			ret = (std::uint8_t)(dbl / 100.0 * 255.0);
		}
		else {
			if (dbl > 1) {
				dbl = 1;
			}
			else if (dbl < 0) {
				dbl = 0;
			}

			ret = (std::uint8_t)(dbl * 255.0);
		}
	}

	return ret;
}

constexpr static inline auto alpha_component_convert(const css_parser_token &tok)
	-> std::uint8_t
{
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

	return (std::uint8_t)(ret * 255.0);
}

constexpr static inline auto h_component_convert(const css_parser_token &tok)
	-> double
{
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
			ret = (dbl / 100.0) * 360.0;
		}
		else {
			if (dbl > 360) {
				dbl = 360;
			}
			else if (dbl < 0) {
				dbl = 0;
			}

			ret = dbl;
		}
	}

	return ret;
}

constexpr static inline auto sl_component_convert(const css_parser_token &tok)
	-> double
{
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
			if (dbl > 1) {
				dbl = 1;
			}
			else if (dbl < 0) {
				dbl = 0;
			}

			ret = (dbl);
		}
	}

	return ret;
}

static inline auto hsl_to_rgb(double h, double s, double l)
	-> css_color
{
	constexpr auto hue2rgb = [](auto p, auto q, auto t) -> auto {
		if (t < 0.0) {
			t += 1.0;
		}
		if (t > 1.0) {
			t -= 1.0;
		}
		if (t < 1.0/6.0) {
			return p + (q - p) * 6.0 * t;
		}
		if (t < 0.5) {
			return q;
		}
		if (t < 2.0/3.0) {
			return p + (q - p) * (2.0/3.0 - t) * 6.0;
		}
		return p * 255.0;
	};

	css_color ret;

	auto q = l < 0.5 ? l * (1.0 + s) : l + s - l * s;
	auto p = 2.0 * l - q;
	ret.r = (std::uint8_t)hue2rgb(p, q, h + 1.0/3.0);
	ret.g = (std::uint8_t)hue2rgb(p, q, h);
	ret.b = (std::uint8_t)hue2rgb(p, q, h - 1.0/3.0);

	return ret;
}

auto css_value::maybe_color_from_function(const std::string_view &func,
									  const std::vector<css_parser_token> &args)
	-> std::optional<css_value>
{
	if (func == "rgb" && args.size() == 3) {
		css_color col{rgb_color_component_convert(args[0]),
					  rgb_color_component_convert(args[1]),
					  rgb_color_component_convert(args[2])};

		return css_value(col);
	}
	else if (func == "rgba" && args.size() == 4) {
		css_color col{rgb_color_component_convert(args[0]),
					  rgb_color_component_convert(args[1]),
					  rgb_color_component_convert(args[2]),
					  alpha_component_convert(args[3])};

		return css_value(col);
	}
	else if (func == "hsl" && args.size() == 3) {
		auto h = h_component_convert(args[0]);
		auto s = sl_component_convert(args[1]);
		auto l = sl_component_convert(args[2]);

		auto col = hsl_to_rgb(h, s, l);

		return css_value(col);
	}
	else if (func == "hsla" && args.size() == 4) {
		auto h = h_component_convert(args[0]);
		auto s = sl_component_convert(args[1]);
		auto l = sl_component_convert(args[2]);

		auto col = hsl_to_rgb(h, s, l);
		col.alpha = alpha_component_convert(args[3]);

		return css_value(col);
	}

	return std::nullopt;
}

}
