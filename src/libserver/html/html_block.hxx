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
#ifndef RSPAMD_HTML_BLOCK_HXX
#define RSPAMD_HTML_BLOCK_HXX
#pragma once

#include "libserver/css/css_value.hxx"
#include <cmath>

namespace rspamd::html {

/*
 * Block tag definition
 */
struct html_block {
	rspamd::css::css_color fg_color;
	rspamd::css::css_color bg_color;
	std::int16_t height;
	std::int16_t width;
	rspamd::css::css_display_value display;
	std::int8_t font_size;

	unsigned fg_color_mask : 2;
	unsigned bg_color_mask : 2;
	unsigned height_mask : 2;
	unsigned width_mask : 2;
	unsigned font_mask : 2;
	unsigned display_mask : 2;
	unsigned visibility_mask : 2;

	constexpr static const auto unset = 0;
	constexpr static const auto inherited = 1;
	constexpr static const auto implicit = 1;
	constexpr static const auto set = 3;
	constexpr static const auto invisible_flag = 1;
	constexpr static const auto transparent_flag = 2;

	/* Helpers to set mask when setting the elements */
	auto set_fgcolor(const rspamd::css::css_color &c, int how =  html_block::set) -> void {
		fg_color = c;
		fg_color_mask = how;
	}
	auto set_bgcolor(const rspamd::css::css_color &c, int how =  html_block::set) -> void {
		bg_color = c;
		bg_color_mask = how;
	}
	auto set_height(float h, bool is_percent = false, int how =  html_block::set) -> void {
		h = is_percent ? (-h) : h;
		if (h < INT16_MIN) {
			/* Negative numbers encode percents... */
			height = -100;
		}
		else if (h > INT16_MAX) {
			height = INT16_MAX;
		}
		else {
			height = h;
		}
		height_mask = how;
	}
	auto set_width(float w, bool is_percent = false, int how =  html_block::set) -> void {
		w = is_percent ? (-w) : w;
		if (w < INT16_MIN) {
			width = INT16_MIN;
		}
		else if (w > INT16_MAX) {
			width = INT16_MAX;
		}
		else {
			width = w;
		}
		width_mask = how;
	}
	auto set_display(bool v, int how = html_block::set) -> void  {
		if (v) {
			display = rspamd::css::css_display_value::DISPLAY_INLINE;
		}
		else {
			display = rspamd::css::css_display_value::DISPLAY_HIDDEN;
		}
		display_mask = how;
	}
	auto set_display(rspamd::css::css_display_value v, int how =  html_block::set) -> void  {
		display = v;
		display_mask = how;
	}
	auto set_font_size(float fs, bool is_percent = false, int how =  html_block::set) -> void  {
		fs = is_percent ? (-fs) : fs;
		if (fs < INT8_MIN) {
			font_size = -100;
		}
		else if (fs > INT8_MAX) {
			font_size = INT8_MAX;
		}
		else {
			font_size = fs;
		}
		font_mask = how;
	}

	/**
	 * Propagate values from the block if they are not defined by the current block
	 * @param other
	 * @return
	 */
	auto propagate_block(const html_block &other) -> void {
		auto simple_prop = [](auto mask_val, auto other_mask, auto &our_val,
				auto other_val) constexpr -> int {
			if (other_mask && other_mask > mask_val) {
				our_val = other_val;
				mask_val =  html_block::inherited;
			}

			return mask_val;
		};

		fg_color_mask = simple_prop(fg_color_mask, other.fg_color_mask, fg_color, other.fg_color);
		bg_color_mask = simple_prop(bg_color_mask, other.bg_color_mask, bg_color, other.bg_color);
		display_mask = simple_prop(display_mask, other.display_mask, display, other.display);

		/* Sizes are very different
		 * We can have multiple cases:
		 * 1) Our size is > 0 and we can use it as is
		 * 2) Parent size is > 0 and our size is undefined, so propagate parent
		 * 3) Parent size is < 0 and our size is undefined - propagate parent
		 * 4) Parent size is > 0 and our size is < 0 - multiply parent by abs(ours)
		 * 5) Parent size is undefined and our size is < 0 - tricky stuff, assume some defaults
		 */
		auto size_prop = [](auto mask_val, auto other_mask, auto &our_val,
				auto other_val, auto default_val) constexpr -> int {
			if (mask_val) {
				/* We have our value */
				if (our_val < 0) {
					if (other_mask > 0) {
						if (other_val >= 0) {
							our_val = other_val * (-our_val / 100.0);
						}
						else {
							our_val *= (-other_val / 100.0);
						}
					}
					else {
						/* Parent value is not defined and our value is relative */
						our_val = default_val * (-our_val / 100.0);
					}
				}
				else if (other_mask && other_mask > mask_val) {
					our_val = other_val;
					mask_val = html_block::inherited;
				}
			}
			else {
				/* We propagate parent if defined */
				if (other_mask && other_mask > mask_val) {
					our_val = other_val;
					mask_val = html_block::inherited;
				}
				/* Otherwise do nothing */
			}

			return mask_val;
		};

		height_mask = size_prop(height_mask, other.height_mask, height, other.height, 800);
		width_mask = size_prop(width_mask, other.width_mask, width, other.width, 1024);
		font_mask = size_prop(font_mask, other.font_mask, font_size, other.font_size, 1024);
	}

	/*
	 * Set block overriding all inherited values
	 */
	auto set_block(const html_block &other) -> void {
		constexpr auto set_value = [](auto mask_val, auto other_mask, auto &our_val,
									   auto other_val) constexpr -> int {
			if (other_mask && mask_val != html_block::set) {
				our_val = other_val;
				mask_val = other_mask;
			}

			return mask_val;
		};

		fg_color_mask = set_value(fg_color_mask, other.fg_color_mask, fg_color, other.fg_color);
		bg_color_mask = set_value(bg_color_mask, other.bg_color_mask, bg_color, other.bg_color);
		display_mask = set_value(display_mask, other.display_mask, display, other.display);
		height_mask = set_value(height_mask, other.height_mask, height, other.height);
		width_mask = set_value(width_mask, other.width_mask, width, other.width);
		font_mask = set_value(font_mask, other.font_mask, font_size, other.font_size);
	}

	auto compute_visibility(void) -> void {
		if (display_mask) {
			if (display == css::css_display_value::DISPLAY_HIDDEN) {
				visibility_mask = html_block::invisible_flag;

				return;
			}
		}

		if (font_mask) {
			if (font_size == 0) {
				visibility_mask = html_block::invisible_flag;

				return;
			}
		}

		auto is_similar_colors = [](const rspamd::css::css_color &fg, const rspamd::css::css_color &bg) -> bool {
			constexpr const auto min_visible_diff = 0.1f;
			auto diff_r = ((float)fg.r - bg.r);
			auto diff_g = ((float)fg.g - bg.g);
			auto diff_b = ((float)fg.b - bg.b);
			auto ravg = ((float)fg.r + bg.r) / 2.0f;

			/* Square diffs */
			diff_r *= diff_r;
			diff_g *= diff_g;
			diff_b *= diff_b;

			auto diff = std::sqrt(2.0f * diff_r + 4.0f * diff_g + 3.0f * diff_b +
								  (ravg * (diff_r - diff_b) / 256.0f)) / 256.0f;

			return diff < min_visible_diff;
		};
		/* Check if we have both bg/fg colors */
		if (fg_color_mask && bg_color_mask) {
			if (fg_color.alpha < 10) {
				/* Too transparent */
				visibility_mask = html_block::transparent_flag;

				return;
			}

			if (bg_color.alpha > 10) {
				if (is_similar_colors(fg_color, bg_color)) {
					visibility_mask = html_block::transparent_flag;
					return;
				}
			}
		}
		else if (fg_color_mask) {
			/* Merely fg color */
			if (fg_color.alpha < 10) {
				/* Too transparent */
				visibility_mask = html_block::transparent_flag;

				return;
			}

			/* Implicit fg color */
			if (is_similar_colors(fg_color, rspamd::css::css_color::white())) {
				visibility_mask = html_block::transparent_flag;
				return;
			}
		}
		else if (bg_color_mask) {
			if (bg_color.alpha > 10) {
				if (is_similar_colors(rspamd::css::css_color::black(), bg_color)) {
					visibility_mask = html_block::transparent_flag;
					return;
				}
			}
		}

		visibility_mask = html_block::unset;
	}

	constexpr auto is_visible(void) const -> bool {
		return visibility_mask == html_block::unset;
	}

	constexpr auto is_transparent(void) const -> bool {
		return visibility_mask == html_block::transparent_flag;
	}

	constexpr auto has_display(int how = html_block::set) const -> bool {
		return display_mask >= how;
	}

	/**
	 * Returns a default html block for root HTML element
	 * @return
	 */
	static auto default_html_block(void) -> html_block {
		return html_block{.fg_color = rspamd::css::css_color::black(),
				.bg_color = rspamd::css::css_color::white(),
				.height = 0,
				.width = 0,
				.display = rspamd::css::css_display_value::DISPLAY_INLINE,
				.font_size = 12,
				.fg_color_mask = html_block::inherited,
				.bg_color_mask = html_block::inherited,
				.height_mask = html_block::unset,
				.width_mask = html_block::unset,
				.font_mask = html_block::unset,
				.display_mask = html_block::inherited,
				.visibility_mask = html_block::unset};
	}
	/**
	 * Produces html block with no defined values allocated from the pool
	 * @param pool
	 * @return
	 */
	static auto undefined_html_block_pool(rspamd_mempool_t *pool) -> html_block* {
		auto *bl = rspamd_mempool_alloc0_type(pool, html_block);

		return bl;
	}
};

}

#endif //RSPAMD_HTML_BLOCK_HXX
