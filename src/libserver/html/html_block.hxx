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
	std::uint16_t mask;
	rspamd::css::css_display_value display;
	std::int8_t font_size;

	constexpr static const auto fg_color_mask = 0x1 << 0;
	constexpr static const auto bg_color_mask = 0x1 << 1;
	constexpr static const auto height_mask = 0x1 << 2;
	constexpr static const auto width_mask = 0x1 << 3;
	constexpr static const auto display_mask = 0x1 << 4;
	constexpr static const auto font_size_mask = 0x1 << 5;
	constexpr static const auto invisible_flag = 0x1 << 6;
	constexpr static const auto transparent_flag = 0x1 << 7;

	/* Helpers to set mask when setting the elements */
	auto set_fgcolor(const rspamd::css::css_color &c) -> void {
		fg_color = c;
		mask |= fg_color_mask;
	}
	auto set_bgcolor(const rspamd::css::css_color &c) -> void {
		bg_color = c;
		mask |= bg_color_mask;
	}
	auto set_height(float h, bool is_percent = false) -> void {
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
		mask |= height_mask;
	}
	auto set_width(float w, bool is_percent = false) -> void {
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
		mask |= width_mask;
	}
	auto set_display(bool v) -> void  {
		if (v) {
			display = rspamd::css::css_display_value::DISPLAY_INLINE;
		}
		else {
			display = rspamd::css::css_display_value::DISPLAY_HIDDEN;
		}
		mask |= display_mask;
	}
	auto set_display(rspamd::css::css_display_value v) -> void  {
		display = v;
		mask |= display_mask;
	}
	auto set_font_size(float fs, bool is_percent = false) -> void  {
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
		mask |= font_size_mask;
	}

	/**
	 * Propagate values from the block if they are not defined by the current block
	 * @param other
	 * @return
	 */
	auto propagate_block(const html_block &other) -> void {
		auto simple_prop = [&](auto mask_val, auto &our_val, auto other_val) constexpr -> void {
			if (!(mask & mask_val) && (other.mask & mask_val)) {
				our_val = other_val;
			}
		};
		simple_prop(fg_color_mask, fg_color, other.fg_color);
		simple_prop(bg_color_mask, bg_color, other.bg_color);
		simple_prop(display_mask, display, other.display);

		/* Sizes are very different
		 * We can have multiple cases:
		 * 1) Our size is > 0 and we can use it as is
		 * 2) Parent size is > 0 and our size is undefined, so propagate parent
		 * 3) Parent size is < 0 and our size is undefined - propagate parent
		 * 4) Parent size is > 0 and our size is < 0 - multiply parent by abs(ours)
		 * 5) Parent size is undefined and our size is < 0 - tricky stuff, assume some defaults
		 */
		auto size_prop = [&](auto mask_val, auto &our_val, auto other_val, auto default_val) constexpr -> void {
			if (!(mask & mask_val)) {
				/* We have our value */
				if (our_val < 0) {
					if (other.mask & mask_val) {
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
				/* We do nothing as we have our own absolute value */
			}
			else {
				/* We propagate parent if defined */
				if (other.mask & mask_val) {
					our_val = other_val;
				}
				/* Otherwise do nothing */
			}
		};

		size_prop(height_mask, height, other.height, 800);
		size_prop(width_mask, width, other.width, 1024);
		size_prop(font_size_mask, font_size, other.font_size, 1024);
	}

	auto compute_visibility(void) -> void {
		if (mask & display_mask) {
			if (display == css::css_display_value::DISPLAY_HIDDEN) {
				mask |= invisible_flag;

				return;
			}
		}

		if (mask & font_size_mask) {
			if (font_size == 0) {
				mask |= invisible_flag;

				return;
			}
		}

		/* Check if we have both bg/fg colors */
		if ((mask & (bg_color_mask|fg_color_mask)) == (bg_color_mask|fg_color_mask)) {
			if (fg_color.alpha < 10) {
				/* Too transparent */
				mask |= invisible_flag|transparent_flag;

				return;
			}

			if (bg_color.alpha > 10) {
				auto diff_r = std::abs(fg_color.r - bg_color.r);
				auto diff_g = std::abs(fg_color.g - bg_color.g);
				auto diff_b = std::abs(fg_color.b - bg_color.b);
				auto ravg = (fg_color.r + bg_color.r) / 2.0;

				diff_r *= diff_r;
				diff_g *= diff_g;
				diff_b *= diff_b;

				auto diff = std::sqrt(2.0 * diff_r + 4.0 * diff_g + 3.0 * diff_b +
						  (ravg * (diff_r - diff_b) / 256.0)) / 256.0;

				if (diff < 0.1) {
					mask |= invisible_flag|transparent_flag;
					return;
				}
			}
		}

		mask &= ~(invisible_flag|transparent_flag);
	}

	constexpr auto is_visible(void) const -> bool {
		return (mask & invisible_flag) == 0;
	}

	constexpr auto is_transparent(void) const -> bool {
		return (mask & transparent_flag) != 0;
	}

	constexpr auto has_display(void) const -> bool {
		return (mask & display_mask) != 0;
	}

	/**
	 * Returns a default html block for root HTML element
	 * @return
	 */
	static auto default_html_block(void) -> html_block {
		return html_block{rspamd::css::css_color::black(),
						  rspamd::css::css_color::white(),
						  0, 0,
						  (fg_color_mask|bg_color_mask|font_size_mask),
						  rspamd::css::css_display_value::DISPLAY_INLINE,
						  12};
	}
	/**
	 * Produces html block with no defined values allocated from the pool
	 * @param pool
	 * @return
	 */
	static auto undefined_html_block_pool(rspamd_mempool_t *pool) -> html_block* {
		auto *bl = rspamd_mempool_alloc_type(pool, html_block);
		bl->mask = 0;

		return bl;
	}
};

}

#endif //RSPAMD_HTML_BLOCK_HXX
