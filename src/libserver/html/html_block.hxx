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

namespace rspamd::html {

/*
 * Block tag definition
 */
struct html_block {
	rspamd::css::css_color fg_color;
	rspamd::css::css_color bg_color;
	std::uint16_t height;
	std::uint16_t width;
	std::uint16_t mask;
	rspamd::css::css_display_value display;
	std::uint8_t font_size;

	constexpr static const auto fg_color_mask = 0x1 << 0;
	constexpr static const auto bg_color_mask = 0x1 << 1;
	constexpr static const auto height_mask = 0x1 << 2;
	constexpr static const auto width_mask = 0x1 << 3;
	constexpr static const auto display_mask = 0x1 << 4;
	constexpr static const auto font_size_mask = 0x1 << 5;

	/* Helpers to set mask when setting the elements */
	auto set_fgcolor(const rspamd::css::css_color &c) -> void {
		fg_color = c;
		mask |= fg_color_mask;
	}
	auto set_bgcolor(const rspamd::css::css_color &c) -> void {
		bg_color = c;
		mask |= bg_color_mask;
	}
	auto set_height(double h) -> void {
		if (h < 0) {
			height = 0;
		}
		else if (h > UINT16_MAX) {
			height = UINT16_MAX;
		}
		else {
			height = h;
		}
		mask |= height_mask;
	}
	auto set_width(double w) -> void {
		if (w < 0) {
			width = 0;
		}
		else if (w > UINT16_MAX) {
			width = UINT16_MAX;
		}
		else {
			width = w;
		}
		mask |= width_mask;
	}
	auto set_display(bool v) -> void  {
		if (v) {
			display = rspamd::css::css_display_value::DISPLAY_NORMAL;
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
	auto set_font_size(float fs) -> void  {
		if (fs < 0) {
			font_size = 0;
		}
		else if (fs > UINT8_MAX) {
			font_size = UINT8_MAX;
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
#define PROPAGATE_ELT(elt) \
    do { if (!(mask & elt##_mask) && (other.mask & elt##_mask)) (elt) = other.elt; } while(0)

		PROPAGATE_ELT(fg_color);
		PROPAGATE_ELT(bg_color);
		PROPAGATE_ELT(height);
		PROPAGATE_ELT(width);
		PROPAGATE_ELT(display);
		PROPAGATE_ELT(font_size);
#undef PROPAGATE_ELT
	}

	/**
	 * Returns a default html block for root HTML element
	 * @return
	 */
	static auto default_html_block(void) -> html_block {
		return html_block{rspamd::css::css_color::black(),
						  rspamd::css::css_color::white(),
						  0, 0,
						  (fg_color_mask|bg_color_mask|display_mask|font_size_mask),
						  rspamd::css::css_display_value::DISPLAY_NORMAL,
						  12};
	}
};

}

#endif //RSPAMD_HTML_BLOCK_HXX
