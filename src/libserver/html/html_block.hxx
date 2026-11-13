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
	std::int16_t font_size;
	bool overflow_hidden;
	/* Hidden via off-screen positioning / clipping */
	bool offscreen;
	/* The `visibility` property: hidden or collapse */
	bool visibility_hidden;
	/*
	 * Hidden by what is not `display`: opacity, a place off the screen, a
	 * clip. No value of `display` shows such a block again, an important
	 * one included
	 */
	bool forced_hidden;

	unsigned fg_color_mask : 3;
	unsigned bg_color_mask : 3;
	unsigned height_mask : 3;
	unsigned width_mask : 3;
	unsigned font_mask : 3;
	unsigned display_mask : 3;
	/* Not a source mask: the invisible and transparent flags of the block */
	unsigned visibility_mask : 2;
	unsigned overflow_mask : 3;
	/* Source mask of `visibility_hidden` */
	unsigned visibility_prop_mask : 3;

	/* Set when the corresponding dimension comes from a max-width /
	 * max-height bound rather than from an actual width / height */
	bool width_from_max = false;
	bool height_from_max = false;

	/* Set when the size field holds the `auto` sentinel, which yields
	 * to a value flattened from a max bound of another rule, as a
	 * maximum caps an auto size, but not to a real size */
	bool width_auto = false;
	bool height_auto = false;

	/* Absolute minimum dimensions from min-width / min-height (in
	 * pixels, fractional ones included); the mask distinguishes an
	 * absolute value (1) from a percent one, which cannot raise the
	 * floor (2), and from the absence of the property (0) */
	float min_width = 0.0;
	float min_height = 0.0;
	unsigned min_width_mask : 2;
	unsigned min_height_mask : 2;

	/* Set when the winning minimum is !important, so it beats any
	 * inline style value */
	bool min_width_important = false;
	bool min_height_important = false;

	/* Absolute max-width / max-height bounds (in pixels, fractional
	 * ones included), kept separately from the width / height values
	 * for the image classification; the mask distinguishes an
	 * explicit bound (1) from `none` or a percent value removing it
	 * (2) and from the absence of the property (0) */
	float width_max = 0.0;
	float height_max = 0.0;
	unsigned width_max_mask : 2;
	unsigned height_max_mask : 2;

	/* Set when the winning maximum is !important, so it beats any
	 * inline style value */
	bool max_width_important = false;
	bool max_height_important = false;

	/* Actual width / height property values from the stylesheet
	 * cascade, recorded before the rule's own max bound flattens the
	 * main width / height fields (fractional ones included): the
	 * image classification applies them, while the flattened values
	 * stay for the visibility detection */
	float width_real = 0.0;
	float height_real = 0.0;
	unsigned width_real_mask : 1;
	unsigned height_real_mask : 1;

	/* The percentage of a percent real size, or zero otherwise (an
	 * absolute size, or one that has no number to report, such as a
	 * font-relative one, whose number the tokeniser has already scaled):
	 * the legacy image size exposed to Lua is derived from it */
	float width_real_raw = 0.0;
	float height_real_raw = 0.0;

	/* Set when the real width / height declaration that won the
	 * cascade is !important, so it beats any inline style value */
	bool width_important = false;
	bool height_important = false;

	/*
	 * Where a value comes from, from the weakest to the strongest: a hint of
	 * a presentational attribute loses to any author declaration, and an
	 * !important declaration wins over a normal one
	 */
	constexpr static const auto unset = 0;
	constexpr static const auto inherited = 1;
	constexpr static const auto implicit = 1;
	constexpr static const auto hint = 2;
	constexpr static const auto set = 3;
	constexpr static const auto important = 4;
	constexpr static const auto invisible_flag = 1;
	constexpr static const auto transparent_flag = 2;

	/*
	 * A value of a parent, whatever its source, replaces only what the child
	 * has not got itself: nothing or an inherited value
	 */
	template<typename MT>
	static constexpr auto inherit_strength(MT mask_val) -> MT
	{
		return mask_val > html_block::hint ? static_cast<MT>(html_block::hint) : mask_val;
	}

	/* Helpers to set mask when setting the elements */
	auto set_fgcolor(const rspamd::css::css_color &c, int how = html_block::set) -> void
	{
		fg_color = c;
		fg_color_mask = how;
	}
	auto set_bgcolor(const rspamd::css::css_color &c, int how = html_block::set) -> void
	{
		bg_color = c;
		bg_color_mask = how;
	}
	auto set_height(float h, bool is_percent = false, int how = html_block::set) -> void
	{
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

	auto set_width(float w, bool is_percent = false, int how = html_block::set) -> void
	{
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

	auto set_display(bool v, int how = html_block::set) -> void
	{
		if (v) {
			display = rspamd::css::css_display_value::DISPLAY_INLINE;
		}
		else {
			display = rspamd::css::css_display_value::DISPLAY_HIDDEN;
		}
		display_mask = how;
	}

	auto set_display(rspamd::css::css_display_value v, int how = html_block::set) -> void
	{
		display = v;
		display_mask = how;
	}

	auto set_visibility(bool hidden, int how = html_block::set) -> void
	{
		visibility_hidden = hidden;
		visibility_prop_mask = how;
	}

	auto set_overflow(bool hidden, int how = html_block::set) -> void
	{
		overflow_hidden = hidden;
		overflow_mask = how;
	}

	auto set_font_size(float fs, bool is_percent = false, int how = html_block::set) -> void
	{
		/* A percent size is stored negated and resolved on propagation */
		fs = is_percent ? (-fs) : fs;
		if (fs < INT16_MIN) {
			font_size = INT16_MIN;
		}
		else if (fs > INT16_MAX) {
			font_size = INT16_MAX;
		}
		else {
			font_size = fs;
		}
		font_mask = how;
	}

private:
	template<typename T, typename MT>
	static constexpr auto simple_prop(MT mask_val, MT other_mask, T &our_val,
									  T other_val) -> MT
	{
		if (other_mask && html_block::inherit_strength(other_mask) > mask_val) {
			our_val = other_val;
			mask_val = html_block::inherited;
		}

		return mask_val;
	}

	/* Sizes propagation logic
	 * We can have multiple cases:
	 * 1) Our size is > 0 and we can use it as is
	 * 2) Parent size is > 0 and our size is undefined, so propagate parent
	 * 3) Parent size is < 0 and our size is undefined - propagate parent
	 * 4) Parent size is > 0 and our size is < 0 - multiply parent by abs(ours)
	 * 5) Parent size is undefined and our size is < 0 - tricky stuff, assume some defaults
	 */
	template<typename T, typename MT>
	static constexpr auto size_prop(MT mask_val, MT other_mask, T &our_val,
									T other_val, T default_val) -> MT
	{
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
			else if (other_mask && html_block::inherit_strength(other_mask) > mask_val) {
				our_val = other_val;
				mask_val = html_block::inherited;
			}
		}
		else {
			/* We propagate parent if defined */
			if (other_mask && html_block::inherit_strength(other_mask) > mask_val) {
				our_val = other_val;
				mask_val = html_block::inherited;
			}
			/* Otherwise do nothing */
		}

		return mask_val;
	}

public:
	/**
	 * Propagate values from the block if they are not defined by the current block
	 * @param other
	 * @param bounded whether the width and height of `other` bound this block
	 * @return
	 */
	auto propagate_block(const html_block &other, bool bounded = true) -> void
	{
		fg_color_mask = html_block::simple_prop(fg_color_mask, other.fg_color_mask,
												fg_color, other.fg_color);
		bg_color_mask = html_block::simple_prop(bg_color_mask, other.bg_color_mask,
												bg_color, other.bg_color);

		if (other.display_mask && other.display == css::css_display_value::DISPLAY_HIDDEN) {
			/*
			 * A hidden ancestor hides all descendants: a child cannot reset
			 * display of a display:none parent, so ignore the own display
			 * value in this case
			 */
			display = css::css_display_value::DISPLAY_HIDDEN;
			display_mask = html_block::inherited;
		}
		else {
			display_mask = html_block::simple_prop(display_mask, other.display_mask,
												   display, other.display);
		}

		/* Visibility is inherited, and a descendant can reset it */
		visibility_prop_mask = html_block::simple_prop(visibility_prop_mask,
													   other.visibility_prop_mask,
													   visibility_hidden, other.visibility_hidden);

		resolve_sizes(other, bounded);
	}

	/*
	 * Turn sizes that are still relative into absolute ones against an
	 * already computed parent. Called on propagation, and again once a
	 * stylesheet block has been merged, since that happens after the parent
	 * has propagated and can introduce a fresh relative value.
	 * When the parent does not bound this block, its width and height are
	 * neither inherited nor used to resolve relative ones
	 */
	auto resolve_sizes(const html_block &other, bool bounded = true) -> void
	{
		static const html_block unbounded{};
		const auto &box = bounded ? other : unbounded;

		height_mask = html_block::size_prop(height_mask, box.height_mask,
											height, box.height, static_cast<std::int16_t>(800));
		width_mask = html_block::size_prop(width_mask, box.width_mask,
										   width, box.width, static_cast<std::int16_t>(1024));
		font_mask = html_block::size_prop(font_mask, other.font_mask,
										  font_size, other.font_size, static_cast<std::int16_t>(16));
	}

	/*
	 * Set block overriding all inherited values
	 */
	auto set_block(const html_block &other) -> void
	{
		constexpr auto set_value = [](auto mask_val, auto other_mask, auto &our_val,
									  auto other_val) constexpr -> int {
			/* An important value replaces a normal one, the others only fill in */
			if (other_mask && (mask_val < html_block::set ||
							   (other_mask == html_block::important && mask_val != html_block::important))) {
				our_val = other_val;
				mask_val = other_mask;
			}

			return mask_val;
		};

		fg_color_mask = set_value(fg_color_mask, other.fg_color_mask, fg_color, other.fg_color);
		bg_color_mask = set_value(bg_color_mask, other.bg_color_mask, bg_color, other.bg_color);
		if (!(display_mask == html_block::inherited &&
			  display == css::css_display_value::DISPLAY_HIDDEN)) {
			/* Display hidden by an ancestor cannot be reset by own rules */
			display_mask = set_value(display_mask, other.display_mask, display, other.display);
		}
		visibility_prop_mask = set_value(visibility_prop_mask, other.visibility_prop_mask,
										 visibility_hidden, other.visibility_hidden);

		/*
		 * Whether the maximum of the same axis was taken from the
		 * other rule: a size flattened from the own maximum yields to
		 * any size of that rule then, while the `auto` sentinel, a
		 * width declaration that won the cascade, yields to one
		 * flattened from the winning maximum only
		 */
		auto other_max_height_wins = other.height_max_mask &&
									 (!height_max_mask ||
									  (other.max_height_important && !max_height_important));
		auto other_max_width_wins = other.width_max_mask &&
									(!width_max_mask ||
									 (other.max_width_important && !max_width_important));
		/* ... and whether ours won instead, so a size of the other
		 * rule flattened from its losing maximum is stale */
		auto our_max_height_wins = height_max_mask &&
								   (!other.height_max_mask ||
									(max_height_important && !other.max_height_important));
		auto our_max_width_wins = width_max_mask &&
								  (!other.width_max_mask ||
								   (max_width_important && !other.max_width_important));

		if (other.height_mask &&
			(height_mask < html_block::set
				 ? !(our_max_height_wins && other.height_from_max)
				 : ((height_from_max ||
					 (height_auto && other.height_from_max)) &&
					other_max_height_wins) ||
					   (other.height_mask == html_block::important &&
						height_mask != html_block::important))) {
			height = other.height;
			height_mask = other.height_mask;
			height_from_max = other.height_from_max;
			height_auto = other.height_auto;
		}
		else if (height_from_max && other_max_height_wins) {
			/*
			 * The maximum this size has been flattened from lost the
			 * cascade, and the winning rule carries no size of its
			 * own: the stale flattened value goes away, so that a
			 * less specific rule can fill the size in
			 */
			height = 0;
			height_mask = html_block::unset;
			height_from_max = false;
			height_auto = false;
		}

		if (other.width_mask &&
			(width_mask < html_block::set
				 ? !(our_max_width_wins && other.width_from_max)
				 : ((width_from_max ||
					 (width_auto && other.width_from_max)) &&
					other_max_width_wins) ||
					   (other.width_mask == html_block::important &&
						width_mask != html_block::important))) {
			width = other.width;
			width_mask = other.width_mask;
			width_from_max = other.width_from_max;
			width_auto = other.width_auto;
		}
		else if (width_from_max && other_max_width_wins) {
			width = 0;
			width_mask = html_block::unset;
			width_from_max = false;
			width_auto = false;
		}

		if (other.height_real_mask &&
			(!height_real_mask ||
			 (other.height_important && !height_important))) {
			height_real = other.height_real;
			height_real_mask = 1;
			height_important = other.height_important;
		}

		if (other.width_real_mask &&
			(!width_real_mask ||
			 (other.width_important && !width_important))) {
			width_real = other.width_real;
			width_real_mask = 1;
			width_important = other.width_important;
		}

		if (other.min_height_mask &&
			(!min_height_mask ||
			 (other.min_height_important && !min_height_important))) {
			min_height = other.min_height;
			min_height_mask = other.min_height_mask;
			min_height_important = other.min_height_important;
		}

		if (other.min_width_mask &&
			(!min_width_mask ||
			 (other.min_width_important && !min_width_important))) {
			min_width = other.min_width;
			min_width_mask = other.min_width_mask;
			min_width_important = other.min_width_important;
		}

		if (other_max_height_wins) {
			height_max = other.height_max;
			height_max_mask = other.height_max_mask;
			max_height_important = other.max_height_important;
		}

		if (other_max_width_wins) {
			width_max = other.width_max;
			width_max_mask = other.width_max_mask;
			max_width_important = other.max_width_important;
		}

		font_mask = set_value(font_mask, other.font_mask, font_size, other.font_size);
		overflow_mask = set_value(overflow_mask, other.overflow_mask, overflow_hidden, other.overflow_hidden);

		if (other.forced_hidden) {
			forced_hidden = true;
		}
		if (other.offscreen) {
			offscreen = true;
		}
	}

	auto compute_visibility(void) -> void
	{
		if (forced_hidden) {
			/*
			 * As a hidden display for the descendants, which cannot bring the
			 * content back
			 */
			set_display(css::css_display_value::DISPLAY_HIDDEN, html_block::important);
			visibility_mask = html_block::invisible_flag;

			return;
		}

		if (display_mask) {
			if (display == css::css_display_value::DISPLAY_HIDDEN) {
				visibility_mask = html_block::invisible_flag;

				return;
			}
		}

		if (visibility_prop_mask && visibility_hidden) {
			visibility_mask = html_block::invisible_flag;

			return;
		}

		if (font_mask) {
			/*
			 * font_size >= 0 is an absolute size in px (percent sizes are
			 * encoded as negative). A font of a few pixels or less is
			 * effectively unreadable and is used to hide text
			 */
			if (font_size >= 0 && font_size <= 3) {
				visibility_mask = html_block::invisible_flag;

				return;
			}
		}

		if (overflow_mask && overflow_hidden) {
			/* Zero height or width with overflow:hidden clips the content entirely */
			if ((height_mask && height == 0) || (width_mask && width == 0)) {
				/*
				 * Convert to hidden display as well: clipping cannot be resurrected
				 * by descendants, so it should be propagated to children as
				 * the display value
				 */
				set_display(css::css_display_value::DISPLAY_HIDDEN);
				visibility_mask = html_block::invisible_flag;

				return;
			}
		}

		auto is_similar_colors = [](const rspamd::css::css_color &fg, const rspamd::css::css_color &bg) -> bool {
			constexpr const auto min_visible_diff = 0.1f;
			auto diff_r = ((float) fg.r - bg.r);
			auto diff_g = ((float) fg.g - bg.g);
			auto diff_b = ((float) fg.b - bg.b);
			auto ravg = ((float) fg.r + bg.r) / 2.0f;

			/* Square diffs */
			diff_r *= diff_r;
			diff_g *= diff_g;
			diff_b *= diff_b;

			auto diff = std::sqrt(2.0f * diff_r + 4.0f * diff_g + 3.0f * diff_b +
								  (ravg * (diff_r - diff_b) / 256.0f)) /
						256.0f;

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

	constexpr auto is_visible(void) const -> bool
	{
		return visibility_mask == html_block::unset;
	}

	constexpr auto is_transparent(void) const -> bool
	{
		return visibility_mask == html_block::transparent_flag;
	}

	constexpr auto has_display(int how = html_block::set) const -> bool
	{
		return display_mask >= how;
	}

	/**
	 * Returns a default html block for root HTML element
	 * @return
	 */
	static auto default_html_block(void) -> html_block
	{
		return html_block{.fg_color = rspamd::css::css_color::black(),
						  .bg_color = rspamd::css::css_color::white(),
						  .height = 0,
						  .width = 0,
						  .display = rspamd::css::css_display_value::DISPLAY_INLINE,
						  .font_size = 12,
						  .overflow_hidden = false,
						  .offscreen = false,
						  .visibility_hidden = false,
						  .forced_hidden = false,
						  .fg_color_mask = html_block::inherited,
						  .bg_color_mask = html_block::inherited,
						  .height_mask = html_block::unset,
						  .width_mask = html_block::unset,
						  .font_mask = html_block::unset,
						  .display_mask = html_block::inherited,
						  .visibility_mask = html_block::unset,
						  .overflow_mask = html_block::unset,
						  .visibility_prop_mask = html_block::unset,
						  .min_width_mask = 0,
						  .min_height_mask = 0,
						  .width_max_mask = 0,
						  .height_max_mask = 0,
						  .width_real_mask = 0,
						  .height_real_mask = 0};
	}
	/**
	 * Produces html block with no defined values allocated from the pool
	 * @param pool
	 * @return
	 */
	static auto undefined_html_block_pool(rspamd_mempool_t *pool) -> html_block *
	{
		auto *bl = rspamd_mempool_alloc0_type(pool, html_block);

		return bl;
	}
};

}// namespace rspamd::html

#endif//RSPAMD_HTML_BLOCK_HXX
