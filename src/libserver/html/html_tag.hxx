/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_HTML_TAG_HXX
#define RSPAMD_HTML_TAG_HXX
#pragma once

#include <utility>
#include <string_view>
#include <variant>
#include <vector>
#include <optional>
#include <cstdint>

#include "html_tags.h"
#include "libutil/str_util.h"

struct rspamd_url;
struct html_image;

namespace rspamd::html {

struct html_content; /* Forward declaration */

// Internal enum for mapping (not exposed in public API)
enum class html_component_enum_type : std::uint8_t {
	RSPAMD_HTML_COMPONENT_NAME = 0,
	RSPAMD_HTML_COMPONENT_HREF,
	RSPAMD_HTML_COMPONENT_COLOR,
	RSPAMD_HTML_COMPONENT_BGCOLOR,
	RSPAMD_HTML_COMPONENT_STYLE,
	RSPAMD_HTML_COMPONENT_CLASS,
	RSPAMD_HTML_COMPONENT_WIDTH,
	RSPAMD_HTML_COMPONENT_HEIGHT,
	RSPAMD_HTML_COMPONENT_SIZE,
	RSPAMD_HTML_COMPONENT_REL,
	RSPAMD_HTML_COMPONENT_ALT,
	RSPAMD_HTML_COMPONENT_ID,
	RSPAMD_HTML_COMPONENT_HIDDEN,
	// Typography
	RSPAMD_HTML_COMPONENT_FONT_FAMILY,
	RSPAMD_HTML_COMPONENT_FONT_SIZE,
	RSPAMD_HTML_COMPONENT_FONT_WEIGHT,
	RSPAMD_HTML_COMPONENT_FONT_STYLE,
	RSPAMD_HTML_COMPONENT_TEXT_ALIGN,
	RSPAMD_HTML_COMPONENT_TEXT_DECORATION,
	RSPAMD_HTML_COMPONENT_LINE_HEIGHT,
	// Layout & positioning
	RSPAMD_HTML_COMPONENT_MARGIN,
	RSPAMD_HTML_COMPONENT_MARGIN_TOP,
	RSPAMD_HTML_COMPONENT_MARGIN_BOTTOM,
	RSPAMD_HTML_COMPONENT_MARGIN_LEFT,
	RSPAMD_HTML_COMPONENT_MARGIN_RIGHT,
	RSPAMD_HTML_COMPONENT_PADDING,
	RSPAMD_HTML_COMPONENT_PADDING_TOP,
	RSPAMD_HTML_COMPONENT_PADDING_BOTTOM,
	RSPAMD_HTML_COMPONENT_PADDING_LEFT,
	RSPAMD_HTML_COMPONENT_PADDING_RIGHT,
	RSPAMD_HTML_COMPONENT_BORDER,
	RSPAMD_HTML_COMPONENT_BORDER_COLOR,
	RSPAMD_HTML_COMPONENT_BORDER_WIDTH,
	RSPAMD_HTML_COMPONENT_BORDER_STYLE,
	// Display & visibility
	RSPAMD_HTML_COMPONENT_DISPLAY,
	RSPAMD_HTML_COMPONENT_VISIBILITY,
	RSPAMD_HTML_COMPONENT_OPACITY,
	// Dimensions
	RSPAMD_HTML_COMPONENT_MIN_WIDTH,
	RSPAMD_HTML_COMPONENT_MAX_WIDTH,
	RSPAMD_HTML_COMPONENT_MIN_HEIGHT,
	RSPAMD_HTML_COMPONENT_MAX_HEIGHT,
	// Table attributes
	RSPAMD_HTML_COMPONENT_CELLPADDING,
	RSPAMD_HTML_COMPONENT_CELLSPACING,
	RSPAMD_HTML_COMPONENT_VALIGN,
	RSPAMD_HTML_COMPONENT_ALIGN,
	// Form attributes
	RSPAMD_HTML_COMPONENT_TYPE,
	RSPAMD_HTML_COMPONENT_VALUE,
	RSPAMD_HTML_COMPONENT_PLACEHOLDER,
	RSPAMD_HTML_COMPONENT_DISABLED,
	RSPAMD_HTML_COMPONENT_READONLY,
	RSPAMD_HTML_COMPONENT_CHECKED,
	RSPAMD_HTML_COMPONENT_SELECTED,
	// Link & media
	RSPAMD_HTML_COMPONENT_TARGET,
	RSPAMD_HTML_COMPONENT_TITLE,
	RSPAMD_HTML_COMPONENT_SRC,
	// Meta & document
	RSPAMD_HTML_COMPONENT_CHARSET,
	RSPAMD_HTML_COMPONENT_CONTENT,
	RSPAMD_HTML_COMPONENT_HTTP_EQUIV,
	// Accessibility
	RSPAMD_HTML_COMPONENT_ROLE,
	RSPAMD_HTML_COMPONENT_TABINDEX,
	// Background
	RSPAMD_HTML_COMPONENT_BACKGROUND,
	RSPAMD_HTML_COMPONENT_BACKGROUND_IMAGE,
	RSPAMD_HTML_COMPONENT_BACKGROUND_COLOR,
	RSPAMD_HTML_COMPONENT_BACKGROUND_REPEAT,
	RSPAMD_HTML_COMPONENT_BACKGROUND_POSITION,
	// Email-specific tracking
	RSPAMD_HTML_COMPONENT_DATA_TRACK,
	RSPAMD_HTML_COMPONENT_DATA_ID,
	RSPAMD_HTML_COMPONENT_DATA_URL,
};

// Forward declarations for component types
struct html_component_name;
struct html_component_href;
struct html_component_color;
struct html_component_bgcolor;
struct html_component_style;
struct html_component_class;
struct html_component_width;
struct html_component_height;
struct html_component_size;
struct html_component_rel;
struct html_component_alt;
struct html_component_id;
struct html_component_hidden;
struct html_component_unknown;

// Base interface for all components
struct html_component_base {
	virtual ~html_component_base() = default;
	virtual constexpr std::string_view get_string_value() const = 0;
};

// String-based components
struct html_component_name : html_component_base {
	std::string_view value;
	explicit constexpr html_component_name(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_href : html_component_base {
	std::string_view value;
	explicit constexpr html_component_href(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_style : html_component_base {
	std::string_view value;
	explicit constexpr html_component_style(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_class : html_component_base {
	std::string_view value;
	explicit constexpr html_component_class(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_rel : html_component_base {
	std::string_view value;
	explicit constexpr html_component_rel(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_alt : html_component_base {
	std::string_view value;
	explicit constexpr html_component_alt(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_id : html_component_base {
	std::string_view value;
	explicit constexpr html_component_id(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

// Color components (could be extended to parse actual colors)
struct html_component_color : html_component_base {
	std::string_view value;
	explicit constexpr html_component_color(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_bgcolor : html_component_base {
	std::string_view value;
	explicit constexpr html_component_bgcolor(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

// Numeric components
struct html_component_width : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_width(const std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	constexpr std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_height : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_height(const std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	constexpr std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_size : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_size(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	constexpr std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

// Boolean/flag component
struct html_component_hidden : html_component_base {
	bool present;
	explicit constexpr html_component_hidden()
		: present(true)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return present ? "true" : "false";
	}
	constexpr bool is_present() const
	{
		return present;
	}
};

// Unknown component with both name and value
struct html_component_unknown : html_component_base {
	std::string_view name;
	std::string_view value;

	constexpr html_component_unknown(std::string_view n, std::string_view v)
		: name(n), value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
	constexpr std::string_view get_name() const
	{
		return name;
	}
};

// Typography components
struct html_component_font_family : html_component_base {
	std::string_view value;
	explicit constexpr html_component_font_family(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_font_size : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_font_size(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	constexpr std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_font_weight : html_component_base {
	std::string_view value;
	explicit constexpr html_component_font_weight(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_font_style : html_component_base {
	std::string_view value;
	explicit constexpr html_component_font_style(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_text_align : html_component_base {
	std::string_view value;
	explicit constexpr html_component_text_align(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_text_decoration : html_component_base {
	std::string_view value;
	explicit constexpr html_component_text_decoration(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_line_height : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_line_height(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

// Layout components (most are string-based for flexibility)
struct html_component_margin : html_component_base {
	std::string_view value;
	explicit constexpr html_component_margin(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_margin_top : html_component_base {
	std::string_view value;
	explicit constexpr html_component_margin_top(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_margin_bottom : html_component_base {
	std::string_view value;
	explicit constexpr html_component_margin_bottom(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_margin_left : html_component_base {
	std::string_view value;
	explicit constexpr html_component_margin_left(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_margin_right : html_component_base {
	std::string_view value;
	explicit constexpr html_component_margin_right(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_padding : html_component_base {
	std::string_view value;
	explicit constexpr html_component_padding(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_padding_top : html_component_base {
	std::string_view value;
	explicit constexpr html_component_padding_top(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_padding_bottom : html_component_base {
	std::string_view value;
	explicit constexpr html_component_padding_bottom(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_padding_left : html_component_base {
	std::string_view value;
	explicit constexpr html_component_padding_left(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_padding_right : html_component_base {
	std::string_view value;
	explicit constexpr html_component_padding_right(std::string_view v)
		: value(v)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_border : html_component_base {
	std::string_view value;
	explicit html_component_border(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_border_color : html_component_base {
	std::string_view value;
	explicit html_component_border_color(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_border_width : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_border_width(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_border_style : html_component_base {
	std::string_view value;
	explicit html_component_border_style(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// Display components
struct html_component_display : html_component_base {
	std::string_view value;
	explicit html_component_display(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_visibility : html_component_base {
	std::string_view value;
	explicit html_component_visibility(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_opacity : html_component_base {
	std::string_view raw_value;
	std::optional<float> numeric_value;

	explicit html_component_opacity(std::string_view v)
		: raw_value(v)
	{
		char *endptr;
		auto val = std::strtof(v.data(), &endptr);
		if (endptr != v.data() && val >= 0.0f && val <= 1.0f) {
			numeric_value = val;
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<float> get_numeric_value() const
	{
		return numeric_value;
	}
};

// Additional dimension components
struct html_component_min_width : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_min_width(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_max_width : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_max_width(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_min_height : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_min_height(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_max_height : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_max_height(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

// Table components
struct html_component_cellpadding : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_cellpadding(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_cellspacing : html_component_base {
	std::string_view raw_value;
	std::optional<std::uint32_t> numeric_value;

	explicit html_component_cellspacing(std::string_view v)
		: raw_value(v)
	{
		unsigned long val;
		if (rspamd_strtoul(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::uint32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::uint32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

struct html_component_valign : html_component_base {
	std::string_view value;
	explicit html_component_valign(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_align : html_component_base {
	std::string_view value;
	explicit html_component_align(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// Form components
struct html_component_type : html_component_base {
	std::string_view value;
	explicit html_component_type(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_value : html_component_base {
	std::string_view value;
	explicit html_component_value(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_placeholder : html_component_base {
	std::string_view value;
	explicit html_component_placeholder(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// Boolean form components
struct html_component_disabled : html_component_base {
	bool present;
	explicit constexpr html_component_disabled()
		: present(true)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return present ? "true" : "false";
	}
	constexpr bool is_present() const
	{
		return present;
	}
};

struct html_component_readonly : html_component_base {
	bool present;
	explicit constexpr html_component_readonly()
		: present(true)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return present ? "true" : "false";
	}
	constexpr bool is_present() const
	{
		return present;
	}
};

struct html_component_checked : html_component_base {
	bool present;
	explicit constexpr html_component_checked()
		: present(true)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return present ? "true" : "false";
	}
	constexpr bool is_present() const
	{
		return present;
	}
};

struct html_component_selected : html_component_base {
	bool present;
	explicit constexpr html_component_selected()
		: present(true)
	{
	}
	constexpr std::string_view get_string_value() const override
	{
		return present ? "true" : "false";
	}
	constexpr bool is_present() const
	{
		return present;
	}
};

// Link & media components
struct html_component_target : html_component_base {
	std::string_view value;
	explicit html_component_target(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_title : html_component_base {
	std::string_view value;
	explicit html_component_title(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_src : html_component_base {
	std::string_view value;
	explicit html_component_src(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// Meta components
struct html_component_charset : html_component_base {
	std::string_view value;
	explicit html_component_charset(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_content : html_component_base {
	std::string_view value;
	explicit html_component_content(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_http_equiv : html_component_base {
	std::string_view value;
	explicit html_component_http_equiv(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// Accessibility components
struct html_component_role : html_component_base {
	std::string_view value;
	explicit html_component_role(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_tabindex : html_component_base {
	std::string_view raw_value;
	std::optional<std::int32_t> numeric_value;

	explicit html_component_tabindex(std::string_view v)
		: raw_value(v)
	{
		long val;
		if (rspamd_strtol(v.data(), v.size(), &val)) {
			numeric_value = static_cast<std::int32_t>(val);
		}
	}

	std::string_view get_string_value() const override
	{
		return raw_value;
	}
	std::optional<std::int32_t> get_numeric_value() const
	{
		return numeric_value;
	}
};

// Background components
struct html_component_background : html_component_base {
	std::string_view value;
	explicit html_component_background(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_background_image : html_component_base {
	std::string_view value;
	explicit html_component_background_image(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_background_color : html_component_base {
	std::string_view value;
	explicit html_component_background_color(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_background_repeat : html_component_base {
	std::string_view value;
	explicit html_component_background_repeat(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_background_position : html_component_base {
	std::string_view value;
	explicit html_component_background_position(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// Email tracking components
struct html_component_data_track : html_component_base {
	std::string_view value;
	explicit html_component_data_track(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_data_id : html_component_base {
	std::string_view value;
	explicit html_component_data_id(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_data_url : html_component_base {
	std::string_view value;
	explicit html_component_data_url(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// The variant type that holds all possible components
using html_tag_component = std::variant<
	html_component_name,
	html_component_href,
	html_component_color,
	html_component_bgcolor,
	html_component_style,
	html_component_class,
	html_component_width,
	html_component_height,
	html_component_size,
	html_component_rel,
	html_component_alt,
	html_component_id,
	html_component_hidden,
	// Typography
	html_component_font_family,
	html_component_font_size,
	html_component_font_weight,
	html_component_font_style,
	html_component_text_align,
	html_component_text_decoration,
	html_component_line_height,
	// Layout
	html_component_margin,
	html_component_margin_top,
	html_component_margin_bottom,
	html_component_margin_left,
	html_component_margin_right,
	html_component_padding,
	html_component_padding_top,
	html_component_padding_bottom,
	html_component_padding_left,
	html_component_padding_right,
	html_component_border,
	html_component_border_color,
	html_component_border_width,
	html_component_border_style,
	// Display
	html_component_display,
	html_component_visibility,
	html_component_opacity,
	// Dimensions
	html_component_min_width,
	html_component_max_width,
	html_component_min_height,
	html_component_max_height,
	// Table
	html_component_cellpadding,
	html_component_cellspacing,
	html_component_valign,
	html_component_align,
	// Form
	html_component_type,
	html_component_value,
	html_component_placeholder,
	html_component_disabled,
	html_component_readonly,
	html_component_checked,
	html_component_selected,
	// Link & media
	html_component_target,
	html_component_title,
	html_component_src,
	// Meta
	html_component_charset,
	html_component_content,
	html_component_http_equiv,
	// Accessibility
	html_component_role,
	html_component_tabindex,
	// Background
	html_component_background,
	html_component_background_image,
	html_component_background_color,
	html_component_background_repeat,
	html_component_background_position,
	// Email tracking
	html_component_data_track,
	html_component_data_id,
	html_component_data_url,
	// Unknown
	html_component_unknown>;

/**
 * Returns component variant from a string
 * @param name attribute name
 * @param value attribute value
 * @return variant component
 */
auto html_component_from_string(std::string_view name, std::string_view value) -> html_tag_component;

/* Public tags flags */
/* XML tag */
#define FL_XML (1u << CM_USER_SHIFT)
/* Fully closed tag (e.g. <a attrs />) */
#define FL_CLOSED (1 << (CM_USER_SHIFT + 1))
#define FL_BROKEN (1 << (CM_USER_SHIFT + 2))
#define FL_IGNORE (1 << (CM_USER_SHIFT + 3))
#define FL_BLOCK (1 << (CM_USER_SHIFT + 4))
#define FL_HREF (1 << (CM_USER_SHIFT + 5))
#define FL_COMMENT (1 << (CM_USER_SHIFT + 6))
#define FL_VIRTUAL (1 << (CM_USER_SHIFT + 7))

using html_tag_extra_t = std::variant<std::monostate, struct rspamd_url *, struct html_image *>;

/* Pairing closing tag representation */
struct html_closing_tag {
	int start = -1;
	int end = -1;

	auto clear() -> void
	{
		start = end = -1;
	}
};

struct html_tag {
	unsigned int tag_start = 0;
	unsigned int content_offset = 0;
	std::uint32_t flags = 0;
	std::int32_t id = Tag_UNKNOWN;
	html_closing_tag closing;

	std::vector<html_tag_component> components;

	html_tag_extra_t extra;
	mutable struct html_block *block = nullptr;
	std::vector<struct html_tag *> children;
	struct html_tag *parent;

	// Template method to find component by type
	template<typename T>
	auto find_component() const -> std::optional<const T *>
	{
		for (const auto &comp: components) {
			if (std::holds_alternative<T>(comp)) {
				return &std::get<T>(comp);
			}
		}
		return std::nullopt;
	}

	// Helper methods for common component access
	auto find_href() const -> std::optional<std::string_view>
	{
		if (auto comp = find_component<html_component_href>()) {
			return comp.value()->value;
		}
		return std::nullopt;
	}

	auto find_class() const -> std::optional<std::string_view>
	{
		if (auto comp = find_component<html_component_class>()) {
			return comp.value()->value;
		}
		return std::nullopt;
	}

	auto find_id() const -> std::optional<std::string_view>
	{
		if (auto comp = find_component<html_component_id>()) {
			return comp.value()->value;
		}
		return std::nullopt;
	}

	auto find_width() const -> std::optional<std::uint32_t>
	{
		if (auto comp = find_component<html_component_width>()) {
			return comp.value()->get_numeric_value();
		}
		return std::nullopt;
	}

	auto find_height() const -> std::optional<std::uint32_t>
	{
		if (auto comp = find_component<html_component_height>()) {
			return comp.value()->get_numeric_value();
		}
		return std::nullopt;
	}

	auto find_style() const -> std::optional<std::string_view>
	{
		if (auto comp = find_component<html_component_style>()) {
			return comp.value()->value;
		}
		return std::nullopt;
	}

	auto find_alt() const -> std::optional<std::string_view>
	{
		if (auto comp = find_component<html_component_alt>()) {
			return comp.value()->value;
		}
		return std::nullopt;
	}

	auto find_rel() const -> std::optional<std::string_view>
	{
		if (auto comp = find_component<html_component_rel>()) {
			return comp.value()->value;
		}
		return std::nullopt;
	}

	auto is_hidden() const -> bool
	{
		return find_component<html_component_hidden>().has_value();
	}

	auto find_unknown_component(std::string_view attr_name) const -> std::optional<std::string_view>
	{
		for (const auto &comp: components) {
			if (std::holds_alternative<html_component_unknown>(comp)) {
				const auto &unknown = std::get<html_component_unknown>(comp);
				if (unknown.name == attr_name) {
					return unknown.value;
				}
			}
		}
		return std::nullopt;
	}

	auto get_unknown_components() const -> std::vector<std::pair<std::string_view, std::string_view>>
	{
		std::vector<std::pair<std::string_view, std::string_view>> unknown_attrs;
		for (const auto &comp: components) {
			if (std::holds_alternative<html_component_unknown>(comp)) {
				const auto &unknown = std::get<html_component_unknown>(comp);
				unknown_attrs.emplace_back(unknown.name, unknown.value);
			}
		}
		return unknown_attrs;
	}

	// Generic visitor method for processing all components
	template<typename Visitor>
	auto visit_components(Visitor &&visitor) const
	{
		for (const auto &comp: components) {
			std::visit(std::forward<Visitor>(visitor), comp);
		}
	}

	// Find any component by attribute name
	auto find_component_by_name(std::string_view attr_name) const -> std::optional<std::string_view>;

	// Get all attributes as name-value pairs
	auto get_all_attributes() const -> std::vector<std::pair<std::string_view, std::string_view>>;

	auto clear(void) -> void
	{
		id = Tag_UNKNOWN;
		tag_start = content_offset = 0;
		extra = std::monostate{};
		components.clear();
		flags = 0;
		block = nullptr;
		children.clear();
		closing.clear();
	}

	auto get_content_length() const -> std::size_t
	{
		if (flags & (FL_IGNORE | CM_HEAD)) {
			return 0;
		}
		if (closing.start > content_offset) {
			return closing.start - content_offset;
		}

		return 0;
	}

	auto get_content(const struct html_content *hc) const -> std::string_view;
};

static_assert(CM_USER_SHIFT + 7 < sizeof(html_tag::flags) * NBBY);

}// namespace rspamd::html

#endif//RSPAMD_HTML_TAG_HXX
