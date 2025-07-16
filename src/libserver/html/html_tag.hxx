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
enum class html_component_type : std::uint8_t {
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
	virtual std::string_view get_string_value() const = 0;
};

// String-based components
struct html_component_name : html_component_base {
	std::string_view value;
	explicit html_component_name(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_href : html_component_base {
	std::string_view value;
	explicit html_component_href(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_style : html_component_base {
	std::string_view value;
	explicit html_component_style(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_class : html_component_base {
	std::string_view value;
	explicit html_component_class(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_rel : html_component_base {
	std::string_view value;
	explicit html_component_rel(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_alt : html_component_base {
	std::string_view value;
	explicit html_component_alt(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_id : html_component_base {
	std::string_view value;
	explicit html_component_id(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

// Color components (could be extended to parse actual colors)
struct html_component_color : html_component_base {
	std::string_view value;
	explicit html_component_color(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
};

struct html_component_bgcolor : html_component_base {
	std::string_view value;
	explicit html_component_bgcolor(std::string_view v)
		: value(v)
	{
	}
	std::string_view get_string_value() const override
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

	std::string_view get_string_value() const override
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

	std::string_view get_string_value() const override
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

	std::string_view get_string_value() const override
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
	explicit html_component_hidden()
		: present(true)
	{
	}
	std::string_view get_string_value() const override
	{
		return present ? "true" : "false";
	}
	bool is_present() const
	{
		return present;
	}
};

// Unknown component with both name and value
struct html_component_unknown : html_component_base {
	std::string_view name;
	std::string_view value;

	html_component_unknown(std::string_view n, std::string_view v)
		: name(n), value(v)
	{
	}
	std::string_view get_string_value() const override
	{
		return value;
	}
	std::string_view get_name() const
	{
		return name;
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

	// Find any component by attribute name (for Lua bindings and generic access)
	auto find_component_by_name(std::string_view attr_name) const -> std::optional<std::string_view>
	{
		// Check known component types first using their helper methods
		if (attr_name == "href") return find_href();
		if (attr_name == "class") return find_class();
		if (attr_name == "id") return find_id();
		if (attr_name == "style") return find_style();
		if (attr_name == "alt") return find_alt();
		if (attr_name == "rel") return find_rel();
		if (attr_name == "hidden") return is_hidden() ? std::optional<std::string_view>{"true"} : std::nullopt;

		// Handle numeric components that need string conversion
		if (attr_name == "width") {
			if (auto comp = find_component<html_component_width>()) {
				return comp.value()->get_string_value();
			}
		}
		if (attr_name == "height") {
			if (auto comp = find_component<html_component_height>()) {
				return comp.value()->get_string_value();
			}
		}
		if (attr_name == "size") {
			if (auto comp = find_component<html_component_size>()) {
				return comp.value()->get_string_value();
			}
		}

		// Handle color components
		if (attr_name == "color") {
			if (auto comp = find_component<html_component_color>()) {
				return comp.value()->value;
			}
		}
		if (attr_name == "bgcolor") {
			if (auto comp = find_component<html_component_bgcolor>()) {
				return comp.value()->value;
			}
		}

		// Handle name component
		if (attr_name == "name") {
			if (auto comp = find_component<html_component_name>()) {
				return comp.value()->value;
			}
		}

		// Finally check unknown components
		return find_unknown_component(attr_name);
	}

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

	constexpr auto get_content_length() const -> std::size_t
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
