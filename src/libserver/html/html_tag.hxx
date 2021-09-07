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

#ifndef RSPAMD_HTML_TAG_HXX
#define RSPAMD_HTML_TAG_HXX
#pragma once

#include <utility>
#include <string_view>
#include <variant>
#include <vector>
#include <optional>

#include "html_tags.h"

struct rspamd_url;
struct html_image;

namespace rspamd::html {

struct html_content; /* Forward declaration */

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

/* Public tags flags */
/* XML tag */
#define FL_XML          (1u << CM_USER_SHIFT)
/* Fully closed tag (e.g. <a attrs />) */
#define FL_CLOSED       (1 << (CM_USER_SHIFT + 1))
#define FL_BROKEN       (1 << (CM_USER_SHIFT + 2))
#define FL_IGNORE       (1 << (CM_USER_SHIFT + 3))
#define FL_BLOCK        (1 << (CM_USER_SHIFT + 4))
#define FL_HREF         (1 << (CM_USER_SHIFT + 5))
#define FL_COMMENT      (1 << (CM_USER_SHIFT + 6))
#define FL_VIRTUAL      (1 << (CM_USER_SHIFT + 7))

/**
 * Returns component type from a string
 * @param st
 * @return
 */
auto html_component_from_string(const std::string_view &st) -> std::optional<html_component_type>;

using html_tag_extra_t = std::variant<std::monostate, struct rspamd_url *, struct html_image *>;
struct html_tag_component {
	html_component_type type;
	std::string_view value;

	html_tag_component(html_component_type type, std::string_view value)
		: type(type), value(value) {}
};

/* Pairing closing tag representation */
struct html_closing_tag {
	int start = -1;
	int end = -1;

	auto clear() -> void {
		start = end = -1;
	}
};

struct html_tag {
	unsigned int tag_start = 0;
	unsigned int content_offset = 0;
	std::uint32_t flags = 0;
	tag_id_t id = Tag_UNKNOWN;
	html_closing_tag closing;

	std::vector<html_tag_component> components;

	html_tag_extra_t extra;
	mutable struct html_block *block = nullptr;
	std::vector<struct html_tag *> children;
	struct html_tag *parent;

	auto find_component(html_component_type what) const -> std::optional<std::string_view>
	{
		for (const auto &comp : components) {
			if (comp.type == what) {
				return comp.value;
			}
		}

		return std::nullopt;
	}

	auto find_component(std::optional<html_component_type> what) const -> std::optional<std::string_view>
	{
		if (what) {
			return find_component(what.value());
		}

		return std::nullopt;
	}

	auto clear(void) -> void {
		id = Tag_UNKNOWN;
		tag_start = content_offset = 0;
		extra = std::monostate{};
		components.clear();
		flags = 0;
		block = nullptr;
		children.clear();
		closing.clear();
	}

	constexpr auto get_content_length() const -> std::size_t {
		if (flags & (FL_IGNORE|CM_HEAD)) {
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

}

#endif //RSPAMD_HTML_TAG_HXX
