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
#include "config.h"
#include "util.h"
#include "message.h"
#include "html.h"
#include "html_tags.h"
#include "html_block.hxx"
#include "html.hxx"
#include "libserver/css/css_value.hxx"
#include "libserver/css/css.hxx"
#include "libserver/css/css_tokeniser.hxx"
#include "libserver/task.h"
#include "libserver/cfg_file.h"

#include "url.h"
#include "contrib/libucl/khash.h"
#include "libmime/images.h"
#include "libutil/cxx/utf8_util.h"
#include "libserver/html/html_cta.hxx"

#include "html_tag_defs.hxx"
#include "html_entities.hxx"
#include "html_tag.hxx"
#include "html_url.hxx"

#include "contrib/frozen/include/frozen/unordered_map.h"
#include "contrib/frozen/include/frozen/string.h"
#include "contrib/fmt/include/fmt/core.h"

#include <functional>
#include <algorithm>
#include <array>
#include <bitset>
#include <limits>
#include <optional>
#include <string>
#include <unicode/uversion.h>

namespace rspamd::html {

static const unsigned int max_tags = 8192; /* Ignore tags if this maximum is reached */
/* Budgets of attributes rspamd does not interpret; the ones it does are always kept, once each */
static const unsigned int max_attrs_per_tag = 128;    /* Ignore attributes of a single tag if this maximum is reached */
static const unsigned int max_attrs_per_task = 65536; /* Ignore attributes in all HTML parts of a task if this maximum is reached */

static const html_tags_storage html_tags_defs;

auto html_components_map = frozen::make_unordered_map<frozen::string, html_component_enum_type>(
	{
		{"name", html_component_enum_type::RSPAMD_HTML_COMPONENT_NAME},
		{"href", html_component_enum_type::RSPAMD_HTML_COMPONENT_HREF},
		{"src", html_component_enum_type::RSPAMD_HTML_COMPONENT_SRC},
		{"action", html_component_enum_type::RSPAMD_HTML_COMPONENT_HREF},
		{"color", html_component_enum_type::RSPAMD_HTML_COMPONENT_COLOR},
		{"bgcolor", html_component_enum_type::RSPAMD_HTML_COMPONENT_BGCOLOR},
		{"style", html_component_enum_type::RSPAMD_HTML_COMPONENT_STYLE},
		{"class", html_component_enum_type::RSPAMD_HTML_COMPONENT_CLASS},
		{"width", html_component_enum_type::RSPAMD_HTML_COMPONENT_WIDTH},
		{"height", html_component_enum_type::RSPAMD_HTML_COMPONENT_HEIGHT},
		{"size", html_component_enum_type::RSPAMD_HTML_COMPONENT_SIZE},
		{"rel", html_component_enum_type::RSPAMD_HTML_COMPONENT_REL},
		{"alt", html_component_enum_type::RSPAMD_HTML_COMPONENT_ALT},
		{"id", html_component_enum_type::RSPAMD_HTML_COMPONENT_ID},
		{"hidden", html_component_enum_type::RSPAMD_HTML_COMPONENT_HIDDEN},
		// Typography
		{"font-family", html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_FAMILY},
		{"font-size", html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_SIZE},
		{"font-weight", html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_WEIGHT},
		{"font-style", html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_STYLE},
		{"text-align", html_component_enum_type::RSPAMD_HTML_COMPONENT_TEXT_ALIGN},
		{"text-decoration", html_component_enum_type::RSPAMD_HTML_COMPONENT_TEXT_DECORATION},
		{"line-height", html_component_enum_type::RSPAMD_HTML_COMPONENT_LINE_HEIGHT},
		// Layout & positioning
		{"margin", html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN},
		{"margin-top", html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_TOP},
		{"margin-bottom", html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_BOTTOM},
		{"margin-left", html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_LEFT},
		{"margin-right", html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_RIGHT},
		{"padding", html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING},
		{"padding-top", html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_TOP},
		{"padding-bottom", html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_BOTTOM},
		{"padding-left", html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_LEFT},
		{"padding-right", html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_RIGHT},
		{"border", html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER},
		{"border-color", html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER_COLOR},
		{"border-width", html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER_WIDTH},
		{"border-style", html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER_STYLE},
		// Display & visibility
		{"display", html_component_enum_type::RSPAMD_HTML_COMPONENT_DISPLAY},
		{"visibility", html_component_enum_type::RSPAMD_HTML_COMPONENT_VISIBILITY},
		{"opacity", html_component_enum_type::RSPAMD_HTML_COMPONENT_OPACITY},
		// Dimensions
		{"min-width", html_component_enum_type::RSPAMD_HTML_COMPONENT_MIN_WIDTH},
		{"max-width", html_component_enum_type::RSPAMD_HTML_COMPONENT_MAX_WIDTH},
		{"min-height", html_component_enum_type::RSPAMD_HTML_COMPONENT_MIN_HEIGHT},
		{"max-height", html_component_enum_type::RSPAMD_HTML_COMPONENT_MAX_HEIGHT},
		// Table attributes
		{"cellpadding", html_component_enum_type::RSPAMD_HTML_COMPONENT_CELLPADDING},
		{"cellspacing", html_component_enum_type::RSPAMD_HTML_COMPONENT_CELLSPACING},
		{"valign", html_component_enum_type::RSPAMD_HTML_COMPONENT_VALIGN},
		{"align", html_component_enum_type::RSPAMD_HTML_COMPONENT_ALIGN},
		// Form attributes
		{"type", html_component_enum_type::RSPAMD_HTML_COMPONENT_TYPE},
		{"value", html_component_enum_type::RSPAMD_HTML_COMPONENT_VALUE},
		{"placeholder", html_component_enum_type::RSPAMD_HTML_COMPONENT_PLACEHOLDER},
		{"disabled", html_component_enum_type::RSPAMD_HTML_COMPONENT_DISABLED},
		{"readonly", html_component_enum_type::RSPAMD_HTML_COMPONENT_READONLY},
		{"checked", html_component_enum_type::RSPAMD_HTML_COMPONENT_CHECKED},
		{"selected", html_component_enum_type::RSPAMD_HTML_COMPONENT_SELECTED},
		// Link & media
		{"target", html_component_enum_type::RSPAMD_HTML_COMPONENT_TARGET},
		{"title", html_component_enum_type::RSPAMD_HTML_COMPONENT_TITLE},
		// Meta & document
		{"charset", html_component_enum_type::RSPAMD_HTML_COMPONENT_CHARSET},
		{"content", html_component_enum_type::RSPAMD_HTML_COMPONENT_CONTENT},
		{"http-equiv", html_component_enum_type::RSPAMD_HTML_COMPONENT_HTTP_EQUIV},
		// Accessibility
		{"role", html_component_enum_type::RSPAMD_HTML_COMPONENT_ROLE},
		{"tabindex", html_component_enum_type::RSPAMD_HTML_COMPONENT_TABINDEX},
		// Background
		{"background", html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND},
		{"background-image", html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_IMAGE},
		{"background-color", html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_COLOR},
		{"background-repeat", html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_REPEAT},
		{"background-position", html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_POSITION},
		// Email-specific tracking
		{"data-track", html_component_enum_type::RSPAMD_HTML_COMPONENT_DATA_TRACK},
		{"data-id", html_component_enum_type::RSPAMD_HTML_COMPONENT_DATA_ID},
		{"data-url", html_component_enum_type::RSPAMD_HTML_COMPONENT_DATA_URL},
		{"xlink:href", html_component_enum_type::RSPAMD_HTML_COMPONENT_XLINK_HREF},
	});

#define msg_debug_html(...) rspamd_conditional_debug_fast(NULL, NULL,                                \
														  rspamd_html_log_id, "html", pool->tag.uid, \
														  __FUNCTION__,                              \
														  __VA_ARGS__)

INIT_LOG_MODULE(html)

/*
 * Comments, declarations, processing instructions and bogus comments are
 * kept in the tree, but have a budget of their own: any number of them must
 * neither use up the limit of elements nor make the tree grow without bound
 */
static const unsigned int max_special_tags = 8192;

static inline auto
html_tag_is_special(int flags) -> bool
{
	return !(flags & FL_VIRTUAL) && (flags & (FL_XML | FL_COMMENT));
}

/*
 * The only way to create a tag: all insertions into hc->all_tags must go
 * through this function to enforce the limits. A comment over its budget is
 * refused without the tags limit flag: the caller skips it
 */
static auto
html_tag_alloc(struct html_content *hc, int flags = 0) -> html_tag *
{
	const auto special = html_tag_is_special(flags);

	if (special) {
		if (hc->special_tags >= max_special_tags) {
			return nullptr;
		}
	}
	else if (hc->all_tags.size() - hc->special_tags >= max_tags) {
		hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_TAGS;

		return nullptr;
	}

	hc->all_tags.emplace_back(std::make_unique<html_tag>());
	auto *ntag = hc->all_tags.back().get();
	ntag->flags = flags;

	if (special) {
		hc->special_tags++;
	}

	return ntag;
}

/*
 * Where the nearest scope boundaries of every kind are on the open elements
 * from the root down to an element: the depth of the nearest boundary that
 * is the element itself or its ancestor, or -1 if there is none
 */
struct html_scope_depths {
	std::int32_t button = -1;  /* "has a p element in button scope" */
	std::int32_t special = -1; /* the loop for li, dd and dt */
	std::int32_t table = -1;   /* "in table scope" */
	std::int32_t marker = -1;  /* markers of the formatting elements list */
};

struct html_balance_state {
	std::size_t indexed_tags = 0;
	ankerl::unordered_dense::map<std::int32_t, std::vector<html_tag *>> open_tags;
	/* The scope depths of the open element at each depth of the stack */
	std::vector<html_scope_depths> scopes;
	/*
	 * Formatting elements closed by an implied end tag and not ended by a
	 * tag of their own yet, from the outermost one, and where this list is
	 * in `formatting_lists` of the content (0 if it is not there)
	 */
	std::vector<const html_tag *> active_formatting;
	std::uint32_t active_formatting_idx = 0;
	constexpr static const std::size_t max_active_formatting = 8;

	static constexpr auto is_formatting(std::int32_t id) -> bool
	{
		switch (id) {
		case Tag_B:
		case Tag_BIG:
		case Tag_CODE:
		case Tag_EM:
		case Tag_FONT:
		case Tag_I:
		case Tag_S:
		case Tag_SMALL:
		case Tag_STRIKE:
		case Tag_STRONG:
		case Tag_TT:
		case Tag_U:
			return true;
		default:
			return false;
		}
	}

	auto clear_formatting() -> void
	{
		active_formatting.clear();
		active_formatting_idx = 0;
	}

	/* An end tag of a formatting element that is not open: it ends an active one */
	auto end_formatting(std::int32_t id) -> void
	{
		for (auto it = active_formatting.rbegin(); it != active_formatting.rend(); ++it) {
			if ((*it)->id == id) {
				active_formatting.erase(std::next(it).base());
				active_formatting_idx = 0;
				break;
			}
		}
	}

	/* Gives a new element the formatting elements that are active around it */
	auto apply_formatting(html_content &hc, html_tag *tag) -> void
	{
		if (active_formatting.empty() || (tag->flags & (FL_COMMENT | FL_XML | FL_VIRTUAL))) {
			return;
		}

		if (active_formatting_idx == 0) {
			hc.formatting_lists.push_back(active_formatting);
			active_formatting_idx = static_cast<std::uint32_t>(hc.formatting_lists.size());
		}

		/* A child of an element that has this list has it through that element */
		if (!(tag->parent && tag->parent->formatting == active_formatting_idx)) {
			tag->formatting = active_formatting_idx;
		}
	}

	html_balance_state()
	{
		/* The root is a boundary of every kind */
		scopes.push_back({0, 0, 0, -1});
	}

	auto index_tags(const html_content &hc) -> void
	{
		/* Index each opening once, including hashed IDs of unknown tags. */
		while (indexed_tags < hc.all_tags.size()) {
			auto *tag = hc.all_tags[indexed_tags++].get();
			if (!(tag->flags & FL_CLOSED)) {
				open_tags[tag->id].push_back(tag);
			}
		}
	}

	/*
	 * Forgets the newest tag of `hc.all_tags`, which is about to be removed
	 * from it: no pointer to it may stay in the index
	 */
	auto forget_last(const html_content &hc, const html_tag *tag) -> void
	{
		if (indexed_tags == hc.all_tags.size()) {
			indexed_tags--;

			if (auto it = open_tags.find(tag->id); it != open_tags.end() &&
												   !it->second.empty() && it->second.back() == tag) {
				it->second.pop_back();
			}
		}
	}

	auto has_open_tag(const html_content &hc, std::int32_t id) -> bool
	{
		return innermost_open(hc, id, nullptr) != nullptr;
	}

	/*
	 * The innermost open element with the id, except `skip`: the open elements
	 * of an id are nested in the order of their creation
	 */
	auto innermost_open(const html_content &hc, std::int32_t id, const html_tag *skip) -> html_tag *
	{
		index_tags(hc);

		auto it = open_tags.find(id);
		if (it == open_tags.end()) {
			return nullptr;
		}
		auto &candidates = it->second;
		html_tag *skipped = nullptr;

		while (!candidates.empty()) {
			auto *back = candidates.back();

			if (back->flags & FL_CLOSED) {
				candidates.pop_back();
			}
			else if (back == skip && skipped == nullptr) {
				skipped = back;
				candidates.pop_back();
			}
			else {
				break;
			}
		}

		auto *ret = candidates.empty() ? nullptr : candidates.back();

		if (skipped) {
			candidates.push_back(skipped);
		}

		return ret;
	}
};

/*
 * This function is expected to be called on a closing tag to fill up all tags
 * and return the current parent (meaning unclosed) tag
 */
static auto
html_check_balance(struct html_content *hc,
				   html_balance_state &balance,
				   struct html_tag *tag,
				   goffset tag_start_offset,
				   goffset tag_end_offset) -> html_tag *
{
	/* As agreed, the closing tag has the last opening at the parent ptr */
	auto *opening_tag = tag->parent;

	auto calculate_content_length = [tag_start_offset, tag_end_offset](html_tag *t) {
		auto opening_content_offset = t->content_offset;

		if (t->flags & (CM_EMPTY)) {
			/* Attach closing tag just at the opening tag */
			t->closing.start = t->tag_start;
			t->closing.end = t->content_offset;
		}
		else {

			if (opening_content_offset <= tag_start_offset) {
				t->closing.start = tag_start_offset;
				t->closing.end = tag_end_offset;
			}
			else {

				t->closing.start = t->content_offset;
				t->closing.end = tag_end_offset;
			}
		}
	};

	auto balance_tag = [&]() -> html_tag * {
		if (!balance.has_open_tag(*hc, tag->id)) {
			return nullptr;
		}
		auto it = tag->parent;
		auto found_pair = false;

		for (; it != nullptr; it = it->parent) {
			if (it->id == tag->id && !(it->flags & FL_CLOSED)) {
				found_pair = true;
				break;
			}
		}

		/*
		 * If we have found a closing pair, then we need to close all tags
		 * up to and including that pair, and return its parent as the new
		 * current (unclosed) tag
		 */
		if (found_pair) {
			for (it = tag->parent; it != nullptr; it = it->parent) {
				auto is_pair = it->id == tag->id && !(it->flags & FL_CLOSED);
				it->flags |= FL_CLOSED;
				/* Insert a virtual closing tag for all tags that are not closed */
				calculate_content_length(it);
				if (is_pair) {
					break;
				}
			}

			return it ? it->parent : nullptr;
		}
		else {
			/*
			 * We have not found a pair, so this closing tag is bogus and should
			 * be ignored completely.
			 * Unfortunately, it also means that we need to insert another tag,
			 * as the current closing tag is unusable for that purposes.
			 *
			 * We assume that callee will recognise that and reconstruct the
			 * tag at the tag_end_closing state, so we return nullptr...
			 */
		}

		/* Tag must be ignored and reconstructed */
		return nullptr;
	};

	if (opening_tag) {

		if (opening_tag->id == tag->id) {
			opening_tag->flags |= FL_CLOSED;

			calculate_content_length(opening_tag);
			/* All good */
			return opening_tag->parent;
		}
		else {
			return balance_tag();
		}
	}
	else {
		/*
		 * We have no opening tag
		 * There are two possibilities:
		 *
		 * 1) We have some block tag in hc->all_tags;
		 * 2) We have no tags
		 */

		if (hc->all_tags.empty()) {
			auto *vtag = html_tag_alloc(hc, FL_VIRTUAL);

			if (vtag == nullptr) {
				return nullptr;
			}

			vtag->id = Tag_HTML;
			vtag->tag_start = 0;
			vtag->content_offset = 0;
			calculate_content_length(vtag);

			if (!hc->root_tag) {
				hc->root_tag = vtag;
			}
			else {
				vtag->parent = hc->root_tag;
			}

			tag->parent = vtag;

			/* Recursively call with a virtual <html> tag inserted */
			return html_check_balance(hc, balance, tag, tag_start_offset, tag_end_offset);
		}
	}

	return nullptr;
}

/*
 * Inline elements that show nothing when they are empty and have no
 * attributes: removing one of them does not change the text. Void elements,
 * blocks and anything that adds line breaks or text of its own are not here
 */
static auto
html_is_foldable_inline(int id) -> bool
{
	switch (id) {
	case Tag_B:
	case Tag_BIG:
	case Tag_CODE:
	case Tag_EM:
	case Tag_FONT:
	case Tag_I:
	case Tag_S:
	case Tag_SMALL:
	case Tag_SPAN:
	case Tag_STRIKE:
	case Tag_STRONG:
	case Tag_SUB:
	case Tag_SUP:
	case Tag_TT:
	case Tag_U:
		return true;
	default:
		return false;
	}
}

/* A closed element with no attributes, children and content between its tags */
static auto
html_is_empty_plain_element(const html_tag *tag) -> bool
{
	constexpr unsigned int not_plain = FL_VIRTUAL | FL_XML | FL_COMMENT | FL_IGNORE |
									   FL_BROKEN | FL_FOREIGN | FL_HREF | FL_LITERAL_TEXT |
									   FL_CONTENT_INVISIBLE | CM_HEAD | CM_EMPTY;

	return html_is_foldable_inline(tag->id) &&
		   (tag->flags & FL_CLOSED) && !(tag->flags & not_plain) &&
		   tag->components.empty() && tag->children.empty() &&
		   std::holds_alternative<std::monostate>(tag->extra) &&
		   tag->content_offset == (unsigned int) tag->closing.start;
}

/*
 * A closed empty element that follows an identical one right away adds
 * nothing to the tree: `<b></b><b></b>` is `<b></b>`. The first element of
 * the run stays and takes over the source range of the others, so that the
 * text around them is cut at the same places and their markup is not text.
 * Sibling selectors still see an element between what comes before and
 * after the run (`b + b` matches one element less than in the source).
 *
 * The element is removed from the tree and from `all_tags`, which gives its
 * slot back to the tags limit. It is the newest tag and the last child of its
 * parent, so nothing else points to it but the balance index. The block of
 * the element is kept for the next element without attributes, so that
 * a long run does not take pool memory for each element.
 */
static auto
html_fold_empty_element(struct html_content *hc,
						html_balance_state &balance,
						struct html_tag *tag,
						goffset tag_end_offset,
						struct html_block **spare_block) -> bool
{
	auto *parent = tag->parent;

	if (parent == nullptr || hc->all_tags.empty() || hc->all_tags.back().get() != tag ||
		parent->children.size() < 2 || parent->children.back() != tag ||
		!html_is_empty_plain_element(tag)) {
		return false;
	}

	auto *prev = parent->children[parent->children.size() - 2];

	if (prev->id != tag->id || prev->flags != tag->flags || !html_is_empty_plain_element(prev) ||
		prev->parent != parent || prev->closing.end < 0 ||
		(unsigned int) prev->closing.end != tag->tag_start) {
		return false;
	}

	prev->closing.end = tag_end_offset;
	parent->children.pop_back();
	balance.forget_last(*hc, tag);

	if (spare_block && *spare_block == nullptr && tag->block) {
		*spare_block = tag->block;
	}

	hc->all_tags.pop_back();

	return true;
}

auto html_component_from_string(std::string_view name, std::string_view value, std::size_t offset, std::size_t len) -> html_tag_component
{
	auto known_component_it = html_components_map.find(name);

	if (known_component_it != html_components_map.end()) {
		switch (known_component_it->second) {
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_NAME:
			return html_component_name{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_HREF:
			return html_component_href{value, offset, len};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_COLOR:
			return html_component_color{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BGCOLOR:
			return html_component_bgcolor{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_STYLE:
			return html_component_style{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_CLASS:
			return html_component_class{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_WIDTH:
			return html_component_width{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_HEIGHT:
			return html_component_height{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_SIZE:
			return html_component_size{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_REL:
			return html_component_rel{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_ALT:
			return html_component_alt{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_ID:
			return html_component_id{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_HIDDEN:
			return html_component_hidden{};
		// Typography
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_FAMILY:
			return html_component_font_family{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_SIZE:
			return html_component_font_size{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_WEIGHT:
			return html_component_font_weight{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_FONT_STYLE:
			return html_component_font_style{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_TEXT_ALIGN:
			return html_component_text_align{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_TEXT_DECORATION:
			return html_component_text_decoration{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_LINE_HEIGHT:
			return html_component_line_height{value};
		// Layout
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN:
			return html_component_margin{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_TOP:
			return html_component_margin_top{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_BOTTOM:
			return html_component_margin_bottom{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_LEFT:
			return html_component_margin_left{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MARGIN_RIGHT:
			return html_component_margin_right{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING:
			return html_component_padding{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_TOP:
			return html_component_padding_top{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_BOTTOM:
			return html_component_padding_bottom{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_LEFT:
			return html_component_padding_left{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_PADDING_RIGHT:
			return html_component_padding_right{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER:
			return html_component_border{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER_COLOR:
			return html_component_border_color{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER_WIDTH:
			return html_component_border_width{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BORDER_STYLE:
			return html_component_border_style{value};
		// Display
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_DISPLAY:
			return html_component_display{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_VISIBILITY:
			return html_component_visibility{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_OPACITY:
			return html_component_opacity{value};
		// Dimensions
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MIN_WIDTH:
			return html_component_min_width{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MAX_WIDTH:
			return html_component_max_width{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MIN_HEIGHT:
			return html_component_min_height{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_MAX_HEIGHT:
			return html_component_max_height{value};
		// Table
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_CELLPADDING:
			return html_component_cellpadding{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_CELLSPACING:
			return html_component_cellspacing{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_VALIGN:
			return html_component_valign{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_ALIGN:
			return html_component_align{value};
		// Form
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_TYPE:
			return html_component_type{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_VALUE:
			return html_component_value{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_PLACEHOLDER:
			return html_component_placeholder{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_DISABLED:
			return html_component_disabled{};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_READONLY:
			return html_component_readonly{};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_CHECKED:
			return html_component_checked{};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_SELECTED:
			return html_component_selected{};
		// Link & media
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_TARGET:
			return html_component_target{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_TITLE:
			return html_component_title{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_SRC:
			return html_component_src{value, offset, len};
		// Meta
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_CHARSET:
			return html_component_charset{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_CONTENT:
			return html_component_content{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_HTTP_EQUIV:
			return html_component_http_equiv{value};
		// Accessibility
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_ROLE:
			return html_component_role{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_TABINDEX:
			return html_component_tabindex{value};
		// Background
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND:
			return html_component_background{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_IMAGE:
			return html_component_background_image{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_COLOR:
			return html_component_background_color{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_REPEAT:
			return html_component_background_repeat{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_BACKGROUND_POSITION:
			return html_component_background_position{value};
		// Email tracking
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_DATA_TRACK:
			return html_component_data_track{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_DATA_ID:
			return html_component_data_id{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_DATA_URL:
			return html_component_data_url{value};
		case html_component_enum_type::RSPAMD_HTML_COMPONENT_XLINK_HREF:
			return html_component_xlink_href{value, offset, len};
		default:
			return html_component_unknown{name, value};
		}
	}
	else {
		return html_component_unknown{name, value};
	}
}

/*
 * The attribute that holds where a tag goes, as browsers read it: "action" of
 * a form, "formaction" of a submit button or input, "src" of a frame or an
 * embedded object, "href" of anything else
 */
static auto
html_tag_destination_attr(std::int32_t id) -> std::string_view
{
	if (html_tag_goes_to_src(id)) {
		return "src";
	}

	switch (id) {
	case Tag_FORM:
		return "action";
	case Tag_BUTTON:
	case Tag_INPUT:
		return "formaction";
	default:
		return "href";
	}
}

/*
 * A button or an input with formaction is a link to where the form goes, if
 * it submits the form: a button that is not of type "button" or "reset", an
 * input of type "submit" or "image". Known once all its attributes are read
 */
static auto
html_tag_mark_submit_link(html_tag *tag) -> void
{
	/* In svg or math, they are foreign elements that submit nothing */
	if ((tag->id != Tag_BUTTON && tag->id != Tag_INPUT) || (tag->flags & FL_FOREIGN) ||
		!tag->find_component<html_component_href>()) {
		return;
	}

	std::optional<std::string_view> type;
	if (auto comp = tag->find_component<html_component_type>()) {
		type = comp.value()->value;
	}
	auto type_is = [&](std::string_view name) -> bool {
		return type && type->size() == name.size() &&
			   g_ascii_strncasecmp(type->data(), name.data(), name.size()) == 0;
	};
	bool submits = tag->id == Tag_BUTTON ? !(type_is("button") || type_is("reset"))
										 : (type_is("submit") || type_is("image"));

	if (submits) {
		tag->flags |= FL_HREF;
	}
}

using component_extractor_func = std::function<std::optional<std::string_view>(const html_tag *)>;
static const auto component_extractors = frozen::make_unordered_map<frozen::string, component_extractor_func>(
	{
		// Basic components
		{"name", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_name>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		/* The destination of a tag is read under its own name, the others are plain attributes */
		{"href", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (html_tag_destination_attr(tag->id) != "href") {
				 return tag->find_unknown_component("href");
			 }
			 /* Not find_href, which falls back to xlink:href */
			 if (auto comp = tag->find_component<html_component_href>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"action", [](const html_tag *tag) -> std::optional<std::string_view> {
			 return html_tag_destination_attr(tag->id) == "action" ? tag->find_href() : tag->find_unknown_component("action");
		 }},
		{"formaction", [](const html_tag *tag) -> std::optional<std::string_view> {
			 return html_tag_destination_attr(tag->id) == "formaction" ? tag->find_href() : tag->find_unknown_component("formaction");
		 }},
		{"src", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_src>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"class", [](const html_tag *tag) { return tag->find_class(); }},
		{"id", [](const html_tag *tag) { return tag->find_id(); }},
		{"style", [](const html_tag *tag) { return tag->find_style(); }},
		{"alt", [](const html_tag *tag) { return tag->find_alt(); }},
		{"rel", [](const html_tag *tag) { return tag->find_rel(); }},
		{"color", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_color>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"bgcolor", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_bgcolor>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},

		// Numeric components (return string representation)
		{"width", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_width>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"height", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_height>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"size", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_size>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},

		// Boolean components
		{"hidden", [](const html_tag *tag) -> std::optional<std::string_view> {
			 return tag->is_hidden() ? std::optional<std::string_view>{"true"} : std::nullopt;
		 }},

		// Typography components
		{"font-family", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_font_family>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"font-size", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_font_size>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"font-weight", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_font_weight>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"font-style", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_font_style>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"text-align", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_text_align>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"text-decoration", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_text_decoration>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"line-height", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_line_height>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},

		// Layout components
		{"margin", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_margin>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"margin-top", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_margin_top>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"margin-bottom", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_margin_bottom>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"margin-left", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_margin_left>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"margin-right", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_margin_right>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"padding", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_padding>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"padding-top", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_padding_top>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"padding-bottom", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_padding_bottom>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"padding-left", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_padding_left>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"padding-right", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_padding_right>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"border", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_border>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"border-color", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_border_color>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"border-width", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_border_width>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"border-style", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_border_style>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},

		// Display components
		{"display", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_display>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"visibility", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_visibility>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"opacity", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_opacity>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},

		// Additional dimensions
		{"min-width", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_min_width>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"max-width", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_max_width>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"min-height", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_min_height>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"max-height", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_max_height>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},

		// Table components
		{"cellpadding", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_cellpadding>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"cellspacing", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_cellspacing>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},
		{"valign", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_valign>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"align", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_align>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},

		// Form components
		{"type", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_type>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"value", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_value>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"placeholder", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_placeholder>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"disabled", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_disabled>()) {
				 return comp.value()->is_present() ? std::optional<std::string_view>{"true"} : std::nullopt;
			 }
			 return std::nullopt;
		 }},
		{"readonly", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_readonly>()) {
				 return comp.value()->is_present() ? std::optional<std::string_view>{"true"} : std::nullopt;
			 }
			 return std::nullopt;
		 }},
		{"checked", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_checked>()) {
				 return comp.value()->is_present() ? std::optional<std::string_view>{"true"} : std::nullopt;
			 }
			 return std::nullopt;
		 }},
		{"selected", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_selected>()) {
				 return comp.value()->is_present() ? std::optional<std::string_view>{"true"} : std::nullopt;
			 }
			 return std::nullopt;
		 }},

		// Link & media components
		{"target", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_target>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"title", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_title>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},

		// Meta components
		{"charset", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_charset>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"content", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_content>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"http-equiv", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_http_equiv>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},

		// Accessibility components
		{"role", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_role>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"tabindex", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_tabindex>()) {
				 return comp.value()->get_string_value();
			 }
			 return std::nullopt;
		 }},

		// Background components
		{"background", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_background>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"background-image", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_background_image>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"background-color", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_background_color>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"background-repeat", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_background_repeat>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"background-position", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_background_position>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},

		// Email tracking components
		{"data-track", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_data_track>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"data-id", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_data_id>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"data-url", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_data_url>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
		{"xlink:href", [](const html_tag *tag) -> std::optional<std::string_view> {
			 if (auto comp = tag->find_component<html_component_xlink_href>()) {
				 return comp.value()->value;
			 }
			 return std::nullopt;
		 }},
	});


auto html_tag::find_component_by_name(std::string_view attr_name) const -> std::optional<std::string_view>
{
	auto it = component_extractors.find(attr_name);
	if (it != component_extractors.end()) {
		return it->second(this);
	}

	// Fallback to unknown components
	return find_unknown_component(attr_name);
}

auto html_tag::get_all_attributes() const -> std::vector<std::pair<std::string_view, std::string_view>>
{
	std::vector<std::pair<std::string_view, std::string_view>> result;

	// First, get all known attributes using the component_extractors map
	for (const auto &[attr_name, extractor_func]: component_extractors) {
		if (auto value = extractor_func(this)) {
			// Convert frozen::string to std::string_view for the key
			std::string_view name_view{attr_name.data(), attr_name.size()};
			result.emplace_back(name_view, value.value());
		}
	}

	// Then add all unknown attributes
	auto unknown_attrs = get_unknown_components();
	for (const auto &[name, value]: unknown_attrs) {
		result.emplace_back(name, value);
	}

	return result;
}

enum tag_parser_state {
	parse_start = 0,
	parse_name,
	parse_attr_name,
	parse_equal,
	parse_start_dquote,
	parse_dqvalue,
	parse_end_dquote,
	parse_start_squote,
	parse_sqvalue,
	parse_end_squote,
	parse_value,
	spaces_before_eq,
	spaces_after_eq,
	spaces_after_param,
	ignore_bad_tag,
	tag_end,
	slash_after_value,
};
/*
 * Attributes the parser reads by name although they have no component type of
 * their own: they are kept like the typed ones, see store_component_value
 */
static constexpr std::array<std::string_view, 3> html_untyped_interpreted_attrs{
	"face", "encoding", "aria-label"};
/* Typed components first, then the attributes above */
static constexpr std::size_t html_interpreted_attrs_count =
	std::numeric_limits<std::uint8_t>::max() + 1 + html_untyped_interpreted_attrs.size();

static inline auto
html_interpreted_attr_index(std::string_view name) -> std::optional<std::size_t>
{
	auto known_it = html_components_map.find(name);

	if (known_it != html_components_map.end()) {
		return static_cast<std::size_t>(known_it->second);
	}

	for (std::size_t i = 0; i < html_untyped_interpreted_attrs.size(); i++) {
		if (name == html_untyped_interpreted_attrs[i]) {
			return std::numeric_limits<std::uint8_t>::max() + 1 + i;
		}
	}

	return std::nullopt;
}

struct tag_content_parser_state {
	tag_parser_state cur_state = parse_start;
	std::string buf;
	std::string attr_name;            // Store current attribute name
	const char *value_start = nullptr;// Track where attribute value starts in input
	/* Where the first quote is in an unquoted value, see html_unquoted_value_length */
	std::size_t value_quote = std::string::npos;
	const char *html_start = nullptr;   // Base pointer to HTML buffer start
	unsigned int *attrs_count = nullptr;// Task-global unknown attributes counter (task pool variable)
	/* Of the current tag: attributes rspamd interprets that it has, and other attributes */
	std::bitset<html_interpreted_attrs_count> known_attrs;
	unsigned int unknown_attrs = 0;

	void reset()
	{
		cur_state = parse_start;
		buf.clear();
		attr_name.clear();
		value_start = nullptr;
		value_quote = std::string::npos;
		known_attrs.reset();
		unknown_attrs = 0;
	}
};

/*
 * Browsers read an unquoted attribute value on past a quote, rspamd up to it:
 * `href=3D"https://...` of undecoded quoted-printable is a relative link,
 * not one to that site, and `href=http://x.com/a"b` goes to x.com anyway.
 * Unless the quote is in the authority of the link and an `@` follows there:
 * browsers go to the host after it then (`https://www.paypal.com"@evil.com/`),
 * so the whole value is kept. Its place in the source is the whole value in
 * any case, which URL rewriting replaces, and gives to its policy whole (see
 * whole_unquoted_value)
 */
static auto
html_unquoted_value_length(std::string_view value, std::size_t quote) -> std::size_t
{
	/*
	 * Character references are decoded in attribute values (none spans the
	 * quote), and URL parsers drop tabs and line breaks anywhere in a link
	 */
	std::string prefix{value.substr(0, quote)}, rest{value.substr(quote)};
	auto normalise = [](std::string &part) {
		part.resize(decode_html_entitles_inplace(part.data(), part.size()));
		std::erase_if(part, [](char c) { return c == '\t' || c == '\n' || c == '\r'; });
	};
	normalise(prefix);
	normalise(rest);

	std::string_view link{prefix};

	/* Browsers skip leading C0 controls and spaces */
	while (!link.empty() && (unsigned char) link.front() <= 0x20) {
		link.remove_prefix(1);
	}

	auto is_slash = [](char c) { return c == '/' || c == '\\'; };
	auto ends_authority = [&](char c) { return is_slash(c) || c == '?' || c == '#'; };
	std::size_t authority = std::string_view::npos;

	if (link.size() >= 2 && is_slash(link[0]) && is_slash(link[1])) {
		authority = 2;
	}
	else if (auto colon = link.find(':'); colon != std::string_view::npos && colon > 0 &&
										  g_ascii_isalpha(link[0])) {
		auto scheme = link.substr(0, colon);
		auto scheme_char = [](char c) { return g_ascii_isalnum(c) || c == '+' || c == '-' || c == '.'; };

		if (std::all_of(scheme.begin(), scheme.end(), scheme_char)) {
			auto is_scheme = [&](std::string_view name) {
				return scheme.size() == name.size() &&
					   g_ascii_strncasecmp(scheme.data(), name.data(), name.size()) == 0;
			};

			authority = colon + 1;

			if (is_scheme("http") || is_scheme("https") || is_scheme("ftp") ||
				is_scheme("ws") || is_scheme("wss")) {
				/* Their authority comes after any slashes, or none */
				while (authority < link.size() && is_slash(link[authority])) {
					authority++;
				}
			}
			else if (link.substr(authority, 2) == "//") {
				authority += 2;
			}
			else {
				authority = std::string_view::npos;
			}
		}
	}

	/* The quote must be in the authority, which an `@` after it ends */
	if (authority == std::string_view::npos || authority > link.size() ||
		std::any_of(link.begin() + authority, link.end(), ends_authority)) {
		return quote;
	}

	for (auto c: rest) {
		if (ends_authority(c)) {
			break;
		}
		if (c == '@') {
			return value.size();
		}
	}

	return quote;
}

/* Unknown tags get a negative hash of their name, so closing tags match */
static inline auto
html_unknown_tag_id(std::string_view name) -> std::int32_t
{
	auto nhash = static_cast<std::int32_t>(std::hash<std::string_view>{}(name));

	/* Not a tag_id_t: the value is outside of that enumeration */
	return nhash | G_MININT32;
}

static inline void
html_parse_tag_content(rspamd_mempool_t *pool,
					   struct html_content *hc,
					   struct html_tag *tag,
					   const char *in,
					   struct tag_content_parser_state &parser_env)
{
	auto state = parser_env.cur_state;

	/*
	 * Stores tag component creating the appropriate variant type
	 * Parser env is cleared after storing
	 */
	auto store_component_value = [&]() -> void {
		if (parser_env.value_quote != std::string::npos) {
			parser_env.buf.resize(html_unquoted_value_length(parser_env.buf, parser_env.value_quote));
			parser_env.value_quote = std::string::npos;
		}

		if (!parser_env.attr_name.empty()) {
			auto drop_attribute = [&]() -> void {
				parser_env.buf.clear();
				parser_env.attr_name.clear();
				parser_env.value_start = nullptr;
			};
			/*
			 * "href" (links) and "action" (forms) are both read as the
			 * destination of a tag, but a tag has only one: browsers follow
			 * "href" of <a> and "action" of <form>. The other one is an
			 * ordinary attribute, which must not take the place of the real
			 * destination: <a action="good" href="evil"> goes to evil.
			 */
			bool destination_name = parser_env.attr_name == "href" ||
									parser_env.attr_name == "action" ||
									parser_env.attr_name == "formaction";
			bool foreign_destination = destination_name &&
									   parser_env.attr_name != html_tag_destination_attr(tag->id);
			auto interpreted_idx = foreign_destination
									   ? std::nullopt
									   : html_interpreted_attr_index(destination_name ? "href" : parser_env.attr_name);

			if (interpreted_idx) {
				/*
				 * An attribute rspamd interprets (href, src, style...) is never
				 * dropped for the budgets below, so junk attributes cannot push
				 * it out. A repeated one is ignored, as browsers do (the first
				 * one wins), which also bounds them per tag.
				 */
				if (parser_env.known_attrs.test(*interpreted_idx)) {
					drop_attribute();

					return;
				}

				parser_env.known_attrs.set(*interpreted_idx);
			}
			else {
				/*
				 * Other attributes have per-tag and task-global budgets: a single
				 * tag must not evade the tags limit by cramming everything into
				 * attributes
				 */
				if (parser_env.unknown_attrs >= max_attrs_per_tag ||
					*parser_env.attrs_count >= max_attrs_per_task) {
					if (!(hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_ATTRS)) {
						msg_warn_pool("too many attributes in HTML tags; ignoring the rest");
						hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_ATTRS;
					}

					drop_attribute();

					return;
				}

				parser_env.unknown_attrs++;
				(*parser_env.attrs_count)++;
			}

			std::string_view attr_name_view, value_view;

			// Store attribute name in persistent memory
			if (!parser_env.attr_name.empty()) {
				auto *name_storage = rspamd_mempool_alloc_buffer(pool, parser_env.attr_name.size());
				memcpy(name_storage, parser_env.attr_name.data(), parser_env.attr_name.size());
				attr_name_view = {name_storage, parser_env.attr_name.size()};
			}

			// Calculate attribute value span for URL rewriting (href/src only)
			std::size_t value_offset = 0, value_len = 0;
			if (parser_env.value_start != nullptr && parser_env.html_start != nullptr) {
				value_offset = parser_env.value_start - parser_env.html_start;
				value_len = in - parser_env.value_start;
			}

			// Store value in persistent memory if not empty
			if (!parser_env.buf.empty()) {
				auto *value_storage = rspamd_mempool_alloc_buffer(pool, parser_env.buf.size());

				// Lowercase for id and class attributes
				if (parser_env.attr_name == "id" || parser_env.attr_name == "class") {
					rspamd_str_copy_lc(parser_env.buf.data(), value_storage, parser_env.buf.size());
				}
				else {
					memcpy(value_storage, parser_env.buf.data(), parser_env.buf.size());
				}

				auto sz = rspamd_html_decode_entitles_inplace(value_storage, parser_env.buf.size());
				value_view = {value_storage, sz};
			}

			if (foreign_destination) {
				tag->components.emplace_back(html_component_unknown{attr_name_view, value_view});
			}
			else if (parser_env.attr_name == "formaction") {
				/* Where a submit control sends its form, see html_tag_mark_submit_link */
				tag->components.emplace_back(html_component_href{value_view, value_offset, value_len});
			}
			else {
				// Create the appropriate component variant with span info
				auto component = html_component_from_string(attr_name_view, value_view, value_offset, value_len);
				tag->components.emplace_back(std::move(component));
			}
		}

		parser_env.buf.clear();
		parser_env.attr_name.clear();
		parser_env.value_start = nullptr;
	};

	auto store_component_name = [&]() -> bool {
		/*
		 * Browsers do not decode character references in attribute names:
		 * hr&#101;f is some other attribute, which must not be taken for the
		 * href that follows it
		 */
		parser_env.attr_name = parser_env.buf;
		parser_env.buf.clear();
		return true;
	};

	auto store_value_character = [&](bool lc) -> void {
		auto c = lc ? g_ascii_tolower(*in) : *in;

		if (c == '\0') {
			/* Replace with u0FFD */
			parser_env.buf.append((const char *) u8"\uFFFD");
		}
		else {
			parser_env.buf.push_back(c);
		}
	};

	switch (state) {
	case parse_start:
		if (!g_ascii_isalpha(*in) && !g_ascii_isspace(*in)) {
			hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			state = ignore_bad_tag;
			tag->id = N_TAGS;
			tag->flags |= FL_BROKEN;
		}
		else if (g_ascii_isalpha(*in)) {
			state = parse_name;
			store_value_character(true);
		}
		break;

	case parse_name:
		if ((g_ascii_isspace(*in) || *in == '>' || *in == '/')) {
			if (parser_env.buf.empty()) {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				tag->id = N_TAGS;
				tag->flags |= FL_BROKEN;
				state = ignore_bad_tag;
			}
			else {
				/* The tokenizer decodes no character references in tag names */
				const auto *tag_def = rspamd::html::html_tags_defs.by_name(parser_env.buf);

				if (tag_def == nullptr) {
					hc->flags |= RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS;
					tag->id = html_unknown_tag_id(parser_env.buf);
				}
				else {
					tag->id = tag_def->id;
					tag->flags = tag_def->flags;
				}

				parser_env.buf.clear();

				state = *in == '/' ? slash_after_value : spaces_after_param;
			}
		}
		else {
			store_value_character(true);
		}
		break;

	case parse_attr_name:
		if (*in == '=') {
			if (!parser_env.buf.empty()) {
				store_component_name();
			}
			state = parse_equal;
		}
		else if (g_ascii_isspace(*in)) {
			store_component_name();
			state = spaces_before_eq;
		}
		else if (*in == '/') {
			store_component_name();
			store_component_value();
			state = slash_after_value;
		}
		else if (*in == '>') {
			store_component_name();
			store_component_value();
			state = tag_end;
		}
		else {
			if (*in == '"' || *in == '\'' || *in == '<') {
				/* Should never be in attribute names but ignored */
				tag->flags |= FL_BROKEN;
			}

			store_value_character(true);
		}

		break;

	case spaces_before_eq:
		/* After attribute name state of the HTML standard tokeniser */
		if (*in == '=') {
			state = parse_equal;
		}
		else if (!g_ascii_isspace(*in)) {
			/*
			 * HTML defines that crap could still be restored and
			 * calculated somehow... So we have to follow this stupid behaviour
			 */
			if (*in == '>') {
				/*
				 * Attribute name followed by end of tag
				 * Should be okay (empty attribute). The rest is handled outside
				 * this automata.
				 */
				store_component_value();
				state = tag_end;
			}
			else if (*in == '/') {
				/* A valueless attribute, then the self-closing start tag state */
				store_component_value();
				state = slash_after_value;
			}
			else {
				/* A valueless attribute, a new attribute name starts here */
				if (*in == '"' || *in == '\'' || *in == '<') {
					/* Missing '=' ? Browsers make it a part of the name */
					hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
					tag->flags |= FL_BROKEN;
				}
				store_component_value();
				store_value_character(true);
				state = parse_attr_name;
			}
		}
		break;

	case spaces_after_eq:
		if (*in == '"') {
			state = parse_start_dquote;
		}
		else if (*in == '\'') {
			state = parse_start_squote;
		}
		else if (!g_ascii_isspace(*in)) {
			// Mark start of unquoted attribute value
			if (parser_env.value_start == nullptr) {
				parser_env.value_start = in;
			}
			store_value_character(false);
			state = parse_value;
		}
		break;

	case parse_equal:
		if (g_ascii_isspace(*in)) {
			state = spaces_after_eq;
		}
		else if (*in == '"') {
			state = parse_start_dquote;
		}
		else if (*in == '\'') {
			state = parse_start_squote;
		}
		else {
			// Mark start of unquoted attribute value
			if (parser_env.value_start == nullptr) {
				parser_env.value_start = in;
			}
			store_value_character(false);
			state = parse_value;
		}
		break;

	case parse_start_dquote:
		if (*in == '"') {
			// Empty quoted value - set value_start to point to the closing quote
			if (parser_env.value_start == nullptr) {
				parser_env.value_start = in;
			}
			store_component_value();
			state = spaces_after_param;
		}
		else {
			// Mark start of attribute value (first char inside quotes)
			if (parser_env.value_start == nullptr) {
				parser_env.value_start = in;
			}
			store_value_character(false);
			state = parse_dqvalue;
		}
		break;

	case parse_start_squote:
		if (*in == '\'') {
			// Empty quoted value - set value_start to point to the closing quote
			if (parser_env.value_start == nullptr) {
				parser_env.value_start = in;
			}
			store_component_value();
			state = spaces_after_param;
		}
		else {
			// Mark start of attribute value (first char inside quotes)
			if (parser_env.value_start == nullptr) {
				parser_env.value_start = in;
			}
			store_value_character(false);
			state = parse_sqvalue;
		}
		break;

	case parse_dqvalue:
		if (*in == '"') {
			store_component_value();
			state = parse_end_dquote;
		}
		else {
			store_value_character(false);
		}
		break;

	case parse_sqvalue:
		if (*in == '\'') {
			store_component_value();
			state = parse_end_squote;
		}
		else {
			store_value_character(false);
		}

		break;

	case parse_value:
		/*
		 * `/` and quotes are a part of an unquoted value, as in browsers:
		 * `<a href=/x/>` is not closed, see html_unquoted_value_length
		 */
		if (g_ascii_isspace(*in) || *in == '>') {
			store_component_value();
			state = spaces_after_param;
		}
		else {
			// Mark start of unquoted attribute value
			if (parser_env.value_start == nullptr) {
				parser_env.value_start = in;
			}

			if (*in == '"' && parser_env.value_quote == std::string::npos) {
				parser_env.value_quote = parser_env.buf.size();
			}

			store_value_character(false);
		}
		break;

	case parse_end_dquote:
	case parse_end_squote:
		if (g_ascii_isspace(*in)) {
			state = spaces_after_param;
		}
		else if (*in == '/') {
			store_component_value();
			state = slash_after_value;
		}
		else {
			/* No space, proceed immediately to the attribute name */
			state = parse_attr_name;
			store_component_value();
			store_value_character(true);
		}
		break;

	case spaces_after_param:
		if (!g_ascii_isspace(*in)) {
			if (*in == '/') {
				state = slash_after_value;
			}
			else if (*in == '=') {
				/* Attributes cannot start with '=' */
				tag->flags |= FL_BROKEN;
				store_value_character(true);
				state = parse_attr_name;
			}
			else {
				store_value_character(true);
				state = parse_attr_name;
			}
		}
		break;
	case slash_after_value:
		/* Only `/` right before `>` closes a tag: `<svg/ >` or `<svg/x>` do not */
		if (*in == '>') {
			tag->flags |= FL_CLOSED;
			state = tag_end;
		}
		else if (g_ascii_isspace(*in)) {
			state = spaces_after_param;
		}
		else if (*in != '/') {
			tag->flags |= FL_BROKEN;
			store_value_character(true);
			state = parse_attr_name;
		}
		break;
	case ignore_bad_tag:
	case tag_end:
		break;
	}

	parser_env.cur_state = state;
}

static inline auto
html_is_absolute_url(std::string_view st) -> bool
{
	auto alnum_pos = std::find_if(std::begin(st), std::end(st),
								  [](auto c) { return !g_ascii_isalnum(c); });

	if (alnum_pos != std::end(st) && alnum_pos != std::begin(st)) {
		if (*alnum_pos == ':') {
			if (st.substr(0, std::distance(std::begin(st), alnum_pos)) == "mailto") {
				return true;
			}

			std::advance(alnum_pos, 1);
			if (alnum_pos != std::end(st)) {
				/* Include even malformed urls */
				if (*alnum_pos == '/' || *alnum_pos == '\\') {
					return true;
				}
			}
		}
	}

	return false;
}

/*
 * Resolves a link against the base url of the document. Returns
 * false for a data: url, which is never inserted as one
 */
static auto
html_resolve_against_base(rspamd_mempool_t *pool,
						  std::string_view &href_value,
						  struct html_content *hc) -> bool
{
	if (!(hc && hc->base_url)) {
		return true;
	}

	/*
	 * Resolved as browsers do: a link with a scheme of its own is not
	 * relative (mailto:, or http:x.com under an https base), two
	 * slashes take only the scheme of the base (//evil.com is another
	 * host), one slash its host, anything else its path
	 */
	auto is_slash = [](char c) { return c == '/' || c == '\\'; };
	auto scheme_char = [](char c) { return g_ascii_isalnum(c) || c == '+' || c == '-' || c == '.'; };
	std::string_view scheme, rest = href_value;
	std::string_view base_scheme{hc->base_url->string, hc->base_url->protocollen};

	if (auto colon = href_value.find(':'); colon != std::string_view::npos && colon > 0 &&
										   g_ascii_isalpha(href_value[0]) &&
										   std::all_of(href_value.begin(), href_value.begin() + colon, scheme_char)) {
		scheme = href_value.substr(0, colon);
	}

	if (!scheme.empty() && scheme.size() == sizeof("data") - 1 &&
		g_ascii_strncasecmp(scheme.data(), "data", scheme.size()) == 0) {
		return false;
	}

	bool same_scheme = !scheme.empty() && scheme.size() == base_scheme.size() &&
					   g_ascii_strncasecmp(scheme.data(), base_scheme.data(), scheme.size()) == 0;

	if (same_scheme) {
		rest = href_value.substr(scheme.size() + 1);
	}

	std::string_view base_str{hc->base_url->string, hc->base_url->urllen};
	auto authority_end = static_cast<std::size_t>(hc->base_url->hostshift) +
						 hc->base_url->hostlen;

	if (authority_end > base_str.size()) {
		authority_end = base_str.size();
	}

	/* A port belongs to the authority of the base */
	if (authority_end < base_str.size() && base_str[authority_end] == ':') {
		auto port_end = authority_end + 1;

		while (port_end < base_str.size() &&
			   g_ascii_isdigit(base_str[port_end])) {
			port_end++;
		}

		if (port_end > authority_end + 1 &&
			(port_end == base_str.size() || base_str[port_end] == '/' ||
			 base_str[port_end] == '?' || base_str[port_end] == '#')) {
			authority_end = port_end;
		}
	}

	auto path_end = base_str.find_first_of("?#", authority_end);

	if (path_end == std::string_view::npos) {
		path_end = base_str.size();
	}

	if (!scheme.empty() && !same_scheme) {
		/* Not relative */
	}
	else if (rest.size() >= 2 && is_slash(rest[0]) && is_slash(rest[1])) {
		/* Relative to the scheme */
		auto len = base_scheme.size() + 1 + rest.size();
		auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
		auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1, "%*s:%*s",
												  (int) base_scheme.size(), base_scheme.data(),
												  (int) rest.size(), rest.data());
		href_value = {buf, nlen};
	}
	else if (!rest.empty() && is_slash(rest[0])) {
		/*
		 * Relative to the host: the authority of the base, its port
		 * included, stays
		 */
		auto len = authority_end + rest.size();
		auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
		auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1, "%*s%*s",
												  (int) authority_end, base_str.data(),
												  (int) rest.size(), rest.data());
		href_value = {buf, nlen};
	}
	else if (!rest.empty() && rest[0] == '#') {
		/*
		 * A fragment link keeps everything of the base but its own
		 * fragment, its query included
		 */
		auto keep_end = base_str.size();

		if (hc->base_url->fragmentlen > 0) {
			keep_end = hc->base_url->fragmentshift;
		}

		auto len = keep_end + rest.size();
		auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
		auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1, "%*s%*s",
												  (int) keep_end, base_str.data(),
												  (int) rest.size(), rest.data());
		href_value = {buf, nlen};
	}
	else if (!rest.empty() && rest[0] == '?') {
		/* A query link keeps the path of the base and replaces the
		 * query and the fragment of it */
		auto len = path_end + rest.size();
		auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
		auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1, "%*s%*s",
												  (int) path_end, base_str.data(),
												  (int) rest.size(), rest.data());
		href_value = {buf, nlen};
	}
	else {
		/*
		 * Relative to the path: resolved against its directory part,
		 * as browsers do, while a query or a fragment of the base
		 * carries over nothing
		 */
		auto dir_end = std::string_view::npos;

		if (path_end > authority_end) {
			dir_end = base_str.substr(authority_end,
									  path_end - authority_end)
						  .find_last_of('/');

			if (dir_end != std::string_view::npos) {
				dir_end += authority_end;
			}
		}

		if (dir_end != std::string_view::npos) {
			/* The directory part of the base path, slash included */
			auto len = dir_end + 1 + rest.size();
			auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
			auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1, "%*s%*s",
													  (int) (dir_end + 1), base_str.data(),
													  (int) rest.size(), rest.data());
			href_value = {buf, nlen};
		}
		else {
			/* No directory part: resolve against the root of the host */
			auto len = authority_end + 1 + rest.size();
			auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
			auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1, "%*s/%*s",
													  (int) authority_end, base_str.data(),
													  (int) rest.size(), rest.data());
			href_value = {buf, nlen};
		}
	}

	return true;
}

static auto
html_process_url_tag(rspamd_mempool_t *pool,
					 struct html_tag *tag,
					 struct html_content *hc,
					 lua_State *L) -> std::optional<struct rspamd_url *>
{
	auto found_href_maybe = tag->find_href();

	if (found_href_maybe) {
		/* Check base url */
		auto &href_value = found_href_maybe.value();

		/* Browsers strip C0 controls and spaces around a link before they resolve it */
		while (!href_value.empty() && (unsigned char) href_value.front() <= 0x20) {
			href_value.remove_prefix(1);
		}

		while (!href_value.empty() && (unsigned char) href_value.back() <= 0x20) {
			href_value.remove_suffix(1);
		}

		/*
		 * Browsers remove tabs and line breaks anywhere in a link before
		 * they read it: `/<tab>/evil.com` is `//evil.com`, another host
		 */
		auto is_tab_or_newline = [](char c) { return c == '\t' || c == '\n' || c == '\r'; };

		if (std::any_of(href_value.begin(), href_value.end(), is_tab_or_newline)) {
			auto *buf = rspamd_mempool_alloc_buffer(pool, href_value.size());
			auto *last = std::remove_copy_if(href_value.begin(), href_value.end(), buf,
											 is_tab_or_newline);
			href_value = {buf, (std::size_t) (last - buf)};
		}

		if (!html_resolve_against_base(pool, href_value, hc)) {
			/* Image data url, never insert as url */
			return std::nullopt;
		}

		auto url = html_process_url(pool, href_value, L).value_or(nullptr);

		if (url) {
			if (tag->id != Tag_A) {
				/* Mark special tags special */
				url->flags |= RSPAMD_URL_FLAG_SPECIAL;
			}

			if (std::holds_alternative<std::monostate>(tag->extra)) {
				tag->extra = url;
			}

			return url;
		}

		return std::nullopt;
	}

	return std::nullopt;
}

struct rspamd_html_url_query_cbd {
	rspamd_mempool_t *pool;
	khash_t(rspamd_url_hash) * url_set;
	struct rspamd_url *url;
	GPtrArray *part_urls;
	uint32_t parent_flags; /* Flags from outer URL to propagate */
	unsigned int max_urls; /* Limit for url_set (0 = unlimited) */
};

static inline auto
html_part_add_url(GPtrArray *part_urls, struct rspamd_url *url) -> void
{
	if (part_urls) {
		g_ptr_array_add(part_urls, url);
	}
}

static gboolean
html_url_query_callback(struct rspamd_url *url, gsize start_offset,
						gsize end_offset, gpointer ud)
{
	struct rspamd_html_url_query_cbd *cbd =
		(struct rspamd_html_url_query_cbd *) ud;
	rspamd_mempool_t *pool;

	pool = cbd->pool;

	if (url->protocol == PROTOCOL_MAILTO) {
		if (url->userlen == 0) {
			return FALSE;
		}
	}

	msg_debug_html("found url %s in query of url"
				   " %*s",
				   url->string,
				   cbd->url->querylen, rspamd_url_query_unsafe(cbd->url));

	url->flags |= RSPAMD_URL_FLAG_QUERY;

	/* Propagate source/classification flags from the parent (outer) URL */
	url->flags |= (cbd->parent_flags & RSPAMD_URL_FLAG_PROPAGATE_MASK);

	/*
	 * Link the query URL to its parent so CTA/button weight can propagate to it
	 * (it owns no tag). Only if unset: a later PHISHED/REDIRECTED decision may
	 * override linked_url, and get_phished/get_redirected only follow it then.
	 */
	if (cbd->url) {
		if (url->ext == nullptr) {
			url->ext = rspamd_mempool_alloc0_type(pool, rspamd_url_ext);
		}
		if (url->ext->linked_url == nullptr) {
			url->ext->linked_url = cbd->url;
		}
	}

	if (rspamd_url_set_add_or_increase(cbd->url_set, url, false, cbd->max_urls)) {
		html_part_add_url(cbd->part_urls, url);
	}

	return TRUE;
}

static void
html_process_query_url(rspamd_mempool_t *pool, struct rspamd_url *url,
					   khash_t(rspamd_url_hash) * url_set,
					   GPtrArray *part_urls,
					   lua_State *L,
					   unsigned int max_urls)
{
	if (url->querylen > 0) {
		struct rspamd_html_url_query_cbd qcbd;

		qcbd.pool = pool;
		qcbd.url_set = url_set;
		qcbd.url = url;
		qcbd.part_urls = part_urls;
		qcbd.parent_flags = url->flags;
		qcbd.max_urls = max_urls;

		rspamd_url_find_in_query(pool, url, RSPAMD_URL_FIND_ALL,
								 html_url_query_callback, &qcbd, L);
	}

	html_part_add_url(part_urls, url);
}

static auto
html_process_data_image(rspamd_mempool_t *pool,
						struct html_image *img,
						std::string_view input) -> void
{
	/*
	 * Here, we do very basic processing of the data:
	 * detect if we have something like: `data:image/xxx;base64,yyyzzz==`
	 * We only parse base64 encoded data.
	 * We ignore content type so far
	 */
	struct rspamd_image *parsed_image;
	const char *semicolon_pos = input.data(),
			   *end = input.data() + input.size();

	if ((semicolon_pos = (const char *) memchr(semicolon_pos, ';', end - semicolon_pos)) != NULL) {
		if (end - semicolon_pos > sizeof("base64,")) {
			if (memcmp(semicolon_pos + 1, "base64,", sizeof("base64,") - 1) == 0) {
				const char *data_pos = semicolon_pos + sizeof("base64,");
				char *decoded;
				gsize encoded_len = end - data_pos, decoded_len;
				/* The parsed image keeps a pointer to it */
				auto *inp = rspamd_mempool_alloc_type(pool, rspamd_ftok_t);

				decoded_len = (encoded_len / 4 * 3) + 12;
				decoded = rspamd_mempool_alloc_buffer(pool, decoded_len);
				rspamd_cryptobox_base64_decode(data_pos, encoded_len,
											   reinterpret_cast<unsigned char *>(decoded), &decoded_len);
				inp->begin = decoded;
				inp->len = decoded_len;

				parsed_image = rspamd_maybe_process_image(pool, inp);

				if (parsed_image) {
					msg_debug_html("detected %s image of size %ud x %ud in data url",
								   rspamd_image_type_str(parsed_image->type),
								   parsed_image->width, parsed_image->height);
					img->embedded_image = parsed_image;
				}
			}
		}
		else {
			/* Nothing useful */
			return;
		}
	}
}

/*
 * Converts a dimension to an unsigned integer one, clamping it to the
 * range of the latter: a style value may exceed it, and casting an
 * out-of-range floating point number is undefined
 */
static inline unsigned int
html_dim_to_unsigned(double dim)
{
	if (dim >= (double) ~0u) {
		return ~0u;
	}

	return (unsigned int) dim;
}

/* Sentinel for the absence of an image dimension bound; a negative
 * maximum imposes no bound at all */
constexpr static const double no_image_bound = -1.0;

/*
 * Whether an image of the given dimensions is a tiny pixel: the area
 * is compared at float precision, as the stylesheet dimensions are
 * stored with it, so a 0.1px x 40px stylesheet size, held as
 * 0.10000000149, still counts as the exact area of 4
 */
static inline bool
html_image_is_tiny(double width, double height)
{
	return ((float) (width * height)) <= 4.0f;
}

enum html_image_dim_source {
	dim_src_none = 0,
	dim_src_attribute = 1,
	dim_src_stylesheet = 2,
	dim_src_inline = 3,
	dim_src_unknown = 4,
};

/* Whether the size of an image axis is known, i.e. has an absolute value */
static inline bool
html_image_size_known(unsigned char source)
{
	return source != dim_src_none && source != dim_src_unknown;
}

/*
 * Applies the inline style of an image, parsed on its own, to the image:
 * a valid width or height declaration overrides the attribute one, and
 * the size stays unknown unless it has an absolute value. The minimums
 * and the maximum bounds are stored as they are, as the stylesheet may
 * still override them. The axes are indexed the way the `*_source` bit
 * masks of the image are: height is the lowest bit, width the next one
 */
static void
html_image_apply_inline_style(struct html_image *img,
							  const html_block &style)
{
	struct axis {
		unsigned int *size;
		double *exact;
		unsigned char *source;
		bool size_set;
		bool size_important;
		float real, real_raw;
		unsigned char min_mask, max_mask;
		bool min_important, max_important;
		float min_value, max_value;
		double *min_out, *max_out;
	};

	const axis axes[2] = {
		{&img->height, &img->height_exact, &img->height_source,
		 style.height_real_mask != 0, style.height_important,
		 style.height_real, style.height_real_raw,
		 (unsigned char) style.min_height_mask,
		 (unsigned char) style.height_max_mask,
		 style.min_height_important, style.max_height_important,
		 style.min_height, style.height_max,
		 &img->min_height, &img->max_height},
		{&img->width, &img->width_exact, &img->width_source,
		 style.width_real_mask != 0, style.width_important,
		 style.width_real, style.width_real_raw,
		 (unsigned char) style.min_width_mask,
		 (unsigned char) style.width_max_mask,
		 style.min_width_important, style.max_width_important,
		 style.min_width, style.width_max,
		 &img->min_width, &img->max_width},
	};

	img->min_height = img->min_width = 0;
	img->max_height = img->max_width = no_image_bound;

	for (auto i = 0; i < 2; i++) {
		const auto &a = axes[i];

		if (a.size_set) {
			*a.source = dim_src_unknown;

			if (a.size_important) {
				img->inline_important |= 1u << i;
			}

			if (a.real >= 0) {
				/* The integer size is rounded up, so a fractional size
				 * is never taken for a zero one */
				*a.size = html_dim_to_unsigned(ceilf(a.real));
				*a.exact = a.real;
				*a.source = dim_src_inline;
			}
			else if (*a.size == 0 && a.real_raw > 0) {
				/* A percent size cannot be resolved, but its number is
				 * still the size reported to Lua when the image has no
				 * attribute one */
				*a.size = html_dim_to_unsigned(ceilf(a.real_raw));
				*a.exact = ceilf(a.real_raw);
			}
		}

		/* A mask of 2 is a valid but unresolvable value: `none`, `auto`,
		 * a percent or a function removes a maximum, and a minimum, which
		 * may raise the size, makes it unknown */
		if (a.min_mask) {
			img->min_source |= 1u << i;

			if (a.min_mask == 1) {
				*a.min_out = a.min_value;
			}
			else {
				img->min_source |= 1u << (i + 2);
			}

			if (a.min_important) {
				img->min_source |= 1u << (i + 4);
			}
		}

		if (a.max_mask) {
			img->max_source |= 1u << i;

			if (a.max_mask == 1) {
				*a.max_out = a.max_value;
			}

			if (a.max_important) {
				img->max_source |= 1u << (i + 2);
			}
		}
	}
}

static void
html_process_img_tag(rspamd_mempool_t *pool,
					 struct html_tag *tag,
					 struct html_content *hc,
					 khash_t(rspamd_url_hash) * url_set,
					 GPtrArray *part_urls,
					 lua_State *L,
					 unsigned int max_urls)
{
	struct html_image *img;

	img = rspamd_mempool_alloc0_type(pool, struct html_image);
	img->tag = tag;

	// Process SRC component (preferred for img tags) or HREF component (fallback)
	std::optional<std::string_view> href_value;

	// Try SRC first (standard for img tags)
	if (auto src_comp = tag->find_component<html_component_src>()) {
		href_value = src_comp.value()->value;
	}
	// Fallback to HREF (for backward compatibility or non-standard usage)
	else if (auto href_comp = tag->find_href()) {
		href_value = href_comp;
	}

	/* Browsers strip C0 controls and spaces around a link before they resolve it */
	while (href_value && !href_value->empty() && (unsigned char) href_value->front() <= 0x20) {
		href_value->remove_prefix(1);
	}

	while (href_value && !href_value->empty() && (unsigned char) href_value->back() <= 0x20) {
		href_value->remove_suffix(1);
	}

	if (href_value && href_value->size() > 0) {
		rspamd_ftok_t fstr;
		fstr.begin = href_value->data();
		fstr.len = href_value->size();
		img->src = rspamd_mempool_ftokdup(pool, &fstr);

		if (href_value->size() > sizeof("cid:") - 1 && g_ascii_strncasecmp(href_value->data(),
																		   "cid:", sizeof("cid:") - 1) == 0) {
			/* We have an embedded image */
			img->src += sizeof("cid:") - 1;
			img->flags |= RSPAMD_HTML_FLAG_IMAGE_EMBEDDED;
		}
		else {
			if (href_value->size() > sizeof("data:") - 1 && g_ascii_strncasecmp(href_value->data(),
																				"data:", sizeof("data:") - 1) == 0) {
				/* We have an embedded image in HTML tag */
				img->flags |=
					(RSPAMD_HTML_FLAG_IMAGE_EMBEDDED | RSPAMD_HTML_FLAG_IMAGE_DATA);
				html_process_data_image(pool, img, *href_value);
				hc->flags |= RSPAMD_HTML_FLAG_HAS_DATA_URLS;
			}
			else {
				if (img->src) {

					std::string_view cpy{*href_value};
					html_resolve_against_base(pool, cpy, hc);
					auto maybe_url = html_process_url(pool, cpy, L);

					if (maybe_url) {
						/* A source that did not resolve to a URL,
						 * such as a same-document fragment, is not
						 * an external image */
						img->flags |= RSPAMD_HTML_FLAG_IMAGE_EXTERNAL;
						img->url = maybe_url.value();

						img->url->flags |= RSPAMD_URL_FLAG_IMAGE;

						if (url_set != NULL) {
							struct rspamd_url *existing;

							existing = rspamd_url_set_add_or_return(url_set,
																	img->url, max_urls);

							if (existing == nullptr) {
								/* Too many urls in the set; do not track this one */
								rspamd_url_note_limit_reached(pool);
							}
							else if (existing != img->url) {
								/*
								 * The url is already known, e.g. as a link or
								 * found in another part. The image flag means
								 * that the url is seen only as an image source,
								 * so it is not added to a known url
								 */
								existing->flags |= img->url->flags & ~RSPAMD_URL_FLAG_IMAGE;
								existing->count++;
							}
							else {
								html_part_add_url(part_urls, img->url);
							}
						}
						else {
							html_part_add_url(part_urls, img->url);
						}
					}
				}
			}
		}
	}

	// Process numeric dimensions using the new helper methods
	if (auto height = tag->find_height()) {
		img->height = height.value();
		img->height_exact = height.value();
		img->height_source = dim_src_attribute;
	}

	if (auto width = tag->find_width()) {
		img->width = width.value();
		img->width_exact = width.value();
		img->width_source = dim_src_attribute;
	}

	/* The inline style overrides the attribute dimensions, and carries the
	 * bounds and minimums that are applied after the stylesheet
	 * reconciliation */
	if (auto style_value = tag->find_style()) {
		if (auto *inline_block = css::parse_css_declaration(pool, *style_value)) {
			html_image_apply_inline_style(img, *inline_block);
		}
	}

	if (img->embedded_image) {
		if (img->height == 0) {
			img->height = img->embedded_image->height;
			img->height_exact = img->embedded_image->height;
		}
		if (img->width == 0) {
			img->width = img->embedded_image->width;
			img->width_exact = img->embedded_image->width;
		}
	}

	hc->images.push_back(img);

	/* Update image-related features */
	hc->features.images_total++;
	if (img->flags & RSPAMD_HTML_FLAG_IMAGE_DATA) {
		hc->features.images_data++;
	}
	if (img->flags & RSPAMD_HTML_FLAG_IMAGE_EXTERNAL) {
		hc->features.images_external++;
		/* tiny external pixel tracking; explicitly zero-sized images
		 * are also invisible, so they are counted as tiny as well */
		if (html_image_size_known(img->width_source) &&
			html_image_size_known(img->height_source) &&
			html_image_is_tiny(img->width_exact, img->height_exact)) {
			hc->features.images_tiny_external++;
		}
	}

	if (std::holds_alternative<std::monostate>(tag->extra)) {
		tag->extra = img;
	}
}

static auto
html_process_link_tag(rspamd_mempool_t *pool, struct html_tag *tag,
					  struct html_content *hc,
					  khash_t(rspamd_url_hash) * url_set,
					  GPtrArray *part_urls,
					  lua_State *L,
					  unsigned int max_urls) -> void
{
	auto found_rel_maybe = tag->find_rel();

	if (found_rel_maybe) {
		if (found_rel_maybe.value() == "icon") {
			html_process_img_tag(pool, tag, hc, url_set, part_urls, L, max_urls);
		}
	}
}

/*
 * Value of the legacy color and bgcolor attributes: browsers ignore
 * surrounding whitespace and case, and take 3 or 6 hex digits without `#`.
 * Other garbage is not recognised
 */
static auto
html_legacy_color_value(std::string_view input) -> std::optional<css::css_value>
{
	auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'; };

	while (!input.empty() && is_ws(input.front())) {
		input.remove_prefix(1);
	}
	while (!input.empty() && is_ws(input.back())) {
		input.remove_suffix(1);
	}

	if (input.empty() || input.size() > 32) {
		return std::nullopt;
	}

	char lowered[32];

	for (std::size_t i = 0; i < input.size(); i++) {
		lowered[i] = g_ascii_tolower(input[i]);
	}

	std::string_view name{lowered, input.size()};

	if (name.front() != '#' && (name.size() == 3 || name.size() == 6) &&
		std::all_of(name.begin(), name.end(), [](char c) { return g_ascii_isxdigit(c); })) {
		if (name.size() == 3) {
			/*
			 * Only `#abc` is the short form of `#aabbcc`. Without the sharp
			 * the legacy rules read each digit as a component of its own:
			 * `fff` is the dark #0f0f0f, not white
			 */
			const char wide[6] = {'0', name[0], '0', name[1], '0', name[2]};

			return css::css_value::maybe_color_from_hex(std::string_view{wide, sizeof(wide)});
		}

		return css::css_value::maybe_color_from_hex(name);
	}

	return css::css_value::maybe_color_from_string(name);
}

static auto
html_process_block_tag(rspamd_mempool_t *pool, struct html_tag *tag,
					   struct html_content *hc,
					   struct html_block **spare_block = nullptr) -> void
{
	std::optional<css::css_value> maybe_fgcolor, maybe_bgcolor;
	bool hidden = false;

	// Process color components
	if (auto color_comp = tag->find_component<html_component_color>()) {
		maybe_fgcolor = html_legacy_color_value(color_comp.value()->value);
	}

	if (auto bgcolor_comp = tag->find_component<html_component_bgcolor>()) {
		maybe_bgcolor = html_legacy_color_value(bgcolor_comp.value()->value);
	}

	// Process style component
	if (auto style_value = tag->find_style()) {
		tag->block = rspamd::css::parse_css_declaration(pool, *style_value);
	}

	// Check if hidden
	hidden = tag->is_hidden();

	if (!tag->block) {
		if (spare_block && *spare_block) {
			/* The block of a removed element, see html_fold_empty_element */
			tag->block = *spare_block;
			*spare_block = nullptr;
			memset(tag->block, 0, sizeof(html_block));
		}
		else {
			tag->block = html_block::undefined_html_block_pool(pool);
		}
	}

	/*
	 * The attributes are presentational hints: they apply only where no
	 * author declaration (inline or from a stylesheet) sets the property,
	 * and a stylesheet block merged later replaces them
	 */
	if (hidden && tag->block->display_mask < html_block::hint) {
		tag->block->set_display(false, html_block::hint);
	}

	if (maybe_fgcolor && tag->block->fg_color_mask < html_block::hint) {
		tag->block->set_fgcolor(maybe_fgcolor->to_color().value(), html_block::hint);
	}

	if (maybe_bgcolor && tag->block->bg_color_mask < html_block::hint) {
		tag->block->set_bgcolor(maybe_bgcolor->to_color().value(), html_block::hint);
	}

	/*
	 * Off-screen positioning / clipping is detected while compiling the
	 * inline style into the block (position+left/top, text-indent, clip).
	 * Count it here, per tag with its own style, before children inherit
	 * a copy of the block
	 */
	if (tag->block->offscreen) {
		hc->features.offscreen_blocks++;
	}
}

static inline auto
html_append_parsed(struct html_content *hc,
				   std::string_view data,
				   bool transparent,
				   std::size_t input_len,
				   std::string &dest,
				   bool literal = false) -> std::size_t
{
	auto cur_offset = dest.size();

	/*
	 * Text never grows over its source but for a NUL, which becomes a three
	 * byte replacement character: anything over that is refused
	 */
	if (dest.size() / 3 > input_len) {
		return 0;
	}

	if (data.size() > 0) {
		/* Handle multiple spaces at the begin */

		if (cur_offset > 0) {
			auto last = dest.back();
			if (!g_ascii_isspace(last) && g_ascii_isspace(data.front())) {
				dest.append(" ");
				data = {data.data() + 1, data.size() - 1};
				cur_offset++;
			}
		}

		if (data.find('\0') != std::string_view::npos) {
			auto replace_zero_func = [](const auto &input, auto &output) {
				const auto last = input.cend();
				for (auto it = input.cbegin(); it != last; ++it) {
					if (*it == '\0') {
						output.append((const char *) u8"\uFFFD");
					}
					else {
						output.push_back(*it);
					}
				}
			};

			/* No reserve to the exact size: it would reallocate for each piece */
			replace_zero_func(data, dest);
			hc->flags |= RSPAMD_HTML_FLAG_HAS_ZEROS;
		}
		else {
			dest.append(data);
		}
	}

	auto nlen = dest.size() - cur_offset;

	if (!literal) {
		nlen = decode_html_entitles_inplace(dest.data() + cur_offset, nlen, true);
		dest.resize(nlen + cur_offset);
	}

	if (transparent) {
		/* Replace all visible characters with spaces */
		auto start = std::next(dest.begin(), cur_offset);
		std::replace_if(
			start, std::end(dest), [](const auto c) {
				return !g_ascii_isspace(c);
			},
			' ');
		/* Accumulate transparent text bytes */
		hc->features.text_transparent += (unsigned int) nlen;
		hc->features.blocks_transparent++;
	}
	else {
		/* Visible or hidden text accounted outside; keep helper here for visible path */
		if (&dest == &hc->parsed) {
			/* Visible text */
			hc->features.text_visible += (unsigned int) nlen;
		}
		else if (&dest == &hc->invisible) {
			/* Hidden text */
			hc->features.text_hidden += (unsigned int) nlen;
			hc->features.blocks_hidden++;
		}
	}

	return nlen;
}

static auto
html_process_displayed_href_tag(rspamd_mempool_t *pool,
								struct html_content *hc,
								std::string_view data,
								const struct html_tag *cur_tag,
								GList **exceptions,
								khash_t(rspamd_url_hash) * url_set,
								goffset dest_offset,
								lua_State *L,
								unsigned int max_urls) -> void
{

	if (std::holds_alternative<rspamd_url *>(cur_tag->extra)) {
		auto *url = std::get<rspamd_url *>(cur_tag->extra);

		html_check_displayed_url(pool,
								 exceptions, url_set,
								 data,
								 dest_offset,
								 url, L, max_urls);
	}
}

static auto
html_append_tag_content(rspamd_mempool_t *pool,
						const char *start, gsize len,
						struct html_content *hc,
						html_tag *tag,
						GList **exceptions,
						khash_t(rspamd_url_hash) * url_set,
						lua_State *L,
						unsigned int max_urls) -> goffset
{
	struct append_frame {
		html_tag *tag;
		std::size_t next_child = 0;
		goffset next_tag_offset = 0;
		goffset initial_parsed_offset = 0;
		goffset initial_invisible_offset = 0;
		goffset cur_offset = 0;
		std::size_t first_visible_offset = std::string::npos;
		std::size_t scanned_parsed_offset = 0;
		bool entered = false;
		bool finished = false;
		bool is_visible = true;
		bool is_block = false;
		bool is_spaces = false;
		bool is_transparent = false;
	};

	/* Scan each appended segment once; parents inherit the child's result. */
	auto scan_visible_content = [hc](append_frame &frame) -> void {
		if (frame.first_visible_offset == std::string::npos &&
			frame.scanned_parsed_offset < hc->parsed.size()) {
			auto sz = hc->parsed.size() - frame.scanned_parsed_offset;
			auto *trimmed = rspamd_string_unicode_trim_inplace(
				hc->parsed.data() + frame.scanned_parsed_offset, &sz);
			if (sz > 0) {
				frame.first_visible_offset = trimmed - hc->parsed.data();
			}
		}
		frame.scanned_parsed_offset = hc->parsed.size();
	};

	auto calculate_final_tag_offsets = [hc](append_frame &frame) -> void {
		/*
		 * Record which buffer the offsets refer to: html_tag::get_content must
		 * read the same one, and the visibility of the block alone cannot tell,
		 * as transparent text is written to the visible buffer as spaces
		 */
		if (frame.is_visible) {
			frame.tag->content_offset = frame.initial_parsed_offset;
			frame.tag->closing.start = hc->parsed.size();
			frame.tag->flags &= ~FL_CONTENT_INVISIBLE;
		}
		else {
			frame.tag->content_offset = frame.initial_invisible_offset;
			frame.tag->closing.start = hc->invisible.size();
			frame.tag->flags |= FL_CONTENT_INVISIBLE;
		}
	};

	auto append_margin = [hc](append_frame &frame, char margin) -> void {
		if (frame.is_visible && !hc->parsed.empty() &&
			hc->parsed.back() != margin && hc->parsed.back() != '\n') {
			if (hc->parsed.back() == ' ') {
				auto last = std::make_reverse_iterator(
					hc->parsed.begin() + frame.initial_parsed_offset);
				auto first = std::find_if(hc->parsed.rbegin(), last,
										  [](auto ch) -> auto {
											  return ch != ' ';
										  });
				hc->parsed.erase(first.base(), hc->parsed.end());
				g_assert(hc->parsed.size() >= frame.initial_parsed_offset);
			}
			hc->parsed.push_back(margin);
		}
	};

	auto enter_frame = [&](append_frame &frame) -> void {
		auto *cur = frame.tag;
		frame.next_tag_offset = cur->closing.end;
		frame.initial_parsed_offset = hc->parsed.size();
		frame.initial_invisible_offset = hc->invisible.size();
		frame.scanned_parsed_offset = hc->parsed.size();

		if (cur->closing.end == -1) {
			if (cur->closing.start != -1) {
				frame.next_tag_offset = cur->closing.start;
				cur->closing.end = cur->closing.start;
			}
			else {
				frame.next_tag_offset = cur->content_offset;
				cur->closing.end = cur->content_offset;
			}
		}
		if (cur->closing.start == -1) {
			cur->closing.start = cur->closing.end;
		}

		if (cur->id == Tag_BR || cur->id == Tag_HR) {
			if (!(cur->flags & FL_IGNORE)) {
				hc->parsed.append("\n");
			}
			frame.next_tag_offset = cur->content_offset;
			calculate_final_tag_offsets(frame);
			frame.finished = true;
			frame.entered = true;
			return;
		}
		if ((cur->id == Tag_HEAD && (cur->flags & FL_IGNORE)) ||
			(cur->flags & CM_HEAD)) {
			frame.next_tag_offset = cur->closing.end;
			calculate_final_tag_offsets(frame);
			frame.finished = true;
			frame.entered = true;
			return;
		}

		if ((cur->flags & (FL_COMMENT | FL_XML | FL_IGNORE | CM_HEAD))) {
			frame.is_visible = false;
		}
		else if (cur->block && !cur->block->is_visible()) {
			if (!cur->block->is_transparent() ||
				(cur->block->has_display() &&
				 cur->block->display == css::css_display_value::DISPLAY_HIDDEN)) {
				frame.is_visible = false;
			}
			else {
				frame.is_transparent = true;
			}
		}
		else if (cur->block) {
			if (cur->block->display == css::css_display_value::DISPLAY_BLOCK) {
				frame.is_block = true;
			}
			else if (cur->block->display == css::css_display_value::DISPLAY_TABLE_ROW) {
				frame.is_spaces = true;
			}
		}

		if (frame.is_block) {
			append_margin(frame, '\n');
		}
		else if (frame.is_spaces) {
			append_margin(frame, ' ');
		}

		frame.cur_offset = cur->content_offset;
		frame.entered = true;
	};

	auto finish_frame = [&](append_frame &frame) -> void {
		auto *cur = frame.tag;

		if (frame.cur_offset < cur->closing.start) {
			goffset final_part_len = cur->closing.start - frame.cur_offset;

			if (final_part_len > 0) {
				auto &dest = frame.is_visible ? hc->parsed : hc->invisible;
				html_append_parsed(hc,
								   {start + frame.cur_offset, std::size_t(final_part_len)},
								   frame.is_transparent, len, dest,
								   (cur->flags & FL_LITERAL_TEXT) != 0);
			}
		}

		if (frame.is_block) {
			append_margin(frame, '\n');
		}
		else if (frame.is_spaces) {
			append_margin(frame, ' ');
		}

		if (frame.is_visible) {
			if (cur->id == Tag_A) {
				scan_visible_content(frame);
				auto visible_offset = frame.first_visible_offset == std::string::npos
										  ? hc->parsed.size()
										  : frame.first_visible_offset;
				auto written_len = hc->parsed.size() - visible_offset;
				html_process_displayed_href_tag(
					pool, hc,
					{hc->parsed.data() + visible_offset,
					 std::size_t(written_len)},
					cur, exceptions, url_set, visible_offset, L,
					max_urls);

				if (std::holds_alternative<rspamd_url *>(cur->extra)) {
					auto *u = std::get<rspamd_url *>(cur->extra);
					if (u && (u->flags & RSPAMD_URL_FLAG_DISPLAY_URL) &&
						(u->flags & RSPAMD_URL_FLAG_HTML_DISPLAYED) &&
						u->ext && u->ext->linked_url && u->ext->linked_url != u) {
						hc->features.links.display_mismatch_links++;
					}
				}
			}
			else if (cur->id == Tag_IMG) {
				auto maybe_alt = cur->find_alt();

				if (maybe_alt) {
					if (!hc->parsed.empty() && !g_ascii_isspace(hc->parsed.back())) {
						hc->parsed += ' ';
					}

					hc->parsed.append(maybe_alt.value());

					if (!hc->parsed.empty() && !g_ascii_isspace(hc->parsed.back())) {
						hc->parsed += ' ';
					}
				}
			}
		}
		else if (std::holds_alternative<rspamd_url *>(cur->extra)) {
			auto *url_enclosed = std::get<rspamd_url *>(cur->extra);

			if (url_enclosed) {
				url_enclosed->flags |= RSPAMD_URL_FLAG_INVISIBLE;
			}
		}

		scan_visible_content(frame);
		calculate_final_tag_offsets(frame);
	};

	std::vector<append_frame> stack;
	stack.reserve(128);
	stack.push_back({tag});
	goffset result = tag->closing.end;

	while (!stack.empty()) {
		auto &frame = stack.back();

		if (!frame.entered) {
			enter_frame(frame);
		}

		if (!frame.finished && frame.next_child < frame.tag->children.size()) {
			auto *child = frame.tag->children[frame.next_child++];
			goffset initial_part_len = child->tag_start - frame.cur_offset;

			if (initial_part_len > 0) {
				auto &dest = frame.is_visible ? hc->parsed : hc->invisible;
				html_append_parsed(hc,
								   {start + frame.cur_offset, std::size_t(initial_part_len)},
								   frame.is_transparent, len, dest,
								   (frame.tag->flags & FL_LITERAL_TEXT) != 0);
			}

			scan_visible_content(frame);
			stack.push_back({child});
			continue;
		}

		if (!frame.finished) {
			finish_frame(frame);
		}

		result = frame.next_tag_offset;
		auto first_visible_offset = frame.first_visible_offset;
		stack.pop_back();

		if (!stack.empty()) {
			auto &parent = stack.back();
			if (result > parent.cur_offset) {
				parent.cur_offset = result;
			}
			if (parent.first_visible_offset == std::string::npos) {
				parent.first_visible_offset = first_visible_offset;
			}
			parent.scanned_parsed_offset = hc->parsed.size();
		}
	}

	return result;
}

/*
 * Table layout sizes a table and its parts by their content: `width` and
 * `height` there are only lower bounds (CSS 2.1 17.5.2 and 17.5.3), so the
 * enclosing box does not constrain them, and a zero width on a table does
 * not clip its cells
 */
static inline auto
html_tag_bounded_by_parent(const html_tag *tag) -> bool
{
	return tag->id != Tag_TABLE && !(tag->flags & (CM_TABLE | CM_ROW));
}

/* The innermost open element, the one that new markup goes into */
static auto
html_current_node(html_tag *tag) -> html_tag *
{
	while (tag && (tag->flags & FL_CLOSED)) {
		tag = tag->parent;
	}

	return tag;
}

static auto
html_is_mathml_text_integration_point(const html_tag *tag) -> bool
{
	static const std::int32_t ids[] = {
		html_unknown_tag_id("mi"),
		html_unknown_tag_id("mo"),
		html_unknown_tag_id("mn"),
		html_unknown_tag_id("ms"),
		html_unknown_tag_id("mtext"),
	};

	return (tag->flags & FL_MATHML) &&
		   std::find(std::begin(ids), std::end(ids), tag->id) != std::end(ids);
}

static auto
html_is_html_integration_point(const html_tag *tag) -> bool
{
	static const auto foreign_object_id = html_unknown_tag_id("foreignobject");
	static const auto desc_id = html_unknown_tag_id("desc");
	static const auto annotation_xml_id = html_unknown_tag_id("annotation-xml");

	if (tag->flags & FL_SVG) {
		return tag->id == foreign_object_id || tag->id == desc_id || tag->id == Tag_TITLE;
	}

	if ((tag->flags & FL_MATHML) && tag->id == annotation_xml_id) {
		auto encoding = tag->find_component_by_name("encoding");

		return encoding &&
			   ((encoding->size() == sizeof("text/html") - 1 &&
				 g_ascii_strncasecmp(encoding->data(), "text/html", encoding->size()) == 0) ||
				(encoding->size() == sizeof("application/xhtml+xml") - 1 &&
				 g_ascii_strncasecmp(encoding->data(), "application/xhtml+xml", encoding->size()) == 0));
	}

	return false;
}

/*
 * HTML elements that browsers do not nest in SVG/MathML: they close the
 * SVG/MathML elements and go into the HTML element around them
 */
static auto
html_is_breakout_tag(const html_tag *tag) -> bool
{
	switch (tag->id) {
	case Tag_B:
	case Tag_BIG:
	case Tag_BLOCKQUOTE:
	case Tag_BODY:
	case Tag_BR:
	case Tag_CENTER:
	case Tag_CODE:
	case Tag_DD:
	case Tag_DIV:
	case Tag_DL:
	case Tag_DT:
	case Tag_EM:
	case Tag_EMBED:
	case Tag_H1:
	case Tag_H2:
	case Tag_H3:
	case Tag_H4:
	case Tag_H5:
	case Tag_H6:
	case Tag_HEAD:
	case Tag_HR:
	case Tag_I:
	case Tag_IMG:
	case Tag_LI:
	case Tag_LISTING:
	case Tag_MENU:
	case Tag_META:
	case Tag_NOBR:
	case Tag_OL:
	case Tag_P:
	case Tag_PRE:
	case Tag_RUBY:
	case Tag_S:
	case Tag_SMALL:
	case Tag_SPAN:
	case Tag_STRONG:
	case Tag_STRIKE:
	case Tag_SUB:
	case Tag_SUP:
	case Tag_TABLE:
	case Tag_TT:
	case Tag_U:
	case Tag_UL:
	case Tag_VAR:
		return true;
	case Tag_FONT:
		return tag->find_component_by_name("color") ||
			   tag->find_component_by_name("face") ||
			   tag->find_component_by_name("size");
	default:
		return false;
	}
}

/*
 * The namespace flags of a new element `tag` going into `node`: browsers
 * build it as HTML under HTML elements and integration points, and as an
 * element of the parent's namespace inside SVG/MathML otherwise
 */
static auto
html_start_tag_namespace(const html_tag *node, const html_tag *tag) -> unsigned int
{
	static const auto annotation_xml_id = html_unknown_tag_id("annotation-xml");
	static const auto mglyph_id = html_unknown_tag_id("mglyph");
	static const auto malignmark_id = html_unknown_tag_id("malignmark");
	auto parent_ns = node ? node->flags & FL_FOREIGN : 0u;

	if (parent_ns && !html_is_html_integration_point(node) &&
		!(html_is_mathml_text_integration_point(node) &&
		  tag->id != mglyph_id && tag->id != malignmark_id) &&
		!((node->flags & FL_MATHML) && node->id == annotation_xml_id && tag->id == Tag_SVG)) {
		return parent_ns;
	}

	if (tag->id == Tag_SVG) {
		return FL_SVG;
	}
	if (tag->id == Tag_MATH) {
		return FL_MATHML;
	}

	return 0;
}

/*
 * Close the SVG/MathML elements from `node` up to the nearest HTML element
 * or integration point, as browsers do for HTML-only tags, at `offset`.
 * Returns the element that stays current
 */
static auto
html_pop_foreign(html_tag *node, goffset offset) -> html_tag *
{
	for (node = html_current_node(node);
		 node && (node->flags & FL_FOREIGN) &&
		 !html_is_html_integration_point(node) &&
		 !html_is_mathml_text_integration_point(node);
		 node = html_current_node(node->parent)) {
		node->flags |= FL_CLOSED;
		node->closing.start = std::max(offset, (goffset) node->content_offset);
		node->closing.end = node->closing.start;
	}

	return node;
}

/*
 * Elements whose content browsers take as text up to their own end tag,
 * so markup inside them, comments included, is not parsed. `<noscript>`
 * is not one of them: mail clients run no scripts and render its content
 */
static inline auto
html_is_raw_text_tag(int id) -> bool
{
	switch (id) {
	case Tag_STYLE:
	case Tag_SCRIPT:
	case Tag_XMP:
	case Tag_IFRAME:
	case Tag_NOEMBED:
	case Tag_NOFRAMES:
	case Tag_TITLE:
	case Tag_TEXTAREA:
	case Tag_PLAINTEXT:
		return true;
	default:
		return false;
	}
}

/*
 * Scope boundaries of the HTML Standard (13.2.4.2): the elements that stop
 * the search for an open element in the insertion mode rules. Elements in
 * SVG/MathML are boundaries only as integration points
 */
static auto
html_is_foreign_scope_boundary(const html_tag *tag) -> bool
{
	static const auto annotation_xml_id = html_unknown_tag_id("annotation-xml");

	return html_is_html_integration_point(tag) ||
		   html_is_mathml_text_integration_point(tag) ||
		   ((tag->flags & FL_MATHML) && tag->id == annotation_xml_id);
}

static auto
html_is_default_scope_boundary(const html_tag *tag) -> bool
{
	static const std::int32_t marquee_id = html_unknown_tag_id("marquee");

	if (tag->flags & FL_FOREIGN) {
		return html_is_foreign_scope_boundary(tag);
	}

	switch (tag->id) {
	case Tag_APPLET:
	case Tag_CAPTION:
	case Tag_HTML:
	case Tag_TABLE:
	case Tag_TD:
	case Tag_TH:
	case Tag_OBJECT:
	case Tag_TEMPLATE:
		return true;
	default:
		return tag->id == marquee_id;
	}
}

/* The special elements but address, div and p: they stop the li/dd/dt loop */
static auto
html_is_special_scope_boundary(const html_tag *tag) -> bool
{
	static const std::int32_t marquee_id = html_unknown_tag_id("marquee");

	if (tag->flags & FL_FOREIGN) {
		return html_is_foreign_scope_boundary(tag);
	}

	switch (tag->id) {
	case Tag_ADDRESS:
	case Tag_DIV:
	case Tag_P:
		return false;
	case Tag_APPLET:
	case Tag_AREA:
	case Tag_ARTICLE:
	case Tag_ASIDE:
	case Tag_BASE:
	case Tag_BASEFONT:
	case Tag_BLOCKQUOTE:
	case Tag_BODY:
	case Tag_BR:
	case Tag_BUTTON:
	case Tag_CAPTION:
	case Tag_CENTER:
	case Tag_COL:
	case Tag_COLGROUP:
	case Tag_DD:
	case Tag_DETAILS:
	case Tag_DIR:
	case Tag_DL:
	case Tag_DT:
	case Tag_EMBED:
	case Tag_FIELDSET:
	case Tag_FIGCAPTION:
	case Tag_FIGURE:
	case Tag_FOOTER:
	case Tag_FORM:
	case Tag_FRAME:
	case Tag_FRAMESET:
	case Tag_H1:
	case Tag_H2:
	case Tag_H3:
	case Tag_H4:
	case Tag_H5:
	case Tag_H6:
	case Tag_HEAD:
	case Tag_HEADER:
	case Tag_HGROUP:
	case Tag_HR:
	case Tag_HTML:
	case Tag_IFRAME:
	case Tag_IMG:
	case Tag_INPUT:
	case Tag_KEYGEN:
	case Tag_LI:
	case Tag_LINK:
	case Tag_LISTING:
	case Tag_MAIN:
	case Tag_MENU:
	case Tag_META:
	case Tag_NAV:
	case Tag_NOEMBED:
	case Tag_NOFRAMES:
	case Tag_NOSCRIPT:
	case Tag_OBJECT:
	case Tag_OL:
	case Tag_PARAM:
	case Tag_PLAINTEXT:
	case Tag_PRE:
	case Tag_SCRIPT:
	case Tag_SECTION:
	case Tag_SELECT:
	case Tag_SOURCE:
	case Tag_STYLE:
	case Tag_SUMMARY:
	case Tag_TABLE:
	case Tag_TBODY:
	case Tag_TD:
	case Tag_TEMPLATE:
	case Tag_TEXTAREA:
	case Tag_TFOOT:
	case Tag_TH:
	case Tag_THEAD:
	case Tag_TITLE:
	case Tag_TR:
	case Tag_TRACK:
	case Tag_UL:
	case Tag_WBR:
	case Tag_XMP:
		return true;
	default:
		return tag->id == marquee_id;
	}
}

/* The scope depths of an open element, from those of its parent */
static auto
html_scope_depths_of(const html_tag *tag, const html_scope_depths &parent) -> html_scope_depths
{
	static const std::int32_t marquee_id = html_unknown_tag_id("marquee");
	auto ret = parent;
	auto depth = static_cast<std::int32_t>(tag->depth);
	auto in_html = !(tag->flags & FL_FOREIGN);

	if (html_is_default_scope_boundary(tag) || (in_html && tag->id == Tag_BUTTON)) {
		ret.button = depth;
	}

	if (html_is_special_scope_boundary(tag)) {
		ret.special = depth;
	}

	if (in_html && (tag->id == Tag_HTML || tag->id == Tag_TABLE || tag->id == Tag_TEMPLATE)) {
		ret.table = depth;
	}

	if (in_html) {
		switch (tag->id) {
		case Tag_APPLET:
		case Tag_OBJECT:
		case Tag_TEMPLATE:
		case Tag_TD:
		case Tag_TH:
		case Tag_CAPTION:
			ret.marker = depth;
			break;
		default:
			if (tag->id == marquee_id) {
				ret.marker = depth;
			}
			break;
		}
	}

	return ret;
}

/*
 * Ends the open elements that the start tag `tag` ends in browsers (the
 * "in body" and table insertion mode rules), at the start of `tag`. Elements
 * are found through the index of the open ones, and the scope depths kept for
 * the open elements tell if a boundary is in between, so the cost is constant
 * for a start tag, plus one step for each element that is closed
 */
static auto
html_close_implied_end_tags(html_content *hc,
							html_balance_state &balance,
							const html_tag *tag,
							html_tag *parent_tag) -> void
{
	if (tag->flags & (FL_FOREIGN | FL_XML | FL_COMMENT | FL_BROKEN)) {
		return;
	}

	enum class kind {
		none,
		paragraph,
		heading,
		list_item,
		definition,
		option,
		optgroup,
		row_group,
		row,
		cell,
		caption,
		anchor,
	} what = kind::none;

	switch (tag->id) {
	case Tag_ADDRESS:
	case Tag_ARTICLE:
	case Tag_ASIDE:
	case Tag_BLOCKQUOTE:
	case Tag_CENTER:
	case Tag_DETAILS:
	case Tag_DIALOG:
	case Tag_DIR:
	case Tag_DIV:
	case Tag_DL:
	case Tag_FIELDSET:
	case Tag_FIGCAPTION:
	case Tag_FIGURE:
	case Tag_FOOTER:
	case Tag_HEADER:
	case Tag_HGROUP:
	case Tag_MAIN:
	case Tag_MENU:
	case Tag_NAV:
	case Tag_OL:
	case Tag_P:
	case Tag_SECTION:
	case Tag_SUMMARY:
	case Tag_UL:
	case Tag_PRE:
	case Tag_LISTING:
	case Tag_FORM:
	case Tag_TABLE:
	case Tag_HR:
	case Tag_XMP:
		what = kind::paragraph;
		break;
	case Tag_H1:
	case Tag_H2:
	case Tag_H3:
	case Tag_H4:
	case Tag_H5:
	case Tag_H6:
		what = kind::heading;
		break;
	case Tag_LI:
		what = kind::list_item;
		break;
	case Tag_DD:
	case Tag_DT:
		what = kind::definition;
		break;
	case Tag_OPTION:
		what = kind::option;
		break;
	case Tag_OPTGROUP:
		what = kind::optgroup;
		break;
	case Tag_THEAD:
	case Tag_TBODY:
	case Tag_TFOOT:
		what = kind::row_group;
		break;
	case Tag_CAPTION:
	case Tag_COLGROUP:
		what = kind::caption;
		break;
	case Tag_TR:
		what = kind::row;
		break;
	case Tag_TD:
	case Tag_TH:
		what = kind::cell;
		break;
	case Tag_A:
		what = kind::anchor;
		break;
	default:
		return;
	}

	const auto offset = static_cast<goffset>(tag->tag_start);
	auto current = [&]() -> html_tag * {
		return html_current_node(parent_tag);
	};
	auto scopes_of = [&](const html_tag *node) -> const html_scope_depths & {
		static const html_scope_depths none{};

		return node->depth < balance.scopes.size() ? balance.scopes[node->depth] : none;
	};
	/*
	 * A paragraph, a heading or a list item that ends this way takes its
	 * open formatting elements with it, and browsers open them again in the
	 * element that follows ("reconstruct the active formatting elements"):
	 * `<p><font color=...>one<p>two` has both lines in that color, and both
	 * are hidden if the font is. Parts of a table do not carry them over
	 */
	const auto keep_formatting = what == kind::paragraph || what == kind::heading ||
								 what == kind::list_item || what == kind::definition;
	/* Ends the open elements from the current one up to `target` */
	auto close_through = [&](html_tag *target) -> void {
		const auto mark = balance.active_formatting.size();

		for (auto *it = current(); it != nullptr; it = it->parent) {
			if (!(it->flags & FL_CLOSED)) {
				it->flags |= FL_CLOSED;
				it->closing.start = std::max(offset, static_cast<goffset>(it->content_offset));
				it->closing.end = it->closing.start;

				if (keep_formatting && it != target && !(it->flags & FL_FOREIGN) &&
					html_balance_state::is_formatting(it->id)) {
					balance.active_formatting.push_back(it);
					balance.active_formatting_idx = 0;
				}
			}

			if (it == target) {
				break;
			}
		}

		/* They were met from the innermost one, and are kept from the outermost */
		std::reverse(balance.active_formatting.begin() + mark, balance.active_formatting.end());

		if (balance.active_formatting.size() > html_balance_state::max_active_formatting) {
			balance.active_formatting.erase(balance.active_formatting.begin(),
											balance.active_formatting.end() -
												html_balance_state::max_active_formatting);
		}
	};
	/* An open element of the id between the current one and the boundary */
	auto find_open = [&](std::int32_t id, std::int32_t boundary, const html_tag *node) -> html_tag * {
		auto *found = balance.innermost_open(*hc, id, tag);

		if (found && !(found->flags & FL_FOREIGN) &&
			static_cast<std::int32_t>(found->depth) >= boundary &&
			found->depth <= node->depth) {
			return found;
		}

		return nullptr;
	};
	auto close_paragraph = [&]() -> void {
		if (auto *node = current()) {
			if (auto *p = find_open(Tag_P, scopes_of(node).button, node)) {
				close_through(p);
			}
		}
	};
	auto close_current_if = [&](auto pred) -> void {
		if (auto *node = current()) {
			if (!(node->flags & FL_FOREIGN) && pred(node->id)) {
				close_through(node);
			}
		}
	};
	/* Table parts end all those of the same or a lower level, up to the table */
	auto close_table_parts = [&](int level) -> void {
		struct part {
			std::int32_t id;
			int level;
		};
		static const part parts[] = {
			{Tag_TBODY, 1},
			{Tag_THEAD, 1},
			{Tag_TFOOT, 1},
			{Tag_TR, 2},
			{Tag_TD, 3},
			{Tag_TH, 3},
			{Tag_CAPTION, 4},
			{Tag_COLGROUP, 4}};
		auto *node = current();

		if (!node) {
			return;
		}

		html_tag *outermost = nullptr;

		for (const auto &pt: parts) {
			if (pt.level >= level) {
				auto *found = find_open(pt.id, scopes_of(node).table, node);

				if (found && (outermost == nullptr || found->depth < outermost->depth)) {
					outermost = found;
				}
			}
		}

		if (outermost) {
			close_through(outermost);
		}
	};

	switch (what) {
	case kind::paragraph:
		close_paragraph();
		break;
	case kind::heading:
		close_paragraph();
		close_current_if([](auto id) { return id >= Tag_H1 && id <= Tag_H6; });
		break;
	case kind::list_item:
	case kind::definition: {
		if (auto *node = current()) {
			auto boundary = scopes_of(node).special;
			html_tag *found = nullptr;

			if (what == kind::list_item) {
				found = find_open(Tag_LI, boundary, node);
			}
			else {
				auto *dd = find_open(Tag_DD, boundary, node);
				auto *dt = find_open(Tag_DT, boundary, node);

				found = dd && dt ? (dd->depth > dt->depth ? dd : dt) : (dd ? dd : dt);
			}

			if (found) {
				close_through(found);
			}
		}

		close_paragraph();
		break;
	}
	case kind::option:
		close_current_if([](auto id) { return id == Tag_OPTION; });
		break;
	case kind::optgroup:
		close_current_if([](auto id) { return id == Tag_OPTION; });
		close_current_if([](auto id) { return id == Tag_OPTGROUP; });
		break;
	case kind::row_group:
	case kind::caption:
		close_table_parts(1);
		break;
	case kind::row:
		close_table_parts(2);
		break;
	case kind::cell:
		close_table_parts(3);
		break;
	case kind::anchor:
		if (auto *node = current()) {
			if (auto *a = find_open(Tag_A, scopes_of(node).marker, node)) {
				close_through(a);
			}
		}
		break;
	case kind::none:
		break;
	}
}

/*
 * Whether `in` starts with the end tag of a raw text element: `</` and its
 * name in any case, followed by a character that ends a tag name
 */
static auto
html_is_raw_text_end_tag(std::string_view in, int raw_tag_id) -> bool
{
	if (raw_tag_id == Tag_PLAINTEXT) {
		/* Nothing ends plaintext */
		return false;
	}

	auto name = html_tags_defs.name_by_id_safe(raw_tag_id);

	if (in.size() <= name.size() + 2 || in[0] != '<' || in[1] != '/' ||
		g_ascii_strncasecmp(in.data() + 2, name.data(), name.size()) != 0) {
		return false;
	}

	switch (in[name.size() + 2]) {
	case '\t':
	case '\n':
	case '\f':
	case '\r':
	case ' ':
	case '/':
	case '>':
		return true;
	default:
		return false;
	}
}

auto html_process_input(struct rspamd_task *task,
						GByteArray *in,
						GList **exceptions,
						khash_t(rspamd_url_hash) * url_set,
						GPtrArray *part_urls,
						bool allow_css,
						std::uint16_t *cur_url_order) -> html_content *
{
	const char *p, *c, *end, *start;
	unsigned char t;
	auto closing = false;
	unsigned int ebrace = 0;
	/* Tag whose end tag finishes the current raw text, Tag_UNKNOWN for none */
	int raw_text_tag_id = Tag_UNKNOWN;
	/* The declaration being parsed opens a CDATA section */
	auto cdata_section = false;
	struct rspamd_url *url = nullptr;
	int href_offset = -1;
	auto overflow_input = false;
	struct html_tag *cur_tag = nullptr, *parent_tag = nullptr, cur_closing_tag;
	struct tag_content_parser_state content_parser_env;
	html_balance_state balance;
	/* The block of a folded element, for the next element without attributes */
	struct html_block *spare_block = nullptr;
	/*
	 * A comment over the budget of comments is not a tag: it extends the
	 * comment before it (merge_target), as the text between them is only
	 * whitespace. `special_scratch` stands for it while it is read
	 */
	struct html_tag special_scratch;
	struct html_tag *merge_target = nullptr, *merge_saved_cur = nullptr;
	/*
	 * Result of the last quote lookahead for `>` inside a quoted attribute:
	 * the position of the next such quote or `end` if there is none. It stays
	 * valid until the parser passes it, so repeated `>` characters do not
	 * rescan the rest of the input each time
	 */
	const char *next_quote = nullptr;
	char next_quote_char = 0;
	auto process_size = in->len;


	enum {
		parse_start = 0,
		content_before_start,
		tag_begin,
		sgml_tag,
		xml_tag,
		comment_tag,
		comment_content,
		sgml_content,
		tag_content,
		tag_end_opening,
		tag_end_closing,
		html_text_content,
		xml_tag_end,
		tag_raw_text,
		cdata_content,
		tags_limit_overflow,
	} state = parse_start;

	enum class html_document_state {
		doctype,
		head,
		body
	} html_document_state = html_document_state::doctype;

	g_assert(in != NULL);
	g_assert(task != NULL);

	auto *pool = task->task_pool;
	auto cur_url_part_order = 0u;
	const unsigned int max_urls = task->cfg ? task->cfg->max_urls : 0;

	auto *hc = new html_content;
	rspamd_mempool_add_destructor(task->task_pool, html_content::html_content_dtor, hc);

	/* Derive first-party eTLD+1 from From: if present (task->message can be NULL) */
	{
		auto *from_mime = MESSAGE_FIELD_CHECK(task, from_mime);
		if (from_mime && from_mime->len > 0) {
			struct rspamd_email_address *addr = (struct rspamd_email_address *) g_ptr_array_index(from_mime, 0);
			if (addr && addr->domain && addr->domain_len > 0) {
				rspamd_ftok_t tld;
				if (rspamd_url_find_tld(addr->domain, addr->domain_len, &tld)) {
					/* eTLD+1: take the last label before tld and the tld */
					const char *dom = addr->domain;
					const char *dom_end = addr->domain + addr->domain_len;
					const char *tld_begin = tld.begin;
					/* Find start of the registrable part */
					const char *p = tld_begin;
					while (p > dom && *(p - 1) != '.') {
						p--;
					}
					hc->first_party_etld1.assign(p, dom_end - p);
				}
			}
		}
	}

	if (task->cfg && in->len > task->cfg->max_html_len) {
		msg_notice_task("html input is too big: %ud, limit is %z",
						in->len,
						task->cfg->max_html_len);
		process_size = task->cfg->max_html_len;
		overflow_input = true;
	}

	auto new_tag = [&](int flags = 0) -> struct html_tag * {
		auto *ntag = html_tag_alloc(hc, flags);

		if (ntag == nullptr) {
			return nullptr;
		}

		ntag->tag_start = c - start;

		if (cur_tag && !(cur_tag->flags & (CM_EMPTY | FL_CLOSED)) && cur_tag != &cur_closing_tag) {
			parent_tag = cur_tag;
		}

		return ntag;
	};

	/*
	 * Starts a comment, a declaration, a processing instruction or a bogus
	 * comment. Over their budget it is not given a tag: it is read into
	 * `special_scratch` and joins the comment that ends where the whitespace
	 * before it begins. If there is no such comment (text stands between), the
	 * rest is read without tags, as at the tags limit
	 */
	auto start_special_tag = [&](decltype(state) next_state) -> void {
		if (auto *ntag = new_tag(FL_XML | FL_CLOSED)) {
			cur_tag = ntag;
			state = next_state;

			return;
		}

		auto *last = hc->all_tags.empty() ? nullptr : hc->all_tags.back().get();
		bool joins = last != nullptr &&
					 (last->flags & (FL_XML | FL_CLOSED | FL_VIRTUAL | FL_LITERAL_TEXT)) == (FL_XML | FL_CLOSED) &&
					 last->closing.end >= 0 && last->closing.end <= c - start;

		for (auto *q = joins ? start + last->closing.end : c; q < c; q++) {
			if (!g_ascii_isspace(*q)) {
				joins = false;
				break;
			}
		}

		if (!joins) {
			hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_TAGS;
			state = tags_limit_overflow;

			return;
		}

		special_scratch.clear();
		special_scratch.flags = FL_XML | FL_CLOSED;
		special_scratch.tag_start = c - start;
		merge_target = last;
		merge_saved_cur = cur_tag;
		cur_tag = &special_scratch;
		state = next_state;
	};
	/* The comment read into `special_scratch` ends at `upto` */
	auto finish_special_merge = [&](goffset upto) -> void {
		merge_target->content_offset = upto;
		merge_target->closing.end = upto;
		merge_target = nullptr;
		cur_tag = merge_saved_cur;
	};

	/* Counts a registered link of the part, and takes its features */
	auto account_href_url = [&](struct rspamd_url *href_url) -> void {
		if (href_url != nullptr) {
			html_part_add_url(part_urls, href_url);

			/* Minimal link features collection */
			hc->features.links.total_links++;
			if (href_url->flags & RSPAMD_URL_FLAG_IDN) {
				hc->features.links.punycode_links++;
			}
			if (href_url->flags & RSPAMD_URL_FLAG_NUMERIC) {
				hc->features.links.ip_links++;
			}
			if (href_url->flags & RSPAMD_URL_FLAG_HAS_PORT) {
				hc->features.links.port_links++;
			}
			if (href_url->flags & RSPAMD_URL_FLAG_QUERY) {
				/* Heuristic: long query length */
				if (href_url->querylen > 64) {
					hc->features.links.long_query_links++;
				}
			}
			/* Scheme type */
			if (href_url->protocol == PROTOCOL_MAILTO) {
				hc->features.links.mailto_links++;
			}
			else if (href_url->protocol == PROTOCOL_HTTP || href_url->protocol == PROTOCOL_HTTPS) {
				hc->features.links.http_links++;
			}
			/* data/javascript schemes can be detected by flags set during parsing */
			if (href_url->protocol == PROTOCOL_UNKNOWN) {
				/* We don't have explicit scheme enum for data/js; check raw prefix quickly */
				if (href_url->raw && href_url->rawlen >= 5) {
					if (g_ascii_strncasecmp(href_url->raw, "data:", 5) == 0) {
						hc->features.links.data_scheme_links++;
					}
					else if (href_url->rawlen >= 11 && g_ascii_strncasecmp(href_url->raw, "javascript:", 11) == 0) {
						hc->features.links.js_scheme_links++;
					}
				}
			}
			/* Domain counting + affiliation */
			if (href_url->hostlen > 0) {
				std::string host{rspamd_url_host_unsafe(href_url), href_url->hostlen};
				auto &cnt = hc->link_domain_counts[host];
				cnt++;
				if (cnt > hc->features.links.max_links_single_domain) {
					hc->features.links.max_links_single_domain = cnt;
				}
				/* same eTLD+1 as first-party? */
				if (!hc->first_party_etld1.empty()) {
					rspamd_ftok_t tld2;
					if (rspamd_url_find_tld(host.c_str(), host.size(), &tld2)) {
						const char *h = host.c_str();
						const char *p2 = tld2.begin;
						while (p2 > h && *(p2 - 1) != '.') {
							p2--;
						}
						std::string etld1_link{p2, static_cast<std::size_t>(h + host.size() - p2)};
						if (!g_ascii_strcasecmp(etld1_link.c_str(), hc->first_party_etld1.c_str())) {
							hc->features.links.same_etld1_links++;
						}
					}
				}
			}
			/* Query presence */
			if (href_url->querylen > 0) {
				hc->features.links.query_links++;
			}
		}
	};

	/*
	 * Registers the url of a tag with FL_HREF (a link, an area, a form...):
	 * returns nothing if it has no valid url, or nullptr if there are too
	 * many urls in the message to track it
	 */
	auto process_href_tag = [&](struct html_tag *tag) -> std::optional<struct rspamd_url *> {
		auto maybe_url = html_process_url_tag(pool, tag, hc,
											  task->cfg ? (lua_State *) task->cfg->lua_state : NULL);

		if (!maybe_url.has_value()) {
			return std::nullopt;
		}

		struct rspamd_url *href_url = maybe_url.value();

		if (url_set != NULL) {
			struct rspamd_url *maybe_existing =
				rspamd_url_set_add_or_return(url_set, maybe_url.value(), max_urls);
			if (maybe_existing == nullptr) {
				/* Too many urls in the message; do not track this one */
				rspamd_url_note_limit_reached(pool);
				href_url = nullptr;
			}
			else if (maybe_existing == maybe_url.value()) {
				if (cur_url_order) {
					href_url->order = (*cur_url_order)++;
				}
				href_url->part_order = cur_url_part_order++;
				html_process_query_url(pool, href_url, url_set,
									   part_urls,
									   task->cfg ? (lua_State *) task->cfg->lua_state : NULL,
									   max_urls);
			}
			else {
				href_url = maybe_existing;
				/* A link is not an image-only url, whatever came first */
				href_url->flags &= ~RSPAMD_URL_FLAG_IMAGE;
				/* Replace extra as well */
				tag->extra = maybe_existing;
				/* Increase count to avoid odd checks failure */
				href_url->count++;
			}
		}

		account_href_url(href_url);

		return href_url;
	};

	/*
	 * Past the tags limit a part can hold any number of links, so one that
	 * repeats an earlier one is taken from here without parsing it again
	 */
	ankerl::unordered_dense::map<std::string_view, struct rspamd_url *> past_limit_hrefs;

	auto process_href_tag_past_limit = [&](struct html_tag *tag) -> std::optional<struct rspamd_url *> {
		auto raw_href = tag->find_href();

		if (raw_href) {
			if (auto it = past_limit_hrefs.find(raw_href.value()); it != past_limit_hrefs.end()) {
				auto *href_url = it->second;

				tag->extra = href_url;
				href_url->count++;
				account_href_url(href_url);

				return href_url;
			}

			if (url_set != NULL && max_urls > 0 && kh_size(url_set) >= max_urls) {
				/* Too many urls in the message: a new one would not be tracked */
				rspamd_url_note_limit_reached(pool);

				return nullptr;
			}
		}

		auto maybe_url = process_href_tag(tag);

		if (raw_href && maybe_url.has_value() && maybe_url.value() != nullptr) {
			past_limit_hrefs.emplace(raw_href.value(), maybe_url.value());
		}

		return maybe_url;
	};

	/*
	 * The namespace of an opening tag and what follows from it, once all its
	 * attributes are read, also for a tag the input ends in
	 */
	auto finish_opening_tag = [&]() {
		if (!(cur_tag->flags & FL_XML)) {
			auto *node = html_current_node(parent_tag);
			auto ns = html_start_tag_namespace(node, cur_tag);

			if (ns != 0 && html_is_breakout_tag(cur_tag)) {
				parent_tag = html_pop_foreign(node, cur_tag->tag_start);
				ns = html_start_tag_namespace(parent_tag, cur_tag);
			}

			cur_tag->flags |= ns;
			html_tag_mark_submit_link(cur_tag);

			/* Browsers ignore `/>` on HTML elements except the void ones */
			if (!(cur_tag->flags & (CM_EMPTY | FL_FOREIGN))) {
				cur_tag->flags &= ~FL_CLOSED;
			}
		}
	};

	auto process_opening_tag = [&]() {
		if (cur_tag->id > Tag_UNKNOWN) {
			if (cur_tag->flags & CM_UNIQUE) {
				if (!hc->tags_seen[cur_tag->id]) {
					/* Duplicate tag has been found */
					hc->flags |= RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS;
				}
			}
			hc->tags_seen[cur_tag->id] = true;
		}

		/* Simple feature collection on opening */
		switch (cur_tag->id) {
		case Tag_FORM:
			hc->features.forms_count++;
			/* If action present and absolute, compare eTLD+1 with first-party */
			if (auto href = cur_tag->find_href()) {
				if (html_is_absolute_url(*href)) {
					auto maybe_url = html_process_url(pool, *href,
													  task->cfg ? (lua_State *) task->cfg->lua_state : NULL);
					if (maybe_url) {
						struct rspamd_url *u = maybe_url.value();
						if (u->hostlen > 0) {
							/* Find eTLD+1 of action host */
							rspamd_ftok_t tld2;
							if (rspamd_url_find_tld(rspamd_url_host_unsafe(u), u->hostlen, &tld2)) {
								const char *host = rspamd_url_host_unsafe(u);
								const char *p2 = tld2.begin;
								while (p2 > host && *(p2 - 1) != '.') {
									p2--;
								}
								std::string etld1_action{p2, static_cast<std::size_t>(host + u->hostlen - p2)};
								if (!hc->first_party_etld1.empty() && !g_ascii_strcasecmp(etld1_action.c_str(), hc->first_party_etld1.c_str())) {
									hc->features.forms_post_affiliated++;
								}
								else {
									hc->features.forms_post_unaffiliated++;
								}
							}
						}
					}
				}
			}
			break;
		case Tag_META: {
			/* Detect meta refresh */
			auto http_equiv = cur_tag->find_component<html_component_http_equiv>();
			if (http_equiv) {
				auto hv = http_equiv.value()->value;
				if (hv.size() >= sizeof("refresh") - 1 &&
					g_ascii_strncasecmp(hv.data(), "refresh", hv.size()) == 0) {
					hc->features.meta_refresh++;
					/* Try to extract URL from content */
					if (auto content = cur_tag->find_component<html_component_content>()) {
						auto cv = content.value()->value;
						/* naive parse: look for 'url=' and capture token */
						auto p = rspamd_substring_search_caseless(cv.data(), cv.size(), "url=", sizeof("url=") - 1);
						if (p != -1) {
							constexpr auto url_key_len = sizeof("url=") - 1;
							/* compute offset as size_type to avoid narrowing on 32-bit */
							auto url_off = static_cast<std::string_view::size_type>(p) + url_key_len;
							if (url_off <= cv.size()) {
								std::string_view urlv{cv.data() + url_off, cv.size() - url_off};
								/* Trim quotes/spaces and trailing separators */
								while (!urlv.empty() && (g_ascii_isspace(urlv.front()) || urlv.front() == '\'' || urlv.front() == '"')) urlv.remove_prefix(1);
								while (!urlv.empty() && (urlv.back() == ';' || urlv.back() == '\'' || urlv.back() == '"' || g_ascii_isspace(urlv.back()))) urlv.remove_suffix(1);

								if (!urlv.empty()) {
									/* validate and count; do not add to urls set */
									auto maybe_url = html_process_url(pool, urlv,
																	  task->cfg ? (lua_State *) task->cfg->lua_state : NULL);
									if (maybe_url) {
										hc->features.meta_refresh_urls++;
									}
								}
							}
						}
					}
				}
			}
			break;
		}
		case Tag_INPUT: {
			if (auto type_comp = cur_tag->find_component<html_component_type>()) {
				auto tv = type_comp.value()->get_string_value();
				if (tv.size() == sizeof("password") - 1 &&
					g_ascii_strncasecmp(tv.data(), "password", tv.size()) == 0) {
					hc->features.has_password_input = 1u;
				}
			}
			break;
		}
		default:
			break;
		}

		/* Browsers end some open elements at this start tag */
		html_close_implied_end_tags(hc, balance, cur_tag, parent_tag);

		/* Shift to the first unclosed tag */
		auto *pt = parent_tag;
		while (pt && (pt->flags & FL_CLOSED)) {
			pt = pt->parent;
		}

		if (pt) {
			g_assert(cur_tag != pt);
			cur_tag->parent = pt;
			g_assert(cur_tag->parent != &cur_closing_tag);
			parent_tag = pt;
			parent_tag->children.push_back(cur_tag);

			if (cur_tag->id == Tag_TABLE || cur_tag->id == Tag_TD || cur_tag->id == Tag_TH ||
				cur_tag->id == Tag_CAPTION) {
				/* Formatting does not go into a table or a cell from outside */
				balance.clear_formatting();
			}
			else {
				balance.apply_formatting(*hc, cur_tag);
			}
		}
		else {
			if (hc->root_tag) {
				if (cur_tag != hc->root_tag) {
					cur_tag->parent = hc->root_tag;
					g_assert(cur_tag->parent != cur_tag);
					hc->root_tag->children.push_back(cur_tag);
					parent_tag = hc->root_tag;
				}
			}
			else {
				if (cur_tag->id == Tag_HTML) {
					hc->root_tag = cur_tag;
				}
				else {
					/* Insert a fake html tag */
					auto *top_tag = html_tag_alloc(hc, FL_VIRTUAL);

					if (top_tag) {
						top_tag->tag_start = 0;
						top_tag->id = Tag_HTML;
						top_tag->content_offset = 0;
						top_tag->children.push_back(cur_tag);
						cur_tag->parent = top_tag;
						g_assert(cur_tag->parent != cur_tag);
						hc->root_tag = top_tag;
						parent_tag = top_tag;
					}
				}
			}
		}

		if (cur_tag->flags & FL_HREF && html_document_state == html_document_state::body) {
			auto maybe_url = process_href_tag(cur_tag);

			if (maybe_url.has_value()) {
				url = maybe_url.value();
				href_offset = hc->parsed.size();
			}
		}
		else if (cur_tag->id == Tag_BASE) {
			/*
			 * Base is allowed only within head tag but HTML is retarded
			 */
			auto maybe_url = html_process_url_tag(pool, cur_tag, hc,
												  task->cfg ? (lua_State *) task->cfg->lua_state : NULL);

			if (maybe_url) {
				msg_debug_html("got valid base tag");
				cur_tag->extra = maybe_url.value();
				cur_tag->flags |= FL_HREF;

				if (hc->base_url == nullptr) {
					hc->base_url = maybe_url.value();
				}
				else {
					msg_debug_html("ignore redundant base tag");
				}
			}
			else {
				msg_debug_html("got invalid base tag!");
			}
		}

		if (cur_tag->id == Tag_IMG) {
			html_process_img_tag(pool, cur_tag, hc, url_set,
								 part_urls,
								 task->cfg ? (lua_State *) task->cfg->lua_state : NULL,
								 max_urls);
		}
		else if (cur_tag->id == Tag_LINK) {
			html_process_link_tag(pool, cur_tag, hc, url_set,
								  part_urls,
								  task->cfg ? (lua_State *) task->cfg->lua_state : NULL,
								  max_urls);
		}

		/* Track DOM tag count and max depth */
		hc->features.tags_count++;
		cur_tag->depth = cur_tag->parent ? cur_tag->parent->depth + 1 : 0;
		if (cur_tag->depth > hc->features.max_dom_depth) {
			hc->features.max_dom_depth = cur_tag->depth;
		}

		if (!(cur_tag->flags & CM_EMPTY) && cur_tag->depth > 0) {
			/* The scope depths of the elements above are those of the parent */
			if (balance.scopes.size() <= cur_tag->depth) {
				balance.scopes.resize(cur_tag->depth + 1);
			}
			balance.scopes[cur_tag->depth] =
				html_scope_depths_of(cur_tag, balance.scopes[cur_tag->depth - 1]);
		}

		if (!(cur_tag->flags & CM_EMPTY)) {
			html_process_block_tag(pool, cur_tag, hc, &spare_block);
		}
		else {
			/* Implicitly close */
			cur_tag->flags |= FL_CLOSED;
		}

		if (cur_tag->flags & FL_CLOSED) {
			cur_tag->closing.end = cur_tag->content_offset;
			cur_tag->closing.start = cur_tag->tag_start;

			cur_tag = parent_tag;
		}
	};

	/*
	 * In the head, a character other than whitespace ends it and starts the
	 * body (the "in head" insertion mode): the text from `c` to `text_end`
	 * then goes into the element around the head
	 */
	auto end_head_for_text = [&](const char *text_end) -> void {
		if (html_document_state != html_document_state::head || cur_tag == &cur_closing_tag) {
			return;
		}

		auto *head = html_current_node(cur_tag);

		if (head == nullptr || head->id != Tag_HEAD || (head->flags & FL_FOREIGN)) {
			return;
		}

		const char *text = c;

		while (text < text_end && (*text == ' ' || *text == '\t' || *text == '\n' ||
								   *text == '\r' || *text == '\f')) {
			text++;
		}

		if (text == text_end) {
			return;
		}

		head->flags |= FL_CLOSED;
		head->closing.start = std::max((goffset) (text - start), (goffset) head->content_offset);
		head->closing.end = head->closing.start;
		html_document_state = html_document_state::body;
		cur_tag = html_current_node(head->parent);
		parent_tag = cur_tag;
	};

	p = (const char *) in->data;
	c = p;
	end = p + process_size;
	start = c;
	content_parser_env.html_start = start;// Initialize for span tracking

	/*
	 * Attributes budget is task-global, as a task can have multiple HTML parts;
	 * the counter is stashed in the task pool to survive across parts
	 */
	static const char attrs_count_var[] = "html_attrs_count";
	auto *task_attrs_count = static_cast<unsigned int *>(rspamd_mempool_get_variable(pool, attrs_count_var));

	if (task_attrs_count == nullptr) {
		task_attrs_count = rspamd_mempool_alloc0_type(pool, unsigned int);
		rspamd_mempool_set_variable(pool, attrs_count_var, task_attrs_count, nullptr);
	}

	content_parser_env.attrs_count = task_attrs_count;

	while (p < end) {
		t = *p;

		switch (state) {
		case parse_start:
			if (t == '<') {
				state = tag_begin;
			}
			else {
				/* We have no starting tag, so assume that it's content */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_START;
				cur_tag = new_tag();
				html_document_state = html_document_state::body;

				if (cur_tag) {
					cur_tag->id = Tag_HTML;
					hc->root_tag = cur_tag;
					state = content_before_start;
				}
				else {
					state = tags_limit_overflow;
				}
			}
			break;
		case content_before_start:
			if (t == '<') {
				state = tag_begin;
			}
			else {
				p++;
			}
			break;
		case tag_begin:
			switch (t) {
			case '<':
				c = p;
				p++;
				closing = FALSE;
				break;
			case '!':
				/* At the tags limit the open element stays current, see overflow */
				start_special_tag(sgml_tag);
				p++;
				break;
			case '?':
				start_special_tag(xml_tag);
				hc->flags |= RSPAMD_HTML_FLAG_XML;
				p++;
				break;
			case '/':
				if (p + 1 < end && !g_ascii_isalpha(p[1])) {
					/*
					 * `</` without a tag name: browsers drop `</>` and take
					 * anything else as a bogus comment up to the first `>`
					 */
					start_special_tag(sgml_content);
					p++;
					break;
				}
				closing = TRUE;
				/* We fill fake closing tag to fill it with the content parser */
				cur_closing_tag.clear();
				/*
				 * For closing tags, we need to find some corresponding opening tag.
				 * However, at this point we have not even parsed a name, so we
				 * can not assume anything about balancing, etc.
				 *
				 * So we need to ensure that:
				 * 1) We have some opening tag in the chain cur_tag->parent...
				 * 2) cur_tag is nullptr - okay, html is just brain damaged
				 * 3) cur_tag must NOT be equal to cur_closing tag. It means that
				 * we had some poor closing tag but we still need to find an opening
				 * tag... Somewhere...
				 */

				if (cur_tag == &cur_closing_tag) {
					if (parent_tag != &cur_closing_tag) {
						cur_closing_tag.parent = parent_tag;
					}
					else {
						cur_closing_tag.parent = nullptr;
					}
				}
				else if (cur_tag && cur_tag->flags & FL_CLOSED) {
					/* Cur tag is already closed, we should find something else */
					auto *tmp = cur_tag;
					while (tmp) {
						tmp = tmp->parent;

						if (tmp == nullptr || !(tmp->flags & FL_CLOSED)) {
							break;
						}
					}

					cur_closing_tag.parent = tmp;
				}
				else {
					cur_closing_tag.parent = cur_tag;
				}

				cur_tag = &cur_closing_tag;
				p++;
				break;
			case '>':
				/* Empty tag */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				state = html_text_content;
				continue;
			default:
				if (g_ascii_isalpha(t)) {
					state = tag_content;
					content_parser_env.reset();

					if (auto *ntag = closing ? cur_tag : new_tag()) {
						cur_tag = ntag;
						state = tag_content;
					}
					else {
						state = tags_limit_overflow;
					}
				}
				else {
					/* Wrong bad tag */
					state = html_text_content;
				}
				break;
			}

			break;

		case sgml_tag:
			switch (t) {
			case '[':
				/*
				 * Browsers open a CDATA section only in SVG/MathML content and
				 * take any other `<![` as a bogus comment up to the first `>`,
				 * so `<![if !mso]>` still works. Inside the section, markup is
				 * text up to `]]>`: ending it earlier would parse that text,
				 * where `<p><style>` leaves SVG and hides what follows
				 */
				if (end - p >= (goffset) sizeof("[CDATA[") - 1 &&
					memcmp(p, "[CDATA[", sizeof("[CDATA[") - 1) == 0) {
					auto *node = html_current_node(parent_tag);

					if (node && (node->flags & FL_FOREIGN) && merge_target != nullptr) {
						/* Text in svg and math is not skipped as a comment */
						merge_target = nullptr;
						cur_tag = merge_saved_cur;
						hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_TAGS;
						state = tags_limit_overflow;
						break;
					}

					if (node && (node->flags & FL_FOREIGN)) {
						/* An element holding the section as literal text */
						cur_tag->flags = FL_LITERAL_TEXT;
						p += sizeof("[CDATA[") - 2;
						cur_tag->content_offset = p - start + 1;
						cdata_section = true;
						state = tag_end_opening;
						break;
					}

					hc->flags |= RSPAMD_HTML_FLAG_CDATA_IN_HTML | RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				}
				state = sgml_content;
				break;
			case '-':
				cur_tag->flags |= FL_COMMENT;
				state = comment_tag;
				p++;
				break;
			default:
				state = sgml_content;
				break;
			}

			break;

		case xml_tag:
			if (t == '?') {
				state = xml_tag_end;
			}
			else if (t == '>') {
				/* Misformed xml tag */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				cur_tag->content_offset = p - start + 1;
				state = tag_end_opening;
				continue;
			}
			/* We efficiently ignore xml tags */
			p++;
			break;

		case xml_tag_end:
			if (t == '>') {
				state = tag_end_opening;
				cur_tag->content_offset = p - start + 1;
				continue;
			}
			else {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			}
			p++;
			break;

		case comment_tag:
			if (t != '-') {
				/* `<!-` alone opens no comment, browsers skip it up to `>` */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				state = sgml_content;
			}
			else {
				p++;
				ebrace = 0;
				/*
				 * https://www.w3.org/TR/2012/WD-html5-20120329/syntax.html#syntax-comments
				 *  ... the text must not start with a single
				 *  U+003E GREATER-THAN SIGN character (>),
				 *  nor start with a "-" (U+002D) character followed by
				 *  a U+003E GREATER-THAN SIGN (>) character,
				 *  nor contain two consecutive U+002D HYPHEN-MINUS
				 *  characters (--), nor end with a "-" (U+002D) character.
				 */
				if (p + 1 < end && p[0] == '-' && p[1] == '>') {
					hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
					p++;
					cur_tag->content_offset = p - start + 1;
					state = tag_end_opening;
				}
				else if (p < end && *p == '>') {
					hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
					cur_tag->content_offset = p - start + 1;
					state = tag_end_opening;
				}
				else {
					state = comment_content;
				}
			}
			break;

		case comment_content:
			if (t == '-') {
				ebrace++;
			}
			else if (t == '>' && ebrace >= 2) {
				cur_tag->content_offset = p - start + 1;
				state = tag_end_opening;
				continue;
			}
			else if (t == '!' && ebrace >= 2 && p + 1 < end && p[1] == '>') {
				/* `--!>` closes a comment as well */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				p++;
				cur_tag->content_offset = p - start + 1;
				state = tag_end_opening;
				continue;
			}
			else {
				ebrace = 0;
			}

			p++;
			break;

		case html_text_content:
			if (t != '<') {
				p++;
			}
			else {
				end_head_for_text(p);
				state = tag_begin;
			}
			break;

		case tag_raw_text:
			if (t == '<' &&
				html_is_raw_text_end_tag({p, (std::size_t) (end - p)}, raw_text_tag_id)) {
				raw_text_tag_id = Tag_UNKNOWN;
				state = tag_begin;
			}
			else {
				auto *next_lt = (const char *) memchr(p + 1, '<', end - p - 1);
				p = next_lt ? next_lt : end;
			}
			break;
		case cdata_content: {
			auto cdata_len = rspamd_substring_search(p, end - p, "]]>", sizeof("]]>") - 1);

			if (cdata_len == -1) {
				/* Browsers take the rest as text, the section is closed at the end */
				p = end;
				break;
			}

			/* cur_tag is the section, `]]>` closes it */
			p += cdata_len;
			cur_tag->flags |= FL_CLOSED;
			cur_tag->closing.start = p - start;
			p += sizeof("]]>") - 1;
			cur_tag->closing.end = p - start;
			cur_tag = cur_tag->parent;
			c = p;
			state = html_text_content;
			break;
		}
		case sgml_content:
			/* TODO: parse DOCTYPE here */
			if (t == '>') {
				cur_tag->content_offset = p - start + 1;
				state = tag_end_opening;
			}
			else {
				p++;
			}
			break;

		case tag_content:
			html_parse_tag_content(pool, hc, cur_tag, p, content_parser_env);

			if (t == '>') {
				if (content_parser_env.cur_state != parse_dqvalue && content_parser_env.cur_state != parse_sqvalue) {
					/* We have a closing element */
					if (closing) {
						cur_tag->closing.start = c - start;
						cur_tag->closing.end = p - start + 1;

						closing = FALSE;
						state = tag_end_closing;
					}
					else {
						cur_tag->content_offset = p - start + 1;
						state = tag_end_opening;
					}
				}
				else {
					/*
					 * We are in the parse_quoted value state but got
					 * an unescaped `>` character.
					 * HTML is written for monkeys, so there are two possibilities:
					 * 1) We have missing ending quote
					 * 2) We have unescaped `>` character
					 * How to distinguish between those possibilities?
					 * Well, the idea is to do some lookahead and try to find a
					 * quote. If we can find a quote, we just pretend as we have
					 * not seen `>` character. Otherwise, we pretend that it is an
					 * unquoted stuff. This logic is quite fragile but I really
					 * don't know any better options...
					 */
					auto end_quote = content_parser_env.cur_state == parse_sqvalue ? '\'' : '"';

					if (next_quote == nullptr || next_quote_char != end_quote || next_quote < p) {
						next_quote = (const char *) memchr(p, end_quote, end - p);
						next_quote_char = end_quote;

						if (next_quote == nullptr) {
							next_quote = end;
						}
					}

					if (next_quote != end) {
						/* Unencoded `>` */
						p++;
						continue;
					}
					else {
						if (closing) {
							cur_tag->closing.start = c - start;
							cur_tag->closing.end = p - start + 1;

							closing = FALSE;
							state = tag_end_closing;
						}
						else {
							cur_tag->content_offset = p - start + 1;
							state = tag_end_opening;
						}
					}
				}
				continue;
			}
			p++;
			break;

		case tag_end_opening:
			content_parser_env.reset();
			state = html_text_content;

			if (merge_target != nullptr) {
				finish_special_merge(cur_tag->content_offset);
				p++;
				c = p;
				break;
			}

			if (cur_tag) {
				finish_opening_tag();

				if (html_is_raw_text_tag(cur_tag->id) && !(cur_tag->flags & FL_FOREIGN)) {
					state = tag_raw_text;
					raw_text_tag_id = cur_tag->id;

					/* Only title and textarea decode character references */
					if (cur_tag->id != Tag_TITLE && cur_tag->id != Tag_TEXTAREA) {
						cur_tag->flags |= FL_LITERAL_TEXT;
					}
				}
				else if (cdata_section) {
					state = cdata_content;
					cdata_section = false;
				}
				if (html_document_state == html_document_state::doctype) {
					if (cur_tag->id == Tag_HEAD || (cur_tag->flags & CM_HEAD)) {
						html_document_state = html_document_state::head;
						cur_tag->flags |= FL_IGNORE;
					}
					else if (cur_tag->id != Tag_HTML) {
						html_document_state = html_document_state::body;
					}
				}
				else if (html_document_state == html_document_state::head) {
					if (!(cur_tag->flags & (CM_EMPTY | CM_HEAD))) {
						if (parent_tag && parent_tag->id == Tag_HTML) {
							/*
							 * The head is implied by head elements without
							 * a `<head>`: it ends here, and the html element
							 * stays open
							 */
							html_document_state = html_document_state::body;
						}
						else if (parent_tag && (parent_tag->id == Tag_HEAD || !(parent_tag->flags & CM_HEAD))) {
							/*
							 * As by standard, we have to close the HEAD tag
							 * and switch to the body state
							 */
							parent_tag->flags |= FL_CLOSED;
							parent_tag->closing.start = cur_tag->tag_start;
							parent_tag->closing.end = cur_tag->content_offset;

							html_document_state = html_document_state::body;
						}
						else if (cur_tag->id == Tag_BODY) {
							html_document_state = html_document_state::body;
						}
						else {
							/*
							 * For propagation in something like
							 * <title><p><a>ololo</a></p></title> - should be unprocessed
							 */
							cur_tag->flags |= CM_HEAD;
						}
					}
				}

				process_opening_tag();
			}

			p++;
			c = p;
			break;
		case tag_end_closing: {
			if (cur_tag) {

				if (cur_tag->flags & CM_EMPTY) {
					/* Ignore closing empty tags */
					cur_tag->flags |= FL_IGNORE;
				}
				if (html_document_state == html_document_state::doctype) {
				}
				else if (html_document_state == html_document_state::head) {
					if (cur_tag->id == Tag_HEAD) {
						html_document_state = html_document_state::body;
					}
				}

				if (cur_tag->id == Tag_P || cur_tag->id == Tag_BR) {
					auto *node = html_current_node(cur_tag->parent);

					if (node && (node->flags & FL_FOREIGN)) {
						/* Like the breakout tags, these leave SVG/MathML */
						cur_tag->parent = html_pop_foreign(node, c - start);
					}
				}

				/* cur_tag here is a closing tag */
				/*
				 * `</body>` and `</html>` do not end the elements in browsers:
				 * what follows them still goes into the open element
				 */
				/* The element this tag closes, if it is the innermost open one */
				auto *closed_directly = cur_tag->parent;

				if (closed_directly && (closed_directly->id != cur_tag->id ||
										(closed_directly->flags & FL_CLOSED))) {
					closed_directly = nullptr;
				}

				if (!balance.active_formatting.empty()) {
					if (cur_tag->id == Tag_TABLE || cur_tag->id == Tag_TD || cur_tag->id == Tag_TH ||
						cur_tag->id == Tag_CAPTION) {
						balance.clear_formatting();
					}
					else if (closed_directly == nullptr &&
							 html_balance_state::is_formatting(cur_tag->id) &&
							 !balance.has_open_tag(*hc, cur_tag->id)) {
						balance.end_formatting(cur_tag->id);
					}
				}

				auto *next_cur_tag = (hc->root_tag &&
									  (cur_tag->id == Tag_BODY || cur_tag->id == Tag_HTML))
										 ? nullptr
										 : html_check_balance(hc, balance, cur_tag,
															  c - start, p - start + 1);

				if (cur_tag->id == Tag_STYLE && allow_css) {
					auto *opening_tag = cur_tag->parent;

					if (opening_tag && opening_tag->id == Tag_STYLE &&
						(int) opening_tag->content_offset < opening_tag->closing.start) {
						auto ret_maybe = rspamd::css::parse_css(pool,
																{start + opening_tag->content_offset,
																 opening_tag->closing.start - opening_tag->content_offset},
																std::move(hc->css_style));

						if (!ret_maybe.has_value()) {
							if (ret_maybe.error().is_fatal()) {
								auto err_str = fmt::format(
									"cannot parse css (error code: {}): {}",
									static_cast<int>(ret_maybe.error().type),
									ret_maybe.error().description.value_or("unknown error"));
								msg_info_pool("%*s", (int) err_str.size(), err_str.data());
							}
						}
						else {
							hc->css_style = ret_maybe.value();
						}
					}
				}

				if (next_cur_tag != nullptr) {
					if (closed_directly != nullptr && next_cur_tag == closed_directly->parent) {
						if (html_fold_empty_element(hc, balance, closed_directly, p - start + 1,
													&spare_block)) {
							cur_closing_tag.parent = nullptr;
						}
					}

					cur_tag = next_cur_tag;
				}
				else {
					/*
					 * Here, we handle cases like <p>lala</b>...
					 * So the tag </b> is bogus and unpaired
					 * However, we need to exclude it from the output of <p> tag
					 * To do that, we create a fake opening tag and insert that to
					 * the current opening tag
					 */
					auto *cur_opening_tag = cur_tag->parent;

					while (cur_opening_tag && (cur_opening_tag->flags & FL_CLOSED)) {
						cur_opening_tag = cur_opening_tag->parent;
					}

					if (!cur_opening_tag) {
						cur_opening_tag = hc->root_tag;
					}

					auto *vtag = html_tag_alloc(hc, FL_VIRTUAL | FL_CLOSED | cur_tag->flags);

					if (vtag == nullptr) {
						state = tags_limit_overflow;
						break;
					}

					vtag->id = cur_tag->id;
					vtag->tag_start = cur_tag->closing.start;
					vtag->content_offset = p - start + 1;
					vtag->closing = cur_tag->closing;
					vtag->parent = cur_opening_tag;
					g_assert(vtag->parent != &cur_closing_tag);
					cur_opening_tag->children.push_back(vtag);
					cur_tag = cur_opening_tag;
					parent_tag = cur_tag->parent;
					g_assert(cur_tag->parent != &cur_closing_tag);
				}
			} /* if cur_tag != nullptr */
			state = html_text_content;
			p++;
			c = p;
			break;
		}
		case tags_limit_overflow:
			/*
			 * `c` is the start of the markup that needed a tag: the rest is
			 * read without creating tags, see scan_after_tags_limit
			 */
			msg_warn_pool("tags limit of %d tags is reached at the position %d;"
						  " reading the rest of the HTML content without tags",
						  (int) hc->all_tags.size(), (int) (c - start));
			p = end;
			break;
		}
	}

	/*
	 * The input can end inside markup. A comment or a declaration still
	 * ends there and a partial opening tag is kept, so they become part of
	 * the tree; a partial closing tag closes nothing. The open element must
	 * then be closed at the end, or the text after its last child is lost
	 */
	if (merge_target != nullptr) {
		/* A comment over the budget goes to the end of the input */
		finish_special_merge(state == tag_end_opening ? special_scratch.content_offset : end - start);
	}
	else {
		switch (state) {
		case html_text_content:
			end_head_for_text(end);
			break;
		case sgml_tag:
		case sgml_content:
		case comment_tag:
		case comment_content:
		case xml_tag:
		case xml_tag_end:
		case tag_content:
			if (cur_tag != nullptr && cur_tag != &cur_closing_tag) {
				cur_tag->content_offset = end - start;
				finish_opening_tag();
				process_opening_tag();
			}
			break;
		case tag_end_opening:
			if (cur_tag != nullptr && cur_tag != &cur_closing_tag) {
				finish_opening_tag();
				process_opening_tag();
			}
			break;
		default:
			break;
		}
	}

	goffset content_end = end - start;

	if (state == tags_limit_overflow || cur_tag == &cur_closing_tag) {
		/*
		 * Past the tags limit the rest is not in the tree, and a partial
		 * closing tag is not text either: open elements end there
		 */
		content_end = c - start;

		if (cur_tag == &cur_closing_tag) {
			cur_tag = cur_closing_tag.parent;
		}
	}

	while (cur_tag && (cur_tag->flags & FL_CLOSED)) {
		cur_tag = cur_tag->parent;
	}

	/* A link open where the tags end goes on past them */
	struct rspamd_url *link_at_limit = nullptr;
	/*
	 * And so does an svg element, before the open elements are closed: a link
	 * in it goes to xlink:href. Only while the current element is in it, as
	 * in the tree: an HTML element in a foreignObject is HTML content. CDATA
	 * past the limit is not text for these, as reading it as text where it is
	 * none would hide the markup in it
	 */
	unsigned int svg_at_limit = 0;
	/*
	 * The open elements where the tags end, the innermost first: they are
	 * the ancestors of everything past the limit
	 */
	std::vector<const html_tag *> open_chain;

	if (state == tags_limit_overflow) {
		bool in_link = false, in_foreign = cur_tag && (cur_tag->flags & FL_FOREIGN);

		for (auto *t = cur_tag; t != nullptr; t = t->parent) {
			open_chain.push_back(t);

			if (t->id == Tag_A && !in_link) {
				/* The innermost link only */
				in_link = true;

				if (std::holds_alternative<struct rspamd_url *>(t->extra)) {
					link_at_limit = std::get<struct rspamd_url *>(t->extra);
				}
			}

			if (!(t->flags & FL_FOREIGN)) {
				in_foreign = false;
			}
			else if (in_foreign && t->id == Tag_SVG) {
				svg_at_limit++;
			}
		}
	}

	if (cur_tag && cur_tag != &cur_closing_tag) {
		cur_closing_tag.parent = cur_tag;
		cur_closing_tag.id = cur_tag->id;
		cur_tag = &cur_closing_tag;
		html_check_balance(hc, balance, cur_tag,
						   content_end, end - start);
	}

	/* Propagate styles */
	hc->traverse_block_tags([&hc, &pool](const html_tag *tag) -> bool {
		/*
		 * Unknown elements have negative ids and are inline elements to
		 * a browser: class, id and universal rules apply to them
		 */
		if (hc->css_style && tag->id != Tag_UNKNOWN && tag->id < Tag_MAX) {
			auto *css_block = hc->css_style->check_tag_block(tag);

			if (css_block) {
				if (tag->block) {
					tag->block->set_block(*css_block);
				}
				else {
					tag->block = css_block;
				}

				/*
				 * The parent has already propagated into this block, so a
				 * relative size coming from the stylesheet is still relative
				 * and would never be compared against the visibility limits
				 */
				if (tag->parent && tag->parent->block) {
					tag->block->resolve_sizes(*tag->parent->block,
											  html_tag_bounded_by_parent(tag));
				}
				else {
					static const html_block undefined_parent{};
					tag->block->resolve_sizes(undefined_parent);
				}
			}
		}
		if (tag->block && tag->formatting != 0 && tag->formatting <= hc->formatting_lists.size()) {
			/*
			 * As if these elements were open here again: what they set goes
			 * over what the parent gave, the inner ones over the outer ones.
			 * They stand before this element, so their blocks are ready
			 */
			for (const auto *fmt: hc->formatting_lists[tag->formatting - 1]) {
				if (fmt->block) {
					tag->block->propagate_block(*fmt->block, false);
				}
			}
		}

		if (tag->block) {
			/* Preserve inherited display:none when assigning tag defaults. */
			if (!tag->block->has_display(html_block::hint) &&
				!(tag->block->has_display(html_block::inherited) &&
				  tag->block->display == css::css_display_value::DISPLAY_HIDDEN)) {
				/* If we have no display field, we can check it by tag */
				if (tag->flags & CM_HEAD) {
					tag->block->set_display(css::css_display_value::DISPLAY_HIDDEN,
											html_block::set);
				}
				else if (tag->flags & (CM_BLOCK | CM_TABLE)) {
					tag->block->set_display(css::css_display_value::DISPLAY_BLOCK,
											html_block::implicit);
				}
				else if (tag->flags & CM_ROW) {
					tag->block->set_display(css::css_display_value::DISPLAY_TABLE_ROW,
											html_block::implicit);
				}
				else {
					tag->block->set_display(css::css_display_value::DISPLAY_INLINE,
											html_block::implicit);
				}
			}

			tag->block->compute_visibility();

			for (const auto *cld_tag: tag->children) {

				if (!cld_tag->block) {
					/*
					 * Tags normally get a block while parsing (from the style
					 * attribute or an empty one). Should one arrive here
					 * without it, inherit through propagation rather than a
					 * copy: a copy would carry the parent's `set` masks, and a
					 * stylesheet rule merged into the child later could not
					 * override what the parent set inline
					 */
					cld_tag->block = rspamd_mempool_alloc0_type(pool, html_block);
				}

				cld_tag->block->propagate_block(*tag->block,
												html_tag_bounded_by_parent(cld_tag));
			}
		}
		return true;
	},
							html_content::traverse_type::PRE_ORDER);

	/*
	 * Style sheets may resize images parsed before the corresponding
	 * <style> tag, so the tiny pixel classification is reconciled here,
	 * when all sheets are already parsed, and in both directions: an
	 * image shrunk to a pixel by a stylesheet is detected, and an image
	 * enlarged by one is not reported. Images sized by a stylesheet
	 * alone are classified as well, and inline max bounds and minimums
	 * are honoured even without any stylesheet. A stylesheet
	 * rule beats the attribute dimensions and fills the missing ones,
	 * but loses to the inline style values; max-width/max-height are
	 * honoured as upper bounds rather than actual sizes, and an inline
	 * maximum overrides a stylesheet one entirely, with `none`
	 * removing the bound. An !important stylesheet width/height
	 * beats a non-important inline style; an inline !important is
	 * not recognised.
	 */
	/* Updates the tiny external images counter after the dimensions
	 * of an image have been reconciled */
	auto count_tiny_external = [hc](bool was_tiny, bool is_tiny) -> void {
		if (was_tiny && !is_tiny) {
			hc->features.images_tiny_external--;
		}
		else if (!was_tiny && is_tiny) {
			hc->features.images_tiny_external++;
		}
	};

	auto known_dim = [](unsigned char source) -> bool {
		return source != dim_src_none && source != dim_src_unknown;
	};

	/* An empty stylesheet block standing in when no rule matches an
	 * image, so that the inline bounds and minimums are still applied
	 * by the common code path */
	html_block no_css_block{};

	if (hc->css_style) {
		for (auto *img: hc->images) {
			if (!(img->flags & RSPAMD_HTML_FLAG_IMAGE_EXTERNAL)) {
				continue;
			}

			auto was_tiny = known_dim(img->width_source) &&
							known_dim(img->height_source) &&
							html_image_is_tiny(img->width_exact, img->height_exact);
			auto *img_tag = static_cast<struct html_tag *>(img->tag);
			auto *css_block = hc->css_style->check_tag_block(img_tag);

			if (css_block == nullptr) {
				css_block = &no_css_block;
			}

			/* An inline minimum keeps winning unless an !important
			 * stylesheet minimum replaces it */
			auto inline_min_width_wins = (img->min_source & 0x2) &&
										 !(css_block->min_width_important &&
										   !(img->min_source & 0x20));
			auto inline_min_height_wins = (img->min_source & 0x1) &&
										  !(css_block->min_height_important &&
											!(img->min_source & 0x10));

			if (css_block) {
				/* An !important stylesheet maximum beats a
				 * non-important inline one */
				auto sheet_max_width_wins =
					css_block->max_width_important &&
					!(img->max_source & 0x8);
				auto sheet_max_height_wins =
					css_block->max_height_important &&
					!(img->max_source & 0x4);

				if (css_block->width_real_mask &&
					css_block->width_real >= 0 &&
					((css_block->width_important &&
					  !(img->inline_important & 0x2)) ||
					 img->width_source == dim_src_attribute ||
					 img->width_source == dim_src_none)) {
					/* An actual width property from the stylesheet
					 * cascade, recorded before the rule's own max
					 * bound is applied; an !important one beats the
					 * inline style, unless the latter is !important
					 * too */
					img->width = html_dim_to_unsigned(ceilf(css_block->width_real));
					img->width_exact = css_block->width_real;
					img->width_source = dim_src_stylesheet;
				}
				else if (css_block->width_real_mask &&
						 ((css_block->width_important &&
						   !(img->inline_important & 0x2)) ||
						  img->width_source == dim_src_attribute ||
						  img->width_source == dim_src_none)) {
					/* A percent real size from the cascade: the
					 * effective size is unknown, and it overrides a
					 * value flattened from a max bound; an !important
					 * one beats the inline style */
					img->width_source = dim_src_unknown;
				}
				else if (css_block->width_mask == html_block::set) {
					if (css_block->width >= 0) {
						if (!css_block->width_from_max &&
							(img->width_source == dim_src_attribute ||
							 img->width_source == dim_src_none)) {
							img->width = css_block->width;
							img->width_exact = css_block->width;
							img->width_source = dim_src_stylesheet;
						}
						else if (css_block->width_from_max &&
								 css_block->width_max_mask != 2 &&
								 (!(img->max_source & 0x2) ||
								  sheet_max_width_wins)) {
							/* An inline max-width supersedes the
							 * stylesheet one entirely, and an effective
							 * `none` maximum invalidates a value
							 * flattened from a removed bound */
							if (css_block->width_max <= 4.0 ||
								(known_dim(img->height_source) &&
								 html_image_is_tiny(css_block->width_max,
													img->height_exact))) {
								/* The bound itself is within the tiny
								 * threshold, so the size is tiny anyway */
								if (!known_dim(img->width_source) ||
									css_block->width_max < img->width_exact) {
									img->width = html_dim_to_unsigned(ceilf(css_block->width_max));
									img->width_exact = css_block->width_max;
									img->width_source = dim_src_stylesheet;
								}
							}
							else if (known_dim(img->width_source)) {
								/* Cap a larger known size; the source
								 * stays, as a maximum is not a size */
								if (css_block->width_max < img->width_exact) {
									img->width = html_dim_to_unsigned(ceilf(css_block->width_max));
									img->width_exact = css_block->width_max;
								}
							}
							else {
								/* An upper bound above the threshold
								 * tells nothing about the actual size */
								img->width_source = dim_src_unknown;
							}
						}
					}
					else if (img->width_source == dim_src_attribute ||
							 img->width_source == dim_src_none) {
						/* Percent value: the effective size is unknown */
						img->width_source = dim_src_unknown;
					}
				}

				if (css_block->height_real_mask &&
					css_block->height_real >= 0 &&
					((css_block->height_important &&
					  !(img->inline_important & 0x1)) ||
					 img->height_source == dim_src_attribute ||
					 img->height_source == dim_src_none)) {
					/* An actual height property from the stylesheet
					 * cascade, recorded before the rule's own max
					 * bound is applied; an !important one beats the
					 * inline style, unless the latter is !important
					 * too */
					img->height = html_dim_to_unsigned(ceilf(css_block->height_real));
					img->height_exact = css_block->height_real;
					img->height_source = dim_src_stylesheet;
				}
				else if (css_block->height_real_mask &&
						 ((css_block->height_important &&
						   !(img->inline_important & 0x1)) ||
						  img->height_source == dim_src_attribute ||
						  img->height_source == dim_src_none)) {
					/* A percent real size from the cascade: the
					 * effective size is unknown, and it overrides a
					 * value flattened from a max bound; an !important
					 * one beats the inline style */
					img->height_source = dim_src_unknown;
				}
				else if (css_block->height_mask == html_block::set) {
					if (css_block->height >= 0) {
						if (!css_block->height_from_max &&
							(img->height_source == dim_src_attribute ||
							 img->height_source == dim_src_none)) {
							img->height = css_block->height;
							img->height_exact = css_block->height;
							img->height_source = dim_src_stylesheet;
						}
						else if (css_block->height_from_max &&
								 css_block->height_max_mask != 2 &&
								 (!(img->max_source & 0x1) ||
								  sheet_max_height_wins)) {
							/* An inline max-height supersedes the
							 * stylesheet one entirely, and an effective
							 * `none` maximum invalidates a value
							 * flattened from a removed bound */
							if (css_block->height_max <= 4.0 ||
								(known_dim(img->width_source) &&
								 html_image_is_tiny(img->width_exact,
													css_block->height_max))) {
								if (!known_dim(img->height_source) ||
									css_block->height_max < img->height_exact) {
									img->height = html_dim_to_unsigned(ceilf(css_block->height_max));
									img->height_exact = css_block->height_max;
									img->height_source = dim_src_stylesheet;
								}
							}
							else if (known_dim(img->height_source)) {
								if (css_block->height_max < img->height_exact) {
									img->height = html_dim_to_unsigned(ceilf(css_block->height_max));
									img->height_exact = css_block->height_max;
								}
							}
							else {
								img->height_source = dim_src_unknown;
							}
						}
					}
					else if (img->height_source == dim_src_attribute ||
							 img->height_source == dim_src_none) {
						img->height_source = dim_src_unknown;
					}
				}

				/* A max bound caps any known size, including an inline
				 * style one; an inline maximum overrides a stylesheet
				 * one entirely, and `none` removes the bound */
				auto width_bound = (img->max_source & 0x2) && !sheet_max_width_wins
									   ? img->max_width
									   : (css_block->width_max_mask == 1
											  ? css_block->width_max
											  : no_image_bound);

				if (width_bound >= 0 &&
					(width_bound <= 4.0 ||
					 (known_dim(img->height_source) &&
					  html_image_is_tiny(width_bound, img->height_exact))) &&
					(!known_dim(img->width_source) ||
					 width_bound < img->width_exact)) {
					/* The bound itself is within the tiny threshold, so
					 * the size is tiny whatever it actually is */
					img->width = html_dim_to_unsigned(ceilf(width_bound));
					img->width_exact = width_bound;
					img->width_source = dim_src_stylesheet;
				}
				else if (width_bound >= 0 &&
						 known_dim(img->width_source) &&
						 width_bound < img->width_exact) {
					img->width = html_dim_to_unsigned(ceilf(width_bound));
					img->width_exact = width_bound;
				}

				auto height_bound = (img->max_source & 0x1) && !sheet_max_height_wins
										? img->max_height
										: (css_block->height_max_mask == 1
											   ? css_block->height_max
											   : no_image_bound);

				if (height_bound >= 0 &&
					(height_bound <= 4.0 ||
					 (known_dim(img->width_source) &&
					  html_image_is_tiny(img->width_exact, height_bound))) &&
					(!known_dim(img->height_source) ||
					 height_bound < img->height_exact)) {
					/* The bound itself is within the tiny threshold, so
					 * the size is tiny whatever it actually is */
					img->height = html_dim_to_unsigned(ceilf(height_bound));
					img->height_exact = height_bound;
					img->height_source = dim_src_stylesheet;
				}
				else if (height_bound >= 0 &&
						 known_dim(img->height_source) &&
						 height_bound < img->height_exact) {
					img->height = html_dim_to_unsigned(ceilf(height_bound));
					img->height_exact = height_bound;
				}

				/* Minimums apply to the cascade result, so re-clamp;
				 * a stylesheet minimum is skipped when an inline one is
				 * specified, as the latter overrides it entirely */
				if (css_block->min_width_mask == 1 &&
					!inline_min_width_wins) {
					if (img->min_source & 0x2) {
						/* An !important stylesheet minimum replaces
						 * the inline one entirely */
						img->min_width = css_block->min_width;
					}
					else if (css_block->min_width >
							 img->min_width) {
						img->min_width = css_block->min_width;
					}
				}

				if (css_block->min_height_mask == 1 &&
					!inline_min_height_wins) {
					if (img->min_source & 0x1) {
						/* An !important stylesheet minimum replaces
						 * the inline one entirely */
						img->min_height = css_block->min_height;
					}
					else if (css_block->min_height >
							 img->min_height) {
						img->min_height = css_block->min_height;
					}
				}

				if (known_dim(img->width_source) &&
					img->min_width > img->width_exact) {
					img->width = html_dim_to_unsigned(ceilf(img->min_width));
					img->width_exact = img->min_width;
				}

				if (known_dim(img->height_source) &&
					img->min_height > img->height_exact) {
					img->height = html_dim_to_unsigned(ceilf(img->min_height));
					img->height_exact = img->min_height;
				}
			}

			/* A percent minimum resolves against the container and may
			 * raise the size above the tiny threshold, so the size
			 * cannot be classified as tiny then; an inline minimum of
			 * the same axis overrides a stylesheet one entirely */
			if ((css_block->min_width_mask == 2 &&
				 !inline_min_width_wins) ||
				((img->min_source & 0x8) &&
				 inline_min_width_wins)) {
				img->width_source = dim_src_unknown;
			}

			if ((css_block->min_height_mask == 2 &&
				 !inline_min_height_wins) ||
				((img->min_source & 0x4) &&
				 inline_min_height_wins)) {
				img->height_source = dim_src_unknown;
			}

			auto is_tiny = known_dim(img->width_source) &&
						   known_dim(img->height_source) &&
						   html_image_is_tiny(img->width_exact, img->height_exact);

			count_tiny_external(was_tiny, is_tiny);
		}
	}
	else {
		/* Without a stylesheet, inline max bounds and minimums still
		 * resize the image for the classification */
		for (auto *img: hc->images) {
			if (!(img->flags & RSPAMD_HTML_FLAG_IMAGE_EXTERNAL)) {
				continue;
			}

			auto was_tiny = known_dim(img->width_source) &&
							known_dim(img->height_source) &&
							html_image_is_tiny(img->width_exact, img->height_exact);

			auto width_bound = no_image_bound;

			if (img->max_source & 0x2) {
				width_bound = img->max_width;
			}

			if (width_bound >= 0 &&
				(width_bound <= 4.0 ||
				 (known_dim(img->height_source) &&
				  html_image_is_tiny(width_bound, img->height_exact))) &&
				(!known_dim(img->width_source) ||
				 width_bound < img->width_exact)) {
				/* The bound itself is within the tiny threshold, so
				 * the size is tiny whatever it actually is */
				img->width = html_dim_to_unsigned(ceilf(width_bound));
				img->width_exact = width_bound;
				img->width_source = dim_src_stylesheet;
			}
			else if (width_bound >= 0 &&
					 known_dim(img->width_source) &&
					 width_bound < img->width_exact) {
				img->width = html_dim_to_unsigned(ceilf(width_bound));
				img->width_exact = width_bound;
			}

			auto height_bound = no_image_bound;

			if (img->max_source & 0x1) {
				height_bound = img->max_height;
			}

			if (height_bound >= 0 &&
				(height_bound <= 4.0 ||
				 (known_dim(img->width_source) &&
				  html_image_is_tiny(img->width_exact, height_bound))) &&
				(!known_dim(img->height_source) ||
				 height_bound < img->height_exact)) {
				img->height = html_dim_to_unsigned(ceilf(height_bound));
				img->height_exact = height_bound;
				img->height_source = dim_src_stylesheet;
			}
			else if (height_bound >= 0 &&
					 known_dim(img->height_source) &&
					 height_bound < img->height_exact) {
				img->height = html_dim_to_unsigned(ceilf(height_bound));
				img->height_exact = height_bound;
			}

			if (known_dim(img->width_source) && img->min_width > img->width_exact) {
				img->width = html_dim_to_unsigned(ceilf(img->min_width));
				img->width_exact = img->min_width;
			}

			if (known_dim(img->height_source) && img->min_height > img->height_exact) {
				img->height = html_dim_to_unsigned(ceilf(img->min_height));
				img->height_exact = img->min_height;
			}

			/* A percent minimum may raise the size above the tiny
			 * threshold, so the size cannot be classified as tiny */
			if (img->min_source & 0x8) {
				img->width_source = dim_src_unknown;
			}

			if (img->min_source & 0x4) {
				img->height_source = dim_src_unknown;
			}

			auto is_tiny = known_dim(img->width_source) &&
						   known_dim(img->height_source) &&
						   html_image_is_tiny(img->width_exact, img->height_exact);

			count_tiny_external(was_tiny, is_tiny);
		}
	}

	if (!hc->all_tags.empty() && hc->root_tag) {
		html_append_tag_content(pool, start, end - start, hc, hc->root_tag,
								exceptions, url_set,
								task->cfg ? (lua_State *) task->cfg->lua_state : NULL,
								max_urls);
	}

	/*
	 * Past the tags limit no tags are created, but the rest of the input is
	 * still read as a browser does instead of being taken as text: markup is
	 * dropped, links are registered and their displayed text is checked (for
	 * phishing), and image urls are registered.
	 *
	 * Text hidden by the inline style or the `hidden` attribute of the element
	 * it is in is not visible text, as in the tree: it goes to `hc->invisible`,
	 * and a link in such an element is flagged as invisible. The open elements
	 * are kept as small records (a tag id and what the element hides), pushed
	 * by a start tag and popped by the end tag that matches. The records are
	 * limited in number; an element past the limit is not tracked and shows
	 * its text, as everything else does when something is not known.
	 *
	 * What this does not know: colours (text of the colour of its background
	 * is read as visible), stylesheet rules with combinators (the elements
	 * have no ancestors here), implied end tags other than the common ones among
	 * the innermost elements, and the stylesheet rules of the elements open where the tags
	 * end are known only through the tree, which has applied them by then.
	 */
	auto scan_after_tags_limit = [&](const char *from, struct rspamd_url *link_at_limit) -> void {
		html_tag scratch;
		const char *pos = from, *text_start = from, *quote_lookahead = nullptr;
		char quote_lookahead_char = 0;
		/* The text of a link open where the tags end continues here */
		struct rspamd_url *open_link = link_at_limit;
		std::size_t open_link_offset = hc->parsed.size();
		/* Open svg and math elements: CDATA is text in them */
		unsigned int foreign_depth = 0;
		/* Open svg elements: a link in them may go to xlink:href */
		unsigned int svg_depth = svg_at_limit;
		auto *L = task->cfg ? (lua_State *) task->cfg->lua_state : nullptr;

		/* What an open element hides, and how many are tracked or built */
		struct open_record {
			std::int32_t id;
			/* display:none, a tiny font or a clip: nothing shows it again */
			bool hard;
			/* visibility:hidden: a descendant with visibility:visible shows it */
			bool vis_hidden;
		};
		/* The elements open past the limit that are tracked, besides those open at it */
		constexpr std::size_t max_open_records = 4096;
		std::size_t record_limit = max_open_records + open_chain.size();
		constexpr unsigned int max_past_limit_blocks = 131072;
		std::vector<open_record> open_records;
		std::array<std::uint32_t, Tag_MAX> known_open{};
		ankerl::unordered_dense::map<std::int32_t, std::uint32_t> unknown_open;
		unsigned int styles_compiled = 0, rules_matched = 0;

		auto is_tracked_id = [](std::int32_t id) -> bool {
			return (id > Tag_UNKNOWN && id < Tag_MAX) || (id < 0 && id != N_TAGS);
		};
		auto open_count = [&](std::int32_t id) -> std::uint32_t {
			if (id > Tag_UNKNOWN && id < Tag_MAX) {
				return known_open[id];
			}

			auto it = unknown_open.find(id);

			return it == unknown_open.end() ? 0 : it->second;
		};
		auto count_open = [&](std::int32_t id, bool opened) -> void {
			if (id > Tag_UNKNOWN && id < Tag_MAX) {
				known_open[id] += opened ? 1 : -1;
			}
			else if (opened) {
				unknown_open[id]++;
			}
			else if (auto it = unknown_open.find(id); it != unknown_open.end() && --it->second == 0) {
				unknown_open.erase(it);
			}
		};
		auto push_record = [&](const open_record &rec) -> void {
			if (open_records.size() < record_limit && is_tracked_id(rec.id)) {
				open_records.push_back(rec);
				count_open(rec.id, true);
			}
		};
		/* Pops down to the nearest open element with the id; false if none is open */
		auto pop_record = [&](std::int32_t id, bool &was_hidden) -> bool {
			if (!is_tracked_id(id) || open_count(id) == 0) {
				return false;
			}

			while (!open_records.empty()) {
				auto rec = open_records.back();

				open_records.pop_back();
				count_open(rec.id, false);

				if (rec.id == id) {
					was_hidden = rec.hard || rec.vis_hidden;
					break;
				}
			}

			return true;
		};
		auto top_hidden = [&]() -> bool {
			return !open_records.empty() &&
				   (open_records.back().hard || open_records.back().vis_hidden);
		};
		/* The criteria of html_block::compute_visibility for a block alone, but colours */
		auto hides_by_itself = [](const html_block &b) -> bool {
			if (b.display_mask && b.display == css::css_display_value::DISPLAY_HIDDEN) {
				return true;
			}

			if (b.font_mask && b.font_size >= 0 && b.font_size <= 3) {
				return true;
			}

			return b.overflow_mask && b.overflow_hidden &&
				   ((b.height_mask && b.height == 0) || (b.width_mask && b.width == 0));
		};
		/* Whether the start tag `id` ends the open element `open_id`, which has no end tag then */
		auto implies_end_of = [](std::int32_t open_id, std::int32_t id, unsigned int flags) -> bool {
			switch (open_id) {
			case Tag_P:
				return id == Tag_P || (flags & (CM_BLOCK | CM_TABLE));
			case Tag_LI:
				return id == Tag_LI;
			case Tag_DT:
			case Tag_DD:
				return id == Tag_DT || id == Tag_DD;
			case Tag_TD:
			case Tag_TH:
				return id == Tag_TD || id == Tag_TH || id == Tag_TR || id == Tag_TBODY ||
					   id == Tag_THEAD || id == Tag_TFOOT;
			case Tag_TR:
				return id == Tag_TR || id == Tag_TBODY || id == Tag_THEAD || id == Tag_TFOOT;
			case Tag_OPTION:
				return id == Tag_OPTION || id == Tag_OPTGROUP;
			default:
				return false;
			}
		};
		/* The element is what its parent on the stack makes it, and what its block says */
		auto record_for = [&](std::int32_t id, const html_block *own) -> open_record {
			open_record rec{id, false, false};

			if (!open_records.empty()) {
				rec.hard = open_records.back().hard;
				rec.vis_hidden = open_records.back().vis_hidden;
			}

			if (own) {
				rec.hard = rec.hard || hides_by_itself(*own);

				if (own->visibility_prop_mask) {
					rec.vis_hidden = own->visibility_hidden;
				}
			}

			return rec;
		};
		/*
		 * The block of the tag in `scratch` from its inline style and `hidden`
		 * attribute, and from the stylesheet rules of a single compound
		 * (`.cls`, `#id`, `tag.cls`): check_tag_block finds no ancestors or
		 * siblings of a tag that is not in the tree, so the others do not
		 * match. Both allocate from the pool only for a tag that has a style
		 * or matches a rule, and are limited in number
		 */
		auto block_of = [&](html_tag &tag) -> const html_block * {
			if (styles_compiled < max_past_limit_blocks && (tag.find_style() || tag.is_hidden())) {
				styles_compiled++;
				html_process_block_tag(pool, &tag, hc);
			}

			if (hc->css_style && rules_matched < max_past_limit_blocks &&
				tag.id != Tag_UNKNOWN && tag.id < Tag_MAX) {
				if (auto *css_block = hc->css_style->check_tag_block(&tag)) {
					rules_matched++;

					if (tag.block) {
						tag.block->set_block(*css_block);
					}
					else {
						tag.block = css_block;
					}
				}
			}

			if (tag.block) {
				static const html_block undefined_parent{};

				tag.block->resolve_sizes(undefined_parent);
			}

			return tag.block;
		};

		auto append_text = [&](const char *upto, bool literal = false) -> void {
			if (upto > text_start) {
				html_append_parsed(hc, {text_start, (std::size_t) (upto - text_start)},
								   false, end - start,
								   top_hidden() ? hc->invisible : hc->parsed, literal);
			}
		};
		/* As the default display of a tag in html_append_tag_content */
		auto append_separator = [&](int id, unsigned int flags, bool hidden) -> void {
			char sep = 0;

			if (hidden) {
				return;
			}

			if (id == Tag_BR || id == Tag_HR || (flags & (CM_BLOCK | CM_TABLE))) {
				sep = '\n';
			}
			else if (flags & CM_ROW) {
				sep = ' ';
			}

			if (sep && !hc->parsed.empty() && !g_ascii_isspace(hc->parsed.back())) {
				hc->parsed.push_back(sep);
			}
		};
		/* Comments end at `-->` or `--!>`, or right away as `<!-->` and `<!--->` */
		auto skip_comment = [&](const char *body) -> const char * {
			if (body < end && *body == '>') {
				return body + 1;
			}

			if (end - body >= 2 && body[0] == '-' && body[1] == '>') {
				return body + 2;
			}

			for (const char *dashes = body; dashes < end;) {
				auto found = rspamd_substring_search(dashes, end - dashes, "--", 2);

				if (found == -1) {
					break;
				}

				const char *after = dashes + found + 2;

				if (after < end && *after == '>') {
					return after + 1;
				}

				if (end - after >= 2 && after[0] == '!' && after[1] == '>') {
					return after + 2;
				}

				dashes = dashes + found + 1;
			}

			return end;
		};
		auto close_link = [&]() -> void {
			if (open_link != nullptr) {
				std::string_view displayed{hc->parsed.data() + open_link_offset,
										   hc->parsed.size() - open_link_offset};

				html_check_displayed_url(pool, exceptions, url_set, displayed,
										 open_link_offset, open_link, L, max_urls);
				open_link = nullptr;
			}
		};
		/* Position after `what` (case insensitive) starting at `from`, or end */
		auto skip_past = [&](const char *search_from, std::string_view what) -> const char * {
			if (search_from >= end) {
				return end;
			}

			auto found = rspamd_substring_search_caseless(search_from, end - search_from,
														  what.data(), what.size());

			return found == -1 ? end : search_from + found + what.size();
		};
		auto register_image = [&](std::string_view src) -> void {
			auto has_prefix = [&](std::string_view prefix) -> bool {
				return src.size() > prefix.size() &&
					   g_ascii_strncasecmp(src.data(), prefix.data(), prefix.size()) == 0;
			};

			/* Embedded images have no url */
			if (src.empty() || has_prefix("cid:") || has_prefix("data:")) {
				return;
			}

			html_resolve_against_base(pool, src, hc);
			auto maybe_url = html_process_url(pool, src, L);

			if (maybe_url) {
				hc->features.images_external++;
				auto *img_url = maybe_url.value();
				img_url->flags |= RSPAMD_URL_FLAG_IMAGE;

				if (url_set != nullptr) {
					auto *existing = rspamd_url_set_add_or_return(url_set, img_url, max_urls);

					if (existing == nullptr) {
						return;
					}
					else if (existing != img_url) {
						/* A known url does not become an image-only one */
						existing->flags |= img_url->flags & ~RSPAMD_URL_FLAG_IMAGE;
						existing->count++;
						img_url = existing;
					}
				}

				html_part_add_url(part_urls, img_url);
			}
		};

		/*
		 * The elements open where the tags end hide the text that follows as
		 * the tree has settled it (their blocks have been through the
		 * propagation, stylesheet rules included). Nothing is tracked while
		 * none of them hides anything. The head is not tracked: a body tag
		 * past the limit would have to end it
		 */
		{
			std::vector<open_record> seeds;
			bool in_head = false, link_hidden = false;
			const html_tag *link_tag = nullptr;

			for (const auto *t: open_chain) {
				if (t->id == Tag_A) {
					link_tag = t;
					break;
				}
			}

			for (auto it = open_chain.rbegin(); it != open_chain.rend(); ++it) {
				const auto *t = *it;

				if (t->flags & (CM_HEAD | FL_IGNORE)) {
					in_head = true;
				}

				if (t->flags & FL_VIRTUAL) {
					continue;
				}

				open_record rec{t->id, false, false};

				if (!in_head && t->block) {
					rec.hard = hides_by_itself(*t->block);
					rec.vis_hidden = t->block->visibility_prop_mask && t->block->visibility_hidden;
				}

				seeds.push_back(rec);

				if (t == link_tag) {
					link_hidden = rec.hard || rec.vis_hidden;
				}
			}

			/*
			 * All of them, hidden or not: an end tag of one of them ends the
			 * elements opened after it, a hidden one among those included
			 */
			for (const auto &seed: seeds) {
				push_record(seed);
			}

			record_limit = open_records.size() + max_open_records;

			/* Its text is not in the visible text to check against */
			if (link_hidden) {
				open_link = nullptr;
			}
		}

		while (pos < end) {
			if (*pos != '<') {
				pos++;
				continue;
			}

			const char *next = pos + 1;

			if (next < end && (*next == '!' || *next == '?')) {
				/* Comments, declarations and processing instructions */
				append_text(pos);

				if (end - pos >= 4 && memcmp(pos, "<!--", 4) == 0) {
					pos = skip_comment(pos + 4);
				}
				else if (foreign_depth > 0 && end - pos >= 9 && memcmp(pos, "<![CDATA[", 9) == 0) {
					/* Text in svg and math */
					text_start = pos + 9;
					pos = skip_past(text_start, "]]>");
					append_text(pos == end ? end : pos - 3, true);
				}
				else {
					pos = skip_past(next, ">");
				}

				text_start = pos;
				continue;
			}

			if (next < end && *next == '/' && next + 1 < end && g_ascii_isalpha(next[1])) {
				/* Closing tag */
				const char *name = next + 1, *name_end = name;

				while (name_end < end && g_ascii_isalnum(*name_end)) {
					name_end++;
				}

				append_text(pos);
				std::string lc_name{name, (std::size_t) (name_end - name)};
				rspamd_str_lc(lc_name.data(), lc_name.size());
				const auto *def = html_tags_defs.by_name(lc_name);

				bool end_hidden = top_hidden();

				if (!open_records.empty()) {
					/* The name of a tag is read up to a space, `>` or `/` */
					auto full_end = name;

					while (full_end < end && !g_ascii_isspace(*full_end) && *full_end != '>' &&
						   *full_end != '/') {
						full_end++;
					}

					std::string full_name{name, (std::size_t) (full_end - name)};
					rspamd_str_lc(full_name.data(), full_name.size());
					const auto *known = html_tags_defs.by_name(full_name);
					std::int32_t closed_id = known ? (std::int32_t) known->id : html_unknown_tag_id(full_name);

					/* Browsers do not end elements by these two */
					if (closed_id != Tag_BODY && closed_id != Tag_HTML) {
						pop_record(closed_id, end_hidden);
					}
				}

				if (def != nullptr) {
					if (def->id == Tag_A) {
						close_link();
					}
					else if (def->id == Tag_SVG || def->id == Tag_MATH) {
						if (foreign_depth > 0) {
							foreign_depth--;
						}

						/* An svg open where the tags end is counted here only */
						if (def->id == Tag_SVG && svg_depth > 0) {
							svg_depth--;
						}
					}

					append_separator(def->id, def->flags, end_hidden);
				}

				pos = skip_past(name_end, ">");
				text_start = pos;
				continue;
			}

			if (next >= end || !g_ascii_isalpha(*next)) {
				/* Not markup, `<` is text then */
				pos++;
				continue;
			}

			/* Opening tag: parse it with the tag content parser */
			append_text(pos);
			scratch.clear();
			content_parser_env.reset();
			const char *tag_end = end;

			for (const char *t = next; t < end; t++) {
				html_parse_tag_content(pool, hc, &scratch, t, content_parser_env);

				if (*t == '>') {
					auto quoted = content_parser_env.cur_state == parse_dqvalue ||
								  content_parser_env.cur_state == parse_sqvalue;

					if (quoted) {
						/* `>` in a quoted value, unless the value is never closed */
						auto end_quote = content_parser_env.cur_state == parse_sqvalue ? '\'' : '"';

						if (quote_lookahead == nullptr || quote_lookahead_char != end_quote ||
							quote_lookahead < t) {
							quote_lookahead = (const char *) memchr(t, end_quote, end - t);
							quote_lookahead_char = end_quote;

							if (quote_lookahead == nullptr) {
								quote_lookahead = end;
							}
						}

						if (quote_lookahead != end) {
							continue;
						}
					}

					tag_end = t + 1;
					break;
				}
			}

			content_parser_env.reset();
			pos = tag_end;
			text_start = pos;

			/*
			 * Namespaces are not tracked here: a link in svg reads xlink:href,
			 * and controls are taken as HTML ones, not to miss a destination
			 */
			if (scratch.id == Tag_A && svg_depth > 0) {
				scratch.flags |= FL_SVG;
			}

			/*
			 * A start tag ends an open element whose end tag is optional, also
			 * with inline elements open in it (`<p hidden><b>x<p>y` shows y).
			 * It is looked for among the innermost records only, up to an
			 * element that bounds a scope; done again for a cell in a row
			 */
			for (auto round = 0; round < 3; round++) {
				constexpr std::size_t max_implied_steps = 64;
				const auto nrecords = open_records.size();
				std::int32_t implied_id = Tag_UNKNOWN;

				for (std::size_t i = 0; i < nrecords && i < max_implied_steps; i++) {
					const auto rec_id = open_records[nrecords - 1 - i].id;

					if (implies_end_of(rec_id, scratch.id, scratch.flags)) {
						implied_id = rec_id;
						break;
					}

					if (rec_id == Tag_TABLE || rec_id == Tag_CAPTION || rec_id == Tag_HTML ||
						rec_id == Tag_BUTTON || rec_id == Tag_OBJECT || rec_id == Tag_TD ||
						rec_id == Tag_TH || rec_id == Tag_UL || rec_id == Tag_OL) {
						break;
					}
				}

				if (implied_id == Tag_UNKNOWN) {
					break;
				}

				bool popped_hidden = false;

				pop_record(implied_id, popped_hidden);
			}

			const bool self_closed = (scratch.flags & FL_CLOSED) &&
									 (foreign_depth > 0 || scratch.id == Tag_SVG || scratch.id == Tag_MATH);
			const auto own_rec = record_for(scratch.id, block_of(scratch));
			const bool tag_hidden = own_rec.hard || own_rec.vis_hidden;

			html_tag_mark_submit_link(&scratch);

			if (auto clickable = scratch.clickable_attr()) {
				/* Not in the tree, but URL rewriting replaces it as well */
				hc->add_clickable_past_limit(clickable.value());
			}

			/* FL_BROKEN is set on markup browsers still take, such as <a/href=...> */
			if (scratch.flags & FL_HREF) {
				auto maybe_url = process_href_tag_past_limit(&scratch);

				if (tag_hidden && maybe_url.has_value() && maybe_url.value() != nullptr) {
					maybe_url.value()->flags |= RSPAMD_URL_FLAG_INVISIBLE;
				}

				if (scratch.id == Tag_A) {
					/* A link ends the previous one */
					close_link();

					/* The text of a hidden link is not visible text to check */
					if (!tag_hidden && maybe_url.has_value() && maybe_url.value() != nullptr) {
						open_link = maybe_url.value();
						open_link_offset = hc->parsed.size();
					}
				}
			}
			else if (scratch.id == Tag_BASE) {
				auto maybe_base = html_process_url_tag(pool, &scratch, hc, L);

				if (maybe_base && hc->base_url == nullptr) {
					hc->base_url = maybe_base.value();
					/* Links are resolved against it from now on */
					past_limit_hrefs.clear();
				}
			}
			else if (scratch.id == Tag_IMG) {
				/* Images past the tags limit cannot be classified by
				 * their dimensions, but they still count, whether they
				 * carry a source or a srcset only, so that a pixel
				 * parsed before the limit cannot remain the only image */
				hc->features.images_total++;

				if (auto src = scratch.find_component<html_component_src>()) {
					register_image(src.value()->value);
				}

				/* Alt text is shown instead of the image, as in the tree */
				if (auto alt = scratch.find_alt(); alt && !alt->empty() && !tag_hidden) {
					if (!hc->parsed.empty() && !g_ascii_isspace(hc->parsed.back())) {
						hc->parsed += ' ';
					}

					hc->parsed.append(alt.value());
					hc->parsed += ' ';
				}
			}
			else if ((scratch.id == Tag_SVG || scratch.id == Tag_MATH) &&
					 !(scratch.flags & FL_CLOSED)) {
				foreign_depth++;

				if (scratch.id == Tag_SVG) {
					svg_depth++;
				}
			}

			append_separator(scratch.id, scratch.flags, tag_hidden);

			if (!(scratch.flags & CM_EMPTY) && !self_closed) {
				push_record(own_rec);
			}

			if (html_is_raw_text_tag(scratch.id) && !(scratch.flags & CM_EMPTY)) {
				/* Its content is raw text up to its end tag; nothing ends plaintext */
				const char *raw_end = end;

				if (scratch.id != Tag_PLAINTEXT) {
					auto close_name = fmt::format("</{}", html_tags_defs.name_by_id_safe(scratch.id));

					for (const char *search = pos; search < end;) {
						auto found = rspamd_substring_search_caseless(search, end - search,
																	  close_name.data(), close_name.size());

						if (found == -1) {
							break;
						}

						if (html_is_raw_text_end_tag({search + found, (std::size_t) (end - search - found)},
													 scratch.id)) {
							raw_end = search + found;
							break;
						}

						search += found + 1;
					}
				}

				if (scratch.id == Tag_TEXTAREA || scratch.id == Tag_XMP ||
					scratch.id == Tag_PLAINTEXT) {
					/* Shown; only textarea decodes character references */
					append_text(raw_end, scratch.id != Tag_TEXTAREA);
				}

				pos = raw_end;
				text_start = pos;
			}
		}

		append_text(end);
		close_link();
	};

	/* Leftover after content */
	switch (state) {
	case tags_limit_overflow:
		scan_after_tags_limit(c, link_at_limit);
		break;
	default:
		/* Do nothing */
		break;
	}

	if (overflow_input) {
		/*
		 * Append the rest of the input as raw html, this might work as
		 * further algorithms can skip words when auto *pool = task->task_pool;there are too many.
		 * It is still unclear about urls though...
		 */
		html_append_parsed(hc, {end, in->len - process_size}, false,
						   end - start, hc->parsed);
	}

	if (!hc->parsed.empty()) {
		/* Trim extra spaces at the end if needed */
		if (g_ascii_isspace(hc->parsed.back())) {
			auto last_it = std::end(hc->parsed);

			/* Allow last newline */
			if (hc->parsed.back() == '\n') {
				--last_it;
			}

			hc->parsed.erase(std::find_if(hc->parsed.rbegin(), hc->parsed.rend(),
										  [](auto ch) -> auto {
											  return !g_ascii_isspace(ch);
										  })
								 .base(),
							 last_it);
		}
	}

	/* Finalize derived link domain counters */
	if (!hc->link_domain_counts.empty()) {
		hc->features.links.domains_total = (unsigned int) hc->link_domain_counts.size();
	}

	/* Mirror parser flags into features */
	hc->features.flags = (unsigned int) hc->flags;

	/* Clamp visibility counters to input length */
	{
		unsigned int total_decoded = hc->features.text_visible + hc->features.text_hidden;
		if (total_decoded > (unsigned int) (end - start)) {
			/* Best-effort clamp */
			unsigned int excess = total_decoded - (unsigned int) (end - start);
			if (hc->features.text_hidden >= excess) {
				hc->features.text_hidden -= excess;
			}
			else {
				hc->features.text_visible -= (excess - hc->features.text_hidden);
				hc->features.text_hidden = 0;
			}
		}
	}

	html_compute_cta_weights(*hc);

	return hc;
}

static auto
html_find_image_by_cid(const html_content &hc, std::string_view cid)
	-> std::optional<const html_image *>
{
	for (const auto *html_image: hc.images) {
		/* Filter embedded images */
		if (html_image->flags & RSPAMD_HTML_FLAG_IMAGE_EMBEDDED &&
			html_image->src != nullptr) {
			if (cid == html_image->src) {
				return html_image;
			}
		}
	}

	return std::nullopt;
}

auto html_debug_structure(const html_content &hc) -> std::string
{
	std::string output;

	if (hc.root_tag) {
		std::vector<std::pair<const html_tag *, int>> stack{{hc.root_tag, 1}};

		while (!stack.empty()) {
			auto [t, level] = stack.back();
			stack.pop_back();

			if (!(t->flags & (FL_VIRTUAL | FL_IGNORE))) {
				std::string pluses(level, '+');

				if (t->flags & FL_XML) {
					output += fmt::format("{}xml;", pluses);
				}
				else {
					output += fmt::format("{}{};", pluses,
										  html_tags_defs.name_by_id_safe(t->id));
				}
				level++;
			}

			for (auto it = t->children.rbegin(); it != t->children.rend(); ++it) {
				stack.emplace_back(*it, level);
			}
		}
	}

	return output;
}

auto html_tag_by_name(const std::string_view &name)
	-> std::optional<tag_id_t>
{
	const auto *td = rspamd::html::html_tags_defs.by_name(name);

	if (td != nullptr) {
		return td->id;
	}

	return std::nullopt;
}

auto html_tag::get_content(const struct html_content *hc) const -> std::string_view
{
	const std::string *dest = (flags & FL_CONTENT_INVISIBLE) ? &hc->invisible : &hc->parsed;
	const auto clen = get_content_length();
	if (content_offset < dest->size()) {
		if (dest->size() - content_offset >= clen) {
			return std::string_view{*dest}.substr(content_offset, clen);
		}
		else {
			return std::string_view{*dest}.substr(content_offset, dest->size() - content_offset);
		}
	}

	return std::string_view{};
}

}// namespace rspamd::html

void *
rspamd_html_process_part_full(struct rspamd_task *task,
							  GByteArray *in, GList **exceptions,
							  khash_t(rspamd_url_hash) * url_set,
							  GPtrArray *part_urls,
							  bool allow_css,
							  uint16_t *cur_url_order)
{
	return rspamd::html::html_process_input(task, in, exceptions, url_set,
											part_urls, allow_css, cur_url_order);
}

void *
rspamd_html_process_part(rspamd_mempool_t *pool,
						 GByteArray *in)
{
	struct rspamd_task fake_task;
	memset(&fake_task, 0, sizeof(fake_task));
	fake_task.task_pool = pool;
	uint16_t order = 0;

	return rspamd_html_process_part_full(&fake_task, in, NULL,
										 NULL, NULL, FALSE, &order);
}

unsigned int rspamd_html_decode_entitles_inplace(char *s, gsize len)
{
	return rspamd::html::decode_html_entitles_inplace(s, len);
}

int rspamd_html_tag_by_name(const char *name)
{
	const auto *td = rspamd::html::html_tags_defs.by_name(name);

	if (td != nullptr) {
		return td->id;
	}

	return -1;
}

gboolean
rspamd_html_tag_seen(void *ptr, const char *tagname)
{
	int id;
	auto *hc = rspamd::html::html_content::from_ptr(ptr);

	g_assert(hc != NULL);

	id = rspamd_html_tag_by_name(tagname);

	if (id != -1) {
		return hc->tags_seen[id];
	}

	return FALSE;
}

const char *
rspamd_html_tag_by_id(int id)
{
	if (id > Tag_UNKNOWN && id < Tag_MAX) {
		const auto *td = rspamd::html::html_tags_defs.by_id(id);

		if (td != nullptr) {
			return td->name.c_str();
		}
	}

	return nullptr;
}

float rspamd_html_url_button_weight(void *html_content, struct rspamd_url *u)
{
	if (html_content == NULL || u == NULL) return 0.0f;
	auto *hc = rspamd::html::html_content::from_ptr(html_content);
	auto it = hc->url_button_weights.find(u);
	if (it != hc->url_button_weights.end()) {
		return it->second;
	}

	return 0.0f;
}

const struct rspamd_html_features *
rspamd_html_get_features(void *html_content)
{
	if (html_content == NULL) {
		return NULL;
	}

	auto *hc = rspamd::html::html_content::from_ptr(html_content);
	return &hc->features;
}

const char *
rspamd_html_tag_name(void *p, gsize *len)
{
	auto *tag = reinterpret_cast<rspamd::html::html_tag *>(p);
	auto tname = rspamd::html::html_tags_defs.name_by_id_safe(tag->id);

	if (len) {
		*len = tname.size();
	}

	return tname.data();
}

struct html_image *
rspamd_html_find_embedded_image(void *html_content,
								const char *cid, gsize cid_len)
{
	auto *hc = rspamd::html::html_content::from_ptr(html_content);

	auto maybe_img = rspamd::html::html_find_image_by_cid(*hc, {cid, cid_len});

	if (maybe_img) {
		return (html_image *) maybe_img.value();
	}

	return nullptr;
}

void rspamd_html_link_embedded_images(void *html_content,
									  GHashTable *cid_images)
{
	auto *hc = rspamd::html::html_content::from_ptr(html_content);

	for (auto *html_image: hc->images) {
		if (html_image->flags & RSPAMD_HTML_FLAG_IMAGE_EMBEDDED &&
			html_image->src != nullptr) {
			auto *parsed_image = static_cast<rspamd_image *>(
				g_hash_table_lookup(cid_images, html_image->src));

			if (parsed_image != nullptr) {
				parsed_image->html_image = html_image;
				html_image->embedded_image = parsed_image;

				if (html_image->height == 0) {
					html_image->height = parsed_image->height;
				}

				if (html_image->width == 0) {
					html_image->width = parsed_image->width;
				}
			}
		}
	}
}

bool rspamd_html_get_parsed_content(void *html_content, rspamd_ftok_t *dest)
{
	auto *hc = rspamd::html::html_content::from_ptr(html_content);

	dest->begin = hc->parsed.data();
	dest->len = hc->parsed.size();

	return true;
}

gsize rspamd_html_get_tags_count(void *html_content)
{
	auto *hc = rspamd::html::html_content::from_ptr(html_content);

	if (!hc) {
		return 0;
	}

	return hc->all_tags.size();
}
