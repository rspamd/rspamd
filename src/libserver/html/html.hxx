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

#ifndef RSPAMD_HTML_HXX
#define RSPAMD_HTML_HXX
#pragma once

#include "config.h"
#include "libserver/url.h"
#include "libserver/html/html_tag.hxx"
#include "libserver/html/html.h"
#include "libserver/html/html_features.h"
#include "libserver/html/html_tags.h"


#include <vector>
#include <array>
#include <algorithm>
#include "contrib/ankerl/unordered_dense.h"
#include <memory>
#include <string>
#include "function2/function2.hpp"

namespace rspamd::css {
/* Forward declaration */
class css_style_sheet;
}// namespace rspamd::css

namespace rspamd::html {

struct html_block;

struct html_content {
	struct rspamd_url *base_url = nullptr;
	struct html_tag *root_tag = nullptr;
	int flags = 0;
	std::vector<bool> tags_seen;
	std::vector<html_image *> images;
	std::vector<std::unique_ptr<struct html_tag>> all_tags;
	/*
	 * Comments, declarations and processing instructions in `all_tags`: they
	 * have a budget of their own, so they do not use up the one of elements
	 */
	std::size_t special_tags = 0;
	/*
	 * Links of the tags past the tags limit, which are not kept: one per tag,
	 * so they are kept small
	 */
	struct clickable_past_limit_entry {
		std::string_view value;
		std::uint32_t offset;
		std::uint32_t len;
		std::int32_t tag_id;
		std::uint8_t attr;
	};
	std::vector<clickable_past_limit_entry> clickable_past_limit;
	std::string parsed;
	std::string invisible;
	std::shared_ptr<css::css_style_sheet> css_style;

	/* Aggregated HTML features */
	struct rspamd_html_features features;
	/* Helper: per-domain link counts */
	ankerl::unordered_dense::map<std::string, unsigned int> link_domain_counts;
	/* Heuristic weights for button-like links */
	ankerl::unordered_dense::map<struct rspamd_url *, float> url_button_weights;
	/* First-party eTLD+1 derived from message (e.g. From:) */
	std::string first_party_etld1;

	/* Preallocate and reserve all internal structures */
	html_content()
	{
		tags_seen.resize(Tag_MAX, false);
		all_tags.reserve(128);
		parsed.reserve(256);
		memset(&features, 0, sizeof(features));
		features.version = 1u;
	}

	static void html_content_dtor(void *ptr)
	{
		delete html_content::from_ptr(ptr);
	}

	static auto from_ptr(void *ptr) -> html_content *
	{
		return static_cast<html_content *>(ptr);
	}

	enum class traverse_type {
		PRE_ORDER,
		POST_ORDER
	};
	auto traverse_block_tags(fu2::function<bool(const html_tag *)> &&func,
							 traverse_type how = traverse_type::PRE_ORDER) const -> bool
	{
		if (root_tag == nullptr) {
			return false;
		}

		switch (how) {
		case traverse_type::PRE_ORDER: {
			std::vector<const html_tag *> stack{root_tag};

			while (!stack.empty()) {
				auto *tag = stack.back();
				stack.pop_back();

				if (!func(tag)) {
					return false;
				}

				for (auto it = tag->children.rbegin(); it != tag->children.rend(); ++it) {
					stack.push_back(*it);
				}
			}

			return true;
		}
		case traverse_type::POST_ORDER: {
			using stack_entry = std::pair<const html_tag *, bool>;
			std::vector<stack_entry> stack{{root_tag, false}};

			while (!stack.empty()) {
				auto [tag, visited] = stack.back();
				stack.pop_back();

				if (visited) {
					if (!func(tag)) {
						return false;
					}
				}
				else {
					stack.emplace_back(tag, true);
					for (auto it = tag->children.rbegin(); it != tag->children.rend(); ++it) {
						stack.emplace_back(*it, false);
					}
				}
			}

			return true;
		}
		default:
			RSPAMD_UNREACHABLE;
		}
	}

	auto traverse_all_tags(fu2::function<bool(const html_tag *)> &&func) const -> bool
	{
		for (const auto &tag: all_tags) {
			if (!(tag->flags & (FL_XML | FL_VIRTUAL))) {
				if (!func(tag.get())) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Enumerate the links URL rewriting replaces (see html_tag::clickable_attr), with their spans
	 * @param callback function(clickable) -> bool (return false to stop iteration)
	 */
	static constexpr std::array<std::string_view, 3> clickable_attr_names{"href", "xlink:href", "src"};

	auto for_each_clickable_attr(fu2::function<bool(const html_clickable_attr &)> &&callback) const -> void
	{
		/*
		 * A tag marked broken can still be a link that browsers follow,
		 * such as <a/href=...>: its href is rewritten when its place in
		 * the source is known (a span), as for any other link
		 */
		for (const auto &tag: all_tags) {
			if (auto clickable = tag->clickable_attr()) {
				if (!callback(clickable.value())) {
					return;
				}
			}
		}

		/* Links past the tags limit, which are in no tag of the tree */
		for (const auto &entry: clickable_past_limit) {
			html_clickable_attr clickable{entry.tag_id, clickable_attr_names[entry.attr], entry.value,
										  attr_span{entry.offset, entry.len}};

			if (!callback(clickable)) {
				return;
			}
		}
	}

	auto add_clickable_past_limit(const html_clickable_attr &clickable) -> void
	{
		/* Values that URL rewriting leaves alone are not kept */
		if (clickable.value.empty() || clickable.value.starts_with("data:") ||
			clickable.value.starts_with("cid:") ||
			clickable.span.offset > G_MAXUINT32 || clickable.span.len > G_MAXUINT32) {
			return;
		}

		auto attr = std::find(clickable_attr_names.begin(), clickable_attr_names.end(),
							  clickable.attr_name);

		if (attr == clickable_attr_names.end()) {
			return;
		}

		clickable_past_limit.push_back({clickable.value, (std::uint32_t) clickable.span.offset,
										(std::uint32_t) clickable.span.len, clickable.tag_id,
										(std::uint8_t) (attr - clickable_attr_names.begin())});
	}

private:
	~html_content() = default;
};


auto html_tag_by_name(const std::string_view &name) -> std::optional<tag_id_t>;
auto html_process_input(struct rspamd_task *task,
						GByteArray *in,
						GList **exceptions,
						khash_t(rspamd_url_hash) * url_set,
						GPtrArray *part_urls,
						bool allow_css,
						std::uint16_t *cur_url_order) -> html_content *;
auto html_debug_structure(const html_content &hc) -> std::string;

}// namespace rspamd::html

#endif//RSPAMD_HTML_HXX
