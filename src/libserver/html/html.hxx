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
#include "libserver/html/html_tags.h"


#include <vector>
#include <memory>
#include <string>
#include "function2/function2.hpp"

namespace rspamd::css {
/* Forward declaration */
class css_style_sheet;
}

namespace rspamd::html {

struct html_block;

struct html_content {
	struct rspamd_url *base_url = nullptr;
	struct html_tag *root_tag = nullptr;
	gint flags = 0;
	std::vector<bool> tags_seen;
	std::vector<html_image *> images;
	std::vector<std::unique_ptr<struct html_tag>> all_tags;
	std::string parsed;
	std::string invisible;
	std::shared_ptr<css::css_style_sheet> css_style;

	/* Preallocate and reserve all internal structures */
	html_content() {
		tags_seen.resize(Tag_MAX, false);
		all_tags.reserve(128);
		parsed.reserve(256);
	}

	static void html_content_dtor(void *ptr) {
		delete html_content::from_ptr(ptr);
	}

	static auto from_ptr(void *ptr) -> html_content * {
		return static_cast<html_content* >(ptr);
	}

	enum class traverse_type {
		PRE_ORDER,
		POST_ORDER
	};
	auto traverse_block_tags(fu2::function<bool(const html_tag *)> &&func,
					traverse_type how = traverse_type::PRE_ORDER) const -> bool {

		if (root_tag == nullptr) {
			return false;
		}

		auto rec_functor_pre_order = [&](const html_tag *root, auto &&rec) -> bool {
			if (func(root)) {

				for (const auto *c : root->children) {
					if (!rec(c, rec)) {
						return false;
					}
				}

				return true;
			}
			return false;
		};
		auto rec_functor_post_order = [&](const html_tag *root, auto &&rec) -> bool {
			for (const auto *c : root->children) {
				if (!rec(c, rec)) {
					return false;
				}
			}

			return func(root);
		};

		switch(how) {
		case traverse_type::PRE_ORDER:
			return rec_functor_pre_order(root_tag, rec_functor_pre_order);
		case traverse_type::POST_ORDER:
			return rec_functor_post_order(root_tag, rec_functor_post_order);
		default:
			RSPAMD_UNREACHABLE;
		}
	}

	auto traverse_all_tags(fu2::function<bool(const html_tag *)> &&func) const -> bool {
		for (const auto &tag : all_tags) {
			if (!(tag->flags & (FL_XML|FL_VIRTUAL))) {
				if (!func(tag.get())) {
					return false;
				}
			}
		}

		return true;
	}

private:
	~html_content() = default;
};


auto html_tag_by_name(const std::string_view &name) -> std::optional<tag_id_t>;
auto html_process_input(rspamd_mempool_t *pool,
				   GByteArray *in,
				   GList **exceptions,
				   khash_t (rspamd_url_hash) *url_set,
				   GPtrArray *part_urls,
				   bool allow_css) -> html_content *;
auto html_debug_structure(const html_content &hc) -> std::string;

}

#endif //RSPAMD_HTML_HXX
