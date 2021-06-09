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
#include "function2/function2.hpp"

namespace rspamd::html {

struct html_block;

struct html_content {
	struct rspamd_url *base_url = nullptr;
	struct html_tag *root_tag = nullptr;
	gint flags = 0;
	guint total_tags = 0;
	std::vector<bool> tags_seen;
	std::vector<html_image *> images;
	std::vector<html_block *> blocks;
	std::vector<std::unique_ptr<struct html_tag>> all_tags;
	std::string parsed;
	void *css_style;

	/* Preallocate and reserve all internal structures */
	html_content() {
		tags_seen.resize(N_TAGS, false);
		blocks.reserve(128);
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
	auto traverse_tags(fu2::function<bool(const html_tag *)> &&func,
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

private:
	~html_content() = default;
};


}

#endif //RSPAMD_HTML_HXX
