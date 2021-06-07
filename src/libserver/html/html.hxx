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

namespace rspamd::html {

struct html_content {
	struct rspamd_url *base_url = nullptr;
	struct html_tag *root_tag = nullptr;
	gint flags = 0;
	guint total_tags = 0;
	struct html_color bgcolor;
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
		/* Set white background color by default */
		bgcolor.d.comp.alpha = 0;
		bgcolor.d.comp.r = 255;
		bgcolor.d.comp.g = 255;
		bgcolor.d.comp.b = 255;
		bgcolor.valid = TRUE;
	}

	static void html_content_dtor(void *ptr) {
		delete html_content::from_ptr(ptr);
	}

	static auto from_ptr(void *ptr) -> html_content * {
		return static_cast<html_content* >(ptr);
	}

private:
	~html_content() {
		g_node_destroy(html_tags);
	}
};

}

#endif //RSPAMD_HTML_HXX
