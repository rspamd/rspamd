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

#include "lua_html_url_rewrite.h"
#include "libserver/html/html_url_rewrite.hxx"
#include "libserver/html/html.h"
#include "libserver/html/html.hxx"
#include "libserver/task.h"
#include "message.h"
#include "lua_common.h"

extern "C" {

int lua_task_get_html_urls(lua_State *L)
{
	// Get task from Lua stack
	auto *task = lua_check_task(L, 1);

	if (!task || !MESSAGE_FIELD_CHECK(task, text_parts)) {
		lua_pushnil(L);
		return 1;
	}

	// Create result table
	lua_newtable(L);
	int results = 0;

	// Iterate through text parts
	unsigned int i;
	void *part;
	PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, part)
	{
		auto *text_part = static_cast<rspamd_mime_text_part *>(part);

		// Only process HTML parts
		if (!IS_TEXT_PART_HTML(text_part) || !text_part->html) {
			continue;
		}

		// Skip if no UTF-8 content available
		if (!text_part->utf_raw_content || text_part->utf_raw_content->len == 0) {
			continue;
		}

		// Enumerate URLs directly using C++ function - no copying!
		auto candidates = rspamd::html::enumerate_rewrite_candidates(
			static_cast<const rspamd::html::html_content *>(text_part->html),
			task,
			text_part->mime_part->part_number);

		if (candidates.empty()) {
			continue;
		}

		// Create array for this part: table[part_number] = {url_info_1, url_info_2, ...}
		lua_pushinteger(L, text_part->mime_part->part_number);
		lua_createtable(L, candidates.size(), 0);// URLs array for this part

		for (size_t j = 0; j < candidates.size(); j++) {
			const auto &cand = candidates[j];

			lua_pushinteger(L, j + 1);// 1-indexed array
			lua_createtable(L, 0, 3); // URL info table with 3 fields: url, attr, tag

			// url field - push string without copying
			lua_pushstring(L, "url");
			lua_pushlstring(L, cand.absolute_url.data(), cand.absolute_url.size());
			lua_settable(L, -3);

			// attr field - push string_view without copying
			lua_pushstring(L, "attr");
			lua_pushlstring(L, cand.attr_name.data(), cand.attr_name.size());
			lua_settable(L, -3);

			// tag field - get tag name
			lua_pushstring(L, "tag");
			if (cand.tag) {
				const char *tag_name = rspamd_html_tag_by_id(cand.tag->id);
				if (tag_name) {
					lua_pushstring(L, tag_name);
				}
				else {
					lua_pushstring(L, "unknown");
				}
			}
			else {
				lua_pushstring(L, "unknown");
			}
			lua_settable(L, -3);

			lua_settable(L, -3);// Add url info to URLs array
		}

		lua_settable(L, -3);// Add part to main table
		results++;
	}

	if (results == 0) {
		lua_pop(L, 1);
		lua_pushnil(L);
	}

	return 1;
}

}// extern "C"
