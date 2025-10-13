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

#include "html_url_rewrite_c.h"
#include "html_url_rewrite.hxx"
#include "html.hxx"
#include "libserver/task.h"

extern "C" {

int rspamd_html_enumerate_urls(struct rspamd_task *task,
							   void *html_content,
							   int part_id,
							   struct rspamd_html_url_candidate **candidates,
							   gsize *n_candidates)
{
	if (!task || !html_content || !candidates || !n_candidates) {
		return -1;
	}

	auto *hc = static_cast<const rspamd::html::html_content *>(html_content);

	// Enumerate candidates using C++ function
	auto cpp_candidates = rspamd::html::enumerate_rewrite_candidates(hc, task, part_id);

	if (cpp_candidates.empty()) {
		*candidates = nullptr;
		*n_candidates = 0;
		return 0;
	}

	// Allocate C-style array from task pool
	*n_candidates = cpp_candidates.size();
	*candidates = (struct rspamd_html_url_candidate *) rspamd_mempool_alloc(
		task->task_pool,
		sizeof(struct rspamd_html_url_candidate) * cpp_candidates.size());

	// Convert C++ candidates to C candidates
	for (size_t i = 0; i < cpp_candidates.size(); i++) {
		const auto &cpp_cand = cpp_candidates[i];

		// Allocate strings from task pool
		char *url_str = (char *) rspamd_mempool_alloc(
			task->task_pool,
			cpp_cand.absolute_url.size() + 1);
		memcpy(url_str, cpp_cand.absolute_url.data(), cpp_cand.absolute_url.size());
		url_str[cpp_cand.absolute_url.size()] = '\0';

		char *attr_str = (char *) rspamd_mempool_alloc(
			task->task_pool,
			cpp_cand.attr_name.size() + 1);
		memcpy(attr_str, cpp_cand.attr_name.data(), cpp_cand.attr_name.size());
		attr_str[cpp_cand.attr_name.size()] = '\0';

		// Get tag name
		const char *tag_name = "unknown";
		gsize tag_len = 7;
		if (cpp_cand.tag) {
			// Use rspamd_html_tag_by_id which returns const char*
			extern const char *rspamd_html_tag_by_id(int id);
			tag_name = rspamd_html_tag_by_id(cpp_cand.tag->id);
			if (tag_name) {
				tag_len = strlen(tag_name);
			}
			else {
				tag_name = "unknown";
				tag_len = 7;
			}
		}

		(*candidates)[i].url = url_str;
		(*candidates)[i].url_len = cpp_cand.absolute_url.size();
		(*candidates)[i].attr = attr_str;
		(*candidates)[i].attr_len = cpp_cand.attr_name.size();
		(*candidates)[i].tag = tag_name;
		(*candidates)[i].tag_len = tag_len;
	}

	return 0;
}

int rspamd_html_url_rewrite(struct rspamd_task *task,
							struct lua_State *L,
							void *html_content,
							int func_ref,
							int part_id,
							const char *original_html,
							gsize html_len,
							char **output_html,
							gsize *output_len)
{
	if (!task || !L || !html_content || !original_html) {
		return -1;
	}

	auto *hc = static_cast<const rspamd::html::html_content *>(html_content);
	std::string_view original{original_html, html_len};

	auto result = rspamd::html::process_html_url_rewrite(
		task, L, hc, func_ref, part_id, original);

	if (!result) {
		return -1;
	}

	/* Allocate from task pool */
	*output_html = (char *) rspamd_mempool_alloc(task->task_pool, result->size());
	memcpy(*output_html, result->data(), result->size());
	*output_len = result->size();

	return 0;
}

}// extern "C"
