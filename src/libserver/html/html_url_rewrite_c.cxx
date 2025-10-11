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
