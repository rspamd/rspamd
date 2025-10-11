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

#ifndef RSPAMD_HTML_URL_REWRITE_C_H
#define RSPAMD_HTML_URL_REWRITE_C_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_task;

/**
 * C wrapper for HTML URL rewriting
 * @param task Rspamd task
 * @param html_content HTML content pointer (void* cast of html_content*)
 * @param func_name Lua function name for rewriting
 * @param part_id MIME part ID
 * @param original_html Original HTML content
 * @param html_len Length of original HTML
 * @param output_html Output pointer for rewritten HTML (allocated from task pool if successful)
 * @param output_len Output length
 * @return 0 on success, -1 on error/no rewrite
 */
int rspamd_html_url_rewrite(struct rspamd_task *task,
							void *html_content,
							const char *func_name,
							int part_id,
							const char *original_html,
							gsize html_len,
							char **output_html,
							gsize *output_len);

#ifdef __cplusplus
}
#endif

#endif//RSPAMD_HTML_URL_REWRITE_C_H
