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

struct lua_State;

/**
 * URL candidate info for C interface
 */
struct rspamd_html_url_candidate {
	const char *url; // Absolute URL string (NUL-terminated)
	const char *attr;// Attribute name: "href" or "src" (NUL-terminated)
	const char *tag; // Tag name (NUL-terminated)
	gsize url_len;   // Length of URL string
	gsize attr_len;  // Length of attr string
	gsize tag_len;   // Length of tag string
};

/**
 * C wrapper for enumerating HTML URL rewrite candidates
 * @param task Rspamd task
 * @param html_content HTML content pointer (void* cast of html_content*)
 * @param part_id MIME part ID
 * @param candidates Output array of candidates (allocated from task pool if successful)
 * @param n_candidates Output count of candidates
 * @return 0 on success, -1 on error
 */
int rspamd_html_enumerate_urls(struct rspamd_task *task,
							   void *html_content,
							   int part_id,
							   struct rspamd_html_url_candidate **candidates,
							   gsize *n_candidates);

/**
 * C wrapper for HTML URL rewriting
 * @param task Rspamd task
 * @param L Lua state
 * @param html_content HTML content pointer (void* cast of html_content*)
 * @param func_ref Lua function reference (from luaL_ref)
 * @param part_id MIME part ID
 * @param original_html Original HTML content
 * @param html_len Length of original HTML
 * @param output_html Output pointer for rewritten HTML (allocated from task pool if successful)
 * @param output_len Output length
 * @return 0 on success, -1 on error/no rewrite
 */
int rspamd_html_url_rewrite(struct rspamd_task *task,
							struct lua_State *L,
							void *html_content,
							int func_ref,
							int part_id,
							const char *original_html,
							gsize html_len,
							char **output_html,
							gsize *output_len);

#ifdef __cplusplus
}
#endif

#endif//RSPAMD_HTML_URL_REWRITE_C_H
