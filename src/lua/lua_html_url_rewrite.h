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

#ifndef RSPAMD_LUA_HTML_URL_REWRITE_H
#define RSPAMD_LUA_HTML_URL_REWRITE_H

#include "config.h"

struct rspamd_task;
struct lua_State;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * C++ Lua binding for task:get_html_urls()
 * Extracts URLs from HTML parts without intermediate C copying
 * @param L Lua state
 * @return number of return values on Lua stack
 */
int lua_task_get_html_urls(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif//RSPAMD_LUA_HTML_URL_REWRITE_H
