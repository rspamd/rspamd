/*
 * Copyright 2026 Vsevolod Stakhov
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

#ifndef RSPAMD_LUA_CASELESS_TABLE_H
#define RSPAMD_LUA_CASELESS_TABLE_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
}
#endif

/**
 * Initialize the caseless table Lua class.
 * Called during rspamd_lua_init().
 */
void luaopen_caseless_table(lua_State *L);

/**
 * Create a new empty caseless table and push it onto the Lua stack.
 * @return 1 (userdata on stack)
 */
int rspamd_lua_caseless_table_create(lua_State *L);

/**
 * Create a caseless table from a regular Lua table at the given stack index.
 * Pushes the new caseless table onto the stack.
 * @param tbl_idx stack index of the source table
 * @return 1 (userdata on stack)
 */
int rspamd_lua_caseless_table_from_table(lua_State *L, int tbl_idx);

#endif /* RSPAMD_LUA_CASELESS_TABLE_H */
