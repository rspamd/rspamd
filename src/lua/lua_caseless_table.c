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

/***
 * @module rspamd_caseless_table
 * Provides a case-insensitive string-keyed table for Lua.
 * Original key case is preserved for iteration, but lookups are case-insensitive.
 * Useful for HTTP headers where header names are case-insensitive per RFC 7230.
 *
 * @example
 * local ct = require "rspamd_caseless_table"
 * local headers = ct.create()
 * headers['Content-Type'] = 'text/html'
 * print(headers['content-type'])  -- 'text/html'
 * print(headers['CONTENT-TYPE'])  -- 'text/html'
 *
 * -- Iteration preserves original key case
 * for k, v in headers:each() do
 *   print(k, v)  -- 'Content-Type', 'text/html'
 * end
 *
 * -- For multi-value entries (e.g. HTTP headers with duplicates):
 * local all_cookies = headers:get_all('Set-Cookie')
 * -- Returns: {'cookie1=a', 'cookie2=b'}
 */

#include "lua_common.h"
#include "lua_caseless_table.h"
#include "utlist.h"
#include "libserver/http/http_private.h"

#define CT_CLASS rspamd_caseless_table_classname

/*
 * Internal structure:
 * The userdata stores two registry references:
 * - values_ref: Lua table mapping lowercased keys to values
 *   For single values: lc_key -> string
 *   For multi-value (from HTTP): lc_key -> {string, string, ...}
 * - origkeys_ref: Lua table mapping lowercased keys to original-case keys
 * - size: number of entries
 *
 * The C layer provides case-insensitive access via metamethods.
 * Method dispatch uses a separate methods table (upvalue of __index)
 * to avoid exposing internal metamethod functions like __gc.
 */
struct rspamd_lua_caseless_table {
	int values_ref;
	int origkeys_ref;
	int size;
};

static struct rspamd_lua_caseless_table *
lua_check_caseless_table(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, CT_CLASS);
	luaL_argcheck(L, ud != NULL, pos, "'caseless_table' expected");
	return (struct rspamd_lua_caseless_table *) ud;
}

/*
 * Lowercase a key and push the result onto the Lua stack.
 * Uses a C stack buffer for typical sizes (<=256 bytes),
 * falls back to lua_newuserdata for larger keys.
 */
static size_t
lua_caseless_table_push_lc_key(lua_State *L, int key_idx)
{
	size_t klen;
	const char *key = lua_tolstring(L, key_idx, &klen);
	char stack_buf[256];

	if (klen <= sizeof(stack_buf)) {
		memcpy(stack_buf, key, klen);
		rspamd_str_lc(stack_buf, klen);
		lua_pushlstring(L, stack_buf, klen);
	}
	else {
		char *buf = lua_newuserdata(L, klen);
		memcpy(buf, key, klen);
		rspamd_str_lc(buf, klen);
		lua_pushlstring(L, buf, klen);
		lua_remove(L, -2); /* remove temp userdata */
	}

	return klen;
}

/***
 * @method caseless_table:__index(key)
 * Case-insensitive lookup. Also dispatches method calls.
 * For multi-value entries (tables), returns the first value.
 * Use :get_all(key) to retrieve all values.
 * @param {string} key
 * @return value or nil
 */
static int
lua_caseless_table_index(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	if (lua_type(L, 2) != LUA_TSTRING) {
		lua_pushnil(L);
		return 1;
	}

	/* Check methods table (upvalue 1) for exact match */
	lua_pushvalue(L, 2);
	lua_rawget(L, lua_upvalueindex(1));
	if (!lua_isnil(L, -1)) {
		return 1; /* found a method */
	}
	lua_pop(L, 1);

	/* Caseless lookup in values table */
	lua_caseless_table_push_lc_key(L, 2);

	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
	lua_pushvalue(L, -2); /* lc_key */
	lua_rawget(L, -2);

	/* For multi-value (table), return first element */
	if (lua_istable(L, -1)) {
		lua_rawgeti(L, -1, 1);
		lua_replace(L, -2);
	}

	return 1;
}

/***
 * @method caseless_table:__newindex(key, value)
 * Case-insensitive set/delete. Preserves original case of first insertion.
 * Setting value to nil deletes the entry.
 * @param {string} key
 * @param value
 */
static int
lua_caseless_table_newindex(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	if (lua_type(L, 2) != LUA_TSTRING) {
		return luaL_error(L, "caseless_table keys must be strings");
	}

	lua_caseless_table_push_lc_key(L, 2); /* index 4: lowercased key */
	int lc_idx = lua_gettop(L);

	if (lua_isnil(L, 3)) {
		/* Deletion */
		lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
		lua_pushvalue(L, lc_idx);
		lua_rawget(L, -2);

		if (!lua_isnil(L, -1)) {
			lua_pop(L, 1);
			/* Remove from values */
			lua_pushvalue(L, lc_idx);
			lua_pushnil(L);
			lua_rawset(L, -3);
			lua_pop(L, 1); /* pop values table */
			/* Remove from origkeys */
			lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->origkeys_ref);
			lua_pushvalue(L, lc_idx);
			lua_pushnil(L);
			lua_rawset(L, -3);
			lua_pop(L, 1);

			tbl->size--;
		}
		else {
			lua_pop(L, 2); /* pop nil + values table */
		}
	}
	else {
		/* Check if this is a new key */
		lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
		lua_pushvalue(L, lc_idx);
		lua_rawget(L, -2);
		int is_new = lua_isnil(L, -1);
		lua_pop(L, 1);

		/* Set value */
		lua_pushvalue(L, lc_idx);
		lua_pushvalue(L, 3);
		lua_rawset(L, -3);
		lua_pop(L, 1); /* pop values table */

		if (is_new) {
			tbl->size++;

			/* Store original key */
			lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->origkeys_ref);
			lua_pushvalue(L, lc_idx);
			lua_pushvalue(L, 2); /* original key */
			lua_rawset(L, -3);
			lua_pop(L, 1);
		}
	}

	return 0;
}

/***
 * @method caseless_table:__len()
 * Returns the number of entries.
 * @return {number}
 */
static int
lua_caseless_table_len(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);
	lua_pushinteger(L, tbl->size);
	return 1;
}

/*
 * Stateful iterator function.
 * Upvalues:
 *   1 - values table
 *   2 - origkeys table
 *   3 - current lowercased key (nil at start)
 *
 * For multi-value entries, returns first element (consistent with __index).
 */
static int
lua_caseless_table_iter_func(lua_State *L)
{
	int values_idx = lua_upvalueindex(1);
	int origkeys_idx = lua_upvalueindex(2);

	/* Push current key to resume iteration */
	lua_pushvalue(L, lua_upvalueindex(3));

	if (lua_next(L, values_idx) != 0) {
		/* Stack: lc_key, value */

		/* Save lc_key for next iteration */
		lua_pushvalue(L, -2);
		lua_replace(L, lua_upvalueindex(3));

		/* For multi-value (table), unwrap to first element */
		if (lua_istable(L, -1)) {
			lua_rawgeti(L, -1, 1);
			lua_replace(L, -2);
		}

		/* Get original key */
		lua_pushvalue(L, -2); /* lc_key */
		lua_rawget(L, origkeys_idx);

		/* Stack: lc_key, value, orig_key */
		/* Return: orig_key, value */
		lua_remove(L, -3); /* remove lc_key -> value, orig_key */
		lua_insert(L, -2); /* swap -> orig_key, value */

		return 2;
	}

	/* No more entries */
	return 0;
}

/***
 * @method caseless_table:each()
 * Returns an iterator function for use in for-in loops.
 * Compatible with all Lua versions including LuaJIT.
 * Keys are returned in their original case.
 * Multi-value entries are unwrapped to first value (use :get_all for all).
 *
 * @example
 * for name, value in headers:each() do
 *   print(name, value)
 * end
 *
 * @return {function} iterator
 */
static int
lua_caseless_table_each(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);   /* upvalue 1 */
	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->origkeys_ref); /* upvalue 2 */
	lua_pushnil(L);                                       /* upvalue 3: start key */
	lua_pushcclosure(L, lua_caseless_table_iter_func, 3);

	return 1;
}

/***
 * @method caseless_table:__pairs()
 * Returns iterator for pairs(). Works in Lua 5.2+ natively,
 * and in LuaJIT/Lua 5.1 via installed polyfill.
 *
 * @return {function,table,nil} iterator, state, initial
 */
static int
lua_caseless_table_pairs(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);   /* upvalue 1 */
	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->origkeys_ref); /* upvalue 2 */
	lua_pushnil(L);                                       /* upvalue 3: start key */
	lua_pushcclosure(L, lua_caseless_table_iter_func, 3);

	lua_pushvalue(L, 1); /* state (ignored by stateful iterator) */
	lua_pushnil(L);      /* initial key (ignored) */

	return 3;
}

/***
 * @method caseless_table:has_key(key)
 * Check if a key exists (case-insensitive).
 * @param {string} key
 * @return {boolean}
 */
static int
lua_caseless_table_has_key(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	if (lua_type(L, 2) != LUA_TSTRING) {
		lua_pushboolean(L, 0);
		return 1;
	}

	lua_caseless_table_push_lc_key(L, 2);
	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
	lua_pushvalue(L, -2);
	lua_rawget(L, -2);

	lua_pushboolean(L, !lua_isnil(L, -1));
	return 1;
}

/***
 * @method caseless_table:get_all(key)
 * Returns all values for a key as an array table.
 * For single-value entries, wraps in a single-element array.
 * For multi-value entries (e.g. duplicate HTTP headers), returns the full array.
 * Returns nil if the key does not exist.
 * @param {string} key
 * @return {table} array of values, or nil
 */
static int
lua_caseless_table_get_all(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	if (lua_type(L, 2) != LUA_TSTRING) {
		lua_pushnil(L);
		return 1;
	}

	lua_caseless_table_push_lc_key(L, 2);

	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
	lua_pushvalue(L, -2); /* lc_key */
	lua_rawget(L, -2);
	/* Stack: ..., lc_key, values_table, stored_value */

	if (lua_isnil(L, -1)) {
		return 1; /* nil */
	}

	if (lua_istable(L, -1)) {
		return 1; /* already an array */
	}

	/* Wrap single value in a one-element array */
	lua_createtable(L, 1, 0);
	lua_pushvalue(L, -2); /* the single value */
	lua_rawseti(L, -2, 1);
	/* Stack: ..., single_value, {single_value} */

	return 1;
}

/***
 * @method caseless_table:to_table()
 * Convert to a regular Lua table with original-case keys.
 * Multi-value entries are unwrapped to their first value.
 * @return {table}
 */
static int
lua_caseless_table_to_table(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	lua_createtable(L, 0, tbl->size);

	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->origkeys_ref);
	/* Stack: result, values, origkeys */

	lua_pushnil(L);
	while (lua_next(L, -3) != 0) {
		/* Stack: result, values, origkeys, lc_key, value */

		/* Get original key */
		lua_pushvalue(L, -2); /* lc_key */
		lua_rawget(L, -4);    /* origkeys[lc_key] */
		/* Stack: result, values, origkeys, lc_key, value, orig_key */

		/* Unwrap multi-value to first element */
		if (lua_istable(L, -2)) {
			lua_rawgeti(L, -2, 1);
			/* Stack: ..., lc_key, value(table), orig_key, first_val */
			lua_rawset(L, -7); /* result[orig_key] = first_val */
		}
		else {
			lua_pushvalue(L, -2); /* value */
			lua_rawset(L, -7);    /* result[orig_key] = value */
		}

		lua_pop(L, 1); /* pop value, keep lc_key for next */
	}

	lua_pop(L, 2); /* pop values, origkeys */

	return 1;
}

/***
 * @method caseless_table:__tostring()
 * @return {string} string representation
 */
static int
lua_caseless_table_tostring(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);
	lua_pushfstring(L, "rspamd{caseless_table: %d entries}", tbl->size);
	return 1;
}

/***
 * @method caseless_table:__gc()
 * Garbage collector handler.
 */
static int
lua_caseless_table_gc(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, 1);

	if (tbl->values_ref != LUA_NOREF) {
		luaL_unref(L, LUA_REGISTRYINDEX, tbl->values_ref);
		tbl->values_ref = LUA_NOREF;
	}
	if (tbl->origkeys_ref != LUA_NOREF) {
		luaL_unref(L, LUA_REGISTRYINDEX, tbl->origkeys_ref);
		tbl->origkeys_ref = LUA_NOREF;
	}
	tbl->size = 0;

	return 0;
}

/***
 * @function rspamd_caseless_table.create()
 * Create a new empty caseless table.
 * @return {caseless_table}
 */
static int
lua_caseless_table_create_lua(lua_State *L)
{
	return rspamd_lua_caseless_table_create(L);
}

/***
 * @function rspamd_caseless_table.from_table(t)
 * Create a caseless table from a regular Lua table.
 * @param {table} t source table with string keys
 * @return {caseless_table}
 */
static int
lua_caseless_table_from_table_lua(lua_State *L)
{
	luaL_checktype(L, 1, LUA_TTABLE);
	return rspamd_lua_caseless_table_from_table(L, 1);
}

/* Module functions (rspamd_caseless_table.create, etc.) */
static const struct luaL_reg caseless_table_lib_f[] = {
	{"create", lua_caseless_table_create_lua},
	{"from_table", lua_caseless_table_from_table_lua},
	{NULL, NULL},
};

/* Metamethods only (registered in metatable) */
static const struct luaL_reg caseless_table_lib_m[] = {
	{"__newindex", lua_caseless_table_newindex},
	{"__len", lua_caseless_table_len},
	{"__pairs", lua_caseless_table_pairs},
	{"__tostring", lua_caseless_table_tostring},
	{"__gc", lua_caseless_table_gc},
	{NULL, NULL},
};

/* Instance methods (stored in separate methods table, dispatched by __index) */
static const struct luaL_reg caseless_table_methods[] = {
	{"each", lua_caseless_table_each},
	{"has_key", lua_caseless_table_has_key},
	{"to_table", lua_caseless_table_to_table},
	{"get_all", lua_caseless_table_get_all},
	{NULL, NULL},
};

static int
lua_load_caseless_table(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, caseless_table_lib_f);
	return 1;
}

void luaopen_caseless_table(lua_State *L)
{
	rspamd_lua_new_class(L, CT_CLASS, caseless_table_lib_m);
	/* Metatable is on top of stack.
	 * rspamd_lua_new_class set __index = metatable (default),
	 * which we now replace with our custom __index closure. */

	/* Create methods table as upvalue for __index */
	lua_newtable(L);
	luaL_register(L, NULL, caseless_table_methods);

	/* Create __index closure with methods table as upvalue 1 */
	lua_pushcclosure(L, lua_caseless_table_index, 1);
	lua_setfield(L, -2, "__index");

	lua_pop(L, 1); /* pop metatable */

	rspamd_lua_add_preload(L, "rspamd_caseless_table", lua_load_caseless_table);
}

/* Public C API */

int rspamd_lua_caseless_table_create(lua_State *L)
{
	struct rspamd_lua_caseless_table *tbl;

	tbl = lua_newuserdata(L, sizeof(*tbl));

	lua_newtable(L);
	tbl->values_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	lua_newtable(L);
	tbl->origkeys_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	tbl->size = 0;

	rspamd_lua_setclass(L, CT_CLASS, -1);

	return 1;
}

int rspamd_lua_caseless_table_from_table(lua_State *L, int tbl_idx)
{
	tbl_idx = lua_absindex(L, tbl_idx);
	luaL_checktype(L, tbl_idx, LUA_TTABLE);

	rspamd_lua_caseless_table_create(L); /* pushes new caseless table */
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, -1);

	/* Get backing tables */
	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
	int vals_idx = lua_gettop(L);
	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->origkeys_ref);
	int orig_idx = lua_gettop(L);

	/* Iterate source table */
	lua_pushnil(L);
	while (lua_next(L, tbl_idx) != 0) {
		/* Stack: ..., vals_tbl, orig_tbl, key, value */
		if (lua_type(L, -2) == LUA_TSTRING) {
			lua_caseless_table_push_lc_key(L, -2);
			/* Stack: ..., vals_tbl, orig_tbl, key, value, lc_key */

			/* Check if key already exists */
			lua_pushvalue(L, -1); /* lc_key */
			lua_rawget(L, orig_idx);
			int is_new = lua_isnil(L, -1);
			lua_pop(L, 1);

			/* Set values[lc_key] = value
			 * Stack: key(-3), value(-2), lc_key(-1) */
			lua_pushvalue(L, -1); /* lc_key */
			lua_pushvalue(L, -3); /* value: -1=copy, -2=lc_key, -3=value */
			lua_rawset(L, vals_idx);
			/* Stack restored: key(-3), value(-2), lc_key(-1) */

			if (is_new) {
				/* Set origkeys[lc_key] = original_key */
				lua_pushvalue(L, -1); /* lc_key: ..key(-4), value(-3), lc_key(-2), copy(-1) */
				lua_pushvalue(L, -4); /* key: -4 = key */
				lua_rawset(L, orig_idx);

				tbl->size++;
			}

			lua_pop(L, 1); /* pop lc_key */
		}
		lua_pop(L, 1); /* pop value, keep key for lua_next */
	}

	lua_pop(L, 2); /* pop vals + orig tables */

	return 1;
}

void rspamd_lua_caseless_table_push_from_http(lua_State *L,
											  khash_t(rspamd_http_headers_hash) * headers)
{
	struct rspamd_http_header *h, *hcur;
	char stack_buf[256];

	rspamd_lua_caseless_table_create(L);
	struct rspamd_lua_caseless_table *tbl = lua_check_caseless_table(L, -1);

	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->values_ref);
	int vals_idx = lua_gettop(L);
	lua_rawgeti(L, LUA_REGISTRYINDEX, tbl->origkeys_ref);
	int orig_idx = lua_gettop(L);

	kh_foreach_value(headers, h, {
		/* Push lowercased key */
		if (h->name.len <= sizeof(stack_buf)) {
			memcpy(stack_buf, h->name.begin, h->name.len);
			rspamd_str_lc(stack_buf, h->name.len);
			lua_pushlstring(L, stack_buf, h->name.len);
		}
		else {
			char *buf = lua_newuserdata(L, h->name.len);
			memcpy(buf, h->name.begin, h->name.len);
			rspamd_str_lc(buf, h->name.len);
			lua_pushlstring(L, buf, h->name.len);
			lua_remove(L, -2);
		}
		/* Stack: lc_key */

		/* Count linked-list entries for this header name */
		int nvalues = 0;
		DL_FOREACH(h, hcur)
		{
			nvalues++;
		}

		if (nvalues == 1) {
			/* Single value - store as string */
			lua_pushvalue(L, -1); /* lc_key */
			lua_pushlstring(L, h->value.begin, h->value.len);
			lua_rawset(L, vals_idx);
		}
		else {
			/* Multiple values - store as array table */
			lua_pushvalue(L, -1); /* lc_key */
			lua_createtable(L, nvalues, 0);
			int i = 1;
			DL_FOREACH(h, hcur)
			{
				lua_pushlstring(L, hcur->value.begin, hcur->value.len);
				lua_rawseti(L, -2, i++);
			}
			lua_rawset(L, vals_idx);
		}

		/* Store original-case key (use the first header's case) */
		lua_pushvalue(L, -1); /* lc_key */
		lua_pushlstring(L, h->name.begin, h->name.len);
		lua_rawset(L, orig_idx);

		tbl->size++;
		lua_pop(L, 1); /* pop lc_key */
	});

	lua_pop(L, 2); /* pop vals + orig tables */

	/* caseless table userdata is on top of stack */
}
