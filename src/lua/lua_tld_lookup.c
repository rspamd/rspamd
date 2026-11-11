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

#include "lua_common.h"
#include "libserver/tld_lookup.h"
#include "libserver/url.h"

/***
 * @module rspamd_tld_lookup
 * Longest-suffix matching of hostnames with public suffix list semantics:
 * exact rules, `*.wildcard` rules and `!exception` rules. Module level
 * functions query the suffix list loaded by rspamd itself, whilst custom
 * rule sets (e.g. URL composition maps) can be built with `create`.
 * @example
local tld_lookup = require "rspamd_tld_lookup"

-- Query the loaded public suffix list
local domain, flags = tld_lookup.registrable('mail.example.co.uk')
-- domain == 'example.co.uk'

-- Custom rule set
local custom = tld_lookup.create({'example.com', '*.foo.example.com'})
local d, fl = custom:registrable('baz.example.com')
-- d == 'baz.example.com'
if bit.band(fl, tld_lookup.flags.wildcard) ~= 0 then ... end
 */

LUA_FUNCTION_DEF(tld_lookup, create);
LUA_FUNCTION_DEF(tld_lookup, registrable);
LUA_FUNCTION_DEF(tld_lookup, suffix);
LUA_FUNCTION_DEF(tld_lookup, is_final_label);
LUA_FUNCTION_DEF(tld_lookup, add_rule);
LUA_FUNCTION_DEF(tld_lookup, nrules);
LUA_FUNCTION_DEF(tld_lookup, inst_registrable);
LUA_FUNCTION_DEF(tld_lookup, inst_suffix);
LUA_FUNCTION_DEF(tld_lookup, inst_is_final_label);
LUA_FUNCTION_DEF(tld_lookup, destroy);

static const struct luaL_reg tld_lookup_m[] = {
	{"add_rule", lua_tld_lookup_add_rule},
	{"nrules", lua_tld_lookup_nrules},
	{"registrable", lua_tld_lookup_inst_registrable},
	{"suffix", lua_tld_lookup_inst_suffix},
	{"is_final_label", lua_tld_lookup_inst_is_final_label},
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_tld_lookup_destroy},
	{NULL, NULL}};

static const struct luaL_reg tld_lookup_f[] = {
	LUA_INTERFACE_DEF(tld_lookup, create),
	LUA_INTERFACE_DEF(tld_lookup, registrable),
	LUA_INTERFACE_DEF(tld_lookup, suffix),
	LUA_INTERFACE_DEF(tld_lookup, is_final_label),
	{NULL, NULL}};

static struct rspamd_tld_lookup *
lua_check_tld_lookup(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_tld_lookup_classname);

	luaL_argcheck(L, ud != NULL, pos, "'tld_lookup' expected");
	return ud ? *((struct rspamd_tld_lookup **) ud) : NULL;
}

static int
lua_tld_lookup_destroy(lua_State *L)
{
	struct rspamd_tld_lookup *lookup = lua_check_tld_lookup(L, 1);

	if (lookup) {
		rspamd_tld_lookup_destroy(lookup);
	}

	return 0;
}

/***
 * @function tld_lookup.create([rules])
 * Creates a custom suffix rule set, optionally filled from an array of
 * rule strings in the public suffix list syntax
 * @param {table} rules optional array of rules
 * @return {tld_lookup} new rule set
 */
static int
lua_tld_lookup_create(lua_State *L)
{
	struct rspamd_tld_lookup *lookup, **plookup;

	lookup = rspamd_tld_lookup_new_empty();

	if (lua_istable(L, 1)) {
		lua_pushvalue(L, 1);
		lua_pushnil(L);

		while (lua_next(L, -2) != 0) {
			gsize len;
			const char *rule = lua_tolstring(L, -1, &len);

			if (rule) {
				rspamd_tld_lookup_add_rule(lookup, rule, len);
			}
			lua_pop(L, 1);
		}

		lua_pop(L, 1);
	}

	plookup = lua_newuserdata(L, sizeof(void *));
	*plookup = lookup;
	rspamd_lua_setclass(L, rspamd_tld_lookup_classname, -1);

	return 1;
}

/***
 * @method tld_lookup:add_rule(rule)
 * Adds a single rule (`foo.bar`, `*.foo.bar` or `!baz.foo.bar`)
 */
static int
lua_tld_lookup_add_rule(lua_State *L)
{
	struct rspamd_tld_lookup *lookup = lua_check_tld_lookup(L, 1);
	gsize len;
	const char *rule = luaL_checklstring(L, 2, &len);

	if (lookup && rule) {
		rspamd_tld_lookup_add_rule(lookup, rule, len);
	}

	return 0;
}

/***
 * @method tld_lookup:nrules()
 * @return {number} number of rules in the set
 */
static int
lua_tld_lookup_nrules(lua_State *L)
{
	struct rspamd_tld_lookup *lookup = lua_check_tld_lookup(L, 1);

	lua_pushinteger(L, rspamd_tld_lookup_nrules(lookup));

	return 1;
}

static int
lua_tld_lookup_registrable_common(lua_State *L, const struct rspamd_tld_lookup *lookup,
								  int str_pos)
{
	gsize len;
	const char *host = luaL_checklstring(L, str_pos, &len);
	rspamd_ftok_t tld;
	unsigned int flags = 0;

	if (lookup == NULL || host == NULL ||
		!rspamd_tld_lookup_registrable(lookup, host, len, &tld)) {
		lua_pushnil(L);

		return 1;
	}

	/* Flags come from the matched suffix */
	(void) rspamd_tld_lookup_suffix(lookup, host, len, NULL, &flags);

	lua_pushlstring(L, tld.begin, tld.len);
	lua_pushinteger(L, flags);

	return 2;
}

static int
lua_tld_lookup_suffix_common(lua_State *L, const struct rspamd_tld_lookup *lookup,
							 int str_pos)
{
	gsize len;
	const char *host = luaL_checklstring(L, str_pos, &len);
	rspamd_ftok_t suffix;
	unsigned int flags = 0;

	if (lookup == NULL || host == NULL ||
		!rspamd_tld_lookup_suffix(lookup, host, len, &suffix, &flags)) {
		lua_pushnil(L);

		return 1;
	}

	lua_pushlstring(L, suffix.begin, suffix.len);
	lua_pushinteger(L, flags);

	return 2;
}

/***
 * @function tld_lookup.registrable(host)
 * Finds the registrable domain (eTLD+1) of a host using the public suffix
 * list loaded by rspamd
 * @return {string} registrable domain (or nil) and match flags
 */
static int
lua_tld_lookup_registrable(lua_State *L)
{
	return lua_tld_lookup_registrable_common(L, rspamd_url_get_tld_lookup(), 1);
}

/***
 * @function tld_lookup.suffix(host)
 * Finds the public suffix of a host using the suffix list loaded by rspamd
 * @return {string} public suffix (or nil) and match flags
 */
static int
lua_tld_lookup_suffix(lua_State *L)
{
	return lua_tld_lookup_suffix_common(L, rspamd_url_get_tld_lookup(), 1);
}

/***
 * @function tld_lookup.is_final_label(label)
 * Checks whether a single label ends any rule of the loaded suffix list
 */
static int
lua_tld_lookup_is_final_label(lua_State *L)
{
	gsize len;
	const char *label = luaL_checklstring(L, 1, &len);

	lua_pushboolean(L,
					rspamd_tld_lookup_is_final_label(rspamd_url_get_tld_lookup(), label, len));

	return 1;
}

/***
 * @method tld_lookup:registrable(host)
 * As tld_lookup.registrable, but against this custom rule set
 */
static int
lua_tld_lookup_inst_registrable(lua_State *L)
{
	return lua_tld_lookup_registrable_common(L, lua_check_tld_lookup(L, 1), 2);
}

/***
 * @method tld_lookup:suffix(host)
 * As tld_lookup.suffix, but against this custom rule set
 */
static int
lua_tld_lookup_inst_suffix(lua_State *L)
{
	return lua_tld_lookup_suffix_common(L, lua_check_tld_lookup(L, 1), 2);
}

/***
 * @method tld_lookup:is_final_label(label)
 * As tld_lookup.is_final_label, but against this custom rule set
 */
static int
lua_tld_lookup_inst_is_final_label(lua_State *L)
{
	struct rspamd_tld_lookup *lookup = lua_check_tld_lookup(L, 1);
	gsize len;
	const char *label = luaL_checklstring(L, 2, &len);

	lua_pushboolean(L, rspamd_tld_lookup_is_final_label(lookup, label, len));

	return 1;
}

static int
lua_load_tld_lookup(lua_State *L)
{
	lua_newtable(L);

	/* Flags of the matched suffix */
	lua_pushstring(L, "flags");
	lua_newtable(L);
	lua_pushinteger(L, RSPAMD_TLD_SUFFIX_WILDCARD);
	lua_setfield(L, -2, "wildcard");
	lua_pushinteger(L, RSPAMD_TLD_SUFFIX_EXCEPTION);
	lua_setfield(L, -2, "exception");
	lua_pushinteger(L, RSPAMD_TLD_SUFFIX_PRIVATE);
	lua_setfield(L, -2, "private");
	lua_settable(L, -3);

	luaL_register(L, NULL, tld_lookup_f);

	return 1;
}

void luaopen_tld_lookup(lua_State *L)
{
	rspamd_lua_new_class(L, rspamd_tld_lookup_classname, tld_lookup_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_tld_lookup", lua_load_tld_lookup);
}
