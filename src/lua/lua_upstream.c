/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "config.h"
#include "lua_common.h"


/***
 * @module rspamd_upstream_list
 * This module implements upstreams manipulation from LUA API. This functionality
 * can be used for load balancing using different strategies including:
 *
 * - round-robin: balance upstreams one by one selecting accordingly to their weight
 * - hash: use stable hashing algorithm to distribute values according to some static strings
 * - master-slave: always prefer upstream with higher priority unless it is not available
 *
 * Here is an example of upstreams manipulations:
 * @example
local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"
local upstreams = upstream_list.create('127.0.0.1,10.0.0.1,10.0.0.2', 6379)

local function sym_callback(task)
	local upstream = upstreams:get_upstream_by_hash(task:get_from()[1]['domain'])

	local function cb(task, err, data)
		if err then
			upstream:fail()
		else
			upstream:ok()
		end
	end

	local addr = upstream:get_addr()
	rspamd_redis.make_request(task, addr, cb,
		'PUSH', {'key', 'value'})
end
 */
/* Upstream list functions */
LUA_FUNCTION_DEF (upstream_list, create);
LUA_FUNCTION_DEF (upstream_list, destroy);
LUA_FUNCTION_DEF (upstream_list, all_upstreams);
LUA_FUNCTION_DEF (upstream_list, get_upstream_by_hash);
LUA_FUNCTION_DEF (upstream_list, get_upstream_round_robin);
LUA_FUNCTION_DEF (upstream_list, get_upstream_master_slave);

static const struct luaL_reg upstream_list_m[] = {

	LUA_INTERFACE_DEF (upstream_list, get_upstream_by_hash),
	LUA_INTERFACE_DEF (upstream_list, get_upstream_round_robin),
	LUA_INTERFACE_DEF (upstream_list, get_upstream_master_slave),
	LUA_INTERFACE_DEF (upstream_list, all_upstreams),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_upstream_list_destroy},
	{NULL, NULL}
};
static const struct luaL_reg upstream_list_f[] = {
	LUA_INTERFACE_DEF (upstream_list, create),
	{NULL, NULL}
};

/* Upstream functions */
LUA_FUNCTION_DEF (upstream, ok);
LUA_FUNCTION_DEF (upstream, fail);
LUA_FUNCTION_DEF (upstream, get_addr);

static const struct luaL_reg upstream_m[] = {
	LUA_INTERFACE_DEF (upstream, ok),
	LUA_INTERFACE_DEF (upstream, fail),
	LUA_INTERFACE_DEF (upstream, get_addr),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Upstream class */

static struct upstream *
lua_check_upstream (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{upstream}");

	luaL_argcheck (L, ud != NULL, 1, "'upstream' expected");
	return ud ? *((struct upstream **)ud) : NULL;
}

/***
 * @method upstream:get_addr()
 * Get ip of upstream
 * @return {ip} ip address object
 */
static gint
lua_upstream_get_addr (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream *up = lua_check_upstream (L);

	if (up) {
		rspamd_lua_ip_push (L, rspamd_upstream_addr (up));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method upstream:fail()
 * Indicate upstream failure. After certain amount of failures during specified time frame, an upstream is marked as down and does not participate in rotations.
 */
static gint
lua_upstream_fail (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream *up = lua_check_upstream (L);
	gboolean fail_addr = FALSE;

	if (up) {

		if (lua_isboolean (L, 2)) {
			fail_addr = lua_toboolean (L, 2);
		}

		rspamd_upstream_fail (up, fail_addr);
	}

	return 0;
}

/***
 * @method upstream:ok()
 * Indicates upstream success. Resets errors count for an upstream.
 */
static gint
lua_upstream_ok (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream *up = lua_check_upstream (L);

	if (up) {
		rspamd_upstream_ok (up);
	}

	return 0;
}

/* Upstream list class */

static struct upstream_list *
lua_check_upstream_list (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{upstream_list}");

	luaL_argcheck (L, ud != NULL, 1, "'upstream_list' expected");
	return ud ? *((struct upstream_list **)ud) : NULL;
}

/***
 * @function upstream_list.create(cfg, def, [default_port])
 * Create new upstream list from its string definition in form `<upstream>,<upstream>;<upstream>`
 * @param {rspamd_config} cfg configuration reference
 * @param {string} def upstream list definition
 * @param {number} default_port default port for upstreams
 * @return {upstream_list} upstream list structure
 */
static gint
lua_upstream_list_create (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream_list *new = NULL, **pnew;
	struct rspamd_config *cfg = NULL;
	const gchar *def;
	guint default_port = 0;
	gint top;


	if (lua_type (L, 1) == LUA_TUSERDATA) {
		cfg = lua_check_config (L, 1);
		top = 2;
	}
	else {
		top = 1;
	}

	if (lua_gettop (L) >= top + 1) {
		default_port = luaL_checknumber (L, top + 1);
	}

	if (lua_type (L, top) == LUA_TSTRING) {
		def = luaL_checkstring (L, top);

		new = rspamd_upstreams_create (cfg ? cfg->ups_ctx : NULL);

		if (rspamd_upstreams_parse_line (new, def, default_port, NULL)) {
			pnew = lua_newuserdata (L, sizeof (struct upstream_list *));
			rspamd_lua_setclass (L, "rspamd{upstream_list}", -1);
			*pnew = new;
		}
		else {
			rspamd_upstreams_destroy (new);
			lua_pushnil (L);
		}
	}
	else if (lua_type (L, top) == LUA_TTABLE) {
		new = rspamd_upstreams_create (cfg ? cfg->ups_ctx : NULL);
		pnew = lua_newuserdata (L, sizeof (struct upstream_list *));
		rspamd_lua_setclass (L, "rspamd{upstream_list}", -1);
		*pnew = new;

		lua_pushvalue (L, top);

		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			def = lua_tostring (L, -1);

			if (!def || !rspamd_upstreams_parse_line (new, def, default_port, NULL)) {
				msg_warn ("cannot parse upstream %s", def);
			}
		}

		lua_pop (L, 1);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/**
 * Destroy a single upstream list object
 * @param L
 * @return
 */
static gint
lua_upstream_list_destroy (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream_list *upl = lua_check_upstream_list (L);

	rspamd_upstreams_destroy (upl);

	return 0;
}

/***
 * @method upstream_list:get_upstream_by_hash(key)
 * Get upstream by hash from key
 * @param {string} key a string used as input for stable hash algorithm
 * @return {upstream} upstream from a list corresponding to the given key
 */
static gint
lua_upstream_list_get_upstream_by_hash (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream_list *upl;
	struct upstream *selected, **pselected;
	const gchar *key;
	gsize keyl;

	upl = lua_check_upstream_list (L);
	if (upl) {
		key = luaL_checklstring (L, 2, &keyl);
		if (key) {
			selected = rspamd_upstream_get (upl, RSPAMD_UPSTREAM_HASHED, key,
					(guint)keyl);
			if (selected) {
				pselected = lua_newuserdata (L, sizeof (struct upstream *));
				rspamd_lua_setclass (L, "rspamd{upstream}", -1);
				*pselected = selected;
			}
			else {
				lua_pushnil (L);
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method upstream_list:get_upstream_round_robin()
 * Get upstream round robin (by current weight)
 * @return {upstream} upstream from a list in round-robin matter
 */
static gint
lua_upstream_list_get_upstream_round_robin (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream_list *upl;
	struct upstream *selected, **pselected;

	upl = lua_check_upstream_list (L);
	if (upl) {

		selected = rspamd_upstream_get (upl, RSPAMD_UPSTREAM_ROUND_ROBIN, NULL, 0);
		if (selected) {
			pselected = lua_newuserdata (L, sizeof (struct upstream *));
			rspamd_lua_setclass (L, "rspamd{upstream}", -1);
			*pselected = selected;
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method upstream_list:get_upstream_master_slave()
 * Get upstream master slave order (by static priority)
 * @return {upstream} upstream from a list in master-slave order
 */
static gint
lua_upstream_list_get_upstream_master_slave (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream_list *upl;
	struct upstream *selected, **pselected;

	upl = lua_check_upstream_list (L);
	if (upl) {

		selected = rspamd_upstream_get (upl, RSPAMD_UPSTREAM_MASTER_SLAVE,
				NULL,
				0);
		if (selected) {
			pselected = lua_newuserdata (L, sizeof (struct upstream *));
			rspamd_lua_setclass (L, "rspamd{upstream}", -1);
			*pselected = selected;
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static void lua_upstream_inserter (struct upstream *up, guint idx, void *ud)
{
	struct upstream **pup;
	lua_State *L = (lua_State *)ud;

	pup = lua_newuserdata (L, sizeof (struct upstream *));
	rspamd_lua_setclass (L, "rspamd{upstream}", -1);
	*pup = up;

	lua_rawseti (L, -2, idx + 1);
}
/***
 * @method upstream_list:all_upstreams()
 * Returns all upstreams for this list
 * @return {table|upstream} all upstreams defined
 */
static gint
lua_upstream_list_all_upstreams (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream_list *upl;

	upl = lua_check_upstream_list (L);
	if (upl) {
		lua_createtable (L, rspamd_upstreams_count (upl), 0);
		rspamd_upstreams_foreach (upl, lua_upstream_inserter, L);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_load_upstream_list (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, upstream_list_f);

	return 1;
}

void
luaopen_upstream (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{upstream_list}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{upstream_list}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,			   upstream_list_m);
	rspamd_lua_add_preload (L, "rspamd_upstream_list", lua_load_upstream_list);

	lua_pop (L, 1);                      /* remove metatable from stack */

	luaL_newmetatable (L, "rspamd{upstream}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{upstream}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,		  upstream_m);

	lua_pop (L, 1);                      /* remove metatable from stack */
}
