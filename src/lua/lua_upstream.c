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
LUA_FUNCTION_DEF (upstream_list, add_watcher);

static const struct luaL_reg upstream_list_m[] = {

	LUA_INTERFACE_DEF (upstream_list, get_upstream_by_hash),
	LUA_INTERFACE_DEF (upstream_list, get_upstream_round_robin),
	LUA_INTERFACE_DEF (upstream_list, get_upstream_master_slave),
	LUA_INTERFACE_DEF (upstream_list, all_upstreams),
	LUA_INTERFACE_DEF (upstream_list, add_watcher),
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
LUA_FUNCTION_DEF (upstream, get_name);
LUA_FUNCTION_DEF (upstream, get_port);
LUA_FUNCTION_DEF (upstream, destroy);

static const struct luaL_reg upstream_m[] = {
	LUA_INTERFACE_DEF (upstream, ok),
	LUA_INTERFACE_DEF (upstream, fail),
	LUA_INTERFACE_DEF (upstream, get_addr),
	LUA_INTERFACE_DEF (upstream, get_port),
	LUA_INTERFACE_DEF (upstream, get_name),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_upstream_destroy},
	{NULL, NULL}
};

/* Upstream class */

struct rspamd_lua_upstream {
	struct upstream *up;
	gint upref;
};

static struct rspamd_lua_upstream *
lua_check_upstream (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{upstream}");

	luaL_argcheck (L, ud != NULL, 1, "'upstream' expected");
	return ud ? (struct rspamd_lua_upstream *)ud : NULL;
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
	struct rspamd_lua_upstream *up = lua_check_upstream (L);

	if (up) {
		rspamd_lua_ip_push (L, rspamd_upstream_addr_next (up->up));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method upstream:get_name()
 * Get name of upstream
 * @return {string} name of the upstream
 */
static gint
lua_upstream_get_name (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_upstream *up = lua_check_upstream (L);

	if (up) {
		lua_pushstring (L, rspamd_upstream_name (up->up));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method upstream:get_port()
 * Get port of upstream
 * @return {int} port of the upstream
 */
static gint
lua_upstream_get_port (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_upstream *up = lua_check_upstream (L);

	if (up) {
		lua_pushinteger (L, rspamd_upstream_port (up->up));
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
	struct rspamd_lua_upstream *up = lua_check_upstream (L);
	gboolean fail_addr = FALSE;
	const gchar *reason = "unknown";

	if (up) {

		if (lua_isboolean (L, 2)) {
			fail_addr = lua_toboolean (L, 2);

			if (lua_isstring (L, 3)) {
				reason = lua_tostring (L, 3);
			}
		}
		else if (lua_isstring (L, 2)) {
			reason = lua_tostring (L, 2);
		}

		rspamd_upstream_fail (up->up, fail_addr, reason);
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
	struct rspamd_lua_upstream *up = lua_check_upstream (L);

	if (up) {
		rspamd_upstream_ok (up->up);
	}

	return 0;
}

static gint
lua_upstream_destroy (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_upstream *up = lua_check_upstream (L);

	if (up) {
		/* Remove reference to the parent */
		luaL_unref (L, LUA_REGISTRYINDEX, up->upref);
		/* Upstream belongs to the upstream list, so no free here */
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

static struct rspamd_lua_upstream *
lua_push_upstream (lua_State * L, gint up_idx, struct upstream *up)
{
	struct rspamd_lua_upstream *lua_ups;

	if (up_idx < 0) {
		up_idx = lua_gettop (L) + up_idx + 1;
	}

	lua_ups = lua_newuserdata (L, sizeof (*lua_ups));
	lua_ups->up = up;
	rspamd_lua_setclass (L, "rspamd{upstream}", -1);
	/* Store parent in the upstream to prevent gc */
	lua_pushvalue (L, up_idx);
	lua_ups->upref = luaL_ref (L, LUA_REGISTRYINDEX);

	return lua_ups;
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
	struct upstream *selected;
	const gchar *key;
	gsize keyl;

	upl = lua_check_upstream_list (L);
	if (upl) {
		key = luaL_checklstring (L, 2, &keyl);
		if (key) {
			selected = rspamd_upstream_get (upl, RSPAMD_UPSTREAM_HASHED, key,
					(guint)keyl);

			if (selected) {
				lua_push_upstream (L, 1, selected);
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
		return luaL_error (L, "invalid arguments");
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
	struct upstream *selected;

	upl = lua_check_upstream_list (L);
	if (upl) {

		selected = rspamd_upstream_get (upl, RSPAMD_UPSTREAM_ROUND_ROBIN, NULL, 0);
		if (selected) {
			lua_push_upstream (L, 1, selected);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
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
	struct upstream *selected;

	upl = lua_check_upstream_list (L);
	if (upl) {

		selected = rspamd_upstream_get (upl, RSPAMD_UPSTREAM_MASTER_SLAVE,
				NULL,
				0);
		if (selected) {
			lua_push_upstream (L, 1, selected);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct upstream_foreach_cbdata {
	lua_State *L;
	gint ups_pos;
};

static void lua_upstream_inserter (struct upstream *up, guint idx, void *ud)
{
	struct upstream_foreach_cbdata *cbd = (struct upstream_foreach_cbdata *)ud;

	lua_push_upstream (cbd->L, cbd->ups_pos, up);
	lua_rawseti (cbd->L, -2, idx + 1);
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
	struct upstream_foreach_cbdata cbd;

	upl = lua_check_upstream_list (L);
	if (upl) {
		cbd.L = L;
		cbd.ups_pos = 1;

		lua_createtable (L, rspamd_upstreams_count (upl), 0);
		rspamd_upstreams_foreach (upl, lua_upstream_inserter, &cbd);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static inline enum rspamd_upstreams_watch_event
lua_str_to_upstream_flag (const gchar *str)
{
	enum rspamd_upstreams_watch_event fl = 0;

	if (strcmp (str, "success") == 0) {
		fl = RSPAMD_UPSTREAM_WATCH_SUCCESS;
	}
	else if (strcmp (str, "failure") == 0) {
		fl = RSPAMD_UPSTREAM_WATCH_FAILURE;
	}
	else if (strcmp (str, "online") == 0) {
		fl = RSPAMD_UPSTREAM_WATCH_ONLINE;
	}
	else if (strcmp (str, "offline") == 0) {
		fl = RSPAMD_UPSTREAM_WATCH_OFFLINE;
	}
	else {
		msg_err ("invalid flag: %s", str);
	}

	return fl;
}

static inline const gchar *
lua_upstream_flag_to_str (enum rspamd_upstreams_watch_event fl)
{
	const gchar *res = "unknown";

	/* Works with single flags, not combinations */
	if (fl & RSPAMD_UPSTREAM_WATCH_SUCCESS) {
		res = "success";
	}
	else if (fl & RSPAMD_UPSTREAM_WATCH_FAILURE) {
		res = "failure";
	}
	else if (fl & RSPAMD_UPSTREAM_WATCH_ONLINE) {
		res = "online";
	}
	else if (fl & RSPAMD_UPSTREAM_WATCH_OFFLINE) {
		res = "offline";
	}
	else {
		msg_err ("invalid flag: %d", fl);
	}

	return res;
}

struct rspamd_lua_upstream_watcher_cbdata {
	lua_State *L;
	gint cbref;
	gint parent_cbref; /* Reference to the upstream list */
	struct upstream_list *upl;
};

static void
lua_upstream_watch_func (struct upstream *up,
						 enum rspamd_upstreams_watch_event event,
						 guint cur_errors,
						 void *ud)
{
	struct rspamd_lua_upstream_watcher_cbdata *cdata =
			(struct rspamd_lua_upstream_watcher_cbdata *)ud;
	lua_State *L;
	const gchar *what;
	gint err_idx;

	L = cdata->L;
	what = lua_upstream_flag_to_str (event);
	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cdata->cbref);
	lua_pushstring (L, what);

	struct rspamd_lua_upstream *lua_ups = lua_newuserdata (L, sizeof (*lua_ups));
	lua_ups->up = up;
	rspamd_lua_setclass (L, "rspamd{upstream}", -1);
	/* Store parent in the upstream to prevent gc */
	lua_rawgeti (L, LUA_REGISTRYINDEX, cdata->parent_cbref);
	lua_ups->upref = luaL_ref (L, LUA_REGISTRYINDEX);

	lua_pushinteger (L, cur_errors);

	if (lua_pcall (L, 3, 0, err_idx) != 0) {
		msg_err ("cannot call watch function for upstream: %s", lua_tostring (L, -1));
		lua_settop (L, 0);

		return;
	}

	lua_settop (L, 0);
}

static void
lua_upstream_watch_dtor (gpointer ud)
{
	struct rspamd_lua_upstream_watcher_cbdata *cdata =
			(struct rspamd_lua_upstream_watcher_cbdata *)ud;

	luaL_unref (cdata->L, LUA_REGISTRYINDEX, cdata->cbref);
	luaL_unref (cdata->L, LUA_REGISTRYINDEX, cdata->parent_cbref);
	g_free (cdata);
}

/***
 * @method upstream_list:add_watcher(what, cb)
 * Add new watcher to the upstream lists events (table or a string):
 *   - `success` - called whenever upstream successfully used
 *   - `failure` - called on upstream error
 *   - `online` - called when upstream is being taken online from offline
 *   - `offline` - called when upstream is being taken offline from online
 * Callback is a function: function(what, upstream, cur_errors) ... end
 * @example
ups:add_watcher('success', function(what, up, cur_errors) ... end)
ups:add_watcher({'online', 'offline'}, function(what, up, cur_errors) ... end)
 * @return nothing
 */
static gint
lua_upstream_list_add_watcher (lua_State *L)
{
	LUA_TRACE_POINT;
	struct upstream_list *upl;

	upl = lua_check_upstream_list (L);
	if (upl &&
		(lua_type (L, 2) == LUA_TTABLE ||  lua_type (L, 2) == LUA_TSTRING) &&
		lua_type (L, 3) == LUA_TFUNCTION) {

		enum rspamd_upstreams_watch_event flags = 0;
		struct rspamd_lua_upstream_watcher_cbdata *cdata;

		if (lua_type (L, 2) == LUA_TSTRING) {
			flags = lua_str_to_upstream_flag (lua_tostring (L, 2));
		}
		else {
			for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
				if (lua_isstring (L, -1)) {
					flags |= lua_str_to_upstream_flag (lua_tostring (L, -1));
				}
				else {
					lua_pop (L, 1);

					return luaL_error (L, "invalid arguments");
				}
			}
		}

		cdata = g_malloc0 (sizeof (*cdata));
		lua_pushvalue (L, 3); /* callback */
		cdata->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		cdata->L = L;
		cdata->upl = upl;
		lua_pushvalue (L, 1); /* upstream list itself */
		cdata->parent_cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		rspamd_upstreams_add_watch_callback (upl, flags,
				lua_upstream_watch_func, lua_upstream_watch_dtor, cdata);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
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
	rspamd_lua_new_class (L, "rspamd{upstream_list}", upstream_list_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_upstream_list", lua_load_upstream_list);

	rspamd_lua_new_class (L, "rspamd{upstream}", upstream_m);
	lua_pop (L, 1);
}
