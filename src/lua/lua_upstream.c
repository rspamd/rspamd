/* Copyright (c) 2010-2011, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "lua_common.h"
#include "upstream.h"
#include "cfg_file.h"

/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

/**
 * This module implements upstreams manipulation from lua
 */
/* Upstream list functions */
LUA_FUNCTION_DEF (upstream_list, create);
LUA_FUNCTION_DEF (upstream_list, destroy);
LUA_FUNCTION_DEF (upstream_list, get_upstream_by_hash);
LUA_FUNCTION_DEF (upstream_list, get_upstream_round_robin);
LUA_FUNCTION_DEF (upstream_list, get_upstream_master_slave);

static const struct luaL_reg  upstream_list_m[] = {

	LUA_INTERFACE_DEF (upstream_list, get_upstream_by_hash),
	LUA_INTERFACE_DEF (upstream_list, get_upstream_round_robin),
	LUA_INTERFACE_DEF (upstream_list, get_upstream_master_slave),
	{"__tostring", lua_class_tostring},
	{"__gc", lua_upstream_list_destroy},
	{NULL, NULL}
};
static const struct luaL_reg  upstream_list_f[] = {
	LUA_INTERFACE_DEF (upstream_list, create),
	{NULL, NULL}
};

/* Upstream functions */
LUA_FUNCTION_DEF (upstream, create);
LUA_FUNCTION_DEF (upstream, destroy);
LUA_FUNCTION_DEF (upstream, ok);
LUA_FUNCTION_DEF (upstream, fail);
LUA_FUNCTION_DEF (upstream, get_ip);
LUA_FUNCTION_DEF (upstream, get_port);
LUA_FUNCTION_DEF (upstream, get_ip_string);
LUA_FUNCTION_DEF (upstream, get_priority);

static const struct luaL_reg  upstream_m[] = {
	LUA_INTERFACE_DEF (upstream, ok),
	LUA_INTERFACE_DEF (upstream, fail),
	LUA_INTERFACE_DEF (upstream, get_ip),
	LUA_INTERFACE_DEF (upstream, get_ip_string),
	LUA_INTERFACE_DEF (upstream, get_port),
	LUA_INTERFACE_DEF (upstream, get_priority),
	LUA_INTERFACE_DEF (upstream, destroy),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};
static const struct luaL_reg  upstream_f[] = {
	LUA_INTERFACE_DEF (upstream, create),
	{NULL, NULL}
};

/* Upstream class */
struct lua_upstream {
	struct upstream up;
	gchar *def;
	guint16 port;
	gchar addr[INET6_ADDRSTRLEN];
};

static struct lua_upstream	*
lua_check_upstream (lua_State * L)
{
	void									*ud = luaL_checkudata (L, 1, "rspamd{upstream}");

	luaL_argcheck (L, ud != NULL, 1, "'upstream' expected");
	return ud ? *((struct lua_upstream **)ud) : NULL;
}

/**
 * Create new upstream from its string definition like 'ip[:port[:priority]]' or 'host[:port[:priority]]'
 * @param L
 * @return upstream structure
 */
static gint
lua_upstream_create (lua_State *L)
{
	struct lua_upstream						*new, **pnew;
	const gchar								*def;

	def = luaL_checkstring (L, 1);
	if (def) {
		new = g_slice_alloc0 (sizeof (struct lua_upstream));
		new->def = g_strdup (def);
		if (!parse_host_port_priority (NULL, new->def, (gchar **)&new->addr, &new->port, &new->up.priority)) {
			g_free (new->def);
			g_slice_free1 (sizeof (struct lua_upstream), new);
			lua_pushnil (L);
		}
		else {
			pnew = lua_newuserdata (L, sizeof (struct lua_upstream *));
			lua_setclass (L, "rspamd{upstream}", -1);
			*pnew = new;
		}
	}

	return 1;
}

/**
 * Destroy a single upstream object
 * @param L
 * @return
 */
static gint
lua_upstream_destroy (lua_State *L)
{
	struct lua_upstream						*up = lua_check_upstream (L);

	if (up) {
		g_free (up->def);
		g_slice_free1 (sizeof (struct lua_upstream), up);
	}

	return 0;
}

/**
 * Get ip of upstream in numeric form (guint32)
 * @param L
 * @return
 */
static gint
lua_upstream_get_ip (lua_State *L)
{
	struct lua_upstream						*up = lua_check_upstream (L);

	if (up) {
		lua_pushstring (L, up->addr);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/**
 * Get ip of upstream in string form
 * @param L
 * @return
 */
static gint
lua_upstream_get_ip_string (lua_State *L)
{
	struct lua_upstream						*up = lua_check_upstream (L);

	if (up) {
		lua_pushstring (L, up->addr);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/**
 * Get port of upstream in numeric form
 * @param L
 * @return
 */
static gint
lua_upstream_get_port (lua_State *L)
{
	struct lua_upstream						*up = lua_check_upstream (L);

	if (up) {
		lua_pushinteger (L, up->port);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/**
 * Get port of upstream in numeric form
 * @param L
 * @return
 */
static gint
lua_upstream_get_priority (lua_State *L)
{
	struct lua_upstream						*up = lua_check_upstream (L);

	if (up) {
		lua_pushinteger (L, up->up.priority);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/**
 * Make upstream fail, the second argument is time, if absent the current time is used
 * @param L
 * @return
 */
static gint
lua_upstream_fail (lua_State *L)
{
	struct lua_upstream						*up = lua_check_upstream (L);
	time_t									 now;

	if (up) {
		if (lua_gettop (L) >= 2) {
			now = luaL_checkinteger (L, 2);
		}
		else {
			now = time (NULL);
		}
		upstream_fail (&up->up, now);
	}

	return 0;
}

/**
 * Make upstream success, the second argument is time, if absent the current time is used
 * @param L
 * @return
 */
static gint
lua_upstream_ok (lua_State *L)
{
	struct lua_upstream						*up = lua_check_upstream (L);
	time_t									 now;

	if (up) {
		if (lua_gettop (L) >= 2) {
			now = luaL_checkinteger (L, 2);
		}
		else {
			now = time (NULL);
		}
		upstream_ok (&up->up, now);
	}

	return 0;
}

/* Upstream list class */
struct lua_upstream_list {
	struct lua_upstream *upstreams;
	guint count;
};

static struct lua_upstream_list	*
lua_check_upstream_list (lua_State * L)
{
	void									*ud = luaL_checkudata (L, 1, "rspamd{upstream_list}");

	luaL_argcheck (L, ud != NULL, 1, "'upstream_list' expected");
	return ud ? *((struct lua_upstream_list **)ud) : NULL;
}

/**
 * Create new upstream list from its string definition like '<upstream>,<upstream>;<upstream>'
 * @param L
 * @return upstream list structure
 */
static gint
lua_upstream_list_create (lua_State *L)
{
	struct lua_upstream_list				*new, **pnew;
	struct lua_upstream						*cur;
	const gchar								*def;
	char									**tokens;
	guint									 i, default_port = 0;

	def = luaL_checkstring (L, 1);
	if (def) {
		if (lua_gettop (L) >= 2) {
			default_port = luaL_checkinteger (L, 2);
		}
		new = g_slice_alloc0 (sizeof (struct lua_upstream_list));

		tokens = g_strsplit_set (def, ",;", 0);
		if (!tokens || !tokens[0]) {
			goto err;
		}
		new->count = g_strv_length (tokens);
		new->upstreams = g_slice_alloc0 (new->count * sizeof (struct lua_upstream));

		for (i = 0; i < new->count; i ++) {
			cur = &new->upstreams[i];
			if (!parse_host_port_priority (NULL, tokens[i], (gchar **)&cur->addr, &cur->port, &cur->up.priority)) {
				goto err;
			}
			if (cur->port == 0) {
				cur->port = default_port;
			}
		}
		pnew = lua_newuserdata (L, sizeof (struct upstream_list *));
		lua_setclass (L, "rspamd{upstream_list}", -1);
		*pnew = new;
	}

	return 1;
err:
	if (tokens) {
		g_strfreev (tokens);
	}
	if (new->upstreams) {
		g_slice_free1 (new->count * sizeof (struct lua_upstream), new->upstreams);
	}
	g_slice_free1 (sizeof (struct lua_upstream_list), new);
	lua_pushnil (L);
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
	struct lua_upstream_list					*upl = lua_check_upstream_list (L);

	if (upl) {
		if (upl->upstreams) {
			g_slice_free1 (upl->count * sizeof (struct lua_upstream), upl->upstreams);
		}
		g_slice_free1 (sizeof (struct lua_upstream_list), upl);
	}

	return 0;
}

/**
 * Get upstream by hash from key, params are: key and time (optional)
 * @param L
 * @return
 */
static gint
lua_upstream_list_get_upstream_by_hash (lua_State *L)
{
	struct lua_upstream_list					*upl;
	struct lua_upstream							*selected, **pselected;
	time_t										 now;
	const gchar									*key;

	upl = lua_check_upstream_list (L);
	if (upl) {
		key = luaL_checkstring (L, 2);
		if (key) {
			if (lua_gettop (L) >= 3) {
				now = luaL_checkinteger (L, 3);
			}
			else {
				now = time (NULL);
			}
			selected = (struct lua_upstream *)get_upstream_by_hash (upl->upstreams, upl->count,
					sizeof (struct lua_upstream), now,
					DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS,
					key, 0);
			if (selected) {
				pselected = lua_newuserdata (L, sizeof (struct lua_upstream *));
				lua_setclass (L, "rspamd{upstream}", -1);
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

/**
 * Get upstream round robin (by current weight), params are: time (optional)
 * @param L
 * @return
 */
static gint
lua_upstream_list_get_upstream_round_robin (lua_State *L)
{
	struct lua_upstream_list					*upl;
	struct lua_upstream							*selected, **pselected;
	time_t										 now;

	upl = lua_check_upstream_list (L);
	if (upl) {
		if (lua_gettop (L) >= 2) {
			now = luaL_checkinteger (L, 2);
		}
		else {
			now = time (NULL);
		}
		selected = (struct lua_upstream *)get_upstream_round_robin (upl->upstreams, upl->count,
				sizeof (struct lua_upstream), now,
				DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
		if (selected) {
			pselected = lua_newuserdata (L, sizeof (struct lua_upstream *));
			lua_setclass (L, "rspamd{upstream}", -1);
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

/**
 * Get upstream master slave order (by static priority), params are: time (optional)
 * @param L
 * @return
 */
static gint
lua_upstream_list_get_upstream_master_slave (lua_State *L)
{
	struct lua_upstream_list					*upl;
	struct lua_upstream							*selected, **pselected;
	time_t										 now;

	upl = lua_check_upstream_list (L);
	if (upl) {
		if (lua_gettop (L) >= 2) {
			now = luaL_checkinteger (L, 2);
		}
		else {
			now = time (NULL);
		}
		selected = (struct lua_upstream *)get_upstream_master_slave (upl->upstreams, upl->count,
				sizeof (struct lua_upstream), now,
				DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
		if (selected) {
			pselected = lua_newuserdata (L, sizeof (struct lua_upstream *));
			lua_setclass (L, "rspamd{upstream}", -1);
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


gint
luaopen_upstream (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{upstream_list}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{upstream_list}");
	lua_rawset (L, -3);

	luaL_openlib (L, NULL, upstream_list_m, 0);
	luaL_openlib (L, "upstream_list", upstream_list_f, 0);

	lua_pop (L, 1);                      /* remove metatable from stack */

	luaL_newmetatable (L, "rspamd{upstream}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{upstream}");
	lua_rawset (L, -3);

	luaL_openlib (L, NULL, upstream_m, 0);
	luaL_openlib (L, "upstream", upstream_f, 0);

	lua_pop (L, 1);                      /* remove metatable from stack */

	return 1;
}
