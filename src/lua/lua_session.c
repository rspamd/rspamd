/* Copyright (c) 2010-2012, Vsevolod Stakhov
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

#include "lua_common.h"

/* Public prototypes */
struct rspamd_async_session *lua_check_session (lua_State * L);
gint luaopen_session (lua_State * L);

/* Lua bindings */
LUA_FUNCTION_DEF (session, register_async_event);
LUA_FUNCTION_DEF (session, remove_normal_event);
LUA_FUNCTION_DEF (session, check_session_pending);
LUA_FUNCTION_DEF (session, create);
LUA_FUNCTION_DEF (session, delete);

static const struct luaL_reg    sessionlib_m[] = {
	LUA_INTERFACE_DEF (session, register_async_event),
	LUA_INTERFACE_DEF (session, remove_normal_event),
	LUA_INTERFACE_DEF (session, check_session_pending),
	{"__gc", lua_session_delete},
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

static const struct luaL_reg    sessionlib_f[] = {
	LUA_INTERFACE_DEF (session, create),
	{NULL, NULL}
};

static const struct luaL_reg    eventlib_m[] = {
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

struct lua_session_udata {
	lua_State *L;
	gint cbref_fin;
	gint cbref_restore;
	gint cbref_cleanup;
	struct rspamd_async_session *session;
};

struct lua_event_udata {
	lua_State *L;
	gint cbref;
	struct rspamd_async_session *session;
};

struct rspamd_async_session      *
lua_check_session (lua_State * L)
{
	void								*ud = luaL_checkudata (L, 1, "rspamd{session}");
	luaL_argcheck (L, ud != NULL, 1, "'session' expected");
	return ud ? *((struct rspamd_async_session **)ud) : NULL;
}

struct rspamd_async_event      *
lua_check_event (lua_State * L, gint pos)
{
	void								*ud = luaL_checkudata (L, pos, "rspamd{event}");
	luaL_argcheck (L, ud != NULL, 1, "'event' expected");
	return ud ? *((struct rspamd_async_event **)ud) : NULL;
}

/* Usage: rspamd_session.create(pool, finalizer, restore, cleanup) */

static gboolean
lua_session_finalizer (gpointer ud)
{
	struct lua_session_udata					*cbdata = ud;
	gboolean								 	need_unlock = FALSE;

	/* Avoid LOR here as mutex can be acquired before in lua_call */
	if (g_mutex_trylock (lua_mtx)) {
		need_unlock = TRUE;
	}

	/* Call finalizer function */
	lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_fin);
	if (lua_pcall (cbdata->L, 0, 0, 0) != 0) {
		msg_info ("call to session finalizer failed: %s", lua_tostring (cbdata->L, -1));
	}
	luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_fin);
	if (need_unlock) {
		g_mutex_unlock (lua_mtx);
	}

	return TRUE;
}

static void
lua_session_restore (gpointer ud)
{
	struct lua_session_udata					*cbdata = ud;
	gboolean									 need_unlock = FALSE;

	if (cbdata->cbref_restore) {
	/* Avoid LOR here as mutex can be acquired before in lua_call */
		if (g_mutex_trylock (lua_mtx)) {
			need_unlock = TRUE;
		}

		/* Call restorer function */
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_restore);
		if (lua_pcall (cbdata->L, 0, 0, 0) != 0) {
			msg_info ("call to session restorer failed: %s", lua_tostring (cbdata->L, -1));
		}
		luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_restore);
		if (need_unlock) {
			g_mutex_unlock (lua_mtx);
		}
	}
}

static void
lua_session_cleanup (gpointer ud)
{
	struct lua_session_udata					*cbdata = ud;
	gboolean								 	 need_unlock = FALSE;

	if (cbdata->cbref_cleanup) {
	/* Avoid LOR here as mutex can be acquired before in lua_call */
		if (g_mutex_trylock (lua_mtx)) {
			need_unlock = TRUE;
		}

		/* Call restorer function */
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_cleanup);
		if (lua_pcall (cbdata->L, 0, 0, 0) != 0) {
			msg_info ("call to session cleanup failed: %s", lua_tostring (cbdata->L, -1));
		}
		luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_cleanup);
		if (need_unlock) {
			g_mutex_unlock (lua_mtx);
		}
	}
}



static int
lua_session_create (lua_State *L)
{
	struct rspamd_async_session					*session, **psession;
	struct lua_session_udata					*cbdata;
	memory_pool_t								*mempool;



	if (lua_gettop (L) < 2 || lua_gettop (L) > 4) {
		msg_err ("invalid arguments number to rspamd_session.create");
		lua_pushnil (L);
		return 1;
	}

	mempool = lua_check_mempool (L);
	if (mempool == NULL) {
		msg_err ("invalid mempool argument to rspamd_session.create");
		lua_pushnil (L);
		return 1;
	}

	if (!lua_isfunction (L, 2)) {
		msg_err ("invalid finalizer argument to rspamd_session.create");
		lua_pushnil (L);
		return 1;
	}

	cbdata = memory_pool_alloc0 (mempool, sizeof (struct lua_session_udata));
	cbdata->L = L;
	lua_pushvalue (L, 2);
	cbdata->cbref_fin = luaL_ref (L, LUA_REGISTRYINDEX);

	if (lua_gettop (L) > 2) {
		/* Also add restore callback */
		if (lua_isfunction (L, 3)) {
			lua_pushvalue (L, 3);
			cbdata->cbref_restore = luaL_ref (L, LUA_REGISTRYINDEX);
		}
	}

	if (lua_gettop (L) > 3) {
		/* Also add cleanup callback */
		if (lua_isfunction (L, 4)) {
			lua_pushvalue (L, 4);
			cbdata->cbref_cleanup = luaL_ref (L, LUA_REGISTRYINDEX);
		}
	}
	session = new_async_session (mempool, lua_session_finalizer, lua_session_restore, lua_session_cleanup, cbdata);
	cbdata->session = session;
	psession = lua_newuserdata (L, sizeof (struct rspamd_async_session *));
	lua_setclass (L, "rspamd{session}", -1);
	*psession = session;

	return 1;
}

static int
lua_session_delete (lua_State *L)
{
	struct rspamd_async_session					*session = lua_check_session (L);

	if (session) {
		destroy_session (session);
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static void
lua_event_fin (gpointer ud)
{
	struct lua_event_udata						*cbdata = ud;
	gboolean								 	 need_unlock = FALSE;

	if (cbdata->cbref) {
	/* Avoid LOR here as mutex can be acquired before in lua_call */
		if (g_mutex_trylock (lua_mtx)) {
			need_unlock = TRUE;
		}

		/* Call restorer function */
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref);
		if (lua_pcall (cbdata->L, 0, 0, 0) != 0) {
			msg_info ("call to event finalizer failed: %s", lua_tostring (cbdata->L, -1));
		}
		luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref);
		if (need_unlock) {
			g_mutex_unlock (lua_mtx);
		}
	}
}

static int
lua_session_register_async_event (lua_State *L)
{
	struct rspamd_async_session					*session = lua_check_session (L);
	struct lua_event_udata						*cbdata;
	gpointer									*pdata;

	if (session) {
		if (lua_isfunction (L, 1)) {
			cbdata = memory_pool_alloc (session->pool, sizeof (struct lua_event_udata));
			cbdata->L = L;
			lua_pushvalue (L, 1);
			cbdata->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			cbdata->session = session;
			register_async_event (session, lua_event_fin, cbdata, g_quark_from_static_string ("lua event"));
			pdata = lua_newuserdata (L, sizeof (gpointer));
			lua_setclass (L, "rspamd{event}", -1);
			*pdata = cbdata;
		}
		else {
			msg_err ("invalid finalizer argument to register async event");
		}
	}
	lua_pushnil (L);

	return 1;
}

static int
lua_session_remove_normal_event (lua_State *L)
{
	struct rspamd_async_session					*session = lua_check_session (L);
	gpointer									 data;

	if (session) {
		data = lua_check_event (L, 2);
		if (data) {
			remove_normal_event (session, lua_event_fin, data);
			return 0;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_session_check_session_pending (lua_State *L)
{
	struct rspamd_async_session					*session = lua_check_session (L);

	if (session) {
		
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

gint
luaopen_session (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{session}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{session}");
	lua_rawset (L, -3);

	luaL_openlib (L, NULL, sessionlib_m, 0);
	luaL_openlib(L, "rspamd_session", sessionlib_f, 0);

	/* Simple event class */
	lua_newclass (L, "rspamd{event}", eventlib_m);
	luaL_openlib (L, "rspamd_event", null_reg, 0);

	return 1;	
}
