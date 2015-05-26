/* Copyright (c) 2010-2015, Vsevolod Stakhov
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

struct lua_session_udata {
	lua_State *L;
	gint cbref_fin;
	gint cbref_restore;
	gint cbref_cleanup;
	rspamd_mempool_t *pool;
	struct rspamd_async_session *session;
};

struct lua_event_udata {
	lua_State *L;
	gint cbref;
	struct rspamd_async_session *session;
};

/* Public prototypes */
struct lua_session_udata * lua_check_session (lua_State * L);
void luaopen_session (lua_State * L);

/* Lua bindings */
LUA_FUNCTION_DEF (session, register_async_event);
LUA_FUNCTION_DEF (session, remove_normal_event);
LUA_FUNCTION_DEF (session, check_session_pending);
LUA_FUNCTION_DEF (session, create);
LUA_FUNCTION_DEF (session, delete);

static const struct luaL_reg sessionlib_m[] = {
	LUA_INTERFACE_DEF (session, register_async_event),
	LUA_INTERFACE_DEF (session, remove_normal_event),
	LUA_INTERFACE_DEF (session, check_session_pending),
	LUA_INTERFACE_DEF (session, delete),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static const struct luaL_reg sessionlib_f[] = {
	LUA_INTERFACE_DEF (session, create),
	{NULL, NULL}
};

static const struct luaL_reg eventlib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct lua_session_udata *
lua_check_session (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{session}");
	luaL_argcheck (L, ud != NULL, 1, "'session' expected");
	return ud ? *((struct lua_session_udata **)ud) : NULL;
}

struct rspamd_async_event *
lua_check_event (lua_State * L, gint pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{event}");
	luaL_argcheck (L, ud != NULL, 1, "'event' expected");
	return ud ? *((struct rspamd_async_event **)ud) : NULL;
}

/* Usage: rspamd_session.create(pool, finalizer, restore, cleanup) */

static gboolean
lua_session_finalizer (gpointer ud)
{
	struct lua_session_udata *cbdata = ud;
	gboolean res;

	/* Call finalizer function */
	lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_fin);
	if (lua_pcall (cbdata->L, 0, 1, 0) != 0) {
		msg_info ("call to session finalizer failed: %s",
			lua_tostring (cbdata->L, -1));
	}
	res = lua_toboolean (cbdata->L, -1);
	lua_pop (cbdata->L, 1);
	luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_fin);


	return res;
}

static void
lua_session_restore (gpointer ud)
{
	struct lua_session_udata *cbdata = ud;

	if (cbdata->cbref_restore) {

		/* Call restorer function */
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_restore);
		if (lua_pcall (cbdata->L, 0, 0, 0) != 0) {
			msg_info ("call to session restorer failed: %s",
				lua_tostring (cbdata->L, -1));
		}
		luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_restore);
	}
}

static void
lua_session_cleanup (gpointer ud)
{
	struct lua_session_udata *cbdata = ud;

	if (cbdata->cbref_cleanup) {

		/* Call restorer function */
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_cleanup);
		if (lua_pcall (cbdata->L, 0, 0, 0) != 0) {
			msg_info ("call to session cleanup failed: %s",
				lua_tostring (cbdata->L, -1));
		}
		luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_cleanup);
	}
}



static int
lua_session_create (lua_State *L)
{
	struct rspamd_async_session *session;
	struct lua_session_udata *cbdata, **pdata;
	rspamd_mempool_t *mempool;

	if (lua_gettop (L) < 2 || lua_gettop (L) > 4) {
		msg_err ("invalid arguments number to rspamd_session.create");
		lua_pushnil (L);
		return 1;
	}

	mempool = rspamd_lua_check_mempool (L, 1);
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

	cbdata = rspamd_mempool_alloc0 (mempool, sizeof (struct lua_session_udata));
	cbdata->L = L;
	cbdata->pool = mempool;
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

	session = rspamd_session_create (mempool,
			lua_session_finalizer,
			lua_session_restore,
			lua_session_cleanup,
			cbdata);
	cbdata->session = session;
	pdata = lua_newuserdata (L, sizeof (struct rspamd_async_session *));
	rspamd_lua_setclass (L, "rspamd{session}", -1);
	*pdata = cbdata;

	return 1;
}

static int
lua_session_delete (lua_State *L)
{
	struct lua_session_udata *cbd = lua_check_session (L);
	struct rspamd_async_session *session;

	session = cbd->session;
	if (session) {
		rspamd_session_destroy (session);
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
	struct lua_event_udata *cbdata = ud;

	if (cbdata->cbref) {
		/* Call restorer function */
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref);
		if (lua_pcall (cbdata->L, 0, 0, 0) != 0) {
			msg_info ("call to event finalizer failed: %s",
				lua_tostring (cbdata->L, -1));
		}
		luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref);
	}
}

static int
lua_session_register_async_event (lua_State *L)
{
	struct lua_session_udata *cbd = lua_check_session (L);
	struct rspamd_async_session *session;
	struct lua_event_udata *cbdata;
	gpointer *pdata;

	session = cbd->session;

	if (session) {
		if (lua_isfunction (L, 1)) {
			cbdata =
				rspamd_mempool_alloc (cbd->pool,
					sizeof (struct lua_event_udata));
			cbdata->L = L;
			lua_pushvalue (L, 1);
			cbdata->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			cbdata->session = session;
			rspamd_session_add_event (session,
				lua_event_fin,
				cbdata,
				g_quark_from_static_string ("lua event"));
			pdata = lua_newuserdata (L, sizeof (gpointer));
			rspamd_lua_setclass (L, "rspamd{event}", -1);
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
	struct lua_session_udata *cbd = lua_check_session (L);
	struct rspamd_async_session *session;
	gpointer data;

	session = cbd->session;

	if (session) {
		data = lua_check_event (L, 2);
		if (data) {
			rspamd_session_remove_event (session, lua_event_fin, data);
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
	struct lua_session_udata *cbd = lua_check_session (L);
	struct rspamd_async_session *session;

	session = cbd->session;

	if (session) {

	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_load_session (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, sessionlib_f);

	return 1;
}

void
luaopen_session (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{session}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{session}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,				sessionlib_m);
	rspamd_lua_add_preload (L, "rspamd_session", lua_load_session);

	lua_pop (L, 1);

	/* Simple event class */
	rspamd_lua_new_class (L, "rspamd{event}", eventlib_m);

	lua_pop (L, 1);
}
