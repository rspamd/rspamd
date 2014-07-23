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
#include "buffer.h"

/* Public prototypes */
struct rspamd_io_dispatcher_s * lua_check_io_dispatcher (lua_State * L);
gint luaopen_io_dispatcher (lua_State * L);

/* Lua bindings */
LUA_FUNCTION_DEF (io_dispatcher, create);
LUA_FUNCTION_DEF (io_dispatcher, set_policy);
LUA_FUNCTION_DEF (io_dispatcher, write);
LUA_FUNCTION_DEF (io_dispatcher, pause);
LUA_FUNCTION_DEF (io_dispatcher, restore);
LUA_FUNCTION_DEF (io_dispatcher, destroy);

static const struct luaL_reg io_dispatcherlib_m[] = {
	LUA_INTERFACE_DEF (io_dispatcher, set_policy),
	LUA_INTERFACE_DEF (io_dispatcher, write),
	LUA_INTERFACE_DEF (io_dispatcher, pause),
	LUA_INTERFACE_DEF (io_dispatcher, restore),
	LUA_INTERFACE_DEF (io_dispatcher, destroy),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

static const struct luaL_reg io_dispatcherlib_f[] = {
	LUA_INTERFACE_DEF (io_dispatcher, create),
	{NULL, NULL}
};

struct lua_dispatcher_cbdata {
	lua_State *L;
	rspamd_io_dispatcher_t *d;
	struct event_base *base;
	gint cbref_read;
	gint cbref_write;
	gint cbref_err;
};

struct rspamd_io_dispatcher_s *
lua_check_io_dispatcher (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{io_dispatcher}");
	luaL_argcheck (L, ud != NULL, 1, "'io_dispatcher' expected");
	return ud ? *((struct rspamd_io_dispatcher_s **)ud) : NULL;
}

struct event_base *
lua_check_event_base (lua_State *L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{ev_base}");
	luaL_argcheck (L, ud != NULL, 1, "'ev_base' expected");
	return ud ? *((struct event_base **)ud) : NULL;
}

/* Dispatcher callbacks */

static gboolean
lua_io_read_cb (f_str_t * in, void *arg)
{
	struct lua_dispatcher_cbdata *cbdata = arg;
	gboolean res;
	rspamd_io_dispatcher_t **pdispatcher;

	/* callback (dispatcher, data) */
	lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_read);
	pdispatcher =
		lua_newuserdata (cbdata->L, sizeof (struct rspamd_io_dispatcher_s *));
	lua_setclass (cbdata->L, "rspamd{io_dispatcher}", -1);
	*pdispatcher = cbdata->d;
	lua_pushlstring (cbdata->L, in->begin, in->len);

	if (lua_pcall (cbdata->L, 2, 1, 0) != 0) {
		msg_info ("call to session finalizer failed: %s",
			lua_tostring (cbdata->L, -1));
	}

	res = lua_toboolean (cbdata->L, -1);
	lua_pop (cbdata->L, 1);

	return res;
}

static gboolean
lua_io_write_cb (void *arg)
{
	struct lua_dispatcher_cbdata *cbdata = arg;
	gboolean res = FALSE;
	rspamd_io_dispatcher_t **pdispatcher;

	if (cbdata->cbref_write) {
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_read);
		/* callback (dispatcher) */
		pdispatcher =
			lua_newuserdata (cbdata->L,
				sizeof (struct rspamd_io_dispatcher_s *));
		lua_setclass (cbdata->L, "rspamd{io_dispatcher}", -1);
		*pdispatcher = cbdata->d;


		if (lua_pcall (cbdata->L, 1, 1, 0) != 0) {
			msg_info ("call to session finalizer failed: %s",
				lua_tostring (cbdata->L, -1));
		}

		res = lua_toboolean (cbdata->L, -1);
		lua_pop (cbdata->L, 1);
	}

	return res;
}

static void
lua_io_err_cb (GError * err, void *arg)
{
	struct lua_dispatcher_cbdata *cbdata = arg;
	rspamd_io_dispatcher_t **pdispatcher;

	/* callback (dispatcher, err) */
	lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_err);
	pdispatcher =
		lua_newuserdata (cbdata->L, sizeof (struct rspamd_io_dispatcher_s *));
	lua_setclass (cbdata->L, "rspamd{io_dispatcher}", -1);
	*pdispatcher = cbdata->d;
	lua_pushstring (cbdata->L, err->message);

	if (lua_pcall (cbdata->L, 2, 0, 0) != 0) {
		msg_info ("call to session finalizer failed: %s",
			lua_tostring (cbdata->L, -1));
	}

	/* Unref callbacks */
	luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_read);
	if (cbdata->cbref_write) {
		luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_write);
	}
	luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref_err);

	g_error_free (err);
	g_slice_free1 (sizeof (struct lua_dispatcher_cbdata), cbdata);
}

/*
 * rspamd_dispatcher.create(base,fd, read_cb, write_cb, err_cb[, timeout])
 */
static int
lua_io_dispatcher_create (lua_State *L)
{
	struct rspamd_io_dispatcher_s *io_dispatcher, **pdispatcher;
	gint fd;
	struct lua_dispatcher_cbdata *cbdata;
	struct timeval tv = {0, 0};
	double tv_num, tmp;

	if (lua_gettop (L) >= 5 && lua_isfunction (L, 3) && lua_isfunction (L, 5)) {
		cbdata = g_slice_alloc0 (sizeof (struct lua_dispatcher_cbdata));
		cbdata->base = lua_check_event_base (L);
		if (cbdata->base == NULL) {
			/* Create new event base */
			msg_warn ("create new event base as it is not specified");
			cbdata->base = event_init ();
		}
		cbdata->L = L;
		fd = lua_tointeger (L, 2);
		lua_pushvalue (L, 3);
		cbdata->cbref_read = luaL_ref (L, LUA_REGISTRYINDEX);
		if (lua_isfunction (L, 4)) {
			/* Push write callback as well */
			lua_pushvalue (L, 4);
			cbdata->cbref_write = luaL_ref (L, LUA_REGISTRYINDEX);
		}
		/* Error callback */
		lua_pushvalue (L, 5);
		cbdata->cbref_err = luaL_ref (L, LUA_REGISTRYINDEX);

		if (lua_gettop (L) > 5) {
			tv_num = lua_tonumber (L, 6);
			tv.tv_sec = trunc (tv_num);
			tv.tv_usec = modf (tv_num, &tmp) * 1000.;
			io_dispatcher = rspamd_create_dispatcher (cbdata->base,
					fd,
					BUFFER_LINE,
					lua_io_read_cb,
					lua_io_write_cb,
					lua_io_err_cb,
					&tv,
					cbdata);
		}
		else {
			io_dispatcher = rspamd_create_dispatcher (cbdata->base,
					fd,
					BUFFER_LINE,
					lua_io_read_cb,
					lua_io_write_cb,
					lua_io_err_cb,
					NULL,
					cbdata);
		}

		cbdata->d = io_dispatcher;
		/* Push result */
		pdispatcher =
			lua_newuserdata (L, sizeof (struct rspamd_io_dispatcher_s *));
		lua_setclass (L, "rspamd{io_dispatcher}", -1);
		*pdispatcher = io_dispatcher;
	}
	else {
		msg_err ("invalid number of arguments to io_dispatcher.create: %d",
			lua_gettop (L));
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_io_dispatcher_set_policy (lua_State *L)
{
	struct rspamd_io_dispatcher_s *io_dispatcher = lua_check_io_dispatcher (L);
	gint policy, limit = -1;

	if (io_dispatcher) {
		policy = lua_tonumber (L, 2);
		if (policy > BUFFER_ANY || policy < BUFFER_LINE) {
			msg_err ("invalid policy: %d", policy);
		}
		else {
			if (lua_gettop (L) > 2) {
				limit = lua_tonumber (L, 3);
			}
			rspamd_set_dispatcher_policy (io_dispatcher, policy, limit);
			return 0;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_io_dispatcher_write (lua_State *L)
{
	struct rspamd_io_dispatcher_s *io_dispatcher = lua_check_io_dispatcher (L);
	gboolean delayed = FALSE, res;
	const gchar *data;
	size_t len;

	if (io_dispatcher) {
		if (lua_gettop (L) < 2) {
			msg_err ("invalid number of arguments to io_dispatcher.create: %d",
				lua_gettop (L));
			lua_pushboolean (L, FALSE);
		}
		else {
			data = lua_tolstring (L, 2, &len);
			if (lua_gettop (L) > 2) {
				delayed = lua_toboolean (L, 3);
			}
			res = rspamd_dispatcher_write (io_dispatcher,
					(void *)data,
					len,
					delayed,
					FALSE);
			lua_pushboolean (L, res);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_io_dispatcher_pause (lua_State *L)
{
	struct rspamd_io_dispatcher_s *io_dispatcher = lua_check_io_dispatcher (L);

	if (io_dispatcher) {
		rspamd_dispatcher_pause (io_dispatcher);
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_io_dispatcher_restore (lua_State *L)
{
	struct rspamd_io_dispatcher_s *io_dispatcher = lua_check_io_dispatcher (L);

	if (io_dispatcher) {
		rspamd_dispatcher_restore (io_dispatcher);
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_io_dispatcher_destroy (lua_State *L)
{
	struct rspamd_io_dispatcher_s *io_dispatcher = lua_check_io_dispatcher (L);

	if (io_dispatcher) {
		rspamd_remove_dispatcher (io_dispatcher);
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


gint
luaopen_io_dispatcher (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{io_dispatcher}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{io_dispatcher}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,					  io_dispatcherlib_m);
	luaL_register (L, "rspamd_io_dispatcher", io_dispatcherlib_f);

	lua_pop (L, 1);                      /* remove metatable from stack */

	/* Simple event class */
	lua_newclass (L, "rspamd{ev_base}", null_reg);
	luaL_register (L, "rspamd_ev_base", null_reg);

	lua_pop (L, 1);                      /* remove metatable from stack */

	/* Set buffer types globals */
	lua_pushnumber (L, BUFFER_LINE);
	lua_setglobal (L, "IO_BUFFER_LINE");
	lua_pushnumber (L, BUFFER_CHARACTER);
	lua_setglobal (L, "IO_BUFFER_CHARACTER");
	lua_pushnumber (L, BUFFER_ANY);
	lua_setglobal (L, "IO_BUFFER_ANY");
	return 1;
}
