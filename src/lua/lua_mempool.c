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
#include "mem_pool.h"

/* Lua bindings */
LUA_FUNCTION_DEF (mempool, create);
LUA_FUNCTION_DEF (mempool, memory_pool_add_destructor);
LUA_FUNCTION_DEF (mempool, memory_pool_delete);
LUA_FUNCTION_DEF (mempool, memory_pool_stat);
LUA_FUNCTION_DEF (mempool, memory_pool_suggest_size);
LUA_FUNCTION_DEF (mempool, memory_pool_set_variable);
LUA_FUNCTION_DEF (mempool, memory_pool_get_variable);

static const struct luaL_reg mempoollib_m[] = {
	LUA_INTERFACE_DEF (mempool, memory_pool_add_destructor),
	LUA_INTERFACE_DEF (mempool, memory_pool_stat),
	LUA_INTERFACE_DEF (mempool, memory_pool_suggest_size),
	LUA_INTERFACE_DEF (mempool, memory_pool_set_variable),
	LUA_INTERFACE_DEF (mempool, memory_pool_get_variable),
	{"destroy", lua_mempool_memory_pool_delete},
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static const struct luaL_reg mempoollib_f[] = {
	LUA_INTERFACE_DEF (mempool, create),
	{NULL, NULL}
};

/*
 * Struct for lua destructor
 */

struct lua_mempool_udata {
	lua_State *L;
	gint cbref;
	rspamd_mempool_t *mempool;
};

struct memory_pool_s *
rspamd_lua_check_mempool (lua_State * L, gint pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{mempool}");
	luaL_argcheck (L, ud != NULL, pos, "'mempool' expected");
	return ud ? *((struct memory_pool_s **)ud) : NULL;
}


static int
lua_mempool_create (lua_State *L)
{
	struct memory_pool_s *mempool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ()), **pmempool;

	if (mempool) {
		pmempool = lua_newuserdata (L, sizeof (struct memory_pool_s *));
		rspamd_lua_setclass (L, "rspamd{mempool}", -1);
		*pmempool = mempool;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static void
lua_mempool_destructor_func (gpointer p)
{
	struct lua_mempool_udata *ud = p;

	lua_rawgeti (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	if (lua_pcall (ud->L, 0, 0, 0) != 0) {
		msg_info ("call to destructor failed: %s", lua_tostring (ud->L, -1));
	}
	luaL_unref (ud->L, LUA_REGISTRYINDEX, ud->cbref);
}

static int
lua_mempool_memory_pool_add_destructor (lua_State *L)
{
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	struct lua_mempool_udata *ud;

	if (mempool) {
		if (lua_isfunction (L, 2)) {
			ud = rspamd_mempool_alloc (mempool,
					sizeof (struct lua_mempool_udata));
			lua_pushvalue (L, 2);
			/* Get a reference */
			ud->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			ud->L = L;
			ud->mempool = mempool;
			rspamd_mempool_add_destructor (mempool,
				lua_mempool_destructor_func,
				ud);
		}
		else {
			msg_err ("trying to add destructor without function");
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_memory_pool_delete (lua_State *L)
{
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);

	if (mempool) {
		rspamd_mempool_delete (mempool);
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_memory_pool_stat (lua_State *L)
{
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);

	if (mempool) {

	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_memory_pool_suggest_size (lua_State *L)
{
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);

	if (mempool) {
		lua_pushinteger (L, rspamd_mempool_suggest_size ());
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_memory_pool_set_variable (lua_State *L)
{
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	const gchar *var = luaL_checkstring (L, 2),
	*value = luaL_checkstring (L, 3);

	if (mempool && var && value) {
		rspamd_mempool_set_variable (mempool, var,
			rspamd_mempool_strdup (mempool, value), NULL);
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_memory_pool_get_variable (lua_State *L)
{
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	const gchar *var = luaL_checkstring (L, 2);
	gchar *value;

	if (mempool && var) {
		value = rspamd_mempool_get_variable (mempool, var);
		if (value) {
			lua_pushstring (L, value);
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

static gint
lua_load_mempool (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, mempoollib_f);

	return 1;
}

void
luaopen_mempool (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{mempool}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{mempool}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,				mempoollib_m);
	rspamd_lua_add_preload (L, "rspamd_mempool", lua_load_mempool);

	lua_pop (L, 1);                      /* remove metatable from stack */
}
