/* Copyright (c) 2010, Vsevolod Stakhov
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
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"
#include "cdb/cdb.h"

#define CDB_REFRESH_TIME 60

LUA_FUNCTION_DEF (cdb, create);
LUA_FUNCTION_DEF (cdb, lookup);
LUA_FUNCTION_DEF (cdb, get_name);
LUA_FUNCTION_DEF (cdb, destroy);

static const struct luaL_reg    cdblib_m[] = {
	LUA_INTERFACE_DEF (cdb, lookup),
	LUA_INTERFACE_DEF (cdb, get_name),
	{"__tostring", lua_class_tostring},
	{"__gc", lua_cdb_destroy},
	{NULL, NULL}
};
static const struct luaL_reg    cdblib_f[] = {
	LUA_INTERFACE_DEF (cdb, create),
	{NULL, NULL}
};

static struct cdb	*
lua_check_cdb (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{cdb}");

	luaL_argcheck (L, ud != NULL, 1, "'cdb' expected");
	return ud ? *((struct cdb **)ud) : NULL;
}

static gint
lua_cdb_create (lua_State *L)
{
	struct cdb                     *cdb, **pcdb;
	const gchar                    *filename;
	gint                            fd;

	filename = luaL_checkstring (L, 1);
	/* If file begins with cdb://, just skip it */
	if (g_ascii_strncasecmp (filename, "cdb://", sizeof ("cdb://") - 1) == 0) {
		filename += sizeof ("cdb://") - 1;
	}

	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_warn ("cannot open cdb: %s, %s", filename, strerror (errno));
		lua_pushnil (L);
	}
	else {
		cdb = g_malloc (sizeof (struct cdb));
		cdb->filename = g_strdup (filename);
		cdb->check_timer_ev = NULL;
		cdb->check_timer_tv = NULL;
		if (cdb_init (cdb, fd) == -1) {
			msg_warn ("cannot open cdb: %s, %s", filename, strerror (errno));
			lua_pushnil (L);
		}
		else {
			pcdb = lua_newuserdata (L, sizeof (struct cdb*));
			lua_setclass (L, "rspamd{cdb}", -1);
			*pcdb = cdb;
		}
	}

	return 1;
}

static gint
lua_cdb_get_name (lua_State *L)
{
	struct cdb                     *cdb = lua_check_cdb (L);

	lua_pushstring (L, cdb->filename);
	return 1;
}

static gint
lua_cdb_lookup (lua_State *L)
{
	struct cdb                     *cdb = lua_check_cdb (L);
	const gchar                    *what;
	gchar                          *value;
	gsize                           vlen;
	gint64                          vpos;

	/*
	 * XXX: this code is placed here because event_loop is called inside workers, so start
	 * monitoring on first check, not on creation
	 */
	if (cdb->check_timer_ev == NULL) {
		cdb_add_timer (cdb, CDB_REFRESH_TIME);
	}

	what = luaL_checkstring (L, 2);
	if (cdb_find (cdb, what, strlen (what)) > 0) {
		/* Extract and push value to lua as string */
		vpos = cdb_datapos (cdb);
		vlen = cdb_datalen (cdb);
		value = g_malloc (vlen);
		cdb_read (cdb, value, vlen, vpos);
		lua_pushlstring (L, value, vlen);
		g_free (value);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_cdb_destroy (lua_State *L)
{
	struct cdb                     *cdb = lua_check_cdb (L);

	if (cdb) {
		cdb_free (cdb);
		(void)close (cdb->cdb_fd);
		g_free (cdb->filename);
		g_free (cdb);
	}

	return 0;
}

gint
luaopen_cdb (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{cdb}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{cdb}");
	lua_rawset (L, -3);

	luaL_openlib (L, NULL, cdblib_m, 0);
	luaL_openlib (L, "cdb", cdblib_f, 0);

	return 1;
}
