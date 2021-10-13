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
#include "lua_common.h"
#include "cdb.h"

#define CDB_REFRESH_TIME 60

LUA_FUNCTION_DEF (cdb, create);
LUA_FUNCTION_DEF (cdb, lookup);
LUA_FUNCTION_DEF (cdb, get_name);
LUA_FUNCTION_DEF (cdb, destroy);

static const struct luaL_reg cdblib_m[] = {
	LUA_INTERFACE_DEF (cdb, lookup),
	LUA_INTERFACE_DEF (cdb, get_name),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cdb_destroy},
	{NULL, NULL}
};
static const struct luaL_reg cdblib_f[] = {
	LUA_INTERFACE_DEF (cdb, create),
	{NULL, NULL}
};

static struct cdb *
lua_check_cdb (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{cdb}");

	luaL_argcheck (L, ud != NULL, 1, "'cdb' expected");
	return ud ? *((struct cdb **)ud) : NULL;
}

static gint
lua_cdb_create (lua_State *L)
{
	struct cdb *cdb, **pcdb;
	const gchar *filename;
	gint fd;
	struct ev_loop *ev_base = lua_check_ev_base (L, 2);

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
		if (cdb_init (cdb, fd) == -1) {
			g_free (cdb->filename);
			g_free (cdb);
			msg_warn ("cannot open cdb: %s, %s", filename, strerror (errno));
			lua_pushnil (L);
		}
		else {
#ifdef HAVE_READAHEAD
			struct stat st;
			/*
			 * Do not readahead more than 100mb,
			 * which is enough for the vast majority of the use cases
			 */
			static const size_t max_readahead = 100 * 0x100000;

			if (fstat(cdb_fileno(cdb), &st) != 1) {
				/* Must always be true because cdb_init calls it as well */
				if (readahead(cdb_fileno(cdb), 0, MIN(max_readahead, st.st_size)) == -1) {
					msg_warn ("cannot readahead cdb: %s, %s", filename, strerror (errno));
				}
			}
#endif
			cdb_add_timer (cdb, ev_base, CDB_REFRESH_TIME);
			pcdb = lua_newuserdata (L, sizeof (struct cdb *));
			rspamd_lua_setclass (L, "rspamd{cdb}", -1);
			*pcdb = cdb;
		}
	}

	return 1;
}

static gint
lua_cdb_get_name (lua_State *L)
{
	struct cdb *cdb = lua_check_cdb (L);

	if (!cdb) {
		lua_error (L);
		return 1;
	}
	lua_pushstring (L, cdb->filename);
	return 1;
}

static gint
lua_cdb_lookup (lua_State *L)
{
	struct cdb *cdb = lua_check_cdb (L);
	const gchar *what;
	gchar *value;
	gsize vlen;
	gint64 vpos;

	if (!cdb) {
		lua_error (L);
		return 1;
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
	struct cdb *cdb = lua_check_cdb (L);

	if (cdb) {
		cdb_free (cdb);
		(void)close (cdb->cdb_fd);
		g_free (cdb->filename);
		g_free (cdb);
	}

	return 0;
}

static gint
lua_load_cdb (lua_State *L)
{
	lua_newtable (L);
	luaL_register (L, NULL, cdblib_f);

	return 1;
}

void
luaopen_cdb (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{cdb}", cdblib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_cdb", lua_load_cdb);
}
