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

/***
 * @module rspamd_cdb
 * Rspamd CDB module is used to read and write key/value pairs to the CDB file
 *
 * @example
local rspamd_cdb = require "rspamd_cdb"
rspamd_cdb.build('/tmp/test.cdb'):add('test', 'value'):finalize()
local c = rspamd_cdb.open('/tmp/test.cdb')
c:find('test')
-- will return 'value'
 */

/***
 * @function rspamd_cdb.open(filename, [ev_base])
 * Opens an existing CDB for reading. If `ev_base` is specified, then cdb file is added
 * for monitoring, that will get updates on disk file changes.
 * @param {string} filename path to file
 * @param {ev_base} event loop object
 * @return {rspamd_cdb} cdb object
 */
LUA_FUNCTION_DEF (cdb, create);
/***
 * @method rspamd_cdb:find(key)
 * Finds a specific key in cdb and returns a string or nil if a key has not been found
 * @param {string} key key to find
 * @return {string/nil} value for the specific key
 */
LUA_FUNCTION_DEF (cdb, lookup);
/***
 * @method rspamd_cdb:get_name()
 * Returns filename for the specific cdb
 * @return {string} filename for cdb
 */
LUA_FUNCTION_DEF (cdb, get_name);
LUA_FUNCTION_DEF (cdb, destroy);

/***
 * @function rspamd_cdb.build(filename, [mode])
 * Creates a new cdb in a file (existing one will be overwritten!). The object
 * returned can be used merely for adding data. Upon finalizing, the data is written to
 * disk and cdb can no longer be changed.
 * @param {string} filename path to file
 * @param {int} mode numeric mode to create a file
 * @return {rspamd_cdb_builder} cdb builder object (or nil + error message)
 */
LUA_FUNCTION_DEF (cdb, build);
/***
 * @method rspamd_cdb_builder:add(key, value)
 * Adds new value to cdb in the builder mode
 * @param {string} key key to add
 * @param {string} value value to associate with the key
 * @return {rspamd_cdb_builder} the same object to allow chaining calls
 */
LUA_FUNCTION_DEF (cdb_builder, add);
/***
 * @method rspamd_cdb_builder:finalize()
 * Finalizes the CDB and writes it to disk. This method also closes FD associated with
 * CDB builder. No further additions are allowed after this point
 */
LUA_FUNCTION_DEF (cdb_builder, finalize);
LUA_FUNCTION_DEF (cdb_builder, dtor);

static const struct luaL_reg cdblib_m[] = {
	LUA_INTERFACE_DEF (cdb, lookup),
	{"find", lua_cdb_lookup},
	LUA_INTERFACE_DEF (cdb, get_name),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cdb_destroy},
	{NULL, NULL}
};

static const struct luaL_reg cdbbuilderlib_m[] = {
		LUA_INTERFACE_DEF (cdb_builder, add),
		LUA_INTERFACE_DEF (cdb_builder, finalize),
		{"__tostring", rspamd_lua_class_tostring},
		{"__gc", lua_cdb_builder_dtor},
		{NULL, NULL}
};

static const struct luaL_reg cdblib_f[] = {
	LUA_INTERFACE_DEF (cdb, create),
	{"open", lua_cdb_create},
	{"build", lua_cdb_build},
	{NULL, NULL}
};

static struct cdb *
lua_check_cdb (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{cdb}");

	luaL_argcheck (L, ud != NULL, pos, "'cdb' expected");
	return ud ? *((struct cdb **)ud) : NULL;
}

static struct cdb_make *
lua_check_cdb_builder (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{cdb_builder}");

	luaL_argcheck (L, ud != NULL, pos, "'cdb_builder' expected");
	return ud ? ((struct cdb_make *)ud) : NULL;
}

static const char *
lua_cdb_get_input (lua_State *L, int pos, gsize *olen)
{
	int t = lua_type (L, pos);

	switch (t) {
	case LUA_TSTRING:
		return lua_tolstring (L, pos, olen);
	case LUA_TNUMBER: {
		static char numbuf[sizeof(lua_Number)];
		lua_Number n = lua_tonumber(L, pos);
		memcpy(numbuf, &n, sizeof(numbuf));
		*olen = sizeof(n);
		return numbuf;
	}
	case LUA_TUSERDATA: {
		void *p = rspamd_lua_check_udata_maybe (L, pos, "rspamd{text}");
		if (p) {
			struct rspamd_lua_text *t = (struct rspamd_lua_text *)p;
			*olen = t->len;
			return t->start;
		}

		p = rspamd_lua_check_udata_maybe (L, pos, "rspamd{int64}");
		if (p) {
			static char numbuf[sizeof(gint64)];

			memcpy(numbuf, p, sizeof(numbuf));
			*olen = sizeof(numbuf);
			return numbuf;
		}
	}
	default:
		break;
	}

	return NULL;
}

static gint
lua_cdb_create (lua_State *L)
{
	struct cdb *cdb, **pcdb;
	const gchar *filename;
	gint fd;

	struct ev_loop *ev_base = NULL;

	if (lua_type(L, 2) == LUA_TUSERDATA) {
		ev_base = lua_check_ev_base(L, 2);
	}

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
		cdb = g_malloc0 (sizeof (struct cdb));
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
			if (ev_base) {
				cdb_add_timer(cdb, ev_base, CDB_REFRESH_TIME);
			}
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
	struct cdb *cdb = lua_check_cdb (L, 1);

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
	struct cdb *cdb = lua_check_cdb (L, 1);
	gsize klen;
	const gchar *what = lua_cdb_get_input(L, 2, &klen);

	if (!cdb || what == NULL) {
		return lua_error (L);
	}

	if (cdb_find (cdb, what, klen) > 0) {
		/* Extract and push value to lua as string */
		lua_pushlstring (L, cdb_getdata (cdb), cdb_datalen (cdb));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_cdb_destroy (lua_State *L)
{
	struct cdb *cdb = lua_check_cdb (L, 1);

	if (cdb) {
		cdb_free (cdb);
		if (cdb->cdb_fd != -1) {
			(void) close(cdb->cdb_fd);
		}
		g_free (cdb->filename);
		g_free (cdb);
	}

	return 0;
}

static gint
lua_cdb_build (lua_State *L)
{
	const char *filename = luaL_checkstring (L, 1);
	int fd, mode = 00755;

	if (filename == NULL) {
		return luaL_error (L, "invalid arguments, filename expected");
	}

	/* If file begins with cdb://, just skip it */
	if (g_ascii_strncasecmp (filename, "cdb://", sizeof ("cdb://") - 1) == 0) {
		filename += sizeof ("cdb://") - 1;
	}

	if (lua_isnumber (L, 2)) {
		mode = lua_tointeger (L, 2);
	}

	fd = rspamd_file_xopen (filename, O_RDWR | O_CREAT | O_TRUNC, mode, 0);

	if (fd == -1) {
		lua_pushnil (L);
		lua_pushfstring (L, "cannot open cdb: %s, %s", filename, strerror (errno));

		return 2;
	}

	struct cdb_make *cdbm = lua_newuserdata (L, sizeof(struct cdb_make));

	g_assert (cdb_make_start(cdbm, fd) == 0);
	rspamd_lua_setclass (L, "rspamd{cdb_builder}", -1);

	return 1;
}

static gint
lua_cdb_builder_add (lua_State *L)
{
	struct cdb_make *cdbm = lua_check_cdb_builder(L, 1);
	gsize data_sz, key_sz;
	const char *key = lua_cdb_get_input (L, 2, &key_sz);
	const char *data = lua_cdb_get_input (L, 3, &data_sz);

	if (cdbm == NULL || key == NULL || data == NULL || cdbm->cdb_fd == -1) {
		return luaL_error(L, "invalid arguments");
	}

	if (cdb_make_add (cdbm, key, key_sz, data, data_sz) == -1) {
		lua_pushvalue(L, 1);
		lua_pushfstring(L, "cannot push value to cdb: %s", strerror(errno));

		return 2;
	}

	/* Allow chaining */
	lua_pushvalue(L, 1);
	return 1;
}

static gint
lua_cdb_builder_finalize (lua_State *L)
{
	struct cdb_make *cdbm = lua_check_cdb_builder(L, 1);

	if (cdbm == NULL || cdbm->cdb_fd == -1) {
		return luaL_error(L, "invalid arguments");
	}

	if (cdb_make_finish (cdbm) == -1) {
		lua_pushvalue(L, 1);
		lua_pushfstring(L, "cannot finish value to cdb: %s", strerror(errno));

		return 2;
	}

	close (cdbm->cdb_fd);
	cdbm->cdb_fd = -1; /* To distinguish finalized object */

	/* Allow chaining */
	lua_pushvalue (L, 1);
	return 1;
}

static gint
lua_cdb_builder_dtor (lua_State *L)
{
	struct cdb_make *cdbm = lua_check_cdb_builder(L, 1);

	if (cdbm == NULL) {
		return luaL_error(L, "invalid arguments");
	}

	if (cdbm->cdb_fd != -1) {
		cdb_make_finish (cdbm);
		close (cdbm->cdb_fd);
		cdbm->cdb_fd = -1; /* Finalized object */
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
	rspamd_lua_new_class (L, "rspamd{cdb_builder}", cdbbuilderlib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_cdb", lua_load_cdb);
}
