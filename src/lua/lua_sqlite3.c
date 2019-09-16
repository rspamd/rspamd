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
#include "sqlite_utils.h"

/***
 * @module rspamd_sqlite3
 * This module provides routines to query sqlite3 databases
@example
local sqlite3 = require "rspamd_sqlite3"

local db = sqlite3.open("/tmp/db.sqlite")

if db then
	db:exec([[ CREATE TABLE x (id INT, value TEXT); ]])

	db:exec([[ INSERT INTO x VALUES (?1, ?2); ]], 1, 'test')

	for row in db:rows([[ SELECT * FROM x ]]) do
		print(string.format('%d -> %s', row.id, row.value))
	end
end
 */

LUA_FUNCTION_DEF (sqlite3, open);
LUA_FUNCTION_DEF (sqlite3, sql);
LUA_FUNCTION_DEF (sqlite3, rows);
LUA_FUNCTION_DEF (sqlite3, close);
LUA_FUNCTION_DEF (sqlite3_stmt, close);

static const struct luaL_reg sqlitelib_f[] = {
	LUA_INTERFACE_DEF (sqlite3, open),
	{NULL, NULL}
};

static const struct luaL_reg sqlitelib_m[] = {
	LUA_INTERFACE_DEF (sqlite3, sql),
	{"query", lua_sqlite3_sql},
	{"exec", lua_sqlite3_sql},
	LUA_INTERFACE_DEF (sqlite3, rows),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_sqlite3_close},
	{NULL, NULL}
};

static const struct luaL_reg sqlitestmtlib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_sqlite3_stmt_close},
	{NULL, NULL}
};

static void lua_sqlite3_push_row (lua_State *L, sqlite3_stmt *stmt);

static sqlite3 *
lua_check_sqlite3 (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{sqlite3}");
	luaL_argcheck (L, ud != NULL, pos, "'sqlite3' expected");
	return ud ? *((sqlite3 **)ud) : NULL;
}

static sqlite3_stmt *
lua_check_sqlite3_stmt (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{sqlite3_stmt}");
	luaL_argcheck (L, ud != NULL, pos, "'sqlite3_stmt' expected");
	return ud ? *((sqlite3_stmt **)ud) : NULL;
}


/***
 * @function rspamd_sqlite3.open(path)
 * Opens sqlite3 database at the specified path. DB is created if not exists.
 * @param {string} path path to db
 * @return {sqlite3} sqlite3 handle
 */
static gint
lua_sqlite3_open (lua_State *L)
{
	const gchar *path = luaL_checkstring (L, 1);
	sqlite3 *db, **pdb;
	GError *err = NULL;

	if (path == NULL) {
		lua_pushnil (L);
		return 1;
	}

	db = rspamd_sqlite3_open_or_create (NULL, path, NULL, 0, &err);

	if (db == NULL) {
		if (err) {
			msg_err ("cannot open db: %e", err);
			g_error_free (err);
		}
		lua_pushnil (L);

		return 1;
	}

	pdb = lua_newuserdata (L, sizeof (db));
	*pdb = db;
	rspamd_lua_setclass (L, "rspamd{sqlite3}", -1);

	return 1;
}

static void
lua_sqlite3_bind_statements (lua_State *L, gint start, gint end,
		sqlite3_stmt *stmt)
{
	gint i, type, num = 1;
	const gchar *str;
	gsize slen;
	gdouble n;

	g_assert (start <= end && start > 0 && end > 0);

	for (i = start; i <= end; i ++) {
		type = lua_type (L, i);

		switch (type) {
		case LUA_TNUMBER:
			n = lua_tonumber (L, i);

			if (n == (gdouble)((gint64)n)) {
				sqlite3_bind_int64 (stmt, num, n);
			}
			else {
				sqlite3_bind_double (stmt, num, n);
			}
			num ++;
			break;
		case LUA_TSTRING:
			str = lua_tolstring (L, i, &slen);
			sqlite3_bind_text (stmt, num, str, slen, SQLITE_TRANSIENT);
			num ++;
			break;
		default:
			msg_err ("invalid type at position %d: %s", i, lua_typename (L, type));
			break;
		}
	}
}

/***
 * @function rspamd_sqlite3:sql(query[, args..])
 * Performs sqlite3 query replacing '?1', '?2' and so on with the subsequent args
 * of the function
 *
 * @param {string} query SQL query
 * @param {string|number} args... variable number of arguments
 * @return {boolean} `true` if a statement has been successfully executed
 */
static gint
lua_sqlite3_sql (lua_State *L)
{
	LUA_TRACE_POINT;
	sqlite3 *db = lua_check_sqlite3 (L, 1);
	const gchar *query = luaL_checkstring (L, 2);
	sqlite3_stmt *stmt;
	gboolean ret = FALSE;
	gint top = 1, rc;

	if (db && query) {
		if (sqlite3_prepare_v2 (db, query, -1, &stmt, NULL) != SQLITE_OK) {
			msg_err ("cannot prepare query %s: %s", query, sqlite3_errmsg (db));
			return luaL_error (L, sqlite3_errmsg (db));
		}
		else {
			top = lua_gettop (L);

			if (top > 2) {
				/* Push additional arguments to sqlite3 */
				lua_sqlite3_bind_statements (L, 3, top, stmt);
			}

			rc = sqlite3_step (stmt);
			top = 1;

			if (rc == SQLITE_ROW || rc == SQLITE_OK || rc == SQLITE_DONE) {
				ret = TRUE;

				if (rc == SQLITE_ROW) {
					lua_sqlite3_push_row (L, stmt);
					top = 2;
				}
			}
			else {
				msg_warn ("sqlite3 error: %s", sqlite3_errmsg (db));
			}

			sqlite3_finalize (stmt);
		}
	}

	lua_pushboolean (L, ret);

	return top;
}

static void
lua_sqlite3_push_row (lua_State *L, sqlite3_stmt *stmt)
{
	const gchar *str;
	gsize slen;
	gint64 num;
	gchar numbuf[32];
	gint nresults, i, type;

	nresults = sqlite3_column_count (stmt);
	lua_createtable (L, 0, nresults);

	for (i = 0; i < nresults; i ++) {
		lua_pushstring (L, sqlite3_column_name (stmt, i));
		type = sqlite3_column_type (stmt, i);

		switch (type) {
		case SQLITE_INTEGER:
			/*
			 * XXX: we represent int64 as strings, as we can nothing else to do
			 * about it portably
			 */
			num = sqlite3_column_int64 (stmt, i);
			rspamd_snprintf (numbuf, sizeof (numbuf), "%uL", num);
			lua_pushstring (L, numbuf);
			break;
		case SQLITE_FLOAT:
			lua_pushnumber (L, sqlite3_column_double (stmt, i));
			break;
		case SQLITE_TEXT:
			slen = sqlite3_column_bytes (stmt, i);
			str = sqlite3_column_text (stmt, i);
			lua_pushlstring (L, str, slen);
			break;
		case SQLITE_BLOB:
			slen = sqlite3_column_bytes (stmt, i);
			str = sqlite3_column_blob (stmt, i);
			lua_pushlstring (L, str, slen);
			break;
		default:
			lua_pushboolean (L, 0);
			break;
		}

		lua_settable (L, -3);
	}
}

static gint
lua_sqlite3_next_row (lua_State *L)
{
	LUA_TRACE_POINT;
	sqlite3_stmt *stmt = *(sqlite3_stmt **)lua_touserdata (L, lua_upvalueindex (1));
	gint rc;

	if (stmt != NULL) {
		rc = sqlite3_step (stmt);

		if (rc == SQLITE_ROW) {
			lua_sqlite3_push_row (L, stmt);
			return 1;
		}
	}

	lua_pushnil (L);

	return 1;
}

/***
 * @function rspamd_sqlite3:rows(query[, args..])
 * Performs sqlite3 query replacing '?1', '?2' and so on with the subsequent args
 * of the function. This function returns iterator suitable for loop construction:
 *
 * @param {string} query SQL query
 * @param {string|number} args... variable number of arguments
 * @return {function} iterator to get all rows
@example
for row in db:rows([[ SELECT * FROM x ]]) do
  print(string.format('%d -> %s', row.id, row.value))
end
 */
static gint
lua_sqlite3_rows (lua_State *L)
{
	LUA_TRACE_POINT;
	sqlite3 *db = lua_check_sqlite3 (L, 1);
	const gchar *query = luaL_checkstring (L, 2);
	sqlite3_stmt *stmt, **pstmt;
	gint top;

	if (db && query) {
		if (sqlite3_prepare_v2 (db, query, -1, &stmt, NULL) != SQLITE_OK) {
			msg_err ("cannot prepare query %s: %s", query, sqlite3_errmsg (db));
			lua_pushstring (L, sqlite3_errmsg (db));
			return lua_error (L);
		}
		else {
			top = lua_gettop (L);

			if (top > 2) {
				/* Push additional arguments to sqlite3 */
				lua_sqlite3_bind_statements (L, 3, top, stmt);
			}

			/* Create C closure */
			pstmt = lua_newuserdata (L, sizeof (stmt));
			*pstmt = stmt;
			rspamd_lua_setclass (L, "rspamd{sqlite3_stmt}", -1);

			lua_pushcclosure (L, lua_sqlite3_next_row, 1);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_sqlite3_close (lua_State *L)
{
	LUA_TRACE_POINT;
	sqlite3 *db = lua_check_sqlite3 (L, 1);

	if (db) {
		sqlite3_close (db);
	}

	return 0;
}

static gint
lua_sqlite3_stmt_close (lua_State *L)
{
	sqlite3_stmt *stmt = lua_check_sqlite3_stmt (L, 1);

	if (stmt) {
		sqlite3_finalize (stmt);
	}

	return 0;
}

static gint
lua_load_sqlite3 (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, sqlitelib_f);

	return 1;
}
/**
 * Open redis library
 * @param L lua stack
 * @return
 */
void
luaopen_sqlite3 (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{sqlite3}", sqlitelib_m);
	lua_pop (L, 1);

	rspamd_lua_new_class (L, "rspamd{sqlite3_stmt}", sqlitestmtlib_m);
	lua_pop (L, 1);

	rspamd_lua_add_preload (L, "rspamd_sqlite3", lua_load_sqlite3);
}
