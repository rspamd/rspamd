/*-
 * Copyright 2019 Vsevolod Stakhov
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
#include "libcryptobox/cryptobox.h"
#include "unix-std.h"

/***
 * @module rspamd_text
 * This module provides access to opaque text structures used widely to prevent
 * copying between Lua and C for various concerns: performance, security etc...
 *
 * You can convert rspamd_text into string but it will copy data.
 */

/**
 * @function rspamd_text.fromstring(str)
 * Creates rspamd_text from Lua string (copied to the text)
 * @param {string} str string to use
 * @return {rspamd_text} resulting text
 */
LUA_FUNCTION_DEF (text, fromstring);
/**
 * @function rspamd_text.fromtable(tbl[, delim])
 * Same as `table.concat` but generates rspamd_text instead of the Lua string
 * @param {table} tbl table to use
 * @param {string} delim optional delimiter
 * @return {rspamd_text} resulting text
 */
LUA_FUNCTION_DEF (text, fromtable);
/***
 * @method rspamd_text:len()
 * Returns length of a string
 * @return {number} length of string in **bytes**
 */
LUA_FUNCTION_DEF (text, len);
/***
 * @method rspamd_text:str()
 * Converts text to string by copying its content
 * @return {string} copy of text as Lua string
 */
LUA_FUNCTION_DEF (text, str);
/***
 * @method rspamd_text:ptr()
 * Converts text to lightuserdata
 * @return {lightuserdata} pointer value of rspamd_text
 */
LUA_FUNCTION_DEF (text, ptr);
/***
 * @method rspamd_text:save_in_file(fname[, mode])
 * Saves text in file
 * @return {boolean} true if save has been completed
 */
LUA_FUNCTION_DEF (text, save_in_file);
LUA_FUNCTION_DEF (text, take_ownership);
LUA_FUNCTION_DEF (text, gc);
LUA_FUNCTION_DEF (text, eq);

static const struct luaL_reg textlib_f[] = {
		LUA_INTERFACE_DEF (text, fromstring),
		LUA_INTERFACE_DEF (text, fromtable),
		{NULL, NULL}
};

static const struct luaL_reg textlib_m[] = {
		LUA_INTERFACE_DEF (text, len),
		LUA_INTERFACE_DEF (text, str),
		LUA_INTERFACE_DEF (text, ptr),
		LUA_INTERFACE_DEF (text, take_ownership),
		LUA_INTERFACE_DEF (text, save_in_file),
		{"write", lua_text_save_in_file},
		{"__len", lua_text_len},
		{"__tostring", lua_text_str},
		{"__gc", lua_text_gc},
		{"__eq", lua_text_eq},
		{NULL, NULL}
};

static gint
lua_text_fromstring (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *str;
	gsize l = 0;
	struct rspamd_lua_text *t;

	str = luaL_checklstring (L, 1, &l);

	if (str) {
		t = lua_newuserdata (L, sizeof (*t));
		t->start = g_malloc (l + 1);
		rspamd_strlcpy ((char *)t->start, str, l + 1);
		t->len = l;
		t->flags = RSPAMD_TEXT_FLAG_OWN;
		rspamd_lua_setclass (L, "rspamd{text}", -1);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}


	return 1;
}

static gint
lua_text_fromtable (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *delim = "", *st;
	struct rspamd_lua_text *t, *elt;
	gsize textlen = 0, dlen, stlen, tblen;
	gchar *dest;

	if (!lua_istable (L, 1)) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 2) == LUA_TSTRING) {
		delim = lua_tolstring (L, 2, &dlen);
	}
	else {
		dlen = strlen (delim);
	}

	/* Calculate length needed */
	tblen = rspamd_lua_table_size (L, 1);

	for (guint i = 0; i < tblen; i ++) {
		lua_rawgeti (L, 1, i + 1);

		if (lua_type (L, -1) == LUA_TSTRING) {
#if LUA_VERSION_NUM >= 502
			stlen = lua_rawlen (L, -1);
#else
			stlen = lua_objlen (L, -1);
#endif
			textlen += stlen;
		}
		else {
			elt = lua_check_text (L, -1);

			if (elt) {
				textlen += elt->len;
			}
		}

		lua_pop (L, 1);
		textlen += dlen;
	}

	/* Allocate new text */
	t = lua_newuserdata (L, sizeof (*t));
	dest = g_malloc (textlen);
	t->start = dest;
	t->len = textlen;
	t->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);

	for (guint i = 0; i < tblen; i ++) {
		lua_rawgeti (L, 1, i + 1);

		if (lua_type (L, -1) == LUA_TSTRING) {
			st = lua_tolstring (L, -1, &stlen);
			memcpy (dest, st, stlen);
			dest += stlen;
		}
		else {
			elt = lua_check_text (L, -1);

			if (elt) {
				memcpy (dest, elt->start, elt->len);
			}
		}

		memcpy (dest, delim, dlen);
		lua_pop (L, 1);
	}

	return 1;
}

static gint
lua_text_len (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text (L, 1);
	gsize l = 0;

	if (t != NULL) {
		l = t->len;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushinteger (L, l);

	return 1;
}

static gint
lua_text_str (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text (L, 1);

	if (t != NULL) {
		lua_pushlstring (L, t->start, t->len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_text_ptr (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text (L, 1);

	if (t != NULL) {
		lua_pushlightuserdata (L, (gpointer)t->start);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_text_take_ownership (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text (L, 1);
	gchar *dest;

	if (t != NULL) {
		if (t->flags & RSPAMD_TEXT_FLAG_OWN) {
			/* We already own it */
			lua_pushboolean (L, true);
		}
		else {
			dest = g_malloc (t->len);
			memcpy (dest, t->start, t->len);
			t->start = dest;
			t->flags |= RSPAMD_TEXT_FLAG_OWN;
			lua_pushboolean (L, true);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_text_save_in_file (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text (L, 1);
	const gchar *fname = NULL;
	guint mode = 00644;
	gint fd = -1;
	gboolean need_close = FALSE;

	if (t != NULL) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			fname = luaL_checkstring (L, 2);

			if (lua_type (L, 3) == LUA_TNUMBER) {
				mode = lua_tonumber (L, 3);
			}
		}
		else if (lua_type (L, 2) == LUA_TNUMBER) {
			/* Created fd */
			fd = lua_tonumber (L, 2);
		}

		if (fd == -1) {
			if (fname) {
				fd = rspamd_file_xopen (fname, O_CREAT | O_WRONLY | O_EXCL, mode, 0);

				if (fd == -1) {
					lua_pushboolean (L, false);
					lua_pushstring (L, strerror (errno));

					return 2;
				}
				need_close = TRUE;
			}
			else {
				fd = STDOUT_FILENO;
			}
		}

		if (write (fd, t->start, t->len) == -1) {
			if (fd != STDOUT_FILENO) {
				close (fd);
			}

			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		if (need_close) {
			close (fd);
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_text_gc (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text (L, 1);

	if (t != NULL) {
		if (t->flags & RSPAMD_TEXT_FLAG_OWN) {
			if (t->flags & RSPAMD_TEXT_FLAG_WIPE) {
				rspamd_explicit_memzero ((guchar *)t->start, t->len);
			}

			if (t->flags & RSPAMD_TEXT_FLAG_MMAPED) {
				munmap ((gpointer)t->start, t->len);
			}
			else {
				g_free ((gpointer)t->start);
			}
		}

	}

	return 0;
}

static gint
lua_text_eq (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t1 = lua_check_text (L, 1),
			*t2 = lua_check_text (L, 2);

	if (t1->len == t2->len) {
		lua_pushboolean (L, memcmp (t1->start, t2->start, t1->len) == 0);
	}
	else {
		lua_pushboolean (L, false);
	}

	return 1;
}

static gint
lua_text_wipe (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text (L, 1);

	if (t != NULL) {
		if (t->flags & RSPAMD_TEXT_FLAG_OWN) {
			rspamd_explicit_memzero ((guchar *)t->start, t->len);
		}
		else {
			return luaL_error (L, "cannot wipe not owned text");
		}

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_load_text (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, textlib_f);

	return 1;
}

void
luaopen_text (lua_State *L)
{
	rspamd_lua_new_class (L, "rspamd{text}", textlib_m);
	lua_pop (L, 1);

	rspamd_lua_add_preload (L, "rspamd_text", lua_load_text);
}
