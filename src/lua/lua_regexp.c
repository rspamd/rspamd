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
#include "../expressions.h"

LUA_FUNCTION_DEF (regexp, create);
LUA_FUNCTION_DEF (regexp, get_cached);
LUA_FUNCTION_DEF (regexp, get_pattern);
LUA_FUNCTION_DEF (regexp, match);
LUA_FUNCTION_DEF (regexp, split);
LUA_FUNCTION_DEF (regexp, destroy);

static const struct luaL_reg    regexplib_m[] = {
	LUA_INTERFACE_DEF (regexp, get_pattern),
	LUA_INTERFACE_DEF (regexp, match),
	LUA_INTERFACE_DEF (regexp, split),
	LUA_INTERFACE_DEF (regexp, destroy),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};
static const struct luaL_reg    regexplib_f[] = {
	LUA_INTERFACE_DEF (regexp, create),
	LUA_INTERFACE_DEF (regexp, get_cached),
	{NULL, NULL}
};

memory_pool_t *regexp_static_pool = NULL;

static GRegex	*
lua_check_regexp (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{regexp}");

	luaL_argcheck (L, ud != NULL, 1, "'regexp' expected");
	return *((GRegex **)ud);
}

static int
lua_regexp_create (lua_State *L)
{
	gint                            regexp_flags = 0;
	GRegex                         *new, **pnew;
	const gchar                    *string, *flags_str = NULL;
	GError                         *err = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	if (flags_str) {
		while (*flags_str) {
			switch (*flags_str) {
			case 'i':
				regexp_flags |= G_REGEX_CASELESS;
				break;
			case 'm':
				regexp_flags |= G_REGEX_MULTILINE;
				break;
			case 's':
				regexp_flags |= G_REGEX_DOTALL;
				break;
			case 'x':
				regexp_flags |= G_REGEX_EXTENDED;
				break;
			case 'u':
				regexp_flags |= G_REGEX_UNGREEDY;
				break;
			case 'o':
				regexp_flags |= G_REGEX_OPTIMIZE;
				break;
			case 'r':
				regexp_flags |= G_REGEX_RAW;
				break;
			default:
				msg_info ("invalid regexp flag: %c", *flags_str);
				break;
			}
			flags_str ++;
		}
	}

	new = g_regex_new (string, regexp_flags, 0, &err);
	if (new == NULL) {
		lua_pushnil (L);
		msg_info ("cannot parse regexp: %s, error: %s", string, err == NULL ? "undefined" : err->message);
	}
	else {
		pnew = lua_newuserdata (L, sizeof (GRegex *));
		lua_setclass (L, "rspamd{regexp}", -1);
		*pnew = new;
		re_cache_add (g_regex_get_pattern (new), new, regexp_static_pool);
	}

	return 1;
}

static int
lua_regexp_get_cached (lua_State *L)
{
	GRegex                         *new, **pnew;
	const gchar                    *line;

	line = luaL_checkstring (L, 1);
	new = re_cache_check (line, regexp_static_pool);
	if (new) {
		pnew = lua_newuserdata (L, sizeof (GRegex *));
		lua_setclass (L, "rspamd{regexp}", -1);
		*pnew = new;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_regexp_get_pattern (lua_State *L)
{
	GRegex                         *re = lua_check_regexp (L);

	if (re) {
		lua_pushstring (L, g_regex_get_pattern (re));
	}

	return 1;
}

static int
lua_regexp_match (lua_State *L)
{
	GRegex                         *re = lua_check_regexp (L);
	GMatchInfo                     *mi;
	const gchar                    *data;
	gchar                         **matches;
	gint                            i;

	if (re) {
		data = luaL_checkstring (L, 2);
		if (data) {
			if (g_regex_match_full (re, data, -1, 0, 0, &mi, NULL)) {
				matches = g_match_info_fetch_all (mi);
				lua_newtable (L);
				for (i = 1; matches[i - 1] != NULL; i ++) {
					lua_pushstring (L, matches[i - 1]);
					lua_rawseti (L, -2, i);
				}
				g_strfreev (matches);
			}
			else {
				lua_pushnil (L);
			}
			g_match_info_free (mi);
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static int
lua_regexp_split (lua_State *L)
{
	GRegex                         *re = lua_check_regexp (L);
	const gchar                    *data;
	gchar                         **parts;
	gint                            i;

	if (re) {
		data = luaL_checkstring (L, 2);
		if (data) {
			parts = g_regex_split (re, data, 0);
			lua_newtable (L);
			for (i = 1; parts[i - 1] != NULL; i ++) {
				lua_pushstring (L, parts[i - 1]);
				lua_rawseti (L, -2, i);
			}
			g_strfreev (parts);
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

/*
 * We are not using __gc metamethod as it is usually good idea to have
 * compiled regexps to be stored permamently, so this method can be used
 * for avoiding memory leaks for temporary regexps
 *
 *
 */
static gint
lua_regexp_destroy (lua_State *L)
{
	GRegex                         *to_del = lua_check_regexp (L);

	if (to_del) {
		re_cache_del (g_regex_get_pattern (to_del), regexp_static_pool);
		g_regex_unref (to_del);
	}

	return 0;
}

gint
luaopen_glib_regexp (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{regexp}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{regexp}");
	lua_rawset (L, -3);

	luaL_openlib (L, NULL, regexplib_m, 0);
	luaL_openlib(L, "regexp", regexplib_f, 0);

	regexp_static_pool = memory_pool_new (memory_pool_get_size ());

	return 1;
}
