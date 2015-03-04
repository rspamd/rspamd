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
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"
#include "expressions.h"

/***
 * Rspamd regexp is an utility module that handles rspamd perl compatible
 * regular expressions
 * @module rspamd_regexp
 * @example
 * local rspamd_regexp = require "rspamd_regexp"
 *
 * local re = rspamd_regexp.create_cached('/^\\s*some_string\\s*^/i')
 * re:match('some_string')
 * -- Required since regexp are optimized to be stored in the cache
 * re:destroy()
 *
 * -- Or it is possible to use metatable if re is an element of some table
 * local tbl = {}
 * tbl['key'] = rspamd_regexp.create_cached('.*')
 * setmetatable(tbl, {
 * 	__gc = function(t) t:destroy() end
 * })
 */

LUA_FUNCTION_DEF (regexp, create);
LUA_FUNCTION_DEF (regexp, create_cached);
LUA_FUNCTION_DEF (regexp, get_cached);
LUA_FUNCTION_DEF (regexp, get_pattern);
LUA_FUNCTION_DEF (regexp, match);
LUA_FUNCTION_DEF (regexp, split);
LUA_FUNCTION_DEF (regexp, destroy);

static const struct luaL_reg regexplib_m[] = {
	LUA_INTERFACE_DEF (regexp, get_pattern),
	LUA_INTERFACE_DEF (regexp, match),
	LUA_INTERFACE_DEF (regexp, split),
	LUA_INTERFACE_DEF (regexp, destroy),
	{"__tostring", lua_regexp_get_pattern},
	{NULL, NULL}
};
static const struct luaL_reg regexplib_f[] = {
	LUA_INTERFACE_DEF (regexp, create),
	LUA_INTERFACE_DEF (regexp, get_cached),
	LUA_INTERFACE_DEF (regexp, create_cached),
	{NULL, NULL}
};

rspamd_mempool_t *regexp_static_pool = NULL;

struct rspamd_lua_regexp {
	GRegex *re;
	gchar *re_pattern;
	gint re_flags;
};

static struct rspamd_lua_regexp *
lua_check_regexp (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{regexp}");

	luaL_argcheck (L, ud != NULL, 1, "'regexp' expected");
	return ud ? *((struct rspamd_lua_regexp **)ud) : NULL;
}

/***
 * @function rspamd_regexp.create(pattern[, flags])
 * Creates new rspamd_regexp
 * @param {string} pattern pattern to build regexp. If this pattern is enclosed in `//` then it is possible to specify flags after it
 * @param {string} flags optional flags to create regular expression
 * @return {regexp} regexp argument that is *not* automatically destroyed
 * @example
 * local regexp = require "rspamd_regexp"
 *
 * local re = regexp.create('/^test.*[0-9]\\s*$/i')
 */
static int
lua_regexp_create (lua_State *L)
{
	gint regexp_flags = 0;
	GRegex *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL, *slash;
	gchar *pattern, sep;
	GError *err = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	if (string[0] == '/') {
		/* We have likely slashed regexp */
		slash = strrchr (string, '/');
		if (slash != NULL && slash != string) {
			flags_str = slash + 1;
			pattern = g_malloc (slash - string);
			rspamd_strlcpy (pattern, string + 1, slash - string);
		}
		else {
			pattern = g_strdup (string);
		}
	}
	else if (string[0] == 'm') {
		/* Special case for perl */
		slash = &string[1];
		sep = *slash;
		slash = strrchr (string, sep);
		if (slash != NULL && slash > &string[1]) {
			flags_str = slash + 1;
			pattern = g_malloc (slash - string - 1);
			rspamd_strlcpy (pattern, string + 2, slash - string - 1);
		}
	}
	else {
		pattern = g_strdup (string);
	}

	if (flags_str && flags_str != '\0') {
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
				goto fin;
				break;
			}
			flags_str++;
		}
	}
fin:
	re = g_regex_new (pattern, regexp_flags, 0, &err);
	if (re == NULL) {
		g_free (pattern);
		lua_pushnil (L);
		msg_info ("cannot parse regexp: %s, error: %s",
			string,
			err == NULL ? "undefined" : err->message);
	}
	else {
		new = g_slice_alloc (sizeof (struct rspamd_lua_regexp));
		new->re = re;
		new->re_flags = regexp_flags;
		new->re_pattern = pattern;
		pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
		rspamd_lua_setclass (L, "rspamd{regexp}", -1);
		*pnew = new;
		re_cache_add (new->re_pattern, new, regexp_static_pool);
	}

	return 1;
}

/***
 * @function rspamd_regexp.get_cached(pattern)
 * This function gets cached and pre-compiled regexp created by either `create`
 * or `create_cached` methods. If no cached regexp is found then `nil` is returned.
 *
 * @param {string} pattern regexp pattern
 * @return {regexp} cached regexp structure or `nil`
 */
static int
lua_regexp_get_cached (lua_State *L)
{
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *line;

	line = luaL_checkstring (L, 1);
	new = re_cache_check (line, regexp_static_pool);
	if (new) {
		pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
		rspamd_lua_setclass (L, "rspamd{regexp}", -1);
		*pnew = new;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @function rspamd_regexp.create_cached(pattern[, flags])
 * This function is similar to `create` but it tries to search for regexp in the
 * cache first.
 * @param {string} pattern pattern to build regexp. If this pattern is enclosed in `//` then it is possible to specify flags after it
 * @param {string} flags optional flags to create regular expression
 * @return {regexp} regexp argument that is *not* automatically destroyed
 * @example
 * local regexp = require "rspamd_regexp"
 *
 * local re = regexp.create_cached('/^test.*[0-9]\\s*$/i')
 * ...
 * -- This doesn't create new regexp object
 * local other_re = regexp.create_cached('/^test.*[0-9]\\s*$/i')
 */
static int
lua_regexp_create_cached (lua_State *L)
{
	const gchar *line;
	struct rspamd_lua_regexp *new, **pnew;

	line = luaL_checkstring (L, 1);
	new = re_cache_check (line, regexp_static_pool);
	if (new) {
		pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
		rspamd_lua_setclass (L, "rspamd{regexp}", -1);
		*pnew = new;
	}
	else {
		return lua_regexp_create (L);
	}

	return 1;
}

/***
 * @method re:get_pattern()
 * Get a pattern for specified regexp object
 * @return {string} pattern line
 */
static int
lua_regexp_get_pattern (lua_State *L)
{
	struct rspamd_lua_regexp *re = lua_check_regexp (L);

	if (re) {
		lua_pushstring (L, re->re_pattern);
	}

	return 1;
}

/***
 * @method re:match(line)
 * Match line against regular expression object. If line matches then this
 * function returns the table of captured strings. Otherwise, nil is returned.
 *
 * @param {string} line match the specified line against regexp object
 * @return {table or nil} table of strings matched or nil
 * @example
 * local re = regexp.create_cached('/^\s*([0-9]+)\s*$/')
 * -- returns nil
 * local m1 = re:match('blah')
 * local m2 = re:match('   190   ')
 * -- prints '190'
 * print(m2[1])
 */
static int
lua_regexp_match (lua_State *L)
{
	struct rspamd_lua_regexp *re = lua_check_regexp (L);
	GMatchInfo *mi;
	const gchar *data;
	gchar **matches;
	gint i;

	if (re) {
		data = luaL_checkstring (L, 2);
		if (data) {
			if ((re->re_flags & G_REGEX_RAW) == 0) {
				/* Validate input */
				if (!g_utf8_validate (data, -1, NULL)) {
					lua_pushnil (L);
					return 1;
				}
			}
			if (g_regex_match_full (re->re, data, -1, 0, 0, &mi, NULL)) {
				matches = g_match_info_fetch_all (mi);
				lua_newtable (L);
				for (i = 1; matches[i - 1] != NULL; i++) {
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

/***
 * @method re:split(line)
 * Split line using the specified regular expression.
 * Breaks the string on the pattern, and returns an array of the tokens.
 * If the pattern contains capturing parentheses, then the text for each
 * of the substrings will also be returned. If the pattern does not match
 * anywhere in the string, then the whole string is returned as the first
 * token.
 * @param {string} line line to split
 * @return {table} table of split line portions
 */
static int
lua_regexp_split (lua_State *L)
{
	struct rspamd_lua_regexp *re = lua_check_regexp (L);
	const gchar *data;
	gchar **parts;
	gint i;

	if (re) {
		data = luaL_checkstring (L, 2);
		if (data) {
			if ((re->re_flags & G_REGEX_RAW) == 0) {
				/* Validate input */
				if (!g_utf8_validate (data, -1, NULL)) {
					lua_pushnil (L);
					return 1;
				}
			}
			parts = g_regex_split (re->re, data, 0);
			lua_newtable (L);
			for (i = 1; parts[i - 1] != NULL; i++) {
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

/***
 * @method re:destroy()
 * We are not using `__gc` meta-method as it is usually good idea to have
 * compiled regexps to be stored permanently, so this method can be used
 * for avoiding memory leaks for temporary regexps
 */
static gint
lua_regexp_destroy (lua_State *L)
{
	struct rspamd_lua_regexp *to_del = lua_check_regexp (L);

	if (to_del) {
		re_cache_del (to_del->re_pattern, regexp_static_pool);
		g_regex_unref (to_del->re);
		g_free (to_del->re_pattern);
		g_slice_free1 (sizeof (struct rspamd_lua_regexp), to_del);
	}

	return 0;
}

static gint
lua_load_regexp (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, regexplib_f);

	return 1;
}

void
luaopen_glib_regexp (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{regexp}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{regexp}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, regexplib_m);
	rspamd_lua_add_preload (L, "rspamd_regexp", lua_load_regexp);

	regexp_static_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
}
