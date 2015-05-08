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
#include "regexp.h"

/***
 * @module rspamd_regexp
 * Rspamd regexp is an utility module that handles rspamd perl compatible
 * regular expressions
 * @example
 * local rspamd_regexp = require "rspamd_regexp"
 *
 * local re = rspamd_regexp.create_cached('/^\\s*some_string\\s*$/i')
 * re:match('some_string')
 * local re = rspamd_regexp.create_cached('/\\s+/i')
 * re:split('word word   word') -- returns ['word', 'word', 'word']
 */

LUA_FUNCTION_DEF (regexp, create);
LUA_FUNCTION_DEF (regexp, create_cached);
LUA_FUNCTION_DEF (regexp, get_cached);
LUA_FUNCTION_DEF (regexp, get_pattern);
LUA_FUNCTION_DEF (regexp, set_limit);
LUA_FUNCTION_DEF (regexp, search);
LUA_FUNCTION_DEF (regexp, match);
LUA_FUNCTION_DEF (regexp, matchn);
LUA_FUNCTION_DEF (regexp, split);
LUA_FUNCTION_DEF (regexp, destroy);
LUA_FUNCTION_DEF (regexp, gc);

static const struct luaL_reg regexplib_m[] = {
	LUA_INTERFACE_DEF (regexp, get_pattern),
	LUA_INTERFACE_DEF (regexp, set_limit),
	LUA_INTERFACE_DEF (regexp, match),
	LUA_INTERFACE_DEF (regexp, matchn),
	LUA_INTERFACE_DEF (regexp, search),
	LUA_INTERFACE_DEF (regexp, split),
	LUA_INTERFACE_DEF (regexp, destroy),
	{"__tostring", lua_regexp_get_pattern},
	{"__gc", lua_regexp_gc},
	{NULL, NULL}
};
static const struct luaL_reg regexplib_f[] = {
	LUA_INTERFACE_DEF (regexp, create),
	LUA_INTERFACE_DEF (regexp, get_cached),
	LUA_INTERFACE_DEF (regexp, create_cached),
	{NULL, NULL}
};

#define LUA_REGEXP_FLAG_DESTROYED (1 << 0)
#define IS_DESTROYED(re) ((re)->re_flags & LUA_REGEXP_FLAG_DESTROYED)

rspamd_mempool_t *regexp_static_pool = NULL;

struct rspamd_lua_regexp {
	rspamd_regexp_t *re;
	gchar *re_pattern;
	gsize match_limit;
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
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;
	GError *err = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	re = rspamd_regexp_new (string, flags_str, &err);
	if (re == NULL) {
		lua_pushnil (L);
		msg_info ("cannot parse regexp: %s, error: %s",
			string,
			err == NULL ? "undefined" : err->message);
		g_error_free (err);
	}
	else {
		new = g_slice_alloc0 (sizeof (struct rspamd_lua_regexp));
		new->re = re;
		pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
		rspamd_lua_setclass (L, "rspamd{regexp}", -1);
		*pnew = new;
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
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	re = rspamd_regexp_cache_query (NULL, string, flags_str);

	if (re) {
		new = g_slice_alloc0 (sizeof (struct rspamd_lua_regexp));
		new->re = rspamd_regexp_ref (re);
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
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;
	GError *err = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	re = rspamd_regexp_cache_query (NULL, string, flags_str);

	if (re) {
		new = g_slice_alloc0 (sizeof (struct rspamd_lua_regexp));
		new->re = rspamd_regexp_ref (re);
		pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));

		rspamd_lua_setclass (L, "rspamd{regexp}", -1);
		*pnew = new;
	}
	else {
		re = rspamd_regexp_cache_create (NULL, string, flags_str, &err);
		if (re == NULL) {
			lua_pushnil (L);
			msg_info ("cannot parse regexp: %s, error: %s",
					string,
					err == NULL ? "undefined" : err->message);
			g_error_free (err);
		}
		else {
			new = g_slice_alloc0 (sizeof (struct rspamd_lua_regexp));
			new->re = rspamd_regexp_ref (re);
			pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
			rspamd_lua_setclass (L, "rspamd{regexp}", -1);
			*pnew = new;
		}
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

	if (re && re->re && !IS_DESTROYED (re)) {
		lua_pushstring (L, rspamd_regexp_get_pattern (re->re));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method re:set_limit(lim)
 * Set maximum size of text length to be matched with this regexp (if `lim` is
 * less or equal to zero then all texts are checked)
 * @param {number} lim limit in bytes
 */
static int
lua_regexp_set_limit (lua_State *L)
{
	struct rspamd_lua_regexp *re = lua_check_regexp (L);
	gint64 lim;

	lim = luaL_checknumber (L, 2);

	if (re && re->re && !IS_DESTROYED (re)) {
		if (lim > 0) {
			re->match_limit = lim;
		}
		else {
			re->match_limit = 0;
		}
	}

	return 0;
}

/***
 * @method re:search(line)
 * Search line in regular expression object. If line matches then this
 * function returns the table of captured strings. Otherwise, nil is returned.
 *
 * @param {string} line match the specified line against regexp object
 * @return {table or nil} table of strings matched or nil
 * @example
 * local re = regexp.create_cached('/^\s*([0-9]+)\s*$/')
 * -- returns nil
 * local m1 = re:search('blah')
 * local m2 = re:search('   190   ')
 * -- prints '190'
 * print(m2[1])
 */
static int
lua_regexp_search (lua_State *L)
{
	struct rspamd_lua_regexp *re = lua_check_regexp (L);
	const gchar *data;
	const gchar *start = NULL, *end = NULL;
	gint i;
	gsize len;
	gboolean matched = FALSE;

	if (re && !IS_DESTROYED (re)) {
		data = luaL_checklstring (L, 2, &len);
		if (data) {
			lua_newtable (L);
			i = 0;

			if (re->match_limit > 0) {
				len = MIN (len, re->match_limit);
			}

			while (rspamd_regexp_search (re->re, data, len, &start, &end, FALSE)) {
				lua_pushlstring (L, start, end - start);
				lua_rawseti (L, -2, ++i);
				matched = TRUE;
			}
			if (!matched) {
				lua_pop (L, 1);
				lua_pushnil (L);
			}
			return 1;
		}
	}

	lua_pushnil (L);

	return 1;
}

/***
 * @method re:match(line[, raw_match])
 * Matches line against the regular expression and return true if line matches
 * (partially or completely)
 *
 * @param {string} line match the specified line against regexp object
 * @param {bool} match raw regexp instead of utf8 one
 * @return {bool} true if `line` matches
 */
static int
lua_regexp_match (lua_State *L)
{
	struct rspamd_lua_regexp *re = lua_check_regexp (L);
	struct rspamd_lua_text *t;
	const gchar *data = NULL;
	gsize len = 0;
	gboolean raw = FALSE;

	if (re && !IS_DESTROYED (re)) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			data = luaL_checklstring (L, 2, &len);
		}
		else if (lua_type (L, 2) == LUA_TUSERDATA) {
			t = lua_check_text (L, 2);
			if (t != NULL) {
				data = t->start;
				len = t->len;
			}
		}

		if (lua_gettop (L) == 3) {
			raw = lua_toboolean (L, 3);
		}

		if (data) {
			if (re->match_limit > 0) {
				len = MIN (len, re->match_limit);
			}

			if (rspamd_regexp_search (re->re, data, len, NULL, NULL, raw)) {
				lua_pushboolean (L, TRUE);
			}
			else {
				lua_pushboolean (L, FALSE);
			}
			return 1;
		}
	}

	lua_pushnil (L);

	return 1;
}

/***
 * @method re:matchn(line, max_matches, [, raw_match])
 * Matches line against the regular expression and return number of matches if line matches
 * (partially or completely). This process stop when `max_matches` is reached.
 * If `max_matches` is zero, then only a single match is counted which is equal to
 * @see re:match If `max_matches` is negative, then all matches are considered.
 *
 * @param {string} line match the specified line against regexp object
 * @param {number} max_matches maximum number of matches
 * @param {bool} match raw regexp instead of utf8 one
 * @return {number} number of matches found in the `line` argument
 */
static int
lua_regexp_matchn (lua_State *L)
{
	struct rspamd_lua_regexp *re = lua_check_regexp (L);
	struct rspamd_lua_text *t;
	const gchar *data = NULL, *start = NULL, *end = NULL;
	gint max_matches, matches;
	gsize len = 0;
	gboolean raw = FALSE;

	if (re && !IS_DESTROYED (re)) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			data = luaL_checklstring (L, 2, &len);
		}
		else if (lua_type (L, 2) == LUA_TUSERDATA) {
			t = lua_check_text (L, 2);
			if (t != NULL) {
				data = t->start;
				len = t->len;
			}
		}

		max_matches = lua_tonumber (L, 3);

		if (lua_gettop (L) == 4) {
			raw = lua_toboolean (L, 4);
		}

		if (data) {
			matches = 0;

			if (re->match_limit > 0) {
				len = MIN (len, re->match_limit);
			}

			for (;;) {
				if (rspamd_regexp_search (re->re, data, len, &start, &end, raw)) {
					matches ++;
				}
				else {
					break;
				}

				if (max_matches >= 0 && matches >= max_matches) {
					break;
				}
			}

			lua_pushnumber (L, matches);

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
	gboolean matched = FALSE;
	gsize len;
	const gchar *start = NULL, *end = NULL, *old_start;
	gint i;

	if (re && !IS_DESTROYED (re)) {
		data = luaL_checklstring (L, 2, &len);

		if (re->match_limit > 0) {
			len = MIN (len, re->match_limit);
		}

		if (data) {
			lua_newtable (L);
			i = 0;
			old_start = data;
			while (rspamd_regexp_search (re->re, data, len, &start, &end, FALSE)) {
				if (start - old_start > 0) {
					lua_pushlstring (L, old_start, start - old_start);
					lua_rawseti (L, -2, ++i);
					matched = TRUE;
				}
				old_start = end;
			}
			if (!matched) {
				lua_pop (L, 1);
				lua_pushnil (L);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

/***
 * @method re:destroy()
 * Destroy regexp from caches if needed (the pointer is removed by garbadge collector)
 */
static gint
lua_regexp_destroy (lua_State *L)
{
	struct rspamd_lua_regexp *to_del = lua_check_regexp (L);

	if (to_del) {
		rspamd_regexp_cache_remove (NULL, to_del->re);
		rspamd_regexp_unref (to_del->re);
		to_del->re = NULL;
		to_del->re_flags |= LUA_REGEXP_FLAG_DESTROYED;
	}

	return 0;
}

static gint
lua_regexp_gc (lua_State *L)
{
	struct rspamd_lua_regexp *to_del = lua_check_regexp (L);

	if (to_del) {
		if (!IS_DESTROYED (to_del)) {
			rspamd_regexp_unref (to_del->re);
		}

		g_slice_free1 (sizeof (*to_del), to_del);
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
luaopen_regexp (lua_State * L)
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
