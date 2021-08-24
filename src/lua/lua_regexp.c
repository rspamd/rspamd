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
LUA_FUNCTION_DEF (regexp, import_glob);
LUA_FUNCTION_DEF (regexp, import_plain);
LUA_FUNCTION_DEF (regexp, create_cached);
LUA_FUNCTION_DEF (regexp, get_cached);
LUA_FUNCTION_DEF (regexp, get_pattern);
LUA_FUNCTION_DEF (regexp, set_limit);
LUA_FUNCTION_DEF (regexp, set_max_hits);
LUA_FUNCTION_DEF (regexp, get_max_hits);
LUA_FUNCTION_DEF (regexp, search);
LUA_FUNCTION_DEF (regexp, match);
LUA_FUNCTION_DEF (regexp, matchn);
LUA_FUNCTION_DEF (regexp, split);
LUA_FUNCTION_DEF (regexp, destroy);
LUA_FUNCTION_DEF (regexp, gc);

static const struct luaL_reg regexplib_m[] = {
	LUA_INTERFACE_DEF (regexp, get_pattern),
	LUA_INTERFACE_DEF (regexp, set_limit),
	LUA_INTERFACE_DEF (regexp, set_max_hits),
	LUA_INTERFACE_DEF (regexp, get_max_hits),
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
	LUA_INTERFACE_DEF (regexp, import_glob),
	LUA_INTERFACE_DEF (regexp, import_plain),
	LUA_INTERFACE_DEF (regexp, get_cached),
	LUA_INTERFACE_DEF (regexp, create_cached),
	{NULL, NULL}
};

#define LUA_REGEXP_FLAG_DESTROYED (1 << 0)
#define IS_DESTROYED(re) ((re)->re_flags & LUA_REGEXP_FLAG_DESTROYED)

rspamd_mempool_t *regexp_static_pool = NULL;

struct rspamd_lua_regexp *
lua_check_regexp (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{regexp}");

	luaL_argcheck (L, ud != NULL, pos, "'regexp' expected");
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
	LUA_TRACE_POINT;
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;
	GError *err = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	if (string) {
		re = rspamd_regexp_new (string, flags_str, &err);
		if (re == NULL) {
			lua_pushnil (L);
			msg_info ("cannot parse regexp: %s, error: %s",
					string,
					err == NULL ? "undefined" : err->message);
			g_error_free (err);
		} else {
			new = g_malloc0 (sizeof (struct rspamd_lua_regexp));
			new->re = re;
			new->re_pattern = g_strdup (string);
			new->module = rspamd_lua_get_module_name (L);
			pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
			rspamd_lua_setclass (L, "rspamd{regexp}", -1);
			*pnew = new;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_regexp.import_glob(glob_pattern[, flags])
 * Creates new rspamd_regexp from glob
 * @param {string} pattern pattern to build regexp.
 * @param {string} flags optional flags to create regular expression
 * @return {regexp} regexp argument that is *not* automatically destroyed
 * @example
 * local regexp = require "rspamd_regexp"
 *
 * local re = regexp.import_glob('ab*', 'i')
 */
static int
lua_regexp_import_glob (lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;
	gchar *escaped;
	gsize pat_len;
	GError *err = NULL;

	string = luaL_checklstring (L, 1, &pat_len);

	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	if (string) {
		escaped = rspamd_str_regexp_escape (string, pat_len, NULL,
				RSPAMD_REGEXP_ESCAPE_GLOB|RSPAMD_REGEXP_ESCAPE_UTF);

		re = rspamd_regexp_new (escaped, flags_str, &err);

		if (re == NULL) {
			lua_pushnil (L);
			msg_info ("cannot parse regexp: %s, error: %s",
					string,
					err == NULL ? "undefined" : err->message);
			g_error_free (err);
			g_free (escaped);
		}
		else {
			new = g_malloc0 (sizeof (struct rspamd_lua_regexp));
			new->re = re;
			new->re_pattern = escaped;
			new->module = rspamd_lua_get_module_name (L);
			pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
			rspamd_lua_setclass (L, "rspamd{regexp}", -1);
			*pnew = new;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_regexp.import_plain(plain_string[, flags])
 * Creates new rspamd_regexp from plain string (escaping specials)
 * @param {string} pattern pattern to build regexp.
 * @param {string} flags optional flags to create regular expression
 * @return {regexp} regexp argument that is *not* automatically destroyed
 * @example
 * local regexp = require "rspamd_regexp"
 *
 * local re = regexp.import_plain('exact_string_with*', 'i')
 */
static int
lua_regexp_import_plain (lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;
	gchar *escaped;
	gsize pat_len;
	GError *err = NULL;

	string = luaL_checklstring (L, 1, &pat_len);

	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	if (string) {
		escaped = rspamd_str_regexp_escape (string, pat_len, NULL,
				RSPAMD_REGEXP_ESCAPE_ASCII);

		re = rspamd_regexp_new (escaped, flags_str, &err);

		if (re == NULL) {
			lua_pushnil (L);
			msg_info ("cannot parse regexp: %s, error: %s",
					string,
					err == NULL ? "undefined" : err->message);
			g_error_free (err);
			g_free (escaped);
		}
		else {
			new = g_malloc0 (sizeof (struct rspamd_lua_regexp));
			new->re = re;
			new->re_pattern = escaped;
			new->module = rspamd_lua_get_module_name (L);
			pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
			rspamd_lua_setclass (L, "rspamd{regexp}", -1);
			*pnew = new;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
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
	LUA_TRACE_POINT;
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	if (string) {
		re = rspamd_regexp_cache_query (NULL, string, flags_str);

		if (re) {
			new = g_malloc0 (sizeof (struct rspamd_lua_regexp));
			new->re = rspamd_regexp_ref (re);
			new->re_pattern = g_strdup (string);
			new->module = rspamd_lua_get_module_name (L);
			pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
			rspamd_lua_setclass (L, "rspamd{regexp}", -1);
			*pnew = new;
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
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
	LUA_TRACE_POINT;
	rspamd_regexp_t *re;
	struct rspamd_lua_regexp *new, **pnew;
	const gchar *string, *flags_str = NULL;
	GError *err = NULL;

	string = luaL_checkstring (L, 1);
	if (lua_gettop (L) == 2) {
		flags_str = luaL_checkstring (L, 2);
	}

	if (string) {
		re = rspamd_regexp_cache_query (NULL, string, flags_str);

		if (re) {
			new = g_malloc0 (sizeof (struct rspamd_lua_regexp));
			new->re = rspamd_regexp_ref (re);
			new->re_pattern = g_strdup (string);
			new->module = rspamd_lua_get_module_name (L);
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
			} else {
				new = g_malloc0 (sizeof (struct rspamd_lua_regexp));
				new->re = rspamd_regexp_ref (re);
				new->re_pattern = g_strdup (string);
				new->module = rspamd_lua_get_module_name (L);
				pnew = lua_newuserdata (L, sizeof (struct rspamd_lua_regexp *));
				rspamd_lua_setclass (L, "rspamd{regexp}", -1);
				*pnew = new;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
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
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);

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
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);
	gint64 lim;

	lim = lua_tointeger (L, 2);

	if (re && re->re && !IS_DESTROYED (re)) {
		if (lim > 0) {
			rspamd_regexp_set_match_limit(re->re, lim);
		}
		else {
			rspamd_regexp_set_match_limit(re->re, 0);
		}
	}

	return 0;
}

/***
 * @method re:set_max_hits(lim)
 * Set maximum number of hits returned by a regexp
 * @param {number} lim limit in hits count
 * @return {number} old number of max hits
 */
static int
lua_regexp_set_max_hits (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);
	guint lim;

	lim = luaL_checkinteger (L, 2);

	if (re && re->re && !IS_DESTROYED (re)) {
		lua_pushinteger (L, rspamd_regexp_set_maxhits (re->re, lim));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method re:get_max_hits(lim)
 * Get maximum number of hits returned by a regexp
 * @return {number} number of max hits
 */
static int
lua_regexp_get_max_hits (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);

	if (re && re->re && !IS_DESTROYED (re)) {
		lua_pushinteger (L, rspamd_regexp_get_maxhits (re->re));
	}
	else {
		lua_pushinteger (L, 1);
	}

	return 1;
}

/***
 * @method re:search(line[, raw[, capture]])
 * Search line in regular expression object. If line matches then this
 * function returns the table of captured strings. Otherwise, nil is returned.
 * If `raw` is specified, then input is treated as raw data not encoded in `utf-8`.
 * If `capture` is true, then this function saves all captures to the table of
 * values, so the first element is the whole matched string and the
 * subsequent elements are ordered captures defined within pattern.
 *
 * @param {string} line match the specified line against regexp object
 * @param {bool} match raw regexp instead of utf8 one
 * @param {bool} capture perform subpatterns capturing
 * @return {table or nil} table of strings or tables (if `capture` is true) or nil if not matched
 * @example
 * local re = regexp.create_cached('/^\s*([0-9]+)\s*$/')
 * -- returns nil
 * local m1 = re:search('blah')
 * local m2 = re:search('   190   ')
 * -- prints '   190    '
 * print(m2[1])
 *
 * local m3 = re:search('   100500 ')
 * -- prints '   100500 '
 * print(m3[1][1])
 * -- prints '100500' capture
 * print(m3[1][2])
 */
static int
lua_regexp_search (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);
	const gchar *data = NULL;
	struct rspamd_lua_text *t;
	const gchar *start = NULL, *end = NULL;
	gint i;
	gsize len = 0, capn;
	gboolean matched = FALSE, capture = FALSE, raw = FALSE;
	GArray *captures = NULL;
	struct rspamd_re_capture *cap;

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

		if (lua_gettop (L) >= 3) {
			raw = lua_toboolean (L, 3);
		}

		if (data && len > 0) {
			if (lua_gettop (L) >= 4 && lua_toboolean (L, 4)) {
				capture = TRUE;
				captures = g_array_new (FALSE, TRUE,
						sizeof (struct rspamd_re_capture));
			}

			lua_newtable (L);
			i = 0;

			while (rspamd_regexp_search (re->re, data, len, &start, &end, raw,
					captures)) {

				if (capture) {
					lua_createtable (L, captures->len, 0);

					for (capn = 0; capn < captures->len; capn ++) {
						cap = &g_array_index (captures, struct rspamd_re_capture,
								capn);
						lua_pushlstring (L, cap->p, cap->len);
						lua_rawseti (L, -2, capn + 1);
					}

					lua_rawseti (L, -2, ++i);
				}
				else {
					lua_pushlstring (L, start, end - start);
					lua_rawseti (L, -2, ++i);
				}

				matched = TRUE;
			}

			if (!matched) {
				lua_pop (L, 1);
				lua_pushnil (L);
			}

			if (capture) {
				g_array_free (captures, TRUE);
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

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
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);
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

		if (data && len > 0) {
			if (rspamd_regexp_search (re->re, data, len, NULL, NULL, raw, NULL)) {
				lua_pushboolean (L, TRUE);
			}
			else {
				lua_pushboolean (L, FALSE);
			}
		}
		else {
			lua_pushboolean (L, FALSE);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

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
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);
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

		max_matches = lua_tointeger (L, 3);
		matches = 0;

		if (lua_gettop (L) == 4) {
			raw = lua_toboolean (L, 4);
		}

		if (data && len > 0) {
			for (;;) {
				if (rspamd_regexp_search (re->re, data, len, &start, &end, raw,
						NULL)) {
					matches ++;
				}
				else {
					break;
				}

				if (max_matches >= 0 && matches >= max_matches) {
					break;
				}
			}
		}

		lua_pushinteger (L, matches);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}


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
 * @param {string/text} line line to split
 * @return {table} table of split line portions (if text was the input, then text is used for return parts)
 */
static int
lua_regexp_split (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 1);
	const gchar *data = NULL;
	struct rspamd_lua_text *t;
	gboolean matched = FALSE, is_text = FALSE;
	gsize len = 0;
	const gchar *start = NULL, *end = NULL, *old_start;
	gint i;

	if (re && !IS_DESTROYED (re)) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			data = luaL_checklstring (L, 2, &len);
		}
		else if (lua_type (L, 2) == LUA_TUSERDATA) {
			t = lua_check_text (L, 2);

			if (t == NULL) {
				lua_error (L);
				return 0;
			}

			data = t->start;
			len = t->len;
			is_text = TRUE;
		}

		if (data && len > 0) {
			lua_newtable (L);
			i = 0;
			old_start = data;

			while (rspamd_regexp_search (re->re, data, len, &start, &end, FALSE,
					NULL)) {
				if (start - old_start > 0) {
					if (!is_text) {
						lua_pushlstring (L, old_start, start - old_start);
					}
					else {
						t = lua_newuserdata (L, sizeof (*t));
						rspamd_lua_setclass (L, "rspamd{text}", -1);
						t->start = old_start;
						t->len = start - old_start;
						t->flags = 0;
					}

					lua_rawseti (L, -2, ++i);
					matched = TRUE;
				}
				else if (start == end) {
					break;
				}
				old_start = end;
			}

			if (len > 0 && (end == NULL || end < data + len)) {
				if (end == NULL) {
					end = data;
				}

				if (!is_text) {
					lua_pushlstring (L, end, (data + len) - end);
				}
				else {
					t = lua_newuserdata (L, sizeof (*t));
					rspamd_lua_setclass (L, "rspamd{text}", -1);
					t->start = end;
					t->len = (data + len) - end;
					t->flags = 0;
				}

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
	else {
		return luaL_error (L, "invalid arguments");
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
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *to_del = lua_check_regexp (L, 1);

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
	LUA_TRACE_POINT;
	struct rspamd_lua_regexp *to_del = lua_check_regexp (L, 1);

	if (to_del) {
		if (!IS_DESTROYED (to_del)) {
			rspamd_regexp_unref (to_del->re);
		}

		g_free (to_del->re_pattern);
		g_free (to_del->module);
		g_free (to_del);
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
	if (!regexp_static_pool) {
		regexp_static_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				"regexp_lua_pool", 0);
	}

	rspamd_lua_new_class (L, "rspamd{regexp}", regexplib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_regexp", lua_load_regexp);
}

RSPAMD_DESTRUCTOR (lua_re_static_pool_dtor) {
	if (regexp_static_pool) {
		rspamd_mempool_delete (regexp_static_pool);
	}
}