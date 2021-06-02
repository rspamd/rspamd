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
#include "message.h"
#include "libutil/multipattern.h"

/***
 * @module rspamd_trie
 * Rspamd trie module provides the data structure suitable for searching of many
 * patterns in arbitrary texts (or binary chunks). The algorithmic complexity of
 * this algorithm is at most O(n + m + z), where `n` is the length of text, `m` is a length of pattern and `z` is a number of patterns in the text.
 *
 * Here is a typical example of trie usage:
 * @example
local rspamd_trie = require "rspamd_trie"
local patterns = {'aab', 'ab', 'bcd\0ef'}

local trie = rspamd_trie.create(patterns)

local function trie_callback(number, pos)
	print('Matched pattern number ' .. tostring(number) .. ' at pos: ' .. tostring(pos))
end

trie:match('some big text', trie_callback)
 */

/* Suffix trie */
LUA_FUNCTION_DEF (trie, create);
LUA_FUNCTION_DEF (trie, has_hyperscan);
LUA_FUNCTION_DEF (trie, match);
LUA_FUNCTION_DEF (trie, search_mime);
LUA_FUNCTION_DEF (trie, search_rawmsg);
LUA_FUNCTION_DEF (trie, search_rawbody);
LUA_FUNCTION_DEF (trie, destroy);

static const struct luaL_reg trielib_m[] = {
	LUA_INTERFACE_DEF (trie, match),
	LUA_INTERFACE_DEF (trie, search_mime),
	LUA_INTERFACE_DEF (trie, search_rawmsg),
	LUA_INTERFACE_DEF (trie, search_rawbody),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_trie_destroy},
	{NULL, NULL}
};
static const struct luaL_reg trielib_f[] = {
	LUA_INTERFACE_DEF (trie, create),
	LUA_INTERFACE_DEF (trie, has_hyperscan),
	{NULL, NULL}
};

static struct rspamd_multipattern *
lua_check_trie (lua_State * L, gint idx)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{trie}");

	luaL_argcheck (L, ud != NULL, 1, "'trie' expected");
	return ud ? *((struct rspamd_multipattern **)ud) : NULL;
}

static gint
lua_trie_destroy (lua_State *L)
{
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);

	if (trie) {
		rspamd_multipattern_destroy (trie);
	}

	return 0;
}

/***
 * function trie.has_hyperscan()
 * Checks for hyperscan support
 *
 * @return {bool} true if hyperscan is supported
 */
static gint
lua_trie_has_hyperscan (lua_State *L)
{
	lua_pushboolean (L, rspamd_multipattern_has_hyperscan ());
	return 1;
}

/***
 * function trie.create(patterns, [flags])
 * Creates new trie data structure
 * @param {table} array of string patterns
 * @return {trie} new trie object
 */
static gint
lua_trie_create (lua_State *L)
{
	struct rspamd_multipattern *trie, **ptrie;
	gint npat = 0, flags = RSPAMD_MULTIPATTERN_ICASE|RSPAMD_MULTIPATTERN_GLOB;
	GError *err = NULL;

	if (lua_isnumber (L, 2)) {
		flags = lua_tointeger (L, 2);
	}

	if (!lua_istable (L, 1)) {
		return luaL_error (L, "lua trie expects array of patterns for now");
	}
	else {
		lua_pushvalue (L, 1);
		lua_pushnil (L);

		while (lua_next (L, -2) != 0) {
			if (lua_isstring (L, -1)) {
				npat ++;
			}

			lua_pop (L, 1);
		}

		trie = rspamd_multipattern_create_sized (npat, flags);
		lua_pushnil (L);

		while (lua_next (L, -2) != 0) {
			if (lua_isstring (L, -1)) {
				const gchar *pat;
				gsize patlen;

				pat = lua_tolstring (L, -1, &patlen);
				rspamd_multipattern_add_pattern_len (trie, pat, patlen, flags);
			}

			lua_pop (L, 1);
		}

		lua_pop (L, 1); /* table */

		if (!rspamd_multipattern_compile (trie, &err)) {
			msg_err ("cannot compile multipattern: %e", err);
			g_error_free (err);
			rspamd_multipattern_destroy (trie);
			lua_pushnil (L);
		}
		else {
			ptrie = lua_newuserdata (L, sizeof (void *));
			rspamd_lua_setclass (L, "rspamd{trie}", -1);
			*ptrie = trie;
		}
	}

	return 1;
}

#define PUSH_TRIE_MATCH(L, start, end, report_start) do { \
	if (report_start) { \
		lua_createtable (L, 2, 0); \
		lua_pushinteger (L, (start)); \
		lua_rawseti (L, -2, 1); \
		lua_pushinteger (L, (end)); \
		lua_rawseti (L, -2, 2); \
	} \
	else { \
		lua_pushinteger (L, (end)); \
	} \
} while(0)

/* Normal callback type */
static gint
lua_trie_lua_cb_callback (struct rspamd_multipattern *mp,
						  guint strnum,
						  gint match_start,
						  gint textpos,
						  const gchar *text,
						  gsize len,
						  void *context)
{
	lua_State *L = context;
	gint ret;

	gboolean report_start = lua_toboolean (L, -1);

	/* Function */
	lua_pushvalue (L, 3);
	lua_pushinteger (L, strnum + 1);

	PUSH_TRIE_MATCH (L, match_start, textpos, report_start);

	if (lua_pcall (L, 2, 1, 0) != 0) {
		msg_info ("call to trie callback has failed: %s",
			lua_tostring (L, -1));
		lua_pop (L, 1);

		return 1;
	}

	ret = lua_tonumber (L, -1);
	lua_pop (L, 1);

	return ret;
}

/* Table like callback, expect result table on top of the stack */
static gint
lua_trie_table_callback (struct rspamd_multipattern *mp,
				   guint strnum,
				   gint match_start,
				   gint textpos,
				   const gchar *text,
				   gsize len,
				   void *context)
{
	lua_State *L = context;

	gint report_start = lua_toboolean (L, -2);
	/* Set table, indexed by pattern number */
	lua_rawgeti (L, -1, strnum + 1);

	if (lua_istable (L, -1)) {
		/* Already have table, add offset */
		gsize last = rspamd_lua_table_size (L, -1);
		PUSH_TRIE_MATCH (L, match_start, textpos, report_start);
		lua_rawseti (L, -2, last + 1);
		/* Remove table from the stack */
		lua_pop (L, 1);
	}
	else {
		/* Pop none */
		lua_pop (L, 1);
		/* New table */
		lua_newtable (L);
		PUSH_TRIE_MATCH (L, match_start, textpos, report_start);
		lua_rawseti (L, -2, 1);
		lua_rawseti (L, -2, strnum + 1);
	}

	return 0;
}

/*
 * We assume that callback argument is at pos 3 and icase is in position 4
 */
static gint
lua_trie_search_str (lua_State *L, struct rspamd_multipattern *trie,
		const gchar *str, gsize len, rspamd_multipattern_cb_t cb)
{
	gint ret;
	guint nfound = 0;

	if ((ret = rspamd_multipattern_lookup (trie, str, len,
			cb, L, &nfound)) == 0) {
		return nfound;
	}

	return ret;
}

/***
 * @method trie:match(input, [cb][, report_start])
 * Search for patterns in `input` invoking `cb` optionally ignoring case
 * @param {table or string} input one or several (if `input` is an array) strings of input text
 * @param {function} cb callback called on each pattern match in form `function (idx, pos)` where `idx` is a numeric index of pattern (starting from 1) and `pos` is a numeric offset where the pattern ends
 * @param {boolean} report_start report both start and end offset when matching patterns
 * @return {boolean} `true` if any pattern has been found (`cb` might be called multiple times however). If `cb` is not defined then it returns a table of match positions indexed by pattern number
 */
static gint
lua_trie_match (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	const gchar *text;
	gsize len;
	gboolean found = FALSE, report_start = FALSE;
	struct rspamd_lua_text *t;
	rspamd_multipattern_cb_t cb = lua_trie_lua_cb_callback;

	gint old_top = lua_gettop (L);

	if (trie) {
		if (lua_type (L, 3) != LUA_TFUNCTION) {
			if (lua_isboolean (L, 3)) {
				report_start = lua_toboolean (L, 3);
			}

			lua_pushboolean (L, report_start);
			/* Table like match */
			lua_newtable (L);
			cb = lua_trie_table_callback;
		}
		else {
			if (lua_isboolean (L, 4)) {
				report_start = lua_toboolean (L, 4);
			}
			lua_pushboolean (L, report_start);
		}

		if (lua_type (L, 2) == LUA_TTABLE) {
			lua_pushvalue (L, 2);
			lua_pushnil (L);

			while (lua_next (L, -2) != 0) {
				if (lua_isstring (L, -1)) {
					text = lua_tolstring (L, -1, &len);

					if (lua_trie_search_str (L, trie, text, len, cb)) {
						found = TRUE;
					}
				}
				else if (lua_isuserdata (L, -1)) {
					t = lua_check_text (L, -1);

					if (t) {
						if (lua_trie_search_str (L, trie, t->start, t->len, cb)) {
							found = TRUE;
						}
					}
				}
				lua_pop (L, 1);
			}
		}
		else if (lua_type (L, 2) == LUA_TSTRING) {
			text = lua_tolstring (L, 2, &len);

			if (lua_trie_search_str (L, trie, text, len, cb)) {
				found = TRUE;
			}
		}
		else if (lua_type (L, 2) == LUA_TUSERDATA) {
			t = lua_check_text (L, 2);

			if (t && lua_trie_search_str (L, trie, t->start, t->len, cb)) {
				found = TRUE;
			}
		}
	}

	if (lua_type (L, 3) == LUA_TFUNCTION) {
		lua_settop (L, old_top);
		lua_pushboolean (L, found);
	}
	else {
		lua_remove (L, -2);
	}

	return 1;
}

/***
 * @method trie:search_mime(task, cb)
 * This is a helper mehthod to search pattern within text parts of a message in rspamd task
 * @param {task} task object
 * @param {function} cb callback called on each pattern match @see trie:match
 * @param {boolean} caseless if `true` then match ignores symbols case (ASCII only)
 * @return {boolean} `true` if any pattern has been found (`cb` might be called multiple times however)
 */
static gint
lua_trie_search_mime (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	struct rspamd_task *task = lua_check_task (L, 2);
	struct rspamd_mime_text_part *part;
	const gchar *text;
	gsize len, i;
	gboolean found = FALSE;
	rspamd_multipattern_cb_t cb = lua_trie_lua_cb_callback;

	if (trie && task) {
		PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, part) {
			if (!IS_TEXT_PART_EMPTY (part) && part->utf_content.len > 0) {
				text = part->utf_content.begin;
				len = part->utf_content.len;

				if (lua_trie_search_str (L, trie, text, len, cb) != 0) {
					found = TRUE;
				}
			}
		}
	}

	lua_pushboolean (L, found);
	return 1;
}

/***
 * @method trie:search_rawmsg(task, cb[, caseless])
 * This is a helper mehthod to search pattern within the whole undecoded content of rspamd task
 * @param {task} task object
 * @param {function} cb callback called on each pattern match @see trie:match
 * @param {boolean} caseless if `true` then match ignores symbols case (ASCII only)
 * @return {boolean} `true` if any pattern has been found (`cb` might be called multiple times however)
 */
static gint
lua_trie_search_rawmsg (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	struct rspamd_task *task = lua_check_task (L, 2);
	const gchar *text;
	gsize len;
	gboolean found = FALSE;

	if (trie && task) {
		text = task->msg.begin;
		len = task->msg.len;

		if (lua_trie_search_str (L, trie, text, len, lua_trie_lua_cb_callback) != 0) {
			found = TRUE;
		}
	}

	lua_pushboolean (L, found);
	return 1;
}

/***
 * @method trie:search_rawbody(task, cb[, caseless])
 * This is a helper mehthod to search pattern within the whole undecoded content of task's body (not including headers)
 * @param {task} task object
 * @param {function} cb callback called on each pattern match @see trie:match
 * @param {boolean} caseless if `true` then match ignores symbols case (ASCII only)
 * @return {boolean} `true` if any pattern has been found (`cb` might be called multiple times however)
 */
static gint
lua_trie_search_rawbody (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	struct rspamd_task *task = lua_check_task (L, 2);
	const gchar *text;
	gsize len;
	gboolean found = FALSE;

	if (trie && task) {
		if (MESSAGE_FIELD (task, raw_headers_content).len > 0) {
			text = task->msg.begin + MESSAGE_FIELD (task, raw_headers_content).len;
			len = task->msg.len - MESSAGE_FIELD (task, raw_headers_content).len;
		}
		else {
			/* Treat as raw message */
			text = task->msg.begin;
			len = task->msg.len;
		}

		if (lua_trie_search_str (L, trie, text, len, lua_trie_lua_cb_callback) != 0) {
			found = TRUE;
		}
	}

	lua_pushboolean (L, found);
	return 1;
}

static gint
lua_load_trie (lua_State *L)
{
	lua_newtable (L);

	/* Flags */
	lua_pushstring (L, "flags");
	lua_newtable (L);

	lua_pushinteger (L, RSPAMD_MULTIPATTERN_GLOB);
	lua_setfield (L, -2, "glob");
	lua_pushinteger (L, RSPAMD_MULTIPATTERN_RE);
	lua_setfield (L, -2, "re");
	lua_pushinteger (L, RSPAMD_MULTIPATTERN_ICASE);
	lua_setfield (L, -2, "icase");
	lua_pushinteger (L, RSPAMD_MULTIPATTERN_UTF8);
	lua_setfield (L, -2, "utf8");
	lua_pushinteger (L, RSPAMD_MULTIPATTERN_TLD);
	lua_setfield (L, -2, "tld");
	lua_pushinteger (L, RSPAMD_MULTIPATTERN_DOTALL);
	lua_setfield (L, -2, "dot_all");
	lua_pushinteger (L, RSPAMD_MULTIPATTERN_SINGLEMATCH);
	lua_setfield (L, -2, "single_match");
	lua_pushinteger (L, RSPAMD_MULTIPATTERN_NO_START);
	lua_setfield (L, -2, "no_start");
	lua_settable (L, -3);

	/* Main content */
	luaL_register (L, NULL, trielib_f);

	return 1;
}

void
luaopen_trie (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{trie}", trielib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_trie", lua_load_trie);
}
