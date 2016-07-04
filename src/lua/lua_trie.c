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
 * function trie.create(patterns)
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

	if (!lua_istable (L, 1)) {
		msg_err ("lua trie expects array of patterns for now");
		lua_pushnil (L);
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

static gint
lua_trie_callback (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint textpos,
		const gchar *text,
		gsize len,
		void *context)
{
	lua_State *L = context;
	gint ret;

	/* Function */
	lua_pushvalue (L, 3);
	lua_pushnumber (L, strnum + 1);
	lua_pushnumber (L, textpos);

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

/*
 * We assume that callback argument is at pos 3 and icase is in position 4
 */
static gint
lua_trie_search_str (lua_State *L, struct rspamd_multipattern *trie,
		const gchar *str, gsize len)
{
	gint ret;
	guint nfound = 0;

	if ((ret = rspamd_multipattern_lookup (trie, str, len,
			lua_trie_callback, L, &nfound)) == 0) {
		return nfound;
	}

	return ret;
}

/***
 * @method trie:match(input, cb[, caseless])
 * Search for patterns in `input` invoking `cb` optionally ignoring case
 * @param {table or string} input one or several (if `input` is an array) strings of input text
 * @param {function} cb callback called on each pattern match in form `function (idx, pos)` where `idx` is a numeric index of pattern (starting from 1) and `pos` is a numeric offset where the pattern ends
 * @param {boolean} caseless if `true` then match ignores symbols case (ASCII only)
 * @return {boolean} `true` if any pattern has been found (`cb` might be called multiple times however)
 */
static gint
lua_trie_match (lua_State *L)
{
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	const gchar *text;
	gsize len;
	gboolean found = FALSE;

	if (trie) {
		if (lua_type (L, 2) == LUA_TTABLE) {
			lua_pushvalue (L, 2);
			lua_pushnil (L);

			while (lua_next (L, -2) != 0) {
				if (lua_isstring (L, -1)) {
					text = lua_tolstring (L, -1, &len);

					if (lua_trie_search_str (L, trie, text, len)) {
						found = TRUE;
					}
				}
				lua_pop (L, 1);
			}

			lua_pop (L, 1); /* table */
		}
		else if (lua_type (L, 2) == LUA_TSTRING) {
			text = lua_tolstring (L, 2, &len);

			if (lua_trie_search_str (L, trie, text, len)) {
				found = TRUE;
			}
		}
	}

	lua_pushboolean (L, found);
	return 1;
}

/***
 * @method trie:search_mime(task, cb[, caseless])
 * This is a helper mehthod to search pattern within text parts of a message in rspamd task
 * @param {task} task object
 * @param {function} cb callback called on each pattern match @see trie:match
 * @param {boolean} caseless if `true` then match ignores symbols case (ASCII only)
 * @return {boolean} `true` if any pattern has been found (`cb` might be called multiple times however)
 */
static gint
lua_trie_search_mime (lua_State *L)
{
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	struct rspamd_task *task = lua_check_task (L, 2);
	struct rspamd_mime_text_part *part;
	const gchar *text;
	gsize len, i;
	gboolean found = FALSE;

	if (trie) {
		for (i = 0; i < task->text_parts->len; i ++) {
			part = g_ptr_array_index (task->text_parts, i);

			if (!IS_PART_EMPTY (part) && part->content != NULL) {
				text = part->content->data;
				len = part->content->len;

				if (lua_trie_search_str (L, trie, text, len) != 0) {
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
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	struct rspamd_task *task = lua_check_task (L, 2);
	const gchar *text;
	gsize len;
	gboolean found = FALSE;

	if (trie) {
		text = task->msg.begin;
		len = task->msg.len;

		if (lua_trie_search_str (L, trie, text, len) != 0) {
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
	struct rspamd_multipattern *trie = lua_check_trie (L, 1);
	struct rspamd_task *task = lua_check_task (L, 2);
	const gchar *text;
	gsize len;
	gboolean found = FALSE;

	if (trie) {
		if (task->raw_headers_content.len > 0) {
			text = task->msg.begin + task->raw_headers_content.len;
			len = task->msg.len - task->raw_headers_content.len;
		}
		else {
			/* Treat as raw message */
			text = task->msg.begin;
			len = task->msg.len;
		}

		if (lua_trie_search_str (L, trie, text, len) != 0) {
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
	luaL_register (L, NULL, trielib_f);

	return 1;
}

void
luaopen_trie (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{trie}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{trie}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,			 trielib_m);
	rspamd_lua_add_preload (L, "rspamd_trie", lua_load_trie);

	lua_pop (L, 1);                      /* remove metatable from stack */
}
