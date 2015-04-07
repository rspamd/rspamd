/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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
#include "acism.h"
#include "message.h"

/* Suffix trie */
LUA_FUNCTION_DEF (trie, create);
LUA_FUNCTION_DEF (trie, search_text);
LUA_FUNCTION_DEF (trie, search_task);
LUA_FUNCTION_DEF (trie, destroy);

static const struct luaL_reg trielib_m[] = {
	LUA_INTERFACE_DEF (trie, search_text),
	LUA_INTERFACE_DEF (trie, search_task),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_trie_destroy},
	{NULL, NULL}
};
static const struct luaL_reg trielib_f[] = {
	LUA_INTERFACE_DEF (trie, create),
	{NULL, NULL}
};

static ac_trie_t *
lua_check_trie (lua_State * L, gint idx)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{trie}");

	luaL_argcheck (L, ud != NULL, 1, "'trie' expected");
	return ud ? *((ac_trie_t **)ud) : NULL;
}

static gint
lua_trie_destroy (lua_State *L)
{
	ac_trie_t *trie = lua_check_trie (L, 1);

	if (trie) {
		acism_destroy (trie);
	}

	return 0;
}

static gint
lua_trie_create (lua_State *L)
{
	ac_trie_t *trie, **ptrie;
	ac_trie_pat_t *pat;
	gint npat = 0;
	gsize sz;

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

		pat = g_new (ac_trie_pat_t, npat);
		lua_pushnil (L);

		npat = 0;
		while (lua_next (L, -2) != 0) {
			if (lua_isstring (L, -1)) {
				pat[npat].ptr = lua_tolstring (L, -1, &sz);
				pat[npat].len = sz;
				npat ++;
			}
			lua_pop (L, 1);
		}

		lua_pop (L, 1); /* table */

		trie = acism_create (pat, npat);
		ptrie = lua_newuserdata (L, sizeof (ac_trie_t *));
		rspamd_lua_setclass (L, "rspamd{trie}", -1);
		*ptrie = trie;

		g_free (pat);
	}

	return 1;
}

static gint
lua_trie_callback (int strnum, int textpos, void *context)
{
	lua_State *L = context;
	gint ret;

	/* Function */
	lua_pushvalue (L, 3);
	lua_pushnumber (L, strnum);
	lua_pushnumber (L, textpos);

	if (lua_pcall (L, 2, 1, 0) != 0) {
		msg_info ("call to trie callback has failed: %s",
			lua_tostring (L, -1));

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
lua_trie_search_str (lua_State *L, ac_trie_t *trie, const gchar *str, gsize len,
		gint *statep)
{
	gboolean icase = FALSE;
	gint ret;

	if (lua_gettop (L) == 4) {
		icase = lua_toboolean (L, 4);
	}

	ret = acism_lookup (trie, str, len,
			lua_trie_callback, L, statep, icase);

	return ret;
}

static gint
lua_trie_search_text (lua_State *L)
{
	ac_trie_t *trie = lua_check_trie (L, 1);
	const gchar *text;
	gint state = 0;
	gsize len;
	gboolean found = FALSE;

	if (trie) {
		if (lua_type (L, 2) == LUA_TTABLE) {
			lua_pushvalue (L, 2);
			lua_pushnil (L);

			while (lua_next (L, -2) != 0) {
				if (lua_isstring (L, -1)) {
					text = lua_tolstring (L, -1, &len);

					if (lua_trie_search_str (L, trie, text, len, &state) != 0) {
						found = TRUE;
						break;
					}
				}
				lua_pop (L, 1);
			}

			lua_pop (L, 1); /* table */
		}
		else if (lua_type (L, 2) == LUA_TSTRING) {
			text = lua_tolstring (L, -1, &len);

			if (lua_trie_search_str (L, trie, text, len, &state) != 0) {
				found = TRUE;
			}
		}
	}

	lua_pushboolean (L, found);
	return 1;
}

static gint
lua_trie_search_task (lua_State *L)
{
	ac_trie_t *trie = lua_check_trie (L, 1);
	struct rspamd_task *task = lua_check_task (L, 2);
	struct mime_text_part *part;
	GList *cur;
	const gchar *text;
	gint state = 0;
	gsize len;
	gboolean found = FALSE;

	if (trie) {
		cur = task->text_parts;

		while (cur) {
			part = cur->data;

			if (!part->is_empty && part->content != NULL) {
				text = part->content->data;
				len = part->content->len;

				if (lua_trie_search_str (L, trie, text, len, &state) != 0) {
					found = TRUE;
				}
			}

			cur = g_list_next (cur);
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
