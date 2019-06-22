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

#include "classifiers.h"
#include "cfg_file.h"
#include "stat_internal.h"
#include "lua/lua_common.h"

struct rspamd_lua_classifier_ctx {
	gchar *name;
	gint classify_ref;
	gint learn_ref;
};

static GHashTable *lua_classifiers = NULL;

#define msg_err_luacl(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "luacl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_luacl(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "luacl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_luacl(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "luacl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_luacl(...)  rspamd_conditional_debug_fast (NULL, task->from_addr, \
        rspamd_luacl_log_id, "luacl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(luacl)

gboolean
lua_classifier_init (struct rspamd_config *cfg,
					 struct ev_loop *ev_base,
					 struct rspamd_classifier *cl)
{
	struct rspamd_lua_classifier_ctx *ctx;
	lua_State *L = cl->ctx->cfg->lua_state;
	gint cb_classify = -1, cb_learn = -1;

	if (lua_classifiers == NULL) {
		lua_classifiers = g_hash_table_new_full (rspamd_strcase_hash,
				rspamd_strcase_equal, g_free, g_free);
	}

	ctx = g_hash_table_lookup (lua_classifiers, cl->subrs->name);

	if (ctx != NULL) {
		msg_err_config ("duplicate lua classifier definition: %s",
				cl->subrs->name);

		return FALSE;
	}

	lua_getglobal (L, "rspamd_classifiers");
	if (lua_type (L, -1) != LUA_TTABLE) {
		msg_err_config ("cannot register classifier %s: no rspamd_classifier global",
				cl->subrs->name);
		lua_pop (L, 1);

		return FALSE;
	}

	lua_pushstring (L, cl->subrs->name);
	lua_gettable (L, -2);

	if (lua_type (L, -1) != LUA_TTABLE) {
		msg_err_config ("cannot register classifier %s: bad lua type: %s",
				cl->subrs->name, lua_typename (L, lua_type (L, -1)));
		lua_pop (L, 2);

		return FALSE;
	}

	lua_pushstring (L, "classify");
	lua_gettable (L, -2);

	if (lua_type (L, -1) != LUA_TFUNCTION) {
		msg_err_config ("cannot register classifier %s: bad lua type for classify: %s",
				cl->subrs->name, lua_typename (L, lua_type (L, -1)));
		lua_pop (L, 3);

		return FALSE;
	}

	cb_classify = luaL_ref (L, LUA_REGISTRYINDEX);

	lua_pushstring (L, "learn");
	lua_gettable (L, -2);

	if (lua_type (L, -1) != LUA_TFUNCTION) {
		msg_err_config ("cannot register classifier %s: bad lua type for learn: %s",
				cl->subrs->name, lua_typename (L, lua_type (L, -1)));
		lua_pop (L, 3);

		return FALSE;
	}

	cb_learn = luaL_ref (L, LUA_REGISTRYINDEX);
	lua_pop (L, 2); /* Table + global */

	ctx = g_malloc0 (sizeof (*ctx));
	ctx->name = g_strdup (cl->subrs->name);
	ctx->classify_ref = cb_classify;
	ctx->learn_ref = cb_learn;
	cl->cfg->flags |= RSPAMD_FLAG_CLASSIFIER_NO_BACKEND;
	g_hash_table_insert (lua_classifiers, ctx->name, ctx);

	return TRUE;
}
gboolean
lua_classifier_classify (struct rspamd_classifier *cl,
		GPtrArray *tokens,
		struct rspamd_task *task)
{
	struct rspamd_lua_classifier_ctx *ctx;
	struct rspamd_task **ptask;
	struct rspamd_classifier_config **pcfg;
	lua_State *L;
	rspamd_token_t *tok;
	guint i;
	guint64 v;

	ctx = g_hash_table_lookup (lua_classifiers, cl->subrs->name);
	g_assert (ctx != NULL);
	L = task->cfg->lua_state;

	lua_rawgeti (L, LUA_REGISTRYINDEX, ctx->classify_ref);
	ptask = lua_newuserdata (L, sizeof (*ptask));
	*ptask = task;
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	pcfg = lua_newuserdata (L, sizeof (*pcfg));
	*pcfg = cl->cfg;
	rspamd_lua_setclass (L, "rspamd{classifier}", -1);

	lua_createtable (L, tokens->len, 0);

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);
		v = tok->data;
		lua_createtable (L, 3, 0);
		/* High word, low word, order */
		lua_pushinteger (L, (guint32)(v >> 32));
		lua_rawseti (L, -2, 1);
		lua_pushinteger (L, (guint32)(v));
		lua_rawseti (L, -2, 2);
		lua_pushinteger (L, tok->window_idx);
		lua_rawseti (L, -2, 3);
		lua_rawseti (L, -2, i + 1);
	}

	if (lua_pcall (L, 3, 0, 0) != 0) {
		msg_err_luacl ("error running classify function for %s: %s", ctx->name,
				lua_tostring (L, -1));
		lua_pop (L, 1);

		return FALSE;
	}

	return TRUE;
}

gboolean
lua_classifier_learn_spam (struct rspamd_classifier *cl,
		GPtrArray *tokens,
		struct rspamd_task *task,
		gboolean is_spam,
		gboolean unlearn,
		GError **err)
{
	struct rspamd_lua_classifier_ctx *ctx;
	struct rspamd_task **ptask;
	struct rspamd_classifier_config **pcfg;
	lua_State *L;
	rspamd_token_t *tok;
	guint i;
	guint64 v;

	ctx = g_hash_table_lookup (lua_classifiers, cl->subrs->name);
	g_assert (ctx != NULL);
	L = task->cfg->lua_state;

	lua_rawgeti (L, LUA_REGISTRYINDEX, ctx->learn_ref);
	ptask = lua_newuserdata (L, sizeof (*ptask));
	*ptask = task;
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	pcfg = lua_newuserdata (L, sizeof (*pcfg));
	*pcfg = cl->cfg;
	rspamd_lua_setclass (L, "rspamd{classifier}", -1);

	lua_createtable (L, tokens->len, 0);

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);
		v = 0;
		v = tok->data;
		lua_createtable (L, 3, 0);
		/* High word, low word, order */
		lua_pushinteger (L, (guint32)(v >> 32));
		lua_rawseti (L, -2, 1);
		lua_pushinteger (L, (guint32)(v));
		lua_rawseti (L, -2, 2);
		lua_pushinteger (L, tok->window_idx);
		lua_rawseti (L, -2, 3);
		lua_rawseti (L, -2, i + 1);
	}

	lua_pushboolean (L, is_spam);
	lua_pushboolean (L, unlearn);

	if (lua_pcall (L, 5, 0, 0) != 0) {
		msg_err_luacl ("error running learn function for %s: %s", ctx->name,
				lua_tostring (L, -1));
		lua_pop (L, 1);

		return FALSE;
	}

	return TRUE;
}
