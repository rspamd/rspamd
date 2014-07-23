/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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
#include "expressions.h"
#include "map.h"
#include "message.h"
#include "radix.h"
#include "trie.h"
#include "classifiers/classifiers.h"

/* Config file methods */
LUA_FUNCTION_DEF (config, get_module_opt);
LUA_FUNCTION_DEF (config, get_all_opt);
LUA_FUNCTION_DEF (config, get_mempool);
LUA_FUNCTION_DEF (config, register_function);
LUA_FUNCTION_DEF (config, add_radix_map);
LUA_FUNCTION_DEF (config, add_hash_map);
LUA_FUNCTION_DEF (config, add_kv_map);
LUA_FUNCTION_DEF (config, add_map);
LUA_FUNCTION_DEF (config, get_classifier);
LUA_FUNCTION_DEF (config, register_symbol);
LUA_FUNCTION_DEF (config, register_symbols);
LUA_FUNCTION_DEF (config, register_virtual_symbol);
LUA_FUNCTION_DEF (config, register_callback_symbol);
LUA_FUNCTION_DEF (config, register_callback_symbol_priority);
LUA_FUNCTION_DEF (config, register_pre_filter);
LUA_FUNCTION_DEF (config, register_post_filter);
LUA_FUNCTION_DEF (config, register_module_option);
LUA_FUNCTION_DEF (config, get_api_version);

static const struct luaL_reg    configlib_m[] = {
	LUA_INTERFACE_DEF (config, get_module_opt),
	LUA_INTERFACE_DEF (config, get_mempool),
	LUA_INTERFACE_DEF (config, get_all_opt),
	LUA_INTERFACE_DEF (config, register_function),
	LUA_INTERFACE_DEF (config, add_radix_map),
	LUA_INTERFACE_DEF (config, add_hash_map),
	LUA_INTERFACE_DEF (config, add_kv_map),
	LUA_INTERFACE_DEF (config, add_map),
	LUA_INTERFACE_DEF (config, get_classifier),
	LUA_INTERFACE_DEF (config, register_symbol),
	LUA_INTERFACE_DEF (config, register_symbols),
	LUA_INTERFACE_DEF (config, register_virtual_symbol),
	LUA_INTERFACE_DEF (config, register_callback_symbol),
	LUA_INTERFACE_DEF (config, register_callback_symbol_priority),
	LUA_INTERFACE_DEF (config, register_module_option),
	LUA_INTERFACE_DEF (config, register_pre_filter),
	LUA_INTERFACE_DEF (config, register_post_filter),
	LUA_INTERFACE_DEF (config, get_api_version),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};


/* Radix tree */
LUA_FUNCTION_DEF (radix, get_key);

static const struct luaL_reg    radixlib_m[] = {
	LUA_INTERFACE_DEF (radix, get_key),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Hash table */
LUA_FUNCTION_DEF (hash_table, get_key);

static const struct luaL_reg    hashlib_m[] = {
	LUA_INTERFACE_DEF (hash_table, get_key),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Suffix trie */
LUA_FUNCTION_DEF (trie, create);
LUA_FUNCTION_DEF (trie, add_pattern);
LUA_FUNCTION_DEF (trie, search_text);
LUA_FUNCTION_DEF (trie, search_task);

static const struct luaL_reg    trielib_m[] = {
	LUA_INTERFACE_DEF (trie, add_pattern),
	LUA_INTERFACE_DEF (trie, search_text),
	LUA_INTERFACE_DEF (trie, search_task),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};
static const struct luaL_reg    trielib_f[] = {
	LUA_INTERFACE_DEF (trie, create),
	{NULL, NULL}
};

static struct rspamd_config      *
lua_check_config (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{config}");
	luaL_argcheck (L, ud != NULL, 1, "'config' expected");
	return ud ? *((struct rspamd_config **)ud) : NULL;
}

static radix_tree_t           *
lua_check_radix (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{radix}");
	luaL_argcheck (L, ud != NULL, 1, "'radix' expected");
	return ud ? **((radix_tree_t ***)ud) : NULL;
}

static GHashTable           *
lua_check_hash_table (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{hash_table}");
	luaL_argcheck (L, ud != NULL, 1, "'hash_table' expected");
	return ud ? **((GHashTable ***)ud) : NULL;
}

static rspamd_trie_t          *
lua_check_trie (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{trie}");

	luaL_argcheck (L, ud != NULL, 1, "'trie' expected");
	return ud ? *((rspamd_trie_t **)ud) : NULL;
}

/*** Config functions ***/
static gint
lua_config_get_api_version (lua_State *L)
{
	lua_pushinteger (L, RSPAMD_LUA_API_VERSION);
	return 1;
}

static gint
lua_config_get_module_opt (lua_State * L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	const gchar                     *mname, *optname;
	const ucl_object_t              *obj;

	if (cfg) {
		mname = luaL_checkstring (L, 2);
		optname = luaL_checkstring (L, 3);

		if (mname && optname) {
			obj = rspamd_config_get_module_opt (cfg, mname, optname);
			if (obj) {
				return ucl_object_push_lua (L, obj, TRUE);
			}
		}
	}
	lua_pushnil (L);
	return 1;
}

static int
lua_config_get_mempool (lua_State * L)
{
	rspamd_mempool_t                  **ppool;
	struct rspamd_config             *cfg = lua_check_config (L);

	if (cfg != NULL) {
		ppool = lua_newuserdata (L, sizeof (rspamd_mempool_t *));
		lua_setclass (L, "rspamd{mempool}", -1);
		*ppool = cfg->cfg_pool;
	}
	return 1;
}

static gint
lua_config_get_all_opt (lua_State * L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	const gchar                     *mname;
	const ucl_object_t              *obj;

	if (cfg) {
		mname = luaL_checkstring (L, 2);

		if (mname) {
			obj = ucl_obj_get_key (cfg->rcl_obj, mname);
			if (obj != NULL) {
				return ucl_object_push_lua (L, obj, TRUE);
			}
		}
	}
	lua_pushnil (L);
	return 1;
}


static gint
lua_config_get_classifier (lua_State * L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	struct rspamd_classifier_config       *clc = NULL, **pclc = NULL;
	const gchar                     *name;
	GList                          *cur;

	if (cfg) {
		name = luaL_checkstring (L, 2);

		cur = g_list_first (cfg->classifiers);
		while (cur) {
			clc = cur->data;
			if (g_ascii_strcasecmp (clc->classifier->name, name) == 0) {
				pclc = &clc;
				break;
			}
			cur = g_list_next (cur);
		}
		if (pclc) {
			pclc = lua_newuserdata (L, sizeof (struct rspamd_classifier_config *));
			lua_setclass (L, "rspamd{classifier}", -1);
			*pclc = clc;
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;

}

struct lua_callback_data {
	union {
		gchar						*name;
		gint						 ref;
	} callback;
	gboolean						 cb_is_ref;
	lua_State						*L;
	gchar 							*symbol;
};

/*
 * Unref symbol if it is local reference
 */
static void
lua_destroy_cfg_symbol (gpointer ud)
{
	struct lua_callback_data       *cd = ud;

	/* Unref callback */
	if (cd->cb_is_ref) {
		luaL_unref (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
	}
}

static gboolean
lua_config_function_callback (struct rspamd_task *task, GList *args, void *user_data)
{
	struct lua_callback_data       *cd = user_data;
	struct rspamd_task            **ptask;
	gint                            i = 1;
	struct expression_argument     *arg;
	GList                          *cur;
	gboolean                        res = FALSE;

	if (cd->cb_is_ref) {
		lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
	}
	else {
		lua_getglobal (cd->L, cd->callback.name);
	}
	ptask = lua_newuserdata (cd->L, sizeof (struct rspamd_task *));
	lua_setclass (cd->L, "rspamd{task}", -1);
	*ptask = task;
	/* Now push all arguments */
	cur = args;
	while (cur) {
		arg = get_function_arg (cur->data, task, TRUE);
		lua_pushstring (cd->L, (const gchar *)arg->data);
		cur = g_list_next (cur);
		i ++;
	}

	if (lua_pcall (cd->L, i, 1, 0) != 0) {
		msg_info ("error processing symbol %s: call to %s failed: %s", cd->symbol,
						cd->cb_is_ref ? "local function" :
						cd->callback.name, lua_tostring (cd->L, -1));
	}
	else {
		if (lua_isboolean (cd->L, 1)) {
			res = lua_toboolean (cd->L, 1);
		}
		lua_pop (cd->L, 1);
	}

	return res;
}

static gint
lua_config_register_function (lua_State *L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	gchar                          *name;
	struct lua_callback_data       *cd;
	
	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		cd = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct lua_callback_data));

		if (lua_type (L, 3) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 3));
			cd->cb_is_ref = FALSE;
		}
		else {
			lua_pushvalue (L, 3);
			/* Get a reference */
			cd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			cd->cb_is_ref = TRUE;
		}
		if (name) {
			cd->L = L;
			cd->symbol = name;
			register_expression_function (name, lua_config_function_callback, cd);
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)lua_destroy_cfg_symbol, cd);
	}
	return 1;
}

static gint
lua_config_register_module_option (lua_State *L)
{
	return 0;
}

void
lua_call_post_filters (struct rspamd_task *task)
{
	struct lua_callback_data       *cd;
	struct rspamd_task            **ptask;
	GList                          *cur;

	cur = task->cfg->post_filters;
	while (cur) {
		cd = cur->data;
		if (cd->cb_is_ref) {
			lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
		}
		else {
			lua_getglobal (cd->L, cd->callback.name);
		}
		ptask = lua_newuserdata (cd->L, sizeof (struct rspamd_task *));
		lua_setclass (cd->L, "rspamd{task}", -1);
		*ptask = task;

		if (lua_pcall (cd->L, 1, 0, 0) != 0) {
			msg_info ("call to %s failed: %s", cd->cb_is_ref ? "local function" :
							cd->callback.name, lua_tostring (cd->L, -1));
		}
		cur = g_list_next (cur);
	}
}

static gint
lua_config_register_post_filter (lua_State *L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	struct lua_callback_data       *cd;

	if (cfg) {
		cd = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct lua_callback_data));
		if (lua_type (L, 2) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
			cd->cb_is_ref = FALSE;
		}
		else {
			lua_pushvalue (L, 2);
			/* Get a reference */
			cd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			cd->cb_is_ref = TRUE;
		}
		cd->L = L;
		cfg->post_filters = g_list_prepend (cfg->post_filters, cd);
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)lua_destroy_cfg_symbol, cd);
	}
	return 1;
}

void
lua_call_pre_filters (struct rspamd_task *task)
{
	struct lua_callback_data       *cd;
	struct rspamd_task            **ptask;
	GList                          *cur;

	cur = task->cfg->pre_filters;
	while (cur) {
		cd = cur->data;
		if (cd->cb_is_ref) {
			lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
		}
		else {
			lua_getglobal (cd->L, cd->callback.name);
		}
		ptask = lua_newuserdata (cd->L, sizeof (struct rspamd_task *));
		lua_setclass (cd->L, "rspamd{task}", -1);
		*ptask = task;

		if (lua_pcall (cd->L, 1, 0, 0) != 0) {
			msg_info ("call to %s failed: %s", cd->cb_is_ref ? "local function" :
							cd->callback.name, lua_tostring (cd->L, -1));
		}
		cur = g_list_next (cur);
	}
}

static gint
lua_config_register_pre_filter (lua_State *L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	struct lua_callback_data       *cd;

	if (cfg) {
		cd = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct lua_callback_data));
		if (lua_type (L, 2) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
			cd->cb_is_ref = FALSE;
		}
		else {
			lua_pushvalue (L, 2);
			/* Get a reference */
			cd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			cd->cb_is_ref = TRUE;
		}
		cd->L = L;
		cfg->pre_filters = g_list_prepend (cfg->pre_filters, cd);
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)lua_destroy_cfg_symbol, cd);
	}
	return 1;
}

static gint
lua_config_add_radix_map (lua_State *L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	const gchar                     *map_line, *description;
	radix_tree_t                   **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		r = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (radix_tree_t *));
		*r = radix_tree_create ();
		if (!add_map (cfg, map_line, description, read_radix_list, fin_radix_list, (void **)r)) {
			msg_warn ("invalid radix map %s", map_line);
			radix_tree_free (*r);
			lua_pushnil (L);
			return 1;
		}
		ud = lua_newuserdata (L, sizeof (radix_tree_t *));
		*ud = r;
		lua_setclass (L, "rspamd{radix}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

static gint
lua_config_add_hash_map (lua_State *L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	const gchar                     *map_line, *description;
	GHashTable                    **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		r = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (GHashTable *));
		*r = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
		if (!add_map (cfg, map_line, description, read_host_list, fin_host_list, (void **)r)) {
			msg_warn ("invalid hash map %s", map_line);
			g_hash_table_destroy (*r);
			lua_pushnil (L);
			return 1;
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)g_hash_table_destroy, *r);
		ud = lua_newuserdata (L, sizeof (GHashTable *));
		*ud = r;
		lua_setclass (L, "rspamd{hash_table}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

static gint
lua_config_add_kv_map (lua_State *L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	const gchar                     *map_line, *description;
	GHashTable                    **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		r = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (GHashTable *));
		*r = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
		if (!add_map (cfg, map_line, description, read_kv_list, fin_kv_list, (void **)r)) {
			msg_warn ("invalid hash map %s", map_line);
			g_hash_table_destroy (*r);
			lua_pushnil (L);
			return 1;
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)g_hash_table_destroy, *r);
		ud = lua_newuserdata (L, sizeof (GHashTable *));
		*ud = r;
		lua_setclass (L, "rspamd{hash_table}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

struct lua_map_callback_data {
	lua_State *L;
	gint ref;
	GString *data;
};

static gchar *
lua_map_read (rspamd_mempool_t *pool, gchar *chunk, gint len,
		struct map_cb_data *data)
{
	struct lua_map_callback_data *cbdata, *old;

	if (data->cur_data == NULL) {
		cbdata = g_slice_alloc (sizeof (*cbdata));
		old = (struct lua_map_callback_data *)data->prev_data;
		cbdata->L = old->L;
		cbdata->ref = old->ref;
	}
	else {
		cbdata = (struct lua_map_callback_data *)data->cur_data;
	}

	if (cbdata->data == NULL) {
		cbdata->data = g_string_new_len (chunk, len);
	}
	else {
		g_string_append_len (cbdata->data, chunk, len);
	}

	return NULL;
}

void
lua_map_fin (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	struct lua_map_callback_data *cbdata, *old;

	if (data->prev_data) {
		/* Cleanup old data */
		old = (struct lua_map_callback_data *)data->prev_data;
		if (old->data) {
			g_string_free (old->data, TRUE);
		}
		g_slice_free1 (sizeof (*old), old);
	}

	if (data->cur_data) {
		cbdata = (struct lua_map_callback_data *)data->cur_data;
	}
	else {
		msg_err ("no data read for map");
		return;
	}

	if (cbdata->data != NULL && cbdata->data->len != 0) {
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->ref);
		lua_pushlstring (cbdata->L, cbdata->data->str, cbdata->data->len);

		if (lua_pcall (cbdata->L, 1, 0, 0) != 0) {
			msg_info ("call to %s failed: %s", "local function",
					lua_tostring (cbdata->L, -1));
		}
	}
}

static gint
lua_config_add_map (lua_State *L)
{
	struct rspamd_config            *cfg = lua_check_config (L);
	const gchar                     *map_line, *description;
	struct lua_map_callback_data    *cbdata, **pcbdata;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);

		if (lua_type (L, 4) == LUA_TFUNCTION) {
			cbdata = g_slice_alloc (sizeof (*cbdata));
			cbdata->L = L;
			cbdata->data = NULL;
			lua_pushvalue (L, 4);
			/* Get a reference */
			cbdata->ref = luaL_ref (L, LUA_REGISTRYINDEX);
			pcbdata = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (cbdata));
			*pcbdata = cbdata;
			if (!add_map (cfg, map_line, description, lua_map_read, lua_map_fin,
					(void **)pcbdata)) {
				msg_warn ("invalid hash map %s", map_line);
				lua_pushboolean (L, false);
			}
			else {
				lua_pushboolean (L, true);
			}
		}
		else {
			msg_warn ("invalid callback argument for map %s", map_line);
			lua_pushboolean (L, false);
		}
	}
	else {
		lua_pushboolean (L, false);
	}

	return 1;
}

/*** Metric functions ***/


static void
lua_metric_symbol_callback (struct rspamd_task *task, gpointer ud)
{
	struct lua_callback_data       *cd = ud;
	struct rspamd_task            **ptask;

	if (cd->cb_is_ref) {
		lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
	}
	else {
		lua_getglobal (cd->L, cd->callback.name);
	}
	ptask = lua_newuserdata (cd->L, sizeof (struct rspamd_task *));
	lua_setclass (cd->L, "rspamd{task}", -1);
	*ptask = task;

	if (lua_pcall (cd->L, 1, 0, 0) != 0) {
		msg_info ("call to %s failed: %s", cd->cb_is_ref ? "local function" :
									cd->callback.name, lua_tostring (cd->L, -1));
	}
}

static gint
lua_config_register_symbol (lua_State * L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	gchar                          *name;
	double                          weight;
	struct lua_callback_data       *cd;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);
		cd = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct lua_callback_data));
		if (lua_type (L, 4) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 4));
			cd->cb_is_ref = FALSE;
		}
		else {
			lua_pushvalue (L, 4);
			/* Get a reference */
			cd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			cd->cb_is_ref = TRUE;
		}
		if (name) {
			cd->symbol = name;
			cd->L = L;
			register_symbol (&cfg->cache, name, weight, lua_metric_symbol_callback, cd);
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)lua_destroy_cfg_symbol, cd);
	}
	return 0;
}

static gint
lua_config_register_symbols (lua_State *L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	struct lua_callback_data       *cd;
	gint                             i, top;
	gchar                           *sym;
	gdouble                          weight = 1.0;

	if (lua_gettop (L) < 3) {
		msg_err ("not enough arguments to register a function");
		return 0;
	}
	if (cfg) {
		cd = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct lua_callback_data));
		if (lua_type (L, 2) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
			cd->cb_is_ref = FALSE;
		}
		else {
			lua_pushvalue (L, 2);
			/* Get a reference */
			cd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			cd->cb_is_ref = TRUE;
		}
		if (lua_type (L, 3) == LUA_TNUMBER) {
			weight = lua_tonumber (L, 3);
			top = 4;
		}
		else {
			top = 3;
		}
		sym = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, top));
		cd->symbol = sym;
		cd->L = L;
		register_symbol (&cfg->cache, sym, weight, lua_metric_symbol_callback, cd);
		for (i = top; i < lua_gettop (L); i ++) {
			sym = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, i + 1));
			register_virtual_symbol (&cfg->cache, sym, weight);
		}
	}

	return 0;
}

static gint
lua_config_register_virtual_symbol (lua_State * L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	gchar                          *name;
	double                          weight;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);
		if (name) {
			register_virtual_symbol (&cfg->cache, name, weight);
		}
	}
	return 0;
}

static gint
lua_config_register_callback_symbol (lua_State * L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	gchar                          *name;
	double                          weight;
	struct lua_callback_data       *cd;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);
		cd = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct lua_callback_data));
		if (lua_type (L, 4) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 4));
			cd->cb_is_ref = FALSE;
		}
		else {
			lua_pushvalue (L, 4);
			/* Get a reference */
			cd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			cd->cb_is_ref = TRUE;
		}
		if (name) {
			cd->symbol = name;
			cd->L = L;
			register_callback_symbol (&cfg->cache, name, weight, lua_metric_symbol_callback, cd);
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)lua_destroy_cfg_symbol, cd);
	}
	return 0;
}

static gint
lua_config_register_callback_symbol_priority (lua_State * L)
{
	struct rspamd_config             *cfg = lua_check_config (L);
	gchar                          *name;
	double                          weight;
	gint                            priority;
	struct lua_callback_data       *cd;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);
		priority = luaL_checknumber (L, 4);
		cd = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct lua_callback_data));
		if (lua_type (L, 5) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 5));
			cd->cb_is_ref = FALSE;
		}
		else {
			lua_pushvalue (L, 5);
			/* Get a reference */
			cd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			cd->cb_is_ref = TRUE;
		}

		if (name) {
			cd->L = L;
			cd->symbol = name;
			register_callback_symbol_priority (&cfg->cache, name, weight, priority, lua_metric_symbol_callback, cd);
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool, (rspamd_mempool_destruct_t)lua_destroy_cfg_symbol, cd);

	}
	return 0;
}


/* Radix and hash table functions */
static gint
lua_radix_get_key (lua_State * L)
{
	radix_tree_t                  *radix = lua_check_radix (L);
	guint32                         key;

	if (radix) {
		key = luaL_checkint (L, 2);

		if (radix32tree_find (radix, key) != RADIX_NO_VALUE) {
			lua_pushboolean (L, 1);
			return 1;
		}
	}

	lua_pushboolean (L, 0);
	return 1;
}

static gint
lua_hash_table_get_key (lua_State * L)
{
	GHashTable                    *tbl = lua_check_hash_table (L);
	const gchar                    *key, *value;

	if (tbl) {
		key = luaL_checkstring (L, 2);

		if ((value = g_hash_table_lookup (tbl, key)) != NULL) {
			lua_pushstring (L, value);
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

/* Trie functions */
static gint
lua_trie_create (lua_State *L)
{
	rspamd_trie_t                 *trie, **ptrie;
	gboolean                       icase = FALSE;

	if (lua_gettop (L) == 1) {
		icase = lua_toboolean (L, 1);
	}

	trie = rspamd_trie_create (icase);

	ptrie = lua_newuserdata (L, sizeof (rspamd_trie_t *));
	lua_setclass (L, "rspamd{trie}", -1);
	*ptrie = trie;

	return 1;
}

static gint
lua_trie_add_pattern (lua_State *L)
{
	rspamd_trie_t                 *trie = lua_check_trie (L);
	const gchar                   *pattern;
	gint                           id;

	if (trie) {
		pattern  = luaL_checkstring (L, 2);
		id = luaL_checknumber (L, 3);

		if (pattern != NULL) {
			rspamd_trie_insert (trie, pattern, id);
			lua_pushboolean (L, 1);
		}
	}

	lua_pushboolean (L, 0);

	return 1;
}

static gint
lua_trie_search_text (lua_State *L)
{
	rspamd_trie_t                 *trie = lua_check_trie (L);
	const gchar                   *text, *pos;
	gint                           id, i = 1;
	gsize                          len;
	gboolean                       found = FALSE;

	if (trie) {
		text = luaL_checkstring (L, 2);
		len = strlen (text);
		if (text) {
			lua_newtable (L);
			pos = text;
			while (pos < text + len && (pos = rspamd_trie_lookup (trie, pos, len, &id)) != NULL) {
				lua_pushinteger (L, i);
				lua_pushinteger (L, id);
				lua_settable (L, -3);
				i ++;
				found = TRUE;
				break;
			}

			if (!found) {
				lua_pushnil (L);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_trie_search_task (lua_State *L)
{
	rspamd_trie_t                 *trie = lua_check_trie (L);
	struct rspamd_task            *task;
	struct mime_text_part         *part;
	GList                         *cur;
	const gchar                   *pos, *end;
	gint                           id, i = 1;
	void                          *ud;
	gboolean                       found = FALSE;

	if (trie) {
		ud = luaL_checkudata (L, 2, "rspamd{task}");
		luaL_argcheck (L, ud != NULL, 1, "'task' expected");
		task = ud ? *((struct rspamd_task **)ud) : NULL;
		if (task) {
			lua_newtable (L);
			cur = task->text_parts;
			while (cur) {
				part = cur->data;
				if (!part->is_empty && part->content != NULL) {
					pos = (const gchar *)part->content->data;
					end = pos + part->content->len;
					while (pos < end && (pos = rspamd_trie_lookup (trie, pos, part->content->len, &id)) != NULL) {
						lua_pushinteger (L, i);
						lua_pushinteger (L, id);
						lua_settable (L, -3);
						i ++;
						found = TRUE;
						break;
					}
				}
				cur = g_list_next (cur);
			}
			if (!found) {
				lua_pushnil (L);
			}
			return 1;
		}
	}

	if (!found) {
		lua_pushnil (L);
	}
	return 1;
}
/* Init functions */

gint
luaopen_config (lua_State * L)
{
	lua_newclass (L, "rspamd{config}", configlib_m);
	luaL_register (L, "rspamd_config", null_reg);

	lua_pop (L, 1);                      /* remove metatable from stack */

	return 1;
}

gint
luaopen_radix (lua_State * L)
{
	lua_newclass (L, "rspamd{radix}", radixlib_m);
	luaL_register (L, "rspamd_radix", null_reg);

	lua_pop (L, 1);                      /* remove metatable from stack */

	return 1;
}

gint
luaopen_hash_table (lua_State * L)
{
	lua_newclass (L, "rspamd{hash_table}", hashlib_m);
	luaL_register (L, "rspamd_hash_table", null_reg);

	lua_pop (L, 1);                      /* remove metatable from stack */

	return 1;
}

gint
luaopen_trie (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{trie}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{trie}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, trielib_m);
	luaL_register (L, "rspamd_trie", trielib_f);

	lua_pop (L, 1);                      /* remove metatable from stack */

	return 1;
}
