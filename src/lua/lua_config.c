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

/***
 * This module is used to configure rspamd and is normally available as global
 * variable named `rspamd_config`. Unlike other modules, it is not necessary to
 * require it before usage.
 * @module rspamd_config
 * @example
-- Register some callback symbol
local function foo(task)
    -- do something
end
rspamd_config:register_symbol('SYMBOL', 1.0, foo)

-- Get configuration
local tab = rspamd_config:get_all_opt('module') -- get table for module's options
local opts = rspamd_config:get_key('options') -- get content of the specified key in rspamd configuration
 */

/* Config file methods */
/***
 * @method rspamd_config:get_module_opt(mname, optname)
 * Returns value of specified option `optname` for a module `mname`,
 * @param {string} mname name of module
 * @param {string} optname option to get
 * @return {string or table} value of the option or `nil` if option is not found
 */
LUA_FUNCTION_DEF (config, get_module_opt);
/***
 * @method rspamd_config:get_all_opt(mname)
 * Returns value of all options for a module `mname`,
 * @param {string} mname name of module
 * @return {table} table of all options for `mname` or `nil` if a module's configuration is not found
 */
LUA_FUNCTION_DEF (config, get_all_opt);
/***
 * @method rspamd_config:get_mempool()
 * Returns static configuration memory pool.
 * @return {mempool} [memory pool](mempool.md) object
 */
LUA_FUNCTION_DEF (config, get_mempool);
/***
 * @method rspamd_config:register_function(name, callback)
 * Registers new rspamd function that could be used in symbols expressions
 * @param {string} name name of function
 * @param {function} callback callback to be called
 * @example

local function lua_header_exists(task, hname)
	if task:get_raw_header(hname) then
		return true
	end

	return false
end

rspamd_config:register_function('lua_header_exists', lua_header_exists)

-- Further in configuration it would be possible to define symbols like:
-- HAS_CONTENT_TYPE = 'lua_header_exists(Content-Type)'
 */
LUA_FUNCTION_DEF (config, register_function);
/***
 * @method rspamd_config:add_radix_map(mapline[, description])
 * Creates new dynamic map of IP/mask addresses.
 * @param {string} mapline URL for a map
 * @param {string} description optional map description
 * @return {radix} radix tree object
 * @example
local ip_map = rspamd_config:add_radix_map ('file:///path/to/file', 'my radix map')
...
local function foo(task)
	local ip = task:get_from_ip()
	if ip_map:get_key(ip) then
		return true
	end
	return false
end
 */
LUA_FUNCTION_DEF (config, add_radix_map);
/***
 * @method rspamd_config:add_hash_map(mapline[, description])
 * Creates new dynamic map string objects.
 * @param {string} mapline URL for a map
 * @param {string} description optional map description
 * @return {hash} hash set object
 * @example
local hash_map = rspamd_config:add_hash_map ('file:///path/to/file', 'my hash map')
...
local function foo(task)
	local from = task:get_from()
	if hash_map:get_key(from['user']) then
		return true
	end
	return false
end
 */
LUA_FUNCTION_DEF (config, add_hash_map);
/***
 * @method rspamd_config:add_kv_map(mapline[, description])
 * Creates new dynamic map of key/values associations.
 * @param {string} mapline URL for a map
 * @param {string} description optional map description
 * @return {hash} hash table object
 * @example
local kv_map = rspamd_config:add_kv_map ('file:///path/to/file', 'my kv map')
...
local function foo(task)
	local from = task:get_from()
	if from then
		local value = kv_map:get_key(from['user'])
		if value then
			return true,value
		end
	end
	return false
end
 */
LUA_FUNCTION_DEF (config, add_kv_map);
/***
 * @method rspamd_config:add_map(mapline[, description], callback)
 * Creates new dynamic map with free-form callback
 * @param {string} mapline URL for a map
 * @param {string} description optional map description
 * @param {function} callback function to be called on map load and/or update
 * @return {bool} `true` if map has been added
 * @example

local str = ''
local function process_map(in)
	str = in
end

rspamd_config:add_map('http://example.com/map', "settings map", process_map)
 */
LUA_FUNCTION_DEF (config, add_map);
/***
 * @method rspamd_config:get_classifier(name)
 * Returns classifier config.
 * @param {string} name name of classifier (e.g. `bayes`)
 * @return {classifier} classifier object or `nil`
 */
LUA_FUNCTION_DEF (config, get_classifier);
/***
 * @method rspamd_config:register_symbol(name, weight, callback)
 * Register callback function to be called for a specified symbol with initial weight.
 * @param {string} name symbol's name
 * @param {number} weight initial weight of symbol (can be less than zero to specify non-spam symbols)
 * @param {function} callback callback function to be called for a specified symbol
 */
LUA_FUNCTION_DEF (config, register_symbol);
/***
 * @method rspamd_config:register_symbols(callback, [weight], callback_name, [, symbol, ...])
 * Register callback function to be called for a set of symbols with initial weight.
 * @param {function} callback callback function to be called for a specified symbol
 * @param {number} weight initial weight of symbol (can be less than zero to specify non-spam symbols)
 * @param {string} callback_name symbolic name of callback
 * @param {list of strings} symbol list of symbols registered by this function
 */
LUA_FUNCTION_DEF (config, register_symbols);
/***
 * @method rspamd_config:register_virtual_symbol(name, weight,)
 * Register virtual symbol that is not associated with any callback.
 * @param {string} virtual name symbol's name
 * @param {number} weight initial weight of symbol (can be less than zero to specify non-spam symbols)
 */
LUA_FUNCTION_DEF (config, register_virtual_symbol);
/***
 * @method rspamd_config:register_callback_symbol(name, weight, callback)
 * Register callback function to be called for a specified symbol with initial weight. Symbol itself is
 * not registered in the metric and is not intended to be visible by a user.
 * @param {string} name symbol's name (just for unique id purposes)
 * @param {number} weight initial weight of symbol (can be less than zero to specify non-spam symbols)
 * @param {function} callback callback function to be called for a specified symbol
 */
LUA_FUNCTION_DEF (config, register_callback_symbol);
LUA_FUNCTION_DEF (config, register_callback_symbol_priority);
/***
 * @method rspamd_config:register_pre_filter(callback)
 * Register function to be called prior to symbols processing.
 * @param {function} callback callback function
 * @example
local function check_function(task)
	-- It is possible to manipulate the task object here: set settings, set pre-action and so on
	...
end

rspamd_config:register_pre_filter(check_function)
 */
LUA_FUNCTION_DEF (config, register_pre_filter);
/***
 * @method rspamd_config:register_pre_filter(callback)
 * Register function to be called after symbols are processed.
 * @param {function} callback callback function
 */
LUA_FUNCTION_DEF (config, register_post_filter);
/* XXX: obsoleted */
LUA_FUNCTION_DEF (config, register_module_option);
/* XXX: not needed now */
LUA_FUNCTION_DEF (config, get_api_version);
/***
 * @method rspamd_config:get_key(name)
 * Returns configuration section with the specified `name`.
 * @param {string} name name of config section
 * @return {variant} specific value of section
 * @example

local set_section = rspamd_config:get_key("settings")
if type(set_section) == "string" then
  -- Just a map of ucl
  if rspamd_config:add_map(set_section, "settings map", process_settings_map) then
    rspamd_config:register_pre_filter(check_settings)
  end
elseif type(set_section) == "table" then
  if process_settings_table(set_section) then
    rspamd_config:register_pre_filter(check_settings)
  end
end
 */
LUA_FUNCTION_DEF (config, get_key);
/***
 * @method rspamd_config:__newindex(name, callback)
 * This metamethod is called if new indicies are added to the `rspamd_config` object.
 * Technically, it is the equialent of @see rspamd_config:register_symbol where `weight` is 1.0.
 * @param {string} name index name
 * @param {function} callback callback to be called
 * @example
rspamd_config.R_EMPTY_IMAGE = function (task)
	parts = task:get_text_parts()
	if parts then
		for _,part in ipairs(parts) do
			if part:is_empty() then
				images = task:get_images()
				if images then
					-- Symbol `R_EMPTY_IMAGE` is inserted
					return true
				end
				return false
			end
		end
	end
	return false
end
 */
LUA_FUNCTION_DEF (config, newindex);

static const struct luaL_reg configlib_m[] = {
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
	LUA_INTERFACE_DEF (config, get_key),
	{"__tostring", rspamd_lua_class_tostring},
	{"__newindex", lua_config_newindex},
	{NULL, NULL}
};


/* Radix tree */
LUA_FUNCTION_DEF (radix, get_key);

static const struct luaL_reg radixlib_m[] = {
	LUA_INTERFACE_DEF (radix, get_key),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Hash table */
LUA_FUNCTION_DEF (hash_table, get_key);

static const struct luaL_reg hashlib_m[] = {
	LUA_INTERFACE_DEF (hash_table, get_key),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Suffix trie */
LUA_FUNCTION_DEF (trie, create);
LUA_FUNCTION_DEF (trie, add_pattern);
LUA_FUNCTION_DEF (trie, search_text);
LUA_FUNCTION_DEF (trie, search_task);

static const struct luaL_reg trielib_m[] = {
	LUA_INTERFACE_DEF (trie, add_pattern),
	LUA_INTERFACE_DEF (trie, search_text),
	LUA_INTERFACE_DEF (trie, search_task),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};
static const struct luaL_reg trielib_f[] = {
	LUA_INTERFACE_DEF (trie, create),
	{NULL, NULL}
};

static struct rspamd_config *
lua_check_config (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{config}");
	luaL_argcheck (L, ud != NULL, 1, "'config' expected");
	return ud ? *((struct rspamd_config **)ud) : NULL;
}

static radix_compressed_t *
lua_check_radix (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{radix}");
	luaL_argcheck (L, ud != NULL, 1, "'radix' expected");
	return ud ? **((radix_compressed_t ***)ud) : NULL;
}

static GHashTable *
lua_check_hash_table (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{hash_table}");
	luaL_argcheck (L, ud != NULL, 1, "'hash_table' expected");
	return ud ? **((GHashTable ***)ud) : NULL;
}

static rspamd_trie_t *
lua_check_trie (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{trie}");

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
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *mname, *optname;
	const ucl_object_t *obj;

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
	rspamd_mempool_t **ppool;
	struct rspamd_config *cfg = lua_check_config (L);

	if (cfg != NULL) {
		ppool = lua_newuserdata (L, sizeof (rspamd_mempool_t *));
		rspamd_lua_setclass (L, "rspamd{mempool}", -1);
		*ppool = cfg->cfg_pool;
	}
	return 1;
}

static gint
lua_config_get_all_opt (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *mname;
	const ucl_object_t *obj;

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
	struct rspamd_config *cfg = lua_check_config (L);
	struct rspamd_classifier_config *clc = NULL, **pclc = NULL;
	const gchar *name;
	GList *cur;

	if (cfg) {
		name = luaL_checkstring (L, 2);

		cur = g_list_first (cfg->classifiers);
		while (cur) {
			clc = cur->data;
			if (g_ascii_strcasecmp (clc->name, name) == 0) {
				pclc = &clc;
				break;
			}
			cur = g_list_next (cur);
		}
		if (pclc) {
			pclc = lua_newuserdata (L,
					sizeof (struct rspamd_classifier_config *));
			rspamd_lua_setclass (L, "rspamd{classifier}", -1);
			*pclc = clc;
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;

}

struct lua_callback_data {
	union {
		gchar *name;
		gint ref;
	} callback;
	gboolean cb_is_ref;
	lua_State *L;
	gchar *symbol;
};

/*
 * Unref symbol if it is local reference
 */
static void
lua_destroy_cfg_symbol (gpointer ud)
{
	struct lua_callback_data *cd = ud;

	/* Unref callback */
	if (cd->cb_is_ref) {
		luaL_unref (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
	}
}

static gboolean
lua_config_function_callback (struct rspamd_task *task,
	GList *args,
	void *user_data)
{
	struct lua_callback_data *cd = user_data;
	struct rspamd_task **ptask;
	gint i = 1;
	struct expression_argument *arg;
	GList *cur;
	gboolean res = FALSE;

	if (cd->cb_is_ref) {
		lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
	}
	else {
		lua_getglobal (cd->L, cd->callback.name);
	}
	ptask = lua_newuserdata (cd->L, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (cd->L, "rspamd{task}", -1);
	*ptask = task;
	/* Now push all arguments */
	cur = args;
	while (cur) {
		arg = get_function_arg (cur->data, task, TRUE);
		lua_pushstring (cd->L, (const gchar *)arg->data);
		cur = g_list_next (cur);
		i++;
	}

	if (lua_pcall (cd->L, i, 1, 0) != 0) {
		msg_info ("error processing symbol %s: call to %s failed: %s",
			cd->symbol,
			cd->cb_is_ref ? "local function" :
			cd->callback.name,
			lua_tostring (cd->L, -1));
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
	struct rspamd_config *cfg = lua_check_config (L);
	gchar *name;
	struct lua_callback_data *cd;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		cd =
			rspamd_mempool_alloc (cfg->cfg_pool,
				sizeof (struct lua_callback_data));

		if (lua_type (L, 3) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool,
					luaL_checkstring (L, 3));
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
			register_expression_function (name, lua_config_function_callback,
				cd);
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)lua_destroy_cfg_symbol,
			cd);
	}
	return 1;
}

static gint
lua_config_register_module_option (lua_State *L)
{
	return 0;
}

void
rspamd_lua_call_post_filters (struct rspamd_task *task)
{
	struct lua_callback_data *cd;
	struct rspamd_task **ptask;
	GList *cur;

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
		rspamd_lua_setclass (cd->L, "rspamd{task}", -1);
		*ptask = task;

		if (lua_pcall (cd->L, 1, 0, 0) != 0) {
			msg_info ("call to %s failed: %s",
				cd->cb_is_ref ? "local function" :
				cd->callback.name,
				lua_tostring (cd->L, -1));
		}
		cur = g_list_next (cur);
	}
}

static gint
lua_config_register_post_filter (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	struct lua_callback_data *cd;

	if (cfg) {
		cd =
			rspamd_mempool_alloc (cfg->cfg_pool,
				sizeof (struct lua_callback_data));
		if (lua_type (L, 2) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool,
					luaL_checkstring (L, 2));
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
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)lua_destroy_cfg_symbol,
			cd);
	}
	return 1;
}

void
rspamd_lua_call_pre_filters (struct rspamd_task *task)
{
	struct lua_callback_data *cd;
	struct rspamd_task **ptask;
	GList *cur;

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
		rspamd_lua_setclass (cd->L, "rspamd{task}", -1);
		*ptask = task;

		if (lua_pcall (cd->L, 1, 0, 0) != 0) {
			msg_info ("call to %s failed: %s",
				cd->cb_is_ref ? "local function" :
				cd->callback.name,
				lua_tostring (cd->L, -1));
		}
		cur = g_list_next (cur);
	}
}

static gint
lua_config_register_pre_filter (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	struct lua_callback_data *cd;

	if (cfg) {
		cd =
			rspamd_mempool_alloc (cfg->cfg_pool,
				sizeof (struct lua_callback_data));
		if (lua_type (L, 2) == LUA_TSTRING) {
			cd->callback.name = rspamd_mempool_strdup (cfg->cfg_pool,
					luaL_checkstring (L, 2));
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
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)lua_destroy_cfg_symbol,
			cd);
	}
	return 1;
}

static gint
lua_config_add_radix_map (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *map_line, *description;
	radix_compressed_t **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		r = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (radix_compressed_t *));
		*r = radix_create_compressed ();
		if (!rspamd_map_add (cfg, map_line, description, rspamd_radix_read,
			rspamd_radix_fin, (void **)r)) {
			msg_warn ("invalid radix map %s", map_line);
			radix_destroy_compressed (*r);
			lua_pushnil (L);
			return 1;
		}
		ud = lua_newuserdata (L, sizeof (radix_compressed_t *));
		*ud = r;
		rspamd_lua_setclass (L, "rspamd{radix}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

static gint
lua_config_add_hash_map (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *map_line, *description;
	GHashTable **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		r = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (GHashTable *));
		*r = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
		if (!rspamd_map_add (cfg, map_line, description, rspamd_hosts_read, rspamd_hosts_fin,
			(void **)r)) {
			msg_warn ("invalid hash map %s", map_line);
			g_hash_table_destroy (*r);
			lua_pushnil (L);
			return 1;
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_hash_table_destroy,
			*r);
		ud = lua_newuserdata (L, sizeof (GHashTable *));
		*ud = r;
		rspamd_lua_setclass (L, "rspamd{hash_table}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

static gint
lua_config_add_kv_map (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *map_line, *description;
	GHashTable **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		r = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (GHashTable *));
		*r = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
		if (!rspamd_map_add (cfg, map_line, description, rspamd_kv_list_read, rspamd_kv_list_fin,
			(void **)r)) {
			msg_warn ("invalid hash map %s", map_line);
			g_hash_table_destroy (*r);
			lua_pushnil (L);
			return 1;
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_hash_table_destroy,
			*r);
		ud = lua_newuserdata (L, sizeof (GHashTable *));
		*ud = r;
		rspamd_lua_setclass (L, "rspamd{hash_table}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

static gint
lua_config_get_key (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *name;
	size_t namelen;
	const ucl_object_t *val;

	name = luaL_checklstring(L, 2, &namelen);
	if (name && cfg) {
		val = ucl_object_find_keyl(cfg->rcl_obj, name, namelen);
		if (val != NULL) {
			ucl_object_push_lua (L, val, val->type != UCL_ARRAY);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static void
lua_metric_symbol_callback (struct rspamd_task *task, gpointer ud)
{
	struct lua_callback_data *cd = ud;
	struct rspamd_task **ptask;
	gint level = lua_gettop (cd->L), nresults;

	if (cd->cb_is_ref) {
		lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->callback.ref);
	}
	else {
		lua_getglobal (cd->L, cd->callback.name);
	}
	ptask = lua_newuserdata (cd->L, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (cd->L, "rspamd{task}", -1);
	*ptask = task;

	if (lua_pcall (cd->L, 1, LUA_MULTRET, 0) != 0) {
		msg_info ("call to (%s)%s failed: %s", cd->symbol,
			cd->cb_is_ref ? "local function" : cd->callback.name,
			lua_tostring (cd->L, -1));
	}

	nresults = lua_gettop (cd->L) - level;
	if (nresults >= 1) {
		/* Function returned boolean, so maybe we need to insert result? */
		gboolean res;
		GList *opts = NULL;
		gint i;
		gdouble flag = 1.0;

		if (lua_type (cd->L, level + 1) == LUA_TBOOLEAN) {
			res = lua_toboolean (cd->L, level + 1);
			if (res) {
				gint first_opt = 2;

				if (lua_type (cd->L, level + 2) == LUA_TNUMBER) {
					flag = lua_tonumber (cd->L, level + 2);
					/* Shift opt index */
					first_opt = 3;
				}

				for (i = lua_gettop (cd->L); i >= level + first_opt; i --) {
					if (lua_type (cd->L, i) == LUA_TSTRING) {
						const char *opt = lua_tostring (cd->L, i);

						opts = g_list_prepend (opts,
							rspamd_mempool_strdup (task->task_pool, opt));
					}
				}
				rspamd_task_insert_result (task, cd->symbol, flag, opts);
			}
		}
		lua_pop (cd->L, nresults);
	}
}

static void
rspamd_register_symbol_fromlua (lua_State *L,
		struct rspamd_config *cfg,
		const gchar *name,
		gint ref,
		gdouble weight,
		gint priority,
		enum rspamd_symbol_type type)
{
	struct lua_callback_data *cd;

	cd = rspamd_mempool_alloc0 (cfg->cfg_pool,
		sizeof (struct lua_callback_data));
	cd->cb_is_ref = TRUE;
	cd->callback.ref = ref;
	cd->L = L;
	if (name) {
		cd->symbol = rspamd_mempool_strdup (cfg->cfg_pool, name);
	}

	register_symbol_common (&cfg->cache,
					name,
					weight,
					priority,
					lua_metric_symbol_callback,
					cd,
					type);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
		(rspamd_mempool_destruct_t)lua_destroy_cfg_symbol,
		cd);
}

static gint
lua_config_register_symbol (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	gchar *name;
	double weight;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);

		if (lua_type (L, 4) == LUA_TSTRING) {
			lua_getglobal (L, luaL_checkstring (L, 4));
		}
		else {
			lua_pushvalue (L, 4);
		}
		if (name) {
			rspamd_register_symbol_fromlua (L,
					cfg,
					name,
					luaL_ref (L, LUA_REGISTRYINDEX),
					weight,
					0,
					SYMBOL_TYPE_NORMAL);
		}
	}

	return 0;
}

static gint
lua_config_register_symbols (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	gint i, top, idx;
	gchar *sym;
	gdouble weight = 1.0;

	if (lua_gettop (L) < 3) {
		msg_err ("not enough arguments to register a function");
		return 0;
	}
	if (cfg) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			lua_getglobal (L, luaL_checkstring (L, 2));
		}
		else {
			lua_pushvalue (L, 2);
		}
		idx = luaL_ref (L, LUA_REGISTRYINDEX);

		if (lua_type (L, 3) == LUA_TNUMBER) {
			weight = lua_tonumber (L, 3);
			top = 4;
		}
		else {
			top = 3;
		}
		sym = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, top ++));
		rspamd_register_symbol_fromlua (L,
				cfg,
				sym,
				idx,
				weight,
				0,
				SYMBOL_TYPE_CALLBACK);
		for (i = top; i <= lua_gettop (L); i++) {
			if (lua_type (L, i) == LUA_TTABLE) {
				lua_pushvalue (L, i);
				lua_pushnil (L);
				while (lua_next (L, -2)) {
					lua_pushvalue (L, -2);
					sym = rspamd_mempool_strdup (cfg->cfg_pool,
							luaL_checkstring (L, -2));
					register_virtual_symbol (&cfg->cache, sym, weight);
					lua_pop (L, 2);
				}
				lua_pop (L, 1);
			}
			else if (lua_type (L, i) == LUA_TSTRING) {
				sym = rspamd_mempool_strdup (cfg->cfg_pool,
						luaL_checkstring (L, i));
				register_virtual_symbol (&cfg->cache, sym, weight);
			}
		}
	}

	return 0;
}

static gint
lua_config_register_virtual_symbol (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	gchar *name;
	double weight;

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
	struct rspamd_config *cfg = lua_check_config (L);
	gchar *name;
	double weight;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);

		if (lua_type (L, 4) == LUA_TSTRING) {
			lua_getglobal (L, luaL_checkstring (L, 4));
		}
		else {
			lua_pushvalue (L, 4);
		}
		if (name) {
			rspamd_register_symbol_fromlua (L,
					cfg,
					name,
					luaL_ref (L, LUA_REGISTRYINDEX),
					weight,
					0,
					SYMBOL_TYPE_CALLBACK);
		}
	}

	return 0;
}

static gint
lua_config_register_callback_symbol_priority (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	gchar *name;
	double weight;
	gint priority;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);
		priority = luaL_checknumber (L, 4);

		if (lua_type (L, 5) == LUA_TSTRING) {
			lua_getglobal (L, luaL_checkstring (L, 5));
		}
		else {
			lua_pushvalue (L, 5);
		}
		if (name) {
			rspamd_register_symbol_fromlua (L,
					cfg,
					name,
					luaL_ref (L, LUA_REGISTRYINDEX),
					weight,
					priority,
					SYMBOL_TYPE_CALLBACK);
		}
	}

	return 0;
}


static gint
lua_config_newindex (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *name;

	name = luaL_checkstring (L, 2);

	if (name != NULL && lua_gettop (L) > 2) {
		if (lua_type (L, 3) == LUA_TFUNCTION) {
			/* Normal symbol from just a function */
			lua_pushvalue (L, 3);
			rspamd_register_symbol_fromlua (L,
					cfg,
					name,
					luaL_ref (L, LUA_REGISTRYINDEX),
					1.0,
					0,
					SYMBOL_TYPE_NORMAL);
		}
		else if (lua_type (L, 3) == LUA_TTABLE) {
			gint type = SYMBOL_TYPE_NORMAL, priority = 0, idx;
			gdouble weight = 1.0;
			const char *type_str;

			/*
			 * Table can have the following attributes:
			 * "callback" - should be a callback function
			 * "weight" - optional weight
			 * "priority" - optional priority
			 * "type" - optional type (normal, virtual, callback)
			 */
			lua_pushstring (L, "callback");
			lua_gettable (L, -2);

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				lua_pop (L, 1);
				msg_info ("cannot find callback definition for %s", name);
				return 0;
			}
			idx = luaL_ref (L, LUA_REGISTRYINDEX);

			/* Optional fields */
			lua_pushstring (L, "weight");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TNUMBER) {
				weight = lua_tonumber (L, -1);
			}
			lua_pop (L, 1);

			lua_pushstring (L, "priority");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TNUMBER) {
				priority = lua_tonumber (L, -1);
			}
			lua_pop (L, 1);

			lua_pushstring (L, "type");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TSTRING) {
				type_str = lua_tostring (L, -1);
				if (strcmp (type_str, "normal") == 0) {
					type = SYMBOL_TYPE_NORMAL;
				}
				else if (strcmp (type_str, "virtual") == 0) {
					type = SYMBOL_TYPE_VIRTUAL;
				}
				else if (strcmp (type_str, "callback") == 0) {
					type = SYMBOL_TYPE_CALLBACK;
				}
				else {
					msg_info ("unknown type: %s", type_str);
				}

			}
			lua_pop (L, 1);

			rspamd_register_symbol_fromlua (L,
					cfg,
					name,
					idx,
					weight,
					priority,
					type);
		}
	}

	return 0;
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
		cbdata = g_slice_alloc0 (sizeof (*cbdata));
		old = (struct lua_map_callback_data *)data->prev_data;
		cbdata->L = old->L;
		cbdata->ref = old->ref;
		data->cur_data = cbdata;
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
		data->prev_data = NULL;
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
	struct rspamd_config *cfg = lua_check_config (L);
	const gchar *map_line, *description;
	struct lua_map_callback_data *cbdata, **pcbdata;
	int cbidx;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);

		if (lua_gettop (L) == 4) {
			description = lua_tostring (L, 3);
			cbidx = 4;
		}
		else {
			description = NULL;
			cbidx = 3;
		}

		if (lua_type (L, cbidx) == LUA_TFUNCTION) {
			cbdata = g_slice_alloc (sizeof (*cbdata));
			cbdata->L = L;
			cbdata->data = NULL;
			lua_pushvalue (L, cbidx);
			/* Get a reference */
			cbdata->ref = luaL_ref (L, LUA_REGISTRYINDEX);
			pcbdata = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (cbdata));
			*pcbdata = cbdata;
			if (!rspamd_map_add (cfg, map_line, description, lua_map_read, lua_map_fin,
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

/* Radix and hash table functions */
static gint
lua_radix_get_key (lua_State * L)
{
	radix_compressed_t *radix = lua_check_radix (L);
	guint32 key;

	if (radix) {
		key = htonl (luaL_checkint (L, 2));

		if (radix_find_compressed (radix, (guint8 *)&key, sizeof (key))
				!= RADIX_NO_VALUE) {
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
	GHashTable *tbl = lua_check_hash_table (L);
	const gchar *key, *value;

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
	rspamd_trie_t *trie, **ptrie;
	gboolean icase = FALSE;

	if (lua_gettop (L) == 1) {
		icase = lua_toboolean (L, 1);
	}

	trie = rspamd_trie_create (icase);

	ptrie = lua_newuserdata (L, sizeof (rspamd_trie_t *));
	rspamd_lua_setclass (L, "rspamd{trie}", -1);
	*ptrie = trie;

	return 1;
}

static gint
lua_trie_add_pattern (lua_State *L)
{
	rspamd_trie_t *trie = lua_check_trie (L);
	const gchar *pattern;
	gint id;

	if (trie) {
		pattern = luaL_checkstring (L, 2);
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
	rspamd_trie_t *trie = lua_check_trie (L);
	const gchar *text, *pos;
	gint id, i = 1;
	gsize len;
	gboolean found = FALSE;

	if (trie) {
		text = luaL_checkstring (L, 2);
		len = strlen (text);
		if (text) {
			lua_newtable (L);
			pos = text;
			while (pos < text + len &&
				(pos = rspamd_trie_lookup (trie, pos, len, &id)) != NULL) {
				lua_pushinteger (L, i);
				lua_pushinteger (L, id);
				lua_settable (L, -3);
				i++;
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
	rspamd_trie_t *trie = lua_check_trie (L);
	struct rspamd_task *task;
	struct mime_text_part *part;
	GList *cur;
	const gchar *pos, *end;
	gint id, i = 1;
	void *ud;
	gboolean found = FALSE;

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
					while (pos < end &&
						(pos =
						rspamd_trie_lookup (trie, pos, part->content->len,
						&id)) != NULL) {
						lua_pushinteger (L, i);
						lua_pushinteger (L, id);
						lua_settable (L, -3);
						i++;
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

void
luaopen_config (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{config}", configlib_m);

	lua_pop (L, 1);                      /* remove metatable from stack */
}

void
luaopen_radix (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{radix}", radixlib_m);

	lua_pop (L, 1);                      /* remove metatable from stack */
}

void
luaopen_hash_table (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{hash_table}", hashlib_m);
	luaL_register (L, "rspamd_hash_table", null_reg);

	lua_pop (L, 1);                      /* remove metatable from stack */
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
