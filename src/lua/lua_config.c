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
#include "libmime/message.h"
#include "libutil/expression.h"
#include "libserver/composites.h"
#include "lua/lua_map.h"
#include "utlist.h"

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
 * Returns value of all options for a module `mname`, flattening values into a single table consisting
 * of all sections with such a name.
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
 * @method rspamd_config:add_radix_map(mapline[, description])
 * Creates new dynamic map of IP/mask addresses.
 * @param {string} mapline URL for a map
 * @param {string} description optional map description
 * @return {map} radix tree object
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

/***
 * @method rspamd_config:radix_from_config(mname, optname)
 * Creates new embedded map of IP/mask addresses from config.
 * @param {string} mname name of module
 * @param {string} optname option to get
 * @return {map} radix tree object
 * @example
local ip_map = rspamd_config:radix_from_config ('mymodule', 'ips')
...
local function foo(task)
	local ip = task:get_from_ip()
	if ip_map:get_key(ip) then
		return true
	end
	return false
end
 */
/***
 * @method rspamd_config:add_hash_map(mapline[, description])
 * Creates new dynamic map string objects.
 * @param {string} mapline URL for a map
 * @param {string} description optional map description
 * @return {map} hash set object
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
/***
 * @method rspamd_config:add_kv_map(mapline[, description])
 * Creates new dynamic map of key/values associations.
 * @param {string} mapline URL for a map
 * @param {string} description optional map description
 * @return {map} hash table object
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
/***
 * @method rspamd_config:add_map({args})
 * Creates new dynamic map according to the attributes passed.
 *
 * - `type`: type of map to be created, can be one of the following set:
 *   + `set`: set of strings
 *   + `radix`: map of IP addresses to strings
 *   + `map`: map of strings to strings
 *   + `regexp`: map of regexps to strings
 *   + `callback`: map processed by lua callback
 * - `url`: url to load map from
 * - `description`: map's description
 * - `callback`: lua callback for the map
 *
 * @return {map} `true` if map has been added
 * @example

local str = ''
local function process_map(in)
	str = in
end

rspamd_config:add_map('http://example.com/map', "settings map", process_map)
 */
/***
 * @method rspamd_config:get_classifier(name)
 * Returns classifier config.
 * @param {string} name name of classifier (e.g. `bayes`)
 * @return {classifier} classifier object or `nil`
 */
LUA_FUNCTION_DEF (config, get_classifier);
/***
 * @method rspamd_config:register_symbol(table)
 * Register symbol of a specified type in rspamd. This function accepts table of arguments:
 *
 * - `name`: name of symbol (can be missing for callback symbols)
 * - `callback`: function to be called for symbol's check (can be absent for virtual symbols)
 * - `weight`: weight of symbol (should normally be 1 or missing)
 * - `priority`: priority of symbol (normally 0 or missing)
 * - `type`: type of symbol: `normal` (default), `virtual` or `callback`
 * - `flags`: various flags splitted by commas or spaces:
 *     + `nice` if symbol can produce negative score;
 *     + `empty` if symbol can be called for empty messages
 *     + `skip` if symbol should be skipped now
 * - `parent`: id of parent symbol (useful for virtual symbols)
 *
 * @return {number} id of symbol registered
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
 *
 * **This method is deprecated and should not be used in newly written code **
 * @param {string} virtual name symbol's name
 * @param {number} weight initial weight of symbol (can be less than zero to specify non-spam symbols)
 */
LUA_FUNCTION_DEF (config, register_virtual_symbol);
/***
 * @method rspamd_config:register_callback_symbol(name, weight, callback)
 * Register callback function to be called for a specified symbol with initial weight. Symbol itself is
 * not registered in the metric and is not intended to be visible by a user.
 *
 * **This method is deprecated and should not be used in newly written code **
 * @param {string} name symbol's name (just for unique id purposes)
 * @param {number} weight initial weight of symbol (can be less than zero to specify non-spam symbols)
 * @param {function} callback callback function to be called for a specified symbol
 */
LUA_FUNCTION_DEF (config, register_callback_symbol);
LUA_FUNCTION_DEF (config, register_callback_symbol_priority);

/***
 * @method rspamd_config:register_dependency(id, dep)
 * Create a dependency between symbol identified by `id` and a symbol identified
 * by some symbolic name `dep`
 * @param {number|string} id id or name of source (numeric id is returned by all register_*_symbol)
 * @param {string} dep dependency name
 * @example
local function cb(task)
...
end

local id = rspamd_config:register_symbol('SYM', 1.0, cb)
rspamd_config:register_dependency(id, 'OTHER_SYM')
-- Alternative form
rspamd_config:register_dependency('SYMBOL_FROM', 'SYMBOL_TO')
 */
LUA_FUNCTION_DEF (config, register_dependency);

/**
 * @method rspamd_config:set_metric_symbol({table})
 * Set the value of a specified symbol in a metric. This function accepts table with the following elements:
 *
 * - `name`: name of symbol (string)
 * - `score`: score for symbol (number)
 * - `metric`: name of metric (string, optional)
 * - `description`: description of symbol (string, optional)
 * - `group`: name of group for symbol (string, optional)
 * - `one_shot`: turn off multiple hits for a symbol (boolean, optional)
 * - `flags`: comma separated string of flags:
 *    + `ignore`: do not strictly check validity of symbol and corresponding rule
 *    + `one_shot`: turn off multiple hits for a symbol
 * - `priority`: priority of symbol's definition
 */
LUA_FUNCTION_DEF (config, set_metric_symbol);

/**
 * @method rspamd_config:set_metric_action({table})
 * Set the score of a specified action in a metric. This function accepts table with the following elements:
 *
 * - `action`: name of action (string)
 * - `score`: score for action (number)
 * - `metric`: name of metric (string, optional)
 * - `priority`: priority of symbol's definition
 */
LUA_FUNCTION_DEF (config, set_metric_action);

/**
 * @method rspamd_config:add_composite(name, expression)
 * @param {string} name name of composite symbol
 * @param {string} expression symbolic expression of the composite rule
 * @return {bool} true if a composite has been added successfully
 */
LUA_FUNCTION_DEF (config, add_composite);
/***
 * @method rspamd_config:register_pre_filter(callback[, order])
 * Register function to be called prior to symbols processing.
 * @param {function} callback callback function
 * @param {number} order filters are called from lower orders to higher orders, order is equal to 0 by default
 * @example
local function check_function(task)
	-- It is possible to manipulate the task object here: set settings, set pre-action and so on
	...
end

rspamd_config:register_pre_filter(check_function)
 */
LUA_FUNCTION_DEF (config, register_pre_filter);
/***
 * @method rspamd_config:register_post_filter(callback[, order])
 * Register function to be called after symbols are processed.
 *
 * @param {function} callback callback function
 * @param {number} order filters are called from lower orders to higher orders, order is equal to 0 by default
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
 * @method rspamd_config:add_condition(symbol, condition)
 * Adds condition callback for specified symbol
 * @param {string} symbol symbol's name
 * @param {function} condition condition callback
 * @return {boolean} true if condition has been added
 * @example

rspamd_config:add_condition('FUZZY_DENIED', function(task)
  if some_map:find_key(task:get_from()) then return false end
  return true
end)
 */
LUA_FUNCTION_DEF (config, add_condition);

/***
 * @method rspamd_config:__newindex(name, callback)
 * This metamethod is called if new indicies are added to the `rspamd_config` object.
 * Technically, it is the equialent of @see rspamd_config:register_symbol where `weight` is 1.0.
 * There is also table form invocation that allows to control more things:
 *
 * - `callback`: has the same meaning and acts as function of task
 * - `score`: default score for a symbol
 * - `group`: default group for a symbol
 * - `description`: default symbol's description
 * - `priority`: additional priority value
 * - `one_shot`: default value for one shot attribute
 * - `condition`: function of task that can enable or disable this specific rule's execution
 * @param {string} name index name
 * @param {function/table} callback callback to be called
 * @return {number} id of the new symbol added
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

rspamd_config.SYMBOL = {
	callback = function(task)
 	...
 	end,
 	score = 5.1,
 	description = 'sample symbol',
 	group = 'sample symbols',
 	condition = function(task)
 		if task:get_from()[1]['addr'] == 'user@example.com' then
 			return false
 		end
 		return true
 	end
}
 */
LUA_FUNCTION_DEF (config, newindex);

/***
 * @method rspamd_config:register_regexp(params)
 * Registers new re for further cached usage
 * Params is the table with the follwoing fields (mandatory fields are marked with `*`):
 * - `re`* : regular expression object
 * - `type`*: type of regular expression:
 *   + `mime`: mime regexp
 *   + `rawmime`: raw mime regexp
 *   + `header`: header regexp
 *   + `rawheader`: raw header expression
 *   + `body`: raw body regexp
 *   + `url`: url regexp
 * - `header`: for header and rawheader regexp means the name of header
 * - `pcre_only`: flag regexp as pcre only regexp
 */
LUA_FUNCTION_DEF (config, register_regexp);

/***
 * @method rspamd_config:replace_regexp(params)
 * Replaces regexp with a new one
 * Params is the table with the follwoing fields (mandatory fields are marked with `*`):
 * - `old_re`* : old regular expression object (must be in the cache)
 * - `new_re`* : old regular expression object (must not be in the cache)
 */
LUA_FUNCTION_DEF (config, replace_regexp);

/***
 * @method rspamd_config:register_worker_script(worker_type, script)
 * Registers the following script for workers of a specified type. The exact type
 * of script function depends on worker type
 * @param {string} worker_type worker type (e.g. "normal")
 * @param {function} script script for a worker
 * @return {boolean} `true` if a script has been registered
 */
LUA_FUNCTION_DEF (config, register_worker_script);

/***
 * @method rspamd_config:add_on_load(function(cfg) ... end)
 * Registers the following script to be executed when configuration is completely loaded
 * @param {function} script function to be executed
 */
LUA_FUNCTION_DEF (config, add_on_load);

/***
 * @method rspamd_config:get_symbols_count()
 * Returns number of symbols registered in rspamd configuration
 * @return {number} number of symbols registered in the configuration
 */
LUA_FUNCTION_DEF (config, get_symbols_count);

/***
 * @method rspamd_config:get_symbol_callback(name)
 * Returns callback function for the specified symbol if it is a lua registered callback
 * @return {function} callback function or nil
 */
LUA_FUNCTION_DEF (config, get_symbol_callback);

/***
 * @method rspamd_config:set_symbol_callback(name, callback)
 * Sets callback for the specified symbol
 * @return {boolean} true if function has been replaced
 */
LUA_FUNCTION_DEF (config, set_symbol_callback);

static const struct luaL_reg configlib_m[] = {
	LUA_INTERFACE_DEF (config, get_module_opt),
	LUA_INTERFACE_DEF (config, get_mempool),
	LUA_INTERFACE_DEF (config, get_all_opt),
	LUA_INTERFACE_DEF (config, add_radix_map),
	LUA_INTERFACE_DEF (config, radix_from_config),
	LUA_INTERFACE_DEF (config, add_hash_map),
	LUA_INTERFACE_DEF (config, add_kv_map),
	LUA_INTERFACE_DEF (config, add_map),
	LUA_INTERFACE_DEF (config, get_classifier),
	LUA_INTERFACE_DEF (config, register_symbol),
	LUA_INTERFACE_DEF (config, register_symbols),
	LUA_INTERFACE_DEF (config, register_virtual_symbol),
	LUA_INTERFACE_DEF (config, register_callback_symbol),
	LUA_INTERFACE_DEF (config, register_callback_symbol_priority),
	LUA_INTERFACE_DEF (config, register_dependency),
	LUA_INTERFACE_DEF (config, set_metric_symbol),
	LUA_INTERFACE_DEF (config, set_metric_action),
	LUA_INTERFACE_DEF (config, add_composite),
	LUA_INTERFACE_DEF (config, register_module_option),
	LUA_INTERFACE_DEF (config, register_pre_filter),
	LUA_INTERFACE_DEF (config, register_post_filter),
	LUA_INTERFACE_DEF (config, get_api_version),
	LUA_INTERFACE_DEF (config, get_key),
	LUA_INTERFACE_DEF (config, add_condition),
	LUA_INTERFACE_DEF (config, register_regexp),
	LUA_INTERFACE_DEF (config, replace_regexp),
	LUA_INTERFACE_DEF (config, register_worker_script),
	LUA_INTERFACE_DEF (config, add_on_load),
	LUA_INTERFACE_DEF (config, get_symbols_count),
	LUA_INTERFACE_DEF (config, get_symbol_callback),
	LUA_INTERFACE_DEF (config, set_symbol_callback),
	{"__tostring", rspamd_lua_class_tostring},
	{"__newindex", lua_config_newindex},
	{NULL, NULL}
};

static const guint64 rspamd_lua_callback_magic = 0x32c118af1e3263c7ULL;

struct rspamd_config *
lua_check_config (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{config}");
	luaL_argcheck (L, ud != NULL, pos, "'config' expected");
	return ud ? *((struct rspamd_config **)ud) : NULL;
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
	struct rspamd_config *cfg = lua_check_config (L, 1);
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
	struct rspamd_config *cfg = lua_check_config (L, 1);

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
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *mname;
	const ucl_object_t *obj, *cur, *cur_elt;
	ucl_object_iter_t it = NULL;
	gint i;

	if (cfg) {
		mname = luaL_checkstring (L, 2);

		if (mname) {
			obj = ucl_obj_get_key (cfg->rcl_obj, mname);
			/* Flatten object */
			if (obj != NULL && (ucl_object_type (obj) == UCL_OBJECT ||
					ucl_object_type (obj) == UCL_ARRAY)) {

				lua_newtable (L);
				it = ucl_object_iterate_new (obj);

				LL_FOREACH (obj, cur) {
					it = ucl_object_iterate_reset (it, cur);

					while ((cur_elt = ucl_object_iterate_safe (it, true))) {
						lua_pushstring (L, ucl_object_key (cur_elt));
						ucl_object_push_lua (L, cur_elt, true);
						lua_settable (L, -3);
					}
				}

				ucl_object_iterate_free (it);

				return 1;
			}
			else if (obj != NULL) {
				lua_newtable (L);
				i = 1;

				LL_FOREACH (obj, cur) {
					lua_pushnumber (L, i++);
					ucl_object_push_lua (L, cur, true);
					lua_settable (L, -3);
				}

				return 1;
			}
		}
	}
	lua_pushnil (L);

	return 1;
}


static gint
lua_config_get_classifier (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
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
	guint64 magic;
	lua_State *L;
	gchar *symbol;

	union {
		gchar *name;
		gint ref;
	} callback;
	gboolean cb_is_ref;
	gint order;
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

static gint
lua_config_register_module_option (lua_State *L)
{
	return 0;
}

static gint
rspamd_compare_order_func (gconstpointer a, gconstpointer b)
{
	const struct lua_callback_data *cb1 = a, *cb2 = b;

	/* order of call goes from lower to higher */
	return cb2->order - cb1->order;
}

static void
lua_metric_symbol_callback (struct rspamd_task *task, gpointer ud)
{
	struct lua_callback_data *cd = ud;
	struct rspamd_task **ptask;
	gint level = lua_gettop (cd->L), nresults, err_idx;
	lua_State *L = cd->L;
	GString *tb;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	level ++;

	if (cd->cb_is_ref) {
		lua_rawgeti (L, LUA_REGISTRYINDEX, cd->callback.ref);
	}
	else {
		lua_getglobal (L, cd->callback.name);
	}

	ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;

	if (lua_pcall (L, 1, LUA_MULTRET, err_idx) != 0) {
		tb = lua_touserdata (L, -1);
		msg_err_task ("call to (%s) failed: %v", cd->symbol, tb);
		g_string_free (tb, TRUE);
		lua_pop (L, 1);
	}
	else {
		nresults = lua_gettop (L) - level;

		if (nresults >= 1) {
			/* Function returned boolean, so maybe we need to insert result? */
			gint res = 0;
			GList *opts = NULL;
			gint i;
			gdouble flag = 1.0;

			if (lua_type (cd->L, level + 1) == LUA_TBOOLEAN) {
				res = lua_toboolean (L, level + 1);
			}
			else {
				res = lua_tonumber (L, level + 1);
			}

			if (res) {
				gint first_opt = 2;

				if (lua_type (L, level + 2) == LUA_TNUMBER) {
					flag = lua_tonumber (L, level + 2);
					/* Shift opt index */
					first_opt = 3;
				}
				else {
					flag = res;
				}

				for (i = lua_gettop (L); i >= level + first_opt; i--) {
					if (lua_type (L, i) == LUA_TSTRING) {
						const char *opt = lua_tostring (L, i);

						opts = g_list_prepend (opts,
								rspamd_mempool_strdup (task->task_pool,
										opt));
					}
				}

				rspamd_task_insert_result (task, cd->symbol, flag, opts);
			}

			lua_pop (L, nresults);
		}
	}

	lua_pop (L, 1); /* Error function */
}

static gint
rspamd_register_symbol_fromlua (lua_State *L,
		struct rspamd_config *cfg,
		const gchar *name,
		gint ref,
		gdouble weight,
		gint priority,
		enum rspamd_symbol_type type,
		gint parent,
		gboolean optional)
{
	struct lua_callback_data *cd;
	gint ret = -1;

	cd = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct lua_callback_data));
	cd->magic = rspamd_lua_callback_magic;
	cd->cb_is_ref = TRUE;
	cd->callback.ref = ref;
	cd->L = L;
	cd->symbol = rspamd_mempool_strdup (cfg->cfg_pool, name);

	if (priority == 0 && weight < 0) {
		priority = 1;
	}

	if ((ret = rspamd_symbols_cache_find_symbol (cfg->cache, name)) != -1) {
		if (optional) {
			msg_debug_config ("duplicate symbol: %s, skip registering", name);

			return ret;
		}
		else {
			msg_err_config ("duplicate symbol: %s, skip registering", name);

			return -1;
		}
	}

	if (ref != -1) {
		ret = rspamd_symbols_cache_add_symbol (cfg->cache,
				name,
				priority,
				lua_metric_symbol_callback,
				cd,
				type,
				parent);
	}
	else {
		ret = rspamd_symbols_cache_add_symbol (cfg->cache,
				name,
				priority,
				NULL,
				cd,
				type,
				parent);
	}
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)lua_destroy_cfg_symbol,
			cd);

	return ret;
}

static gint
lua_config_register_post_filter (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	gint order = 0, cbref, ret;

	if (cfg) {
		if (lua_type (L, 3) == LUA_TNUMBER) {
			order = lua_tonumber (L, 3);
		}

		if (lua_type (L, 2) == LUA_TFUNCTION) {
			lua_pushvalue (L, 2);
			/* Get a reference */
			cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		}
		else {
			return luaL_error (L, "invalid type for callback: %s",
					lua_typename (L, lua_type (L, 2)));
		}

		msg_warn_config ("register_post_filter function is deprecated, "
				"use register_symbol instead");

		ret = rspamd_register_symbol_fromlua (L,
				cfg,
				NULL,
				cbref,
				1.0,
				order,
				SYMBOL_TYPE_POSTFILTER|SYMBOL_TYPE_CALLBACK,
				-1,
				FALSE);

		lua_pushboolean (L, ret);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_register_pre_filter (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	gint order = 0, cbref, ret;

	if (cfg) {
		if (lua_type (L, 3) == LUA_TNUMBER) {
			order = lua_tonumber (L, 3);
		}

		if (lua_type (L, 2) == LUA_TFUNCTION) {
			lua_pushvalue (L, 2);
			/* Get a reference */
			cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		}
		else {
			return luaL_error (L, "invalid type for callback: %s",
					lua_typename (L, lua_type (L, 2)));
		}

		msg_warn_config ("register_pre_filter function is deprecated, "
				"use register_symbol instead");

		ret = rspamd_register_symbol_fromlua (L,
				cfg,
				NULL,
				cbref,
				1.0,
				order,
				SYMBOL_TYPE_PREFILTER|SYMBOL_TYPE_CALLBACK,
				-1,
				FALSE);

		lua_pushboolean (L, ret);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_get_key (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name;
	size_t namelen;
	const ucl_object_t *val;

	name = luaL_checklstring(L, 2, &namelen);
	if (name && cfg) {
		val = ucl_object_lookup_len(cfg->rcl_obj, name, namelen);
		if (val != NULL) {
			ucl_object_push_lua (L, val, val->type != UCL_ARRAY);
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

static gint
lua_parse_symbol_type (const gchar *str)
{
	gint ret = SYMBOL_TYPE_NORMAL;

	if (str) {
		if (strcmp (str, "virtual") == 0) {
			ret = SYMBOL_TYPE_VIRTUAL;
		}
		else if (strcmp (str, "callback") == 0) {
			ret = SYMBOL_TYPE_CALLBACK;
		}
		else if (strcmp (str, "normal") == 0) {
			ret = SYMBOL_TYPE_NORMAL;
		}
		else if (strcmp (str, "prefilter") == 0) {
			ret = SYMBOL_TYPE_PREFILTER|SYMBOL_TYPE_GHOST;
		}
		else if (strcmp (str, "postfilter") == 0) {
			ret = SYMBOL_TYPE_POSTFILTER|SYMBOL_TYPE_GHOST;
		}
		else {
			msg_warn ("bad type: %s", str);
		}
	}

	return ret;
}

static gint
lua_parse_symbol_flags (const gchar *str)
{
	int ret = 0;

	if (str) {
		if (strstr (str, "fine") != NULL) {
			ret |= SYMBOL_TYPE_FINE;
		}
		if (strstr (str, "nice") != NULL) {
			ret |= SYMBOL_TYPE_FINE;
		}
		if (strstr (str, "empty") != NULL) {
			ret |= SYMBOL_TYPE_EMPTY;
		}
		if (strstr (str, "skip") != NULL) {
			ret |= SYMBOL_TYPE_SKIPPED;
		}
	}

	return ret;
}

static gint
lua_config_register_symbol (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = NULL, *flags_str = NULL, *type_str = NULL;
	double weight = 0;
	gint ret = -1, cbref = -1, type;
	gint64 parent = 0, priority = 0;
	GError *err = NULL;

	if (cfg) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				"name=S;weigth=N;callback=F;flags=S;type=S;priority=I;parent=I",
				&name, &weight, &cbref, &flags_str, &type_str,
				&priority, &parent)) {
			msg_err_config ("bad arguments: %e", err);
			g_error_free (err);

			return luaL_error (L, "invalid arguments");
		}

		type = lua_parse_symbol_type (type_str);

		if (!name && !(type & SYMBOL_TYPE_CALLBACK)) {
			return luaL_error (L, "no symbol name but type is not callback");
		}
		else if (!(type & SYMBOL_TYPE_VIRTUAL) && cbref == -1) {
			return luaL_error (L, "no callback for symbol %s", name);
		}

		type |= lua_parse_symbol_flags (flags_str);

		ret = rspamd_register_symbol_fromlua (L,
				cfg,
				name,
				cbref,
				weight == 0 ? 1.0 : weight,
				priority,
				type,
				parent == 0 ? -1 : parent,
				FALSE);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushnumber (L, ret);

	return 1;
}

static gint
lua_config_register_symbols (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	gint i, top, idx, ret = -1;
	const gchar *sym;
	gdouble weight = 1.0;

	if (lua_gettop (L) < 3) {
		if (cfg) {
			msg_err_config ("not enough arguments to register a function");
		}

		lua_error (L);

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
		sym = luaL_checkstring (L, top ++);
		ret = rspamd_register_symbol_fromlua (L,
				cfg,
				sym,
				idx,
				weight,
				0,
				SYMBOL_TYPE_CALLBACK,
				-1,
				FALSE);

		for (i = top; i <= lua_gettop (L); i++) {
			if (lua_type (L, i) == LUA_TTABLE) {
				lua_pushvalue (L, i);
				lua_pushnil (L);
				while (lua_next (L, -2)) {
					lua_pushvalue (L, -2);
					sym = luaL_checkstring (L, -2);
					rspamd_symbols_cache_add_symbol (cfg->cache, sym,
							0, NULL, NULL,
							SYMBOL_TYPE_VIRTUAL, ret);
					lua_pop (L, 2);
				}
				lua_pop (L, 1);
			}
			else if (lua_type (L, i) == LUA_TSTRING) {
				sym = luaL_checkstring (L, i);
				rspamd_symbols_cache_add_symbol (cfg->cache, sym,
						0, NULL, NULL,
						SYMBOL_TYPE_VIRTUAL, ret);
			}
		}
	}

	lua_pushnumber (L, ret);

	return 1;
}

static gint
lua_config_register_virtual_symbol (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name;
	double weight;
	gint ret = -1, parent = -1;

	if (cfg) {
		name = luaL_checkstring (L, 2);
		weight = luaL_checknumber (L, 3);

		if (lua_gettop (L) > 3) {
			parent = lua_tonumber (L, 4);
		}

		if (name) {
			ret = rspamd_symbols_cache_add_symbol (cfg->cache, name,
					weight > 0 ? 0 : -1, NULL, NULL,
					SYMBOL_TYPE_VIRTUAL, parent);
		}
	}

	lua_pushnumber (L, ret);

	return 1;
}

static gint
lua_config_register_callback_symbol (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = NULL;
	double weight;
	gint ret = -1, top = 2;

	if (cfg) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			/* Legacy syntax */
			name = luaL_checkstring (L, 2);
			top ++;
		}

		weight = luaL_checknumber (L, top);

		if (lua_type (L, top + 1) == LUA_TSTRING) {
			lua_getglobal (L, luaL_checkstring (L, top + 1));
		}
		else {
			lua_pushvalue (L, top + 1);
		}
		ret = rspamd_register_symbol_fromlua (L,
				cfg,
				name,
				luaL_ref (L, LUA_REGISTRYINDEX),
				weight,
				0,
				SYMBOL_TYPE_CALLBACK,
				-1,
				FALSE);
	}

	lua_pushnumber (L, ret);

	return 1;
}

static gint
lua_config_register_callback_symbol_priority (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = NULL;
	double weight;
	gint priority, ret = -1, top = 2;

	if (cfg) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			/* Legacy syntax */
			name = luaL_checkstring (L, 2);
			top ++;
		}

		weight = luaL_checknumber (L, top);
		priority = luaL_checknumber (L, top + 1);

		if (lua_type (L, top + 2) == LUA_TSTRING) {
			lua_getglobal (L, luaL_checkstring (L, top + 2));
		}
		else {
			lua_pushvalue (L, top + 2);
		}

		ret = rspamd_register_symbol_fromlua (L,
				cfg,
				name,
				luaL_ref (L, LUA_REGISTRYINDEX),
				weight,
				priority,
				SYMBOL_TYPE_CALLBACK,
				-1,
				FALSE);
	}

	lua_pushnumber (L, ret);

	return 1;
}

static gint
lua_config_register_dependency (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = NULL, *from = NULL;
	gint id;

	if (cfg == NULL) {
		lua_error (L);
		return 0;
	}

	if (lua_type (L, 2) == LUA_TNUMBER) {
		id = luaL_checknumber (L, 2);
		name = luaL_checkstring (L, 3);

		if (id > 0 && name != NULL) {
			rspamd_symbols_cache_add_dependency (cfg->cache, id, name);
		}
	}
	else {
		from = luaL_checkstring (L,2);
		name = luaL_checkstring (L, 3);

		if (from != NULL && name != NULL) {
			rspamd_symbols_cache_add_delayed_dependency (cfg->cache, from, name);
		}
	}

	return 0;
}

static gint
lua_config_set_metric_symbol (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *metric_name = DEFAULT_METRIC, *description = NULL,
			*group = NULL, *name = NULL, *flags_str = NULL;
	double weight;
	struct metric *metric;
	gboolean one_shot = FALSE;
	GError *err = NULL;
	gdouble priority = 0.0;
	guint flags = 0;

	if (cfg) {

		if (lua_type (L, 2) == LUA_TTABLE) {
			if (!rspamd_lua_parse_table_arguments (L, 2, &err,
					"*name=S;score=N;description=S;"
					"group=S;one_shot=B;metric=S;priority=N;flags=S",
					&name, &weight, &description,
					&group, &one_shot, &metric_name, &priority, &flags_str)) {
				msg_err_config ("bad arguments: %e", err);
				g_error_free (err);

				return 0;
			}
		}
		else {
			name = luaL_checkstring (L, 2);
			weight = luaL_checknumber (L, 3);

			if (lua_gettop (L) > 3 && lua_type (L, 4) == LUA_TSTRING) {
				description = luaL_checkstring (L, 4);
			}
			if (lua_gettop (L) > 4 && lua_type (L, 5) == LUA_TSTRING) {
				metric_name = luaL_checkstring (L, 5);
			}
			if (lua_gettop (L) > 5 && lua_type (L, 6) == LUA_TSTRING) {
				group = luaL_checkstring (L, 6);
			}
			if (lua_gettop (L) > 6 && lua_type (L, 7) == LUA_TBOOLEAN) {
				one_shot = lua_toboolean (L, 7);
			}
		}

		if (metric_name == NULL) {
			metric_name = DEFAULT_METRIC;
		}

		metric = g_hash_table_lookup (cfg->metrics, metric_name);
		if (one_shot) {
			flags |= RSPAMD_SYMBOL_FLAG_ONESHOT;
		}

		if (flags_str) {
			if (strstr (flags_str, "one_shot") != NULL) {
				flags |= RSPAMD_SYMBOL_FLAG_ONESHOT;
			}
			else if (strstr (flags_str, "ignore") != NULL) {
				flags |= RSPAMD_SYMBOL_FLAG_IGNORE;
			}
		}

		if (metric == NULL) {
			msg_err_config ("metric named %s is not defined", metric_name);
		}
		else if (name != NULL && weight != 0) {
			rspamd_config_add_metric_symbol (cfg, metric_name, name,
					weight, description, group, flags, (guint)priority);
		}
	}
	else {
		return luaL_error (L, "invalid arguments, rspamd_config expected");
	}

	return 0;
}

static gint
lua_config_set_metric_action (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *metric_name = DEFAULT_METRIC, *name = NULL, *flags_str = NULL;
	double weight;
	struct metric *metric;
	GError *err = NULL;
	gdouble priority = 0.0;

	if (cfg) {

		if (lua_type (L, 2) == LUA_TTABLE) {
			if (!rspamd_lua_parse_table_arguments (L, 2, &err,
					"*action=S;score=N;"
					"metric=S;priority=N",
					&name, &weight,
					&metric_name, &priority, &flags_str)) {
				msg_err_config ("bad arguments: %e", err);
				g_error_free (err);

				return 0;
			}
		}
		else {
			return luaL_error (L, "invalid arguments, table expected");
		}

		if (metric_name == NULL) {
			metric_name = DEFAULT_METRIC;
		}

		metric = g_hash_table_lookup (cfg->metrics, metric_name);

		if (metric == NULL) {
			msg_err_config ("metric named %s is not defined", metric_name);
		}
		else if (name != NULL && weight != 0) {
			rspamd_config_set_action_score (cfg, metric_name, name,
					weight, (guint)priority);
		}
	}
	else {
		return luaL_error (L, "invalid arguments, rspamd_config expected");
	}

	return 0;
}


static gint
lua_config_add_composite (lua_State * L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_expression *expr;
	gchar *name;
	const gchar *expr_str;
	struct rspamd_composite *composite;
	gboolean ret = FALSE, new = TRUE;
	GError *err = NULL;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		expr_str = luaL_checkstring (L, 3);

		if (name && expr_str) {
			if (!rspamd_parse_expression (expr_str, 0, &composite_expr_subr,
					NULL, cfg->cfg_pool, &err, &expr)) {
				msg_err_config ("cannot parse composite expression %s: %e",
						expr_str,
						err);
				g_error_free (err);
			}
			else {
				if (g_hash_table_lookup (cfg->composite_symbols, name) != NULL) {
					msg_warn_config ("composite %s is redefined", name);
					new = FALSE;
				}
				composite = rspamd_mempool_alloc (cfg->cfg_pool,
						sizeof (struct rspamd_composite));
				composite->expr = expr;
				composite->id = g_hash_table_size (cfg->composite_symbols);
				g_hash_table_insert (cfg->composite_symbols,
						(gpointer)name,
						composite);

				if (new) {
					rspamd_symbols_cache_add_symbol (cfg->cache, name,
							0, NULL, NULL, SYMBOL_TYPE_COMPOSITE, -1);
				}

				ret = TRUE;
			}
		}
	}

	lua_pushboolean (L, ret);

	return 1;
}

static gint
lua_config_newindex (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name;
	gint id;
	gboolean optional = FALSE;

	name = luaL_checkstring (L, 2);

	if (cfg != NULL && name != NULL && lua_gettop (L) > 2) {
		if (lua_type (L, 3) == LUA_TFUNCTION) {
			/* Normal symbol from just a function */
			lua_pushvalue (L, 3);
			rspamd_register_symbol_fromlua (L,
					cfg,
					name,
					luaL_ref (L, LUA_REGISTRYINDEX),
					1.0,
					0,
					SYMBOL_TYPE_NORMAL,
					-1,
					FALSE);
		}
		else if (lua_type (L, 3) == LUA_TTABLE) {
			gint type = SYMBOL_TYPE_NORMAL, priority = 0, idx;
			gdouble weight = 1.0, score;
			const char *type_str, *group = NULL, *description = NULL;
			guint flags = 0;

			/*
			 * Table can have the following attributes:
			 * "callback" - should be a callback function
			 * "weight" - optional weight
			 * "priority" - optional priority
			 * "type" - optional type (normal, virtual, callback)
			 * -- Metric options
			 * "score" - optional default score (overrided by metric)
			 * "group" - optional default group
			 * "one_shot" - optional one shot mode
			 * "description" - optional description
			 */
			lua_pushvalue (L, 3);
			lua_pushstring (L, "callback");
			lua_gettable (L, -2);

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				lua_pop (L, 2);
				msg_info_config ("cannot find callback definition for %s",
						name);
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

			lua_pushstring (L, "optional");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TBOOLEAN) {
				optional = lua_toboolean (L, -1);
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
					msg_info_config ("unknown type: %s", type_str);
				}

			}
			lua_pop (L, 1);

			id = rspamd_register_symbol_fromlua (L,
					cfg,
					name,
					idx,
					weight,
					priority,
					type,
					-1,
					optional);

			if (id != -1) {
				/* Check for condition */
				lua_pushstring (L, "condition");
				lua_gettable (L, -2);

				if (lua_type (L, -1) == LUA_TFUNCTION) {
					gint condref;

					/* Here we pop function from the stack, so no lua_pop is required */
					condref = luaL_ref (L, LUA_REGISTRYINDEX);
					rspamd_symbols_cache_add_condition (cfg->cache, id, L, condref);
				}
				else {
					lua_pop (L, 1);
				}
			}

			/*
			 * Now check if a symbol has not been registered in any metric and
			 * insert default value if applicable
			 */
			if (g_hash_table_lookup (cfg->metrics_symbols, name) == NULL) {
				lua_pushstring (L, "score");
				lua_gettable (L, -2);

				if (lua_type (L, -1) == LUA_TNUMBER) {
					score = lua_tonumber (L, -1);
					lua_pop (L, 1);

					/* If score defined, then we can check other metric fields */
					lua_pushstring (L, "group");
					lua_gettable (L, -2);

					if (lua_type (L, -1) == LUA_TSTRING) {
						group = lua_tostring (L, -1);
					}
					lua_pop (L, 1);

					lua_pushstring (L, "description");
					lua_gettable (L, -2);

					if (lua_type (L, -1) == LUA_TSTRING) {
						description = lua_tostring (L, -1);
					}
					lua_pop (L, 1);

					lua_pushstring (L, "one_shot");
					lua_gettable (L, -2);

					if (lua_type (L, -1) == LUA_TBOOLEAN) {
						if (lua_toboolean (L, -1)) {
							flags |= RSPAMD_SYMBOL_FLAG_ONESHOT;
						}
					}
					lua_pop (L, 1);

					/*
					 * Do not override the existing symbols (using zero priority),
					 * since we are defining default values here
					 */
					rspamd_config_add_metric_symbol (cfg, NULL, name, score,
							description, group, flags, 0);
				}
				else {
					lua_pop (L, 1);
				}
			}

			/* Remove table from stack */
			lua_pop (L, 1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_config_add_condition (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	gboolean ret = FALSE;
	gint condref;

	if (cfg && sym && lua_type (L, 3) == LUA_TFUNCTION) {
		lua_pushvalue (L, 3);
		condref = luaL_ref (L, LUA_REGISTRYINDEX);

		ret = rspamd_symbols_cache_add_condition_delayed (cfg->cache, sym, L,
				condref);

		if (!ret) {
			luaL_unref (L, LUA_REGISTRYINDEX, condref);
		}
	}

	lua_pushboolean (L, ret);
	return 1;
}

static gint
lua_config_register_regexp (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_lua_regexp *re = NULL;
	rspamd_regexp_t *cache_re;
	const gchar *type_str = NULL, *header_str = NULL;
	gsize header_len = 0;
	GError *err = NULL;
	enum rspamd_re_type type = RSPAMD_RE_BODY;
	gboolean pcre_only = FALSE;
	guint old_flags;

	/*
	 * - `re`* : regular expression object
 	 * - `type`*: type of regular expression:
	 *   + `mime`: mime regexp
	 *   + `rawmime`: raw mime regexp
	 *   + `header`: header regexp
	 *   + `rawheader`: raw header expression
	 *   + `body`: raw body regexp
	 *   + `url`: url regexp
	 * - `header`: for header and rawheader regexp means the name of header
	 * - `pcre_only`: allow merely pcre for this regexp
	 */
	if (cfg != NULL) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				"*re=U{regexp};*type=S;header=S;pcre_only=B",
				&re, &type_str, &header_str, &pcre_only)) {
			msg_err_config ("cannot get parameters list: %e", err);

			if (err) {
				g_error_free (err);
			}
		}
		else {
			type = rspamd_re_cache_type_from_string (type_str);

			if ((type == RSPAMD_RE_HEADER ||
					type == RSPAMD_RE_RAWHEADER ||
					type == RSPAMD_RE_MIMEHEADER) &&
					header_str == NULL) {
				msg_err_config (
						"header argument is mandatory for header/rawheader regexps");
			}
			else {
				if (pcre_only) {
					old_flags = rspamd_regexp_get_flags (re->re);
					old_flags |= RSPAMD_REGEXP_FLAG_PCRE_ONLY;
					rspamd_regexp_set_flags (re->re, old_flags);
				}

				if (header_str != NULL) {
					/* Include the last \0 */
					header_len = strlen (header_str) + 1;
				}

				cache_re = rspamd_re_cache_add (cfg->re_cache, re->re, type,
						(gpointer) header_str, header_len);

				/*
				 * XXX: here are dragons!
				 * Actually, lua regexp contains internal rspamd_regexp_t
				 * and it owns it.
				 * However, after this operation we have some OTHER regexp,
				 * which we really would like to use.
				 * So we do the following:
				 * 1) Remove old re and unref it
				 * 2) Replace the internal re with cached one
				 * 3) Increase its refcount to share ownership between cache and
				 *   lua object
				 */
				if (cache_re != re->re) {
					rspamd_regexp_unref (re->re);
					re->re = rspamd_regexp_ref (cache_re);
				}
			}
		}
	}

	return 0;
}

static gint
lua_config_replace_regexp (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_lua_regexp *old_re = NULL, *new_re = NULL;
	GError *err = NULL;

	if (cfg != NULL) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				"*old_re=U{regexp};*new_re=U{regexp}",
				&old_re, &new_re)) {
			msg_err_config ("cannot get parameters list: %e", err);

			if (err) {
				g_error_free (err);
			}
		}
		else {
			rspamd_re_cache_replace (cfg->re_cache, old_re->re, new_re->re);
		}
	}

	return 0;
}

static gint
lua_config_register_worker_script (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *worker_type = luaL_checkstring (L, 2), *wtype;
	struct rspamd_worker_conf *cf;
	GList *cur;
	struct rspamd_worker_lua_script *sc;
	gboolean found = FALSE;

	if (cfg == NULL || worker_type == NULL || lua_type (L, 3) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid arguments");
	}

	for (cur = g_list_first (cfg->workers); cur != NULL; cur = g_list_next (cur)) {
		cf = cur->data;

		wtype = g_quark_to_string (cf->type);

		if (g_ascii_strcasecmp (wtype, worker_type) == 0) {
			sc = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*sc));
			lua_pushvalue (L, 3);
			sc->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			DL_APPEND (cf->scripts, sc);
			found = TRUE;
		}
	}

	lua_pushboolean (L, found);

	return 1;
}

static gint
lua_config_add_on_load (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_config_post_load_script *sc;

	if (cfg == NULL || lua_type (L, 2) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid arguments");
	}

	sc = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*sc));
	lua_pushvalue (L, 2);
	sc->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	DL_APPEND (cfg->on_load, sc);

	return 0;
}

static gint
lua_config_get_symbols_count (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	guint res = 0;

	if (cfg != NULL) {
		res = rspamd_symbols_cache_symbols_count (cfg->cache);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushnumber (L, res);

	return 1;
}

static gint
lua_config_get_symbol_callback (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	struct rspamd_abstract_callback_data *abs_cbdata;
	struct lua_callback_data *cbd;

	if (cfg != NULL && sym != NULL) {
		abs_cbdata = rspamd_symbols_cache_get_cbdata (cfg->cache, sym);

		if (abs_cbdata == NULL || abs_cbdata->magic != rspamd_lua_callback_magic) {
			lua_pushnil (L);
		}
		else {
			cbd = (struct lua_callback_data *)abs_cbdata;

			if (cbd->cb_is_ref) {
				lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->callback.ref);
			}
			else {
				lua_getglobal (L, cbd->callback.name);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_set_symbol_callback (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	struct rspamd_abstract_callback_data *abs_cbdata;
	struct lua_callback_data *cbd;

	if (cfg != NULL && sym != NULL && lua_type (L, 3) == LUA_TFUNCTION) {
		abs_cbdata = rspamd_symbols_cache_get_cbdata (cfg->cache, sym);

		if (abs_cbdata == NULL || abs_cbdata->magic != rspamd_lua_callback_magic) {
			lua_pushboolean (L, FALSE);
		}
		else {
			cbd = (struct lua_callback_data *)abs_cbdata;

			if (cbd->cb_is_ref) {
				luaL_unref (L, LUA_REGISTRYINDEX, cbd->callback.ref);
			}
			else {
				cbd->cb_is_ref = TRUE;
			}

			lua_pushvalue (L, 3);
			cbd->callback.ref = luaL_ref (L, LUA_REGISTRYINDEX);
			lua_pushboolean (L, TRUE);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

void
luaopen_config (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{config}", configlib_m);

	lua_pop (L, 1);
}
