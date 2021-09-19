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
#include "src/libserver/composites/composites.h"
#include "libserver/cfg_file_private.h"
#include "libmime/lang_detection.h"
#include "lua/lua_map.h"
#include "lua/lua_thread_pool.h"
#include "utlist.h"
#include <math.h>

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
 * @method rspamd_config:get_ucl()
 * Returns full configuration as a native Lua object (ucl to lua conversion).
 * This method uses caching if possible.
 * @return {table} table of all options in the configuration
 */
LUA_FUNCTION_DEF (config, get_ucl);
/***
 * @method rspamd_config:get_mempool()
 * Returns static configuration memory pool.
 * @return {mempool} [memory pool](mempool.md) object
 */
LUA_FUNCTION_DEF (config, get_mempool);
/***
 * @method rspamd_config:get_resolver()
 * Returns DNS resolver.
 * @return {dns_resolver} opaque DNS resolver pointer if any
 */
LUA_FUNCTION_DEF (config, get_resolver);
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
* @method rspamd_config:radix_from_ucl(obj)
* Creates new embedded map of IP/mask addresses from object.
* @param {ucl} obj object
* @return {map} radix tree object
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
* @method rspamd_config:get_maps()
* Get all maps defined as an array of rspamd{map} objects
 *
* @return {table|rspamd{map}}
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
 * - `type`: type of symbol:
 *   + `normal`: executed after prefilters, according to dependency graph or in undefined order
 *   + `callback`: a check that merely inserts virtual symbols
 *   + `connfilter`: executed early; before message body is available
 *   + `idempotent`: cannot change result in any way; executed last
 *   + `postfilter`: executed after most other checks
 *   + `prefilter`: executed before most other checks
 *   + `virtual`: a symbol inserted by its parent check
 * - `flags`: various flags split by commas or spaces:
 *   + `nice` if symbol can produce negative score;
 *   + `empty` if symbol can be called for empty messages
 *   + `skip` if symbol should be skipped now
 *   + `nostat` if symbol should be excluded from stat tokens
 *   + `trivial` symbol is trivial (e.g. no network requests)
 *   + `explicit_disable` requires explicit disabling (e.g. via settings)
 *   + `ignore_passthrough` executed even if passthrough result has been set
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
 * @method rspamd_config:register_dependency(id|name, depname)
 * Create a dependency on symbol identified by name for symbol identified by ID or name.
 * This affects order of checks only (a symbol is still checked if its dependencys are disabled).
 * @param {number|string} id id or name of source (numeric id is returned by all register_*_symbol)
 * @param {string} depname dependency name
 * @example
local function cb(task)
...
end

local id = rspamd_config:register_symbol('SYM', 1.0, cb)
rspamd_config:register_dependency(id, 'OTHER_SYM')
-- Alternative form
-- Symbol MY_RULE needs result from SPF_CHECK
rspamd_config:register_dependency('MY_RULE', 'SPF_CHECK')
 */
LUA_FUNCTION_DEF (config, register_dependency);

/***
 * @method rspamd_config:get_symbol_flags(name)
 * Returns symbol flags
 * @param {string} name symbols's name
 * @return {table|string} list of flags for symbol or nil
 */
LUA_FUNCTION_DEF (config, get_symbol_flags);

/***
 * @method rspamd_config:add_symbol_flags(name, flags)
 * Adds flags to a symbol
 * @param {string} name symbols's name
 * @param {table|string} flags flags to add
 * @return {table|string} new set of flags
 */
LUA_FUNCTION_DEF (config, add_symbol_flags);

/**
 * @method rspamd_config:register_re_selector(name, selector_str, [delimiter, [flatten]])
 * Registers selector with the specific name to use in regular expressions in form
 * name=/re/$ or name=/re/{selector}
 * @param {string} name name of the selector
 * @param {string} selector_str selector definition
 * @param {string} delimiter delimiter to use when joining strings if flatten is false
 * @param {bool} flatten if true then selector will return a table of captures instead of a single string
 * @return true if selector has been registered
 */
LUA_FUNCTION_DEF (config, register_re_selector);

/**
 * @method rspamd_config:set_symbol({table})
 * Sets the value of a specified symbol in a metric. This function accepts table with the following elements:
 *
 * - `name`: name of symbol (string)
 * - `score`: score for symbol (number)
 * - `metric`: name of metric (string, optional)
 * - `description`: description of symbol (string, optional)
 * - `group`: name of group for symbol (string, optional)
 * - `one_shot`: turn off multiple hits for a symbol (boolean, optional)
 * - `one_param`: turn off multiple options for a symbol (boolean, optional)
 * - `flags`: comma separated string of flags:
 *   + `ignore`: do not strictly check validity of symbol and corresponding rule
 *   + `one_shot`: turn off multiple hits for a symbol
 *   + `one_param`: allow only one parameter for a symbol
 * - `priority`: priority of symbol's definition
 */
LUA_FUNCTION_DEF (config, set_metric_symbol);

/**
 * @method rspamd_config:set_action({table})
 * Sets the score of a specified action in a metric. This function accepts table with the following elements:
 *
 * - `action`: name of action (string)
 * - `score`: score for action (number)
 * - `metric`: name of metric (string, optional)
 * - `priority`: priority of action's definition
 */
LUA_FUNCTION_DEF (config, set_metric_action);

/**
 * @method rspamd_config:get_symbol(name)
 * Gets metric data for a specific symbol identified by `name`:
 *
 * - `score`: score for symbol (number)
 * - `description`: description of symbol (string, optional)
 * - `group`: name of group for symbol (string, optional)
 * - `one_shot`: turn off multiple hits for a symbol (boolean, optional)
 * - `flags`: comma separated string of flags:
 *   + `ignore`: do not strictly check validity of symbol and corresponding rule
 *   + `one_shot`: turn off multiple hits for a symbol
 *
 * @param {string} name name of symbol
 * @return {table} symbol's definition or nil in case of undefined symbol
 */
LUA_FUNCTION_DEF (config, get_metric_symbol);

/**
 * @method rspamd_config:get_action(name)
 * Gets data for a specific action in config. This function returns number reperesenting action's score
 *
 * @param {string} name name of action
 * @return {number} action's score or nil in case of undefined score or action
 */
LUA_FUNCTION_DEF (config, get_metric_action);

/**
 * @method rspamd_config:get_all_actions()
 * Gets data for all action in config
 * @return {table|str->num} action's score or nil in case of undefined score or action
 */
LUA_FUNCTION_DEF (config, get_all_actions);

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
 * @method rspamd_config:enable_symbol(symbol)
 * Enables execution for the specified symbol
 * @param {string} symbol symbol's name
 */
LUA_FUNCTION_DEF (config, enable_symbol);

/***
 * @method rspamd_config:disable_symbol(symbol, [disable_parent=true])
 * Disables execution for the specified symbol
 * @param {string} symbol symbol's name
 * @param {boolean} disable_parent if true then disable parent execution in case of a virtual symbol
 */
LUA_FUNCTION_DEF (config, disable_symbol);

/***
 * @method rspamd_config:get_symbol_parent(symbol)
 * Returns a parent symbol for specific symbol (or symbol itself if top level)
 * @param {string} symbol symbol's name
 */
LUA_FUNCTION_DEF (config, get_symbol_parent);

/***
 * @method rspamd_config:get_group_symbols(group)
 * Returns list of symbols for a specific group
 * @param {string} group group's name
 * @available 2.0+
 * @return {list|string} list of all symbols in a specific group
 */
LUA_FUNCTION_DEF (config, get_group_symbols);

/***
 * @method rspamd_config:get_groups([need_private])
 * Returns list of all groups defined
 * @param {boolean} need_private optional flag to include private groups
 * @available 2.3+
 * @return {list|table} list of all groups
 */
LUA_FUNCTION_DEF (config, get_groups);

/***
 * @method rspamd_config:register_settings_id(name, symbols_enabled, symbols_disabled)
 * Register new static settings id in config
 * @param {string} name id name (not numeric!)
 * @param {map|string->string} symbols_enabled map from symbol's name to boolean (currently)
 * @param {map|string->string} symbols_disabled map from symbol's name to boolean (currently)
 * @available 2.0+
 */
LUA_FUNCTION_DEF (config, register_settings_id);

/***
 * @method rspamd_config:__newindex(name, callback)
 * This metamethod is called if new indicies are added to the `rspamd_config` object.
 * Technically, it is the equivalent of @see rspamd_config:register_symbol where `weight` is 1.0.
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
 * Params is the table with the following fields (mandatory fields are marked with `*`):
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
 * Params is the table with the following fields (mandatory fields are marked with `*`):
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
 * @method rspamd_config:add_on_load(function(cfg, ev_base, worker) ... end)
 * Registers the following script to be executed when configuration is completely loaded
 * and the worker is already started (forked)
 * @param {function} script function to be executed
 * @example
rspamd_config:add_on_load(function(cfg, ev_base, worker)
	rspamd_config:add_periodic(ev_base, 1.0, function(cfg, ev_base)
		local logger = require "rspamd_logger"
		logger.infox(cfg, "periodic function in worker %s", worker:get_name())
		return true
	end)
end)
 */
LUA_FUNCTION_DEF (config, add_on_load);

/***
 * @method rspamd_config:add_periodic(event_base, timeout, function(cfg, ev_base) ... end, [jitter = false])
 * Registers function to be periodically executed by Rspamd
 * @param {ev_base} event_base event base that is needed for async events
 * @param {number} timeout time in seconds (could be fractional)
 * @param {function} script function to be executed
 * @param {boolean} jitter `true` if timeout jittering is needed
 * @example
rspamd_config:add_on_load(function(cfg, ev_base)
	rspamd_config:add_periodic(ev_base, 1.0, function(cfg, ev_base)
		local logger = require "rspamd_logger"
		logger.infox(cfg, "periodic function")
		return true -- if return numeric, a new interval is set. if return false, then the periodic event is removed
	end)
end)
 */
LUA_FUNCTION_DEF (config, add_periodic);

/***
 * @method rspamd_config:add_post_init(function(cfg) ... end)
 * Registers the following script to be executed when configuration is completely loaded
 * @available 2.0+
 * @param {function} script function to be executed
 */
LUA_FUNCTION_DEF (config, add_post_init);

/***
 * @method rspamd_config:add_config_unload(function(cfg) ... end)
 * Registers the following script to be executed when configuration is unloaded
 * @available 2.0+
 * @param {function} script function to be executed
 */
LUA_FUNCTION_DEF (config, add_config_unload);

/***
 * @method rspamd_config:get_symbols_count()
 * Returns number of symbols registered in rspamd configuration
 * @return {number} number of symbols registered in the configuration
 */
LUA_FUNCTION_DEF (config, get_symbols_count);

/***
 * @method rspamd_config:get_symbols_cksum()
 * Returns checksum for all symbols in the cache
 * @return {int64} boxed value of the 64 bit checksum
 */
LUA_FUNCTION_DEF (config, get_symbols_cksum);

/***
 * @method rspamd_config:get_symbols_counters()
 * Returns table of all counters in the cache (weights, frequencies etc)
 * @return {table|tables} all symbols indexed by name
 */
LUA_FUNCTION_DEF (config, get_symbols_counters);

/***
 * @method rspamd_config:get_symbols()
 * Returns table of all scores defined in config. From version 2.0 returns table:
 * - name
 * - score
 * - flags (e.g. `ignore` or `oneparam`)
 * - nshots (== maxhits)
 * - group - main group
 * - groups - array of all groups
 * @available 2.0+
 * @return {table|tables} all symbols indexed by name
 */
LUA_FUNCTION_DEF (config, get_symbols);

/***
 * @method rspamd_config:get_symbol_callback(name)
 * Returns callback function for the specified symbol if it is a lua registered callback
 * @return {function} callback function or nil
 */
LUA_FUNCTION_DEF (config, get_symbol_callback);

/***
 * @method rspamd_config:get_symbol_stat(name)
 * Returns table with statistics for a specific symbol:
 * - `frequency`: frequency for symbol's hits
 * - `stddev`: standard deviation of `frequency`
 * - `time`: average time in seconds (floating point)
 * - `count`: total number of hits
 * @return {table} symbol stats
 */
LUA_FUNCTION_DEF (config, get_symbol_stat);

/***
 * @method rspamd_config:set_symbol_callback(name, callback)
 * Sets callback for the specified symbol
 * @return {boolean} true if function has been replaced
 */
LUA_FUNCTION_DEF (config, set_symbol_callback);

/***
 * @method rspamd_config:register_finish_script(callback)
 * Adds new callback that is called on worker process termination when all
 * tasks pending are processed
 *
 * @param callback {function} a function with one argument (rspamd_task)
 */
LUA_FUNCTION_DEF (config, register_finish_script);

/***
 * @method rspamd_config:register_monitored(url, type, [{params}])
 * Registers monitored resource to watch its availability. Supported types:
 *
 * - `dns`: DNS monitored object
 *
 * Params are optional table specific for each type. For DNS it supports the
 * following options:
 *
 * - `prefix`: prefix to add before making request
 * - `type`: type of request (e.g. 'a' or 'txt')
 * - `ipnet`: array of ip/networks to expect on reply
 * - `rcode`: expected return code (e.g. `nxdomain`)
 *
 * Returned object has the following methods:
 *
 * - `alive`: returns `true` if monitored resource is alive
 * - `offline`: returns number of seconds of the current offline period (or 0 if alive)
 * - `total_offline`: returns number of seconds of the overall offline
 * - `latency`: returns the current average latency in seconds (or 0 if offline)
 *
 * @param {string} url resource to monitor
 * @param {string} type type of monitoring
 * @param {table} opts optional parameters
 * @return {rspamd_monitored} rspamd monitored object
 */
LUA_FUNCTION_DEF (config, register_monitored);

/***
 * @method rspamd_config:add_doc(path, option, doc_string, [{params}])
 * Adds new documentation string for an option `option` at path `path`
 * Options defines optional params, such as:
 *
 * - `default`: default option value
 * - `type`: type of an option (`string`, `number`, `object`, `array` etc)
 * - `reqired`: if an option is required
 *
 * @param {string} path documentation path (e.g. module name)
 * @param {string} option name of the option
 * @param {string} doc_string documentation string
 * @param {table} params optional parameters
 */
LUA_FUNCTION_DEF (config, add_doc);

/***
 * @method rspamd_config:add_example(path, option, doc_string, example)
 * Adds new documentation
 *
 * @param {string} path documentation path (e.g. module name or nil for top)
 * @param {string} option name of the option
 * @param {string} doc_string documentation string
 * @param {string} example example in ucl format, comments are also parsed
 */
LUA_FUNCTION_DEF (config, add_example);

/***
 * @method rspamd_config:set_peak_cb(function)
 * Sets a function that will be called when frequency of some symbol goes out of
 * stddev * 2 over the last period of refreshment.
 *
 * @example
rspamd_config:set_peak_cb(function(ev_base, sym, mean, stddev, value, error)
  -- ev_base: event base for async events (e.g. redis)
  -- sym: symbol's name
  -- mean: mean frequency value
  -- stddev: standard deviation of frequency
  -- value: current frequency value
  -- error: squared error
  local logger = require "rspamd_logger"
  logger.infox(rspamd_config, "symbol %s has changed frequency significantly: %s(%s) over %s(%s)",
      sym, value, error, mean, stddev)
end)
 */
LUA_FUNCTION_DEF (config, set_peak_cb);
/***
 *  @method rspamd_config:get_cpu_flags()
 * Returns architecture dependent flags supported by the CPU
 * Currently, only x86 flags are supported:
 * - 'ssse3'
 * - 'sse42'
 * - 'avx'
 * - 'avx2'
 * @return {table} flag -> true table
 */
LUA_FUNCTION_DEF (config, get_cpu_flags);

/***
 * @method rspamd_config:has_torch()
 * Returns true if Rspamd is compiled with torch support and the runtime CPU
 * supports sse4.2 required for torch.
 * @return {boolean} true if torch is compiled and supported
 */
LUA_FUNCTION_DEF (config, has_torch);

/***
 * @method rspamd_config:experimental_enabled()
 * Returns true if experimental plugins are enabled
 * @return {boolean} true if experimental plugins are enabled
 */
LUA_FUNCTION_DEF (config, experimental_enabled);

/***
 * @method rspamd_config:load_ucl(filename[, include_trace])
 * Loads config from the UCL file (but does not perform parsing using rcl)
 * @param {string} filename file to load
 * @return true or false + error message
 */
LUA_FUNCTION_DEF (config, load_ucl);

/***
 * @method rspamd_config:parse_rcl([skip_sections])
 * Parses RCL using loaded ucl file
 * @param {table|string} sections to skip
 * @return true or false + error message
 */
LUA_FUNCTION_DEF (config, parse_rcl);

/***
 * @method rspamd_config:init_modules()
 * Initialize lua and internal modules
 * @return true or false
 */
LUA_FUNCTION_DEF (config, init_modules);

/***
 * @method rspamd_config:init_subsystem(str)
 * Initialize config subsystem from a comma separated list:
 * - `modules` - init modules
 * - `langdet` - language detector
 * - `dns` - DNS resolver
 * - TODO: add more
 */
LUA_FUNCTION_DEF (config, init_subsystem);

/***
 * @method rspamd_config:get_tld_path()
 * Returns path to TLD file
 * @return {string} path to tld file
 */
LUA_FUNCTION_DEF (config, get_tld_path);

/***
 * @method rspamd_config:get_dns_max_requests()
 * Returns limit of DNS requests per task
 * @return {number} number of dns requests allowed
 */
LUA_FUNCTION_DEF (config, get_dns_max_requests);

static const struct luaL_reg configlib_m[] = {
	LUA_INTERFACE_DEF (config, get_module_opt),
	LUA_INTERFACE_DEF (config, get_mempool),
	LUA_INTERFACE_DEF (config, get_resolver),
	LUA_INTERFACE_DEF (config, get_all_opt),
	LUA_INTERFACE_DEF (config, get_ucl),
	LUA_INTERFACE_DEF (config, add_radix_map),
	LUA_INTERFACE_DEF (config, radix_from_config),
	LUA_INTERFACE_DEF (config, radix_from_ucl),
	LUA_INTERFACE_DEF (config, add_hash_map),
	LUA_INTERFACE_DEF (config, add_kv_map),
	LUA_INTERFACE_DEF (config, add_map),
	LUA_INTERFACE_DEF (config, get_maps),
	LUA_INTERFACE_DEF (config, get_classifier),
	LUA_INTERFACE_DEF (config, register_symbol),
	LUA_INTERFACE_DEF (config, register_symbols),
	LUA_INTERFACE_DEF (config, register_virtual_symbol),
	LUA_INTERFACE_DEF (config, register_callback_symbol),
	LUA_INTERFACE_DEF (config, register_callback_symbol_priority),
	LUA_INTERFACE_DEF (config, register_dependency),
	LUA_INTERFACE_DEF (config, register_settings_id),
	LUA_INTERFACE_DEF (config, get_symbol_flags),
	LUA_INTERFACE_DEF (config, add_symbol_flags),
	LUA_INTERFACE_DEF (config, set_metric_symbol),
	{"set_symbol", lua_config_set_metric_symbol},
	LUA_INTERFACE_DEF (config, set_metric_action),
	{"set_action", lua_config_set_metric_action},
	LUA_INTERFACE_DEF (config, get_metric_symbol),
	{"get_symbol", lua_config_get_metric_symbol},
	LUA_INTERFACE_DEF (config, get_metric_action),
	{"get_action", lua_config_get_metric_action},
	LUA_INTERFACE_DEF (config, get_all_actions),
	LUA_INTERFACE_DEF (config, add_composite),
	LUA_INTERFACE_DEF (config, register_module_option),
	LUA_INTERFACE_DEF (config, register_pre_filter),
	LUA_INTERFACE_DEF (config, register_post_filter),
	LUA_INTERFACE_DEF (config, get_api_version),
	LUA_INTERFACE_DEF (config, get_key),
	LUA_INTERFACE_DEF (config, add_condition),
	LUA_INTERFACE_DEF (config, enable_symbol),
	LUA_INTERFACE_DEF (config, disable_symbol),
	LUA_INTERFACE_DEF (config, register_regexp),
	LUA_INTERFACE_DEF (config, replace_regexp),
	LUA_INTERFACE_DEF (config, register_worker_script),
	LUA_INTERFACE_DEF (config, register_re_selector),
	LUA_INTERFACE_DEF (config, add_on_load),
	LUA_INTERFACE_DEF (config, add_periodic),
	LUA_INTERFACE_DEF (config, add_post_init),
	LUA_INTERFACE_DEF (config, add_config_unload),
	LUA_INTERFACE_DEF (config, get_symbols_count),
	LUA_INTERFACE_DEF (config, get_symbols_cksum),
	LUA_INTERFACE_DEF (config, get_symbols_counters),
	{"get_symbols_scores", lua_config_get_symbols},
	LUA_INTERFACE_DEF (config, get_symbols),
	LUA_INTERFACE_DEF (config, get_groups),
	LUA_INTERFACE_DEF (config, get_symbol_callback),
	LUA_INTERFACE_DEF (config, set_symbol_callback),
	LUA_INTERFACE_DEF (config, get_symbol_stat),
	LUA_INTERFACE_DEF (config, get_symbol_parent),
	LUA_INTERFACE_DEF (config, get_group_symbols),
	LUA_INTERFACE_DEF (config, register_finish_script),
	LUA_INTERFACE_DEF (config, register_monitored),
	LUA_INTERFACE_DEF (config, add_doc),
	LUA_INTERFACE_DEF (config, add_example),
	LUA_INTERFACE_DEF (config, set_peak_cb),
	LUA_INTERFACE_DEF (config, get_cpu_flags),
	LUA_INTERFACE_DEF (config, has_torch),
	LUA_INTERFACE_DEF (config, experimental_enabled),
	LUA_INTERFACE_DEF (config, load_ucl),
	LUA_INTERFACE_DEF (config, parse_rcl),
	LUA_INTERFACE_DEF (config, init_modules),
	LUA_INTERFACE_DEF (config, init_subsystem),
	LUA_INTERFACE_DEF (config, get_tld_path),
	LUA_INTERFACE_DEF (config, get_dns_max_requests),
	{"__tostring", rspamd_lua_class_tostring},
	{"__newindex", lua_config_newindex},
	{NULL, NULL}
};

LUA_FUNCTION_DEF (monitored, alive);
LUA_FUNCTION_DEF (monitored, latency);
LUA_FUNCTION_DEF (monitored, offline);
LUA_FUNCTION_DEF (monitored, total_offline);

static const struct luaL_reg monitoredlib_m[] = {
	LUA_INTERFACE_DEF (monitored, alive),
	LUA_INTERFACE_DEF (monitored, latency),
	LUA_INTERFACE_DEF (monitored, offline),
	LUA_INTERFACE_DEF (monitored, total_offline),
	{"__tostring", rspamd_lua_class_tostring},
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

static struct rspamd_monitored *
lua_check_monitored (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{monitored}");
	luaL_argcheck (L, ud != NULL, pos, "'monitored' expected");
	return ud ? *((struct rspamd_monitored **)ud) : NULL;
}

/*** Config functions ***/
static gint
lua_config_get_api_version (lua_State *L)
{
	msg_warn ("get_api_version is deprecated, do not use it");
	lua_pushnumber (L, 100);

	return 1;
}

static gint
lua_config_get_module_opt (lua_State * L)
{
	LUA_TRACE_POINT;
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
	LUA_TRACE_POINT;
	rspamd_mempool_t **ppool;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (cfg != NULL) {
		ppool = lua_newuserdata (L, sizeof (rspamd_mempool_t *));
		rspamd_lua_setclass (L, "rspamd{mempool}", -1);
		*ppool = cfg->cfg_pool;
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static int
lua_config_get_resolver (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_dns_resolver **pres;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (cfg != NULL && cfg->dns_resolver) {
		pres = lua_newuserdata (L, sizeof (*pres));
		rspamd_lua_setclass (L, "rspamd{resolver}", -1);
		*pres = cfg->dns_resolver;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_config_get_all_opt (lua_State * L)
{
	LUA_TRACE_POINT;
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
					lua_pushinteger (L, i++);
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

struct rspamd_lua_cached_config {
	lua_State *L;
	gint ref;
};

static void
lua_config_ucl_dtor (gpointer p)
{
	struct rspamd_lua_cached_config *cached = p;

	luaL_unref (cached->L, LUA_REGISTRYINDEX, cached->ref);
}

static gint
lua_config_get_ucl (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_lua_cached_config *cached;

	if (cfg) {
		cached = rspamd_mempool_get_variable (cfg->cfg_pool, "ucl_cached");

		if (cached) {
			lua_rawgeti (L, LUA_REGISTRYINDEX, cached->ref);
		}
		else {
			if (cfg->rcl_obj) {
				ucl_object_push_lua(L, cfg->rcl_obj, true);
				lua_pushvalue(L, -1);
				cached = rspamd_mempool_alloc (cfg->cfg_pool, sizeof(*cached));
				cached->L = L;
				cached->ref = luaL_ref(L, LUA_REGISTRYINDEX);
				rspamd_mempool_set_variable(cfg->cfg_pool, "ucl_cached",
						cached, lua_config_ucl_dtor);
			}
			else {
				lua_pushnil (L);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


static gint
lua_config_get_classifier (lua_State * L)
{
	LUA_TRACE_POINT;
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

	/* Dynamic data */
	gint stack_level;
	gint order;
	struct rspamd_symcache_item *item;
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
lua_metric_symbol_callback (struct rspamd_task *task,
							struct rspamd_symcache_item *item,
							gpointer ud)
{
	struct lua_callback_data *cd = ud;
	struct rspamd_task **ptask;
	gint level = lua_gettop (cd->L), nresults, err_idx, ret;
	lua_State *L = cd->L;
	struct rspamd_symbol_result *s;

	cd->item = item;
	rspamd_symcache_item_async_inc (task, item, "lua symbol");
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

	if ((ret = lua_pcall (L, 1, LUA_MULTRET, err_idx)) != 0) {
		msg_err_task ("call to (%s) failed (%d): %s", cd->symbol, ret,
				lua_tostring (L, -1));
		lua_settop (L, err_idx); /* Not -1 here, as err_func is popped below */
	}
	else {
		nresults = lua_gettop (L) - level;

		if (nresults >= 1) {
			/* Function returned boolean, so maybe we need to insert result? */
			gint res = 0;
			gint i;
			gdouble flag = 1.0;
			gint type;

			type = lua_type (cd->L, level + 1);

			if (type == LUA_TBOOLEAN) {
				res = lua_toboolean (L, level + 1);
			}
			else if (type == LUA_TNUMBER) {
				res = lua_tonumber (L, level + 1);
			}
			else if (type == LUA_TNIL) {
				/* Can happen sometimes... */
				res = FALSE;
			}
			else {
				g_assert_not_reached ();
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

				s = rspamd_task_insert_result (task, cd->symbol, flag, NULL);

				if (s) {
					guint last_pos = lua_gettop (L);

					for (i = level + first_opt; i <= last_pos; i++) {
						if (lua_type (L, i) == LUA_TSTRING) {
							gsize optlen;
							const char *opt = lua_tolstring (L, i, &optlen);

							rspamd_task_add_result_option (task, s, opt, optlen);
						}
						else if (lua_type (L, i) == LUA_TUSERDATA) {
							struct rspamd_lua_text *t = lua_check_text (L, i);

							if (t) {
								rspamd_task_add_result_option (task, s, t->start,
										t->len);
							}
						}
						else if (lua_type (L, i) == LUA_TTABLE) {
							gsize objlen = rspamd_lua_table_size (L, i);

							for (guint j = 1; j <= objlen; j ++) {
								lua_rawgeti (L, i, j);

								if (lua_type (L, -1) == LUA_TSTRING) {
									gsize optlen;
									const char *opt = lua_tolstring (L, -1, &optlen);

									rspamd_task_add_result_option (task, s, opt, optlen);
								}
								else if (lua_type (L, -1) == LUA_TUSERDATA) {
									struct rspamd_lua_text *t = lua_check_text (L, -1);

									if (t) {
										rspamd_task_add_result_option (task, s, t->start,
												t->len);
									}
								}

								lua_pop (L, 1);
							}
						}
					}
				}
			}

			lua_pop (L, nresults);
		}
	}

	lua_pop (L, 1); /* Error function */
	rspamd_symcache_item_async_dec_check (task, cd->item, "lua symbol");
	g_assert (lua_gettop (L) == level - 1);
}

static void lua_metric_symbol_callback_return (struct thread_entry *thread_entry,
											   int ret);

static void lua_metric_symbol_callback_error (struct thread_entry *thread_entry,
											  int ret,
											  const char *msg);

static void
lua_metric_symbol_callback_coro (struct rspamd_task *task,
							struct rspamd_symcache_item *item,
							gpointer ud)
{
	struct lua_callback_data *cd = ud;
	struct rspamd_task **ptask;
	struct thread_entry *thread_entry;

	rspamd_symcache_item_async_inc (task, item, "lua coro symbol");
	thread_entry = lua_thread_pool_get_for_task (task);

	g_assert(thread_entry->cd == NULL);
	thread_entry->cd = cd;

	lua_State *thread = thread_entry->lua_state;
	cd->stack_level = lua_gettop (thread);
	cd->item = item;

	if (cd->cb_is_ref) {
		lua_rawgeti (thread, LUA_REGISTRYINDEX, cd->callback.ref);
	}
	else {
		lua_getglobal (thread, cd->callback.name);
	}

	ptask = lua_newuserdata (thread, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (thread, "rspamd{task}", -1);
	*ptask = task;

	thread_entry->finish_callback = lua_metric_symbol_callback_return;
	thread_entry->error_callback = lua_metric_symbol_callback_error;

	lua_thread_call (thread_entry, 1);
}

static void
lua_metric_symbol_callback_error (struct thread_entry *thread_entry,
								  int ret,
								  const char *msg)
{
	struct lua_callback_data *cd = thread_entry->cd;
	struct rspamd_task *task = thread_entry->task;
	msg_err_task ("call to coroutine (%s) failed (%d): %s", cd->symbol, ret, msg);

	rspamd_symcache_item_async_dec_check (task, cd->item, "lua coro symbol");
}

static void
lua_metric_symbol_callback_return (struct thread_entry *thread_entry, int ret)
{
	struct lua_callback_data *cd = thread_entry->cd;
	struct rspamd_task *task = thread_entry->task;
	int nresults;
	struct rspamd_symbol_result *s;

	(void)ret;

	lua_State *L = thread_entry->lua_state;

	nresults = lua_gettop (L) - cd->stack_level;

	if (nresults >= 1) {
		/* Function returned boolean, so maybe we need to insert result? */
		gint res = 0;
		gint i;
		gdouble flag = 1.0;
		gint type;

		type = lua_type (L, cd->stack_level + 1);

		if (type == LUA_TBOOLEAN) {
			res = lua_toboolean (L, cd->stack_level + 1);
		}
		else if (type == LUA_TFUNCTION) {
			g_assert_not_reached ();
		}
		else {
			res = lua_tonumber (L, cd->stack_level + 1);
		}

		if (res) {
			gint first_opt = 2;

			if (lua_type (L, cd->stack_level + 2) == LUA_TNUMBER) {
				flag = lua_tonumber (L, cd->stack_level + 2);
				/* Shift opt index */
				first_opt = 3;
			}
			else {
				flag = res;
			}

			s = rspamd_task_insert_result (task, cd->symbol, flag, NULL);

			if (s) {
				guint last_pos = lua_gettop (L);

				for (i = cd->stack_level + first_opt; i <= last_pos; i++) {
					if (lua_type (L, i) == LUA_TSTRING) {
						gsize optlen;
						const char *opt = lua_tolstring (L, i, &optlen);

						rspamd_task_add_result_option (task, s, opt, optlen);
					}
					else if (lua_type (L, i) == LUA_TUSERDATA) {
						struct rspamd_lua_text *t = lua_check_text (L, i);

						if (t) {
							rspamd_task_add_result_option (task, s, t->start,
									t->len);
						}
					}
					else if (lua_type (L, i) == LUA_TTABLE) {
						gsize objlen = rspamd_lua_table_size (L, i);

						for (guint j = 1; j <= objlen; j ++) {
							lua_rawgeti (L, i, j);

							if (lua_type (L, -1) == LUA_TSTRING) {
								gsize optlen;
								const char *opt = lua_tolstring (L, -1, &optlen);

								rspamd_task_add_result_option (task, s, opt, optlen);
							}
							else if (lua_type (L, -1) == LUA_TUSERDATA) {
								struct rspamd_lua_text *t = lua_check_text (L, -1);

								if (t) {
									rspamd_task_add_result_option (task, s, t->start,
											t->len);
								}
							}

							lua_pop (L, 1);
						}
					}
				}
			}

		}

		lua_pop (L, nresults);
	}

	g_assert (lua_gettop (L) == cd->stack_level); /* we properly cleaned up the stack */

	cd->stack_level = 0;
	rspamd_symcache_item_async_dec_check (task, cd->item, "lua coro symbol");
}

static guint32*
rspamd_process_id_list (const gchar *entries, guint32 *plen)
{
	gchar **sym_elts;
	guint32 *ids, nids;

	sym_elts = g_strsplit_set (entries, ",;", -1);
	nids = g_strv_length (sym_elts);

	ids = g_malloc (nids * sizeof (guint32));

	for (guint i = 0; i < nids; i ++) {
		ids[i] = rspamd_config_name_to_id (sym_elts[i], strlen (sym_elts[i]));
	}

	*plen = nids;
	g_strfreev (sym_elts);

	return ids;
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
		const gchar *allowed_ids,
		const gchar *forbidden_ids,
		gboolean optional)
{
	struct lua_callback_data *cd;
	gint ret = -1;
	guint32 *ids, nids;

	if (priority == 0 && weight < 0) {
		priority = 1;
	}

	if ((ret = rspamd_symcache_find_symbol (cfg->cache, name)) != -1) {
		if (optional) {
			msg_debug_config ("duplicate symbol: %s, skip registering", name);

			return ret;
		}
		else {
			msg_err_config ("duplicate symbol: %s, skip registering", name);

			return -1;
		}
	}

	if (allowed_ids && !(type & SYMBOL_TYPE_EXPLICIT_DISABLE)) {
		/* Mark symbol as explicit allow */
		msg_info_config ("mark symbol %s as explicit enable as its execution is"
				   "allowed merely on specific settings ids", name);
		type |= SYMBOL_TYPE_EXPLICIT_ENABLE;
	}

	if (ref != -1) {
		cd = rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct lua_callback_data));
		cd->magic = rspamd_lua_callback_magic;
		cd->cb_is_ref = TRUE;
		cd->callback.ref = ref;
		cd->L = L;

		if (name) {
			cd->symbol = rspamd_mempool_strdup (cfg->cfg_pool, name);
		}

		if (type & SYMBOL_TYPE_USE_CORO) {
			ret = rspamd_symcache_add_symbol (cfg->cache,
					name,
					priority,
					lua_metric_symbol_callback_coro,
					cd,
					type,
					parent);
		}
		else {
			ret = rspamd_symcache_add_symbol (cfg->cache,
					name,
					priority,
					lua_metric_symbol_callback,
					cd,
					type,
					parent);
		}
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)lua_destroy_cfg_symbol,
				cd);
	}
	else {
		/* No callback */
		ret = rspamd_symcache_add_symbol (cfg->cache,
				name,
				priority,
				NULL,
				NULL,
				type,
				parent);
	}

	if (allowed_ids) {
		ids = rspamd_process_id_list (allowed_ids, &nids);

		if (nids > 0) {
			GString *dbg = g_string_new ("");

			for (guint i = 0; i < nids; i ++) {
				rspamd_printf_gstring (dbg, "%ud,", ids[i]);
			}

			dbg->len --;

			msg_debug_config ("allowed ids for %s are: %v", name, dbg);
			g_string_free (dbg, TRUE);

			rspamd_symcache_set_allowed_settings_ids (cfg->cache, name,
					ids, nids);
		}

		g_free (ids);
	}

	if (forbidden_ids) {
		ids = rspamd_process_id_list (forbidden_ids, &nids);

		if (nids > 0) {
			GString *dbg = g_string_new ("");

			for (guint i = 0; i < nids; i ++) {
				rspamd_printf_gstring (dbg, "%ud,", ids[i]);
			}

			dbg->len --;

			msg_debug_config ("forbidden ids for %s are: %v", name, dbg);
			g_string_free (dbg, TRUE);

			rspamd_symcache_set_forbidden_settings_ids (cfg->cache, name,
					ids, nids);
		}

		g_free (ids);
	}

	return ret;
}

static gint
lua_config_register_post_filter (lua_State *L)
{
	LUA_TRACE_POINT;
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
				NULL, NULL,
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
	LUA_TRACE_POINT;
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
				NULL, NULL,
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
	LUA_TRACE_POINT;
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

static guint
lua_parse_symbol_flags (const gchar *str)
{
	guint ret = 0;

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
		if (strstr (str, "nostat") != NULL) {
			ret |= SYMBOL_TYPE_NOSTAT;
		}
		if (strstr (str, "idempotent") != NULL) {
			ret |= SYMBOL_TYPE_IDEMPOTENT;
		}
		if (strstr (str, "trivial") != NULL) {
			ret |= SYMBOL_TYPE_TRIVIAL;
		}
		if (strstr (str, "ghost") != NULL) {
			ret |= SYMBOL_TYPE_GHOST;
		}
		if (strstr (str, "mime") != NULL) {
			ret |= SYMBOL_TYPE_MIME_ONLY;
		}
		if (strstr (str, "ignore_passthrough") != NULL) {
			ret |= SYMBOL_TYPE_IGNORE_PASSTHROUGH;
		}
		if (strstr (str, "explicit_disable") != NULL) {
			ret |= SYMBOL_TYPE_EXPLICIT_DISABLE;
		}
		if (strstr (str, "explicit_enable") != NULL) {
			ret |= SYMBOL_TYPE_EXPLICIT_ENABLE;
		}
		if (strstr (str, "coro") != NULL) {
			ret |= SYMBOL_TYPE_USE_CORO;
		}
	}

	return ret;
}

static guint
lua_parse_symbol_type (const gchar *str)
{
	guint ret = SYMBOL_TYPE_NORMAL;
	gchar **vec;
	guint i, l;

	if (str) {
		vec = g_strsplit_set (str, ",;", -1);

		if (vec) {
			l = g_strv_length (vec);

			for (i = 0; i < l; i ++) {
				str = vec[i];

				if (g_ascii_strcasecmp (str, "virtual") == 0) {
					ret |= SYMBOL_TYPE_VIRTUAL;
					ret &= ~SYMBOL_TYPE_NORMAL;
					ret &= ~SYMBOL_TYPE_CALLBACK;
				}
				else if (g_ascii_strcasecmp (str, "callback") == 0) {
					ret |= SYMBOL_TYPE_CALLBACK;
					ret &= ~SYMBOL_TYPE_NORMAL;
					ret &= ~SYMBOL_TYPE_VIRTUAL;
				}
				else if (g_ascii_strcasecmp (str, "normal") == 0) {
					ret |= SYMBOL_TYPE_NORMAL;
					ret &= ~SYMBOL_TYPE_CALLBACK;
					ret &= ~SYMBOL_TYPE_VIRTUAL;
				}
				else if (g_ascii_strcasecmp (str, "prefilter") == 0) {
					ret |= SYMBOL_TYPE_PREFILTER | SYMBOL_TYPE_GHOST;
				}
				else if (g_ascii_strcasecmp (str, "postfilter") == 0) {
					ret |= SYMBOL_TYPE_POSTFILTER | SYMBOL_TYPE_GHOST;
				}
				else if (g_ascii_strcasecmp (str, "connfilter") == 0 ||
						 g_ascii_strcasecmp (str, "conn_filter") == 0) {
					ret |= SYMBOL_TYPE_CONNFILTER | SYMBOL_TYPE_GHOST;
				}
				else if (g_ascii_strcasecmp (str, "idempotent") == 0) {
					ret |= SYMBOL_TYPE_POSTFILTER | SYMBOL_TYPE_GHOST |
						   SYMBOL_TYPE_IDEMPOTENT | SYMBOL_TYPE_CALLBACK;
				}
				else {
					gint fl = 0;

					fl = lua_parse_symbol_flags (str);

					if (fl == 0) {
						msg_warn ("bad type: %s", str);
					}
					else {
						ret |= fl;
					}
				}
			}

			g_strfreev (vec);
		}
	}

	return ret;
}

enum lua_push_symbol_flags_opts {
	LUA_SYMOPT_FLAG_CREATE_ARRAY = 1u << 0u,
	LUA_SYMOPT_FLAG_CREATE_MAP = 1u << 1u,
	LUA_SYMOPT_FLAG_USE_MAP = 1u << 2u,
	LUA_SYMOPT_FLAG_USE_ARRAY = 1u << 3u,
};

#define LUA_SYMOPT_IS_ARRAY(f) ((f) & (LUA_SYMOPT_FLAG_CREATE_ARRAY|LUA_SYMOPT_FLAG_USE_ARRAY))
#define LUA_SYMOPT_IS_CREATE(f) ((f) & (LUA_SYMOPT_FLAG_CREATE_ARRAY|LUA_SYMOPT_FLAG_CREATE_MAP))
#define LUA_OPTION_PUSH(nm) do { \
	if (LUA_SYMOPT_IS_ARRAY(fl)) { \
		lua_pushstring (L, #nm); \
		lua_rawseti (L, -2, i++); \
	} \
	else { \
		lua_pushboolean (L, true); \
		lua_setfield (L, -2, #nm); \
	} \
} while(0)

static void
lua_push_symbol_flags (lua_State *L, guint flags, enum lua_push_symbol_flags_opts fl)
{
	guint i = 1;

	if (LUA_SYMOPT_IS_CREATE (fl)) {
		lua_newtable (L);
	}

	if (flags & SYMBOL_TYPE_FINE) {
		LUA_OPTION_PUSH (fine);
	}

	if (flags & SYMBOL_TYPE_EMPTY) {
		LUA_OPTION_PUSH (empty);
	}

	if (flags & SYMBOL_TYPE_EXPLICIT_DISABLE) {
		LUA_OPTION_PUSH (explicit_disable);
	}

	if (flags & SYMBOL_TYPE_EXPLICIT_ENABLE) {
		LUA_OPTION_PUSH (explicit_enable);
	}

	if (flags & SYMBOL_TYPE_IGNORE_PASSTHROUGH) {
		LUA_OPTION_PUSH (ignore_passthrough);
	}

	if (flags & SYMBOL_TYPE_NOSTAT) {
		LUA_OPTION_PUSH (nostat);
	}

	if (flags & SYMBOL_TYPE_IDEMPOTENT) {
		LUA_OPTION_PUSH (idempotent);
	}

	if (flags & SYMBOL_TYPE_MIME_ONLY) {
		LUA_OPTION_PUSH (mime);
	}

	if (flags & SYMBOL_TYPE_TRIVIAL) {
		LUA_OPTION_PUSH (trivial);
	}

	if (flags & SYMBOL_TYPE_SKIPPED) {
		LUA_OPTION_PUSH (skip);
	}

	if (flags & SYMBOL_TYPE_COMPOSITE) {
		LUA_OPTION_PUSH (composite);
	}
}

static gint
lua_config_get_symbol_flags (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = luaL_checkstring (L, 2);
	guint flags;

	if (cfg && name) {
		flags = rspamd_symcache_get_symbol_flags (cfg->cache,
				name);

		if (flags != 0) {
			lua_push_symbol_flags (L, flags, LUA_SYMOPT_FLAG_CREATE_ARRAY);
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
lua_config_add_symbol_flags (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = luaL_checkstring (L, 2);
	guint flags, new_flags = 0;

	if (cfg && name && lua_istable (L, 3)) {

		for (lua_pushnil (L); lua_next (L, 3); lua_pop (L, 1)) {
			new_flags |= lua_parse_symbol_flags (lua_tostring (L, -1));
		}

		flags = rspamd_symcache_get_symbol_flags (cfg->cache,
				name);

		if (flags != 0) {
			rspamd_symcache_add_symbol_flags (cfg->cache, name, new_flags);
			/* Push old flags */
			lua_push_symbol_flags (L, flags, LUA_SYMOPT_FLAG_CREATE_ARRAY);
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
lua_config_register_symbol (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = NULL, *flags_str = NULL, *type_str = NULL,
			*description = NULL, *group = NULL, *allowed_ids = NULL,
			*forbidden_ids = NULL;
	double weight = 0, score = NAN, parent_float = NAN;
	gboolean one_shot = FALSE;
	gint ret = -1, cbref = -1, type, flags = 0;
	gint64 parent = 0, priority = 0, nshots = 0;
	GError *err = NULL;

	if (cfg) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
				"name=S;weight=N;callback=F;flags=S;type=S;priority=I;parent=D;"
				"score=D;description=S;group=S;one_shot=B;nshots=I;"
				"allowed_ids=S;forbidden_ids=S",
				&name, &weight, &cbref, &flags_str, &type_str,
				&priority, &parent_float,
				&score, &description, &group, &one_shot, &nshots,
				&allowed_ids, &forbidden_ids)) {
			msg_err_config ("bad arguments: %e", err);
			g_error_free (err);

			return luaL_error (L, "invalid arguments");
		}

		if (nshots == 0) {
			nshots = cfg->default_max_shots;
		}

		type = lua_parse_symbol_type (type_str);

		if (!name && !(type & SYMBOL_TYPE_CALLBACK)) {
			return luaL_error (L, "no symbol name but type is not callback");
		}
		else if (!(type & SYMBOL_TYPE_VIRTUAL) && cbref == -1) {
			return luaL_error (L, "no callback for symbol %s", name);
		}

		if (flags_str) {
			type |= lua_parse_symbol_flags (flags_str);
		}

		if (isnan (parent_float)) {
			parent = -1;
		}
		else {
			parent = parent_float;
		}

		ret = rspamd_register_symbol_fromlua (L,
				cfg,
				name,
				cbref,
				weight == 0 ? 1.0 : weight,
				priority,
				type,
				parent,
				allowed_ids, forbidden_ids,
				FALSE);

		if (!isnan (score) || group) {
			if (one_shot) {
				nshots = 1;
			}

			rspamd_config_add_symbol (cfg, name,
					score, description, group, flags,
					0, nshots);

			lua_pushstring (L, "groups");
			lua_gettable (L, 2);

			if (lua_istable (L, -1)) {
				for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
					if (lua_isstring (L, -1)) {
						rspamd_config_add_symbol_group (cfg, name,
								lua_tostring (L, -1));
					}
					else {
						return luaL_error (L, "invalid groups element");
					}
				}
			}

			lua_pop (L, 1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushinteger (L, ret);

	return 1;
}

static gint
lua_config_register_symbols (lua_State *L)
{
	LUA_TRACE_POINT;
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
				NULL, NULL,
				FALSE);

		for (i = top; i <= lua_gettop (L); i++) {
			if (lua_type (L, i) == LUA_TTABLE) {
				lua_pushvalue (L, i);
				lua_pushnil (L);
				while (lua_next (L, -2)) {
					lua_pushvalue (L, -2);
					sym = luaL_checkstring (L, -2);
					rspamd_symcache_add_symbol (cfg->cache, sym,
							0, NULL, NULL,
							SYMBOL_TYPE_VIRTUAL, ret);
					lua_pop (L, 2);
				}
				lua_pop (L, 1);
			}
			else if (lua_type (L, i) == LUA_TSTRING) {
				sym = luaL_checkstring (L, i);
				rspamd_symcache_add_symbol (cfg->cache, sym,
						0, NULL, NULL,
						SYMBOL_TYPE_VIRTUAL, ret);
			}
		}
	}

	lua_pushinteger (L, ret);

	return 1;
}

static gint
lua_config_register_virtual_symbol (lua_State * L)
{
	LUA_TRACE_POINT;
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
			ret = rspamd_symcache_add_symbol (cfg->cache, name,
					weight > 0 ? 0 : -1, NULL, NULL,
					SYMBOL_TYPE_VIRTUAL, parent);
		}
	}

	lua_pushinteger (L, ret);

	return 1;
}

static gint
lua_config_register_callback_symbol (lua_State * L)
{
	LUA_TRACE_POINT;
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
				NULL, NULL,
				FALSE);
	}

	lua_pushinteger (L, ret);

	return 1;
}

static gint
lua_config_register_callback_symbol_priority (lua_State * L)
{
	LUA_TRACE_POINT;
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
				NULL, NULL,
				FALSE);
	}

	lua_pushinteger (L, ret);

	return 1;
}


static gint
lua_config_register_dependency (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *parent = NULL, *child = NULL;
	gint child_id;

	if (cfg == NULL) {
		lua_error (L);
		return 0;
	}

	if (lua_type (L, 2) == LUA_TNUMBER) {
		child_id = luaL_checknumber (L, 2);
		parent = luaL_checkstring (L, 3);

		msg_warn_config ("calling for obsolete method to register deps for symbol %d->%s",
				child_id, parent);

		if (child_id > 0 && parent != NULL) {

			rspamd_symcache_add_dependency (cfg->cache, child_id, parent,
					-1);
		}
	}
	else {
		child = luaL_checkstring (L,2);
		parent = luaL_checkstring (L, 3);

		if (child != NULL && parent != NULL) {
			rspamd_symcache_add_delayed_dependency (cfg->cache, child,
					parent);
		}
	}

	return 0;
}

static gint
lua_config_set_metric_symbol (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *description = NULL,
			*group = NULL, *name = NULL, *flags_str = NULL;
	double score;
	gboolean one_shot = FALSE, one_param = FALSE;
	GError *err = NULL;
	gdouble priority = 0.0;
	guint flags = 0;
	gint64 nshots = 0;

	if (cfg) {

		if (lua_type (L, 2) == LUA_TTABLE) {
			if (!rspamd_lua_parse_table_arguments (L, 2, &err,
					RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
					"*name=S;score=N;description=S;"
					"group=S;one_shot=B;one_param=B;priority=N;flags=S;"
					"nshots=I",
					&name, &score, &description,
					&group, &one_shot, &one_param,
					&priority, &flags_str, &nshots)) {
				msg_err_config ("bad arguments: %e", err);
				g_error_free (err);

				return 0;
			}
		}
		else {
			name = luaL_checkstring (L, 2);
			score = luaL_checknumber (L, 3);

			if (lua_gettop (L) > 3 && lua_type (L, 4) == LUA_TSTRING) {
				description = luaL_checkstring (L, 4);
			}
			if (lua_gettop (L) > 4 && lua_type (L, 5) == LUA_TSTRING) {
				/* XXX: metrics */
			}
			if (lua_gettop (L) > 5 && lua_type (L, 6) == LUA_TSTRING) {
				group = luaL_checkstring (L, 6);
			}
			if (lua_gettop (L) > 6 && lua_type (L, 7) == LUA_TBOOLEAN) {
				one_shot = lua_toboolean (L, 7);
			}
		}

		if (nshots == 0) {
			nshots = cfg->default_max_shots;
		}

		if (one_shot) {
			nshots = 1;
		}
		if (one_param) {
			flags |= RSPAMD_SYMBOL_FLAG_ONEPARAM;
		}

		if (flags_str) {
			if (strstr (flags_str, "one_shot") != NULL) {
				nshots = 1;
			}
			if (strstr (flags_str, "ignore") != NULL) {
				flags |= RSPAMD_SYMBOL_FLAG_IGNORE_METRIC;
			}
			if (strstr (flags_str, "one_param") != NULL) {
				flags |= RSPAMD_SYMBOL_FLAG_ONEPARAM;
			}
		}

		rspamd_config_add_symbol (cfg, name,
				score, description, group, flags, (guint) priority, nshots);


		if (lua_type (L, 2) == LUA_TTABLE) {
			lua_pushstring (L, "groups");
			lua_gettable (L, 2);

			if (lua_istable (L, -1)) {
				for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
					if (lua_isstring (L, -1)) {
						rspamd_config_add_symbol_group (cfg, name,
								lua_tostring (L, -1));
					} else {
						return luaL_error (L, "invalid groups element");
					}
				}
			}

			lua_pop (L, 1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments, rspamd_config expected");
	}

	return 0;
}

static gint
lua_config_get_metric_symbol (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym_name = luaL_checkstring (L, 2);
	struct rspamd_symbol *sym_def;
	struct rspamd_symbols_group *sym_group;
	guint i;

	if (cfg && sym_name) {
		sym_def = g_hash_table_lookup (cfg->symbols, sym_name);

		if (sym_def == NULL) {
			lua_pushnil (L);
		}
		else {
			lua_createtable (L, 0, 3);
			lua_pushstring (L, "score");
			lua_pushnumber (L, sym_def->score);
			lua_settable (L, -3);

			if (sym_def->description) {
				lua_pushstring (L, "description");
				lua_pushstring (L, sym_def->description);
				lua_settable (L, -3);
			}

			if (sym_def->gr) {
				lua_pushstring (L, "group");
				lua_pushstring (L, sym_def->gr->name);
				lua_settable (L, -3);
			}

			lua_pushstring (L, "groups");
			lua_createtable (L, sym_def->groups->len, 0);

			PTR_ARRAY_FOREACH (sym_def->groups, i, sym_group) {
				lua_pushstring (L, sym_group->name);
				lua_rawseti (L, -2, i + 1);
			}

			lua_settable (L, -3);
		}
	}
	else {
		luaL_error (L, "Invalid arguments");
	}

	return 1;
}

static gint
lua_config_set_metric_action (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = NULL;
	double threshold = NAN;
	GError *err = NULL;
	gdouble priority = 0.0;
	ucl_object_t *obj_tbl = NULL;

	if (cfg) {

		if (lua_type (L, 2) == LUA_TTABLE) {
			if (!rspamd_lua_parse_table_arguments (L, 2, &err,
					RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
					"*action=S;score=N;"
					"priority=N",
					&name, &threshold,
					&priority)) {
				msg_err_config ("bad arguments: %e", err);
				g_error_free (err);

				return 0;
			}
		}
		else if (lua_type (L, 2) == LUA_TSTRING && lua_type (L, 3) == LUA_TTABLE) {
			name = lua_tostring (L, 2);
			obj_tbl = ucl_object_lua_import (L, 3);

			if (obj_tbl) {
				if (name) {
					rspamd_config_set_action_score (cfg, name, obj_tbl);
					ucl_object_unref (obj_tbl);
				}
				else {
					ucl_object_unref (obj_tbl);
					return luaL_error (L, "invalid first argument, action name expected");
				}
			}
			else {
				return luaL_error (L, "invalid second argument, table expected");
			}
		}
		else {
			return luaL_error (L, "invalid arguments, table expected");
		}

		if (name != NULL && !isnan (threshold) && threshold != 0) {
			obj_tbl = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (obj_tbl, ucl_object_fromdouble (threshold),
					"score", 0, false);
			ucl_object_insert_key (obj_tbl, ucl_object_fromdouble (priority),
					"priority", 0, false);
			rspamd_config_set_action_score (cfg, name, obj_tbl);
			ucl_object_unref (obj_tbl);
		}
	}
	else {
		return luaL_error (L, "invalid arguments, rspamd_config expected");
	}

	return 0;
}

static gint
lua_config_get_metric_action (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *act_name = luaL_checkstring (L, 2);
	struct rspamd_action *act;

	if (cfg && act_name) {
		act = rspamd_config_get_action (cfg, act_name);

		if (act) {
			if (!isnan (act->threshold)) {
				lua_pushnumber (L, act->threshold);
			}
			else {
				lua_pushnil (L);
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments, rspamd_config expected");
	}

	return 1;
}

static gint
lua_config_get_all_actions (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_action *act, *tmp;

	if (cfg) {
		lua_createtable (L, 0, HASH_COUNT (cfg->actions));

		HASH_ITER (hh, cfg->actions, act, tmp) {
			if (!isnan (act->threshold)) {
				lua_pushstring (L, act->name);
				lua_pushnumber (L, act->threshold);
				lua_settable (L, -3);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments, rspamd_config expected");
	}

	return 1;
}

static gint
lua_config_add_composite (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	gchar *name;
	const gchar *expr_str;
	struct rspamd_composite *composite;
	gboolean ret = FALSE;

	if (cfg) {
		name = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, 2));
		expr_str = luaL_checkstring (L, 3);

		if (name && expr_str) {
			composite = rspamd_composites_manager_add_from_string(cfg->composites_manager,
					name, expr_str);

			if (composite) {
				rspamd_symcache_add_symbol (cfg->cache, name,
						0, NULL, composite, SYMBOL_TYPE_COMPOSITE, -1);
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
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name, *allowed_ids = NULL, *forbidden_ids = NULL;
	gint id, nshots, flags = 0;
	gboolean optional = FALSE;

	name = luaL_checkstring (L, 2);

	if (cfg != NULL && name != NULL && lua_gettop (L) == 3) {

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
					NULL, NULL,
					FALSE);
		}
		else if (lua_type (L, 3) == LUA_TTABLE) {
			gint type = SYMBOL_TYPE_NORMAL, priority = 0, idx;
			gdouble weight = 1.0, score = NAN;
			const char *type_str, *group = NULL, *description = NULL;

			/*
			 * Table can have the following attributes:
			 * "callback" - should be a callback function
			 * "weight" - optional weight
			 * "priority" - optional priority
			 * "type" - optional type (normal, virtual, callback)
			 * "flags" - optional flags
			 * -- Metric options
			 * "score" - optional default score (overridden by metric)
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
				type = lua_parse_symbol_type (type_str);
			}
			lua_pop (L, 1);

			lua_pushstring (L, "flags");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TSTRING) {
				type_str = lua_tostring (L, -1);
				type |= lua_parse_symbol_flags (type_str);
			}
			lua_pop (L, 1);

			lua_pushstring (L, "allowed_ids");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TSTRING) {
				allowed_ids = lua_tostring (L, -1);
			}
			lua_pop (L, 1);

			lua_pushstring (L, "forbidden_ids");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TSTRING) {
				forbidden_ids = lua_tostring (L, -1);
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
					allowed_ids, forbidden_ids,
					optional);

			if (id != -1) {
				/* Check for condition */
				lua_pushstring (L, "condition");
				lua_gettable (L, -2);

				if (lua_type (L, -1) == LUA_TFUNCTION) {
					gint condref;

					/* Here we pop function from the stack, so no lua_pop is required */
					condref = luaL_ref (L, LUA_REGISTRYINDEX);
					g_assert (name != NULL);
					rspamd_symcache_add_condition_delayed (cfg->cache,
							name, L, condref);
				}
				else {
					lua_pop (L, 1);
				}
			}

			/*
			 * Now check if a symbol has not been registered in any metric and
			 * insert default value if applicable
			 */
			struct rspamd_symbol *sym = g_hash_table_lookup (cfg->symbols, name);
			if (sym == NULL || (sym->flags & RSPAMD_SYMBOL_FLAG_UNSCORED)) {
				nshots = cfg->default_max_shots;

				lua_pushstring (L, "score");
				lua_gettable (L, -2);
				if (lua_type (L, -1) == LUA_TNUMBER) {
					score = lua_tonumber (L, -1);

					if (sym) {
						/* Reset unscored flag */
						sym->flags &= ~RSPAMD_SYMBOL_FLAG_UNSCORED;
					}
				}
				lua_pop (L, 1);

				lua_pushstring (L, "group");
				lua_gettable (L, -2);
				if (lua_type (L, -1) == LUA_TSTRING) {
					group = lua_tostring (L, -1);
				}
				lua_pop (L, 1);

				if (!isnan (score) || group != NULL) {
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
							nshots = 1;
						}
					}
					lua_pop (L, 1);

					lua_pushstring (L, "one_param");
					lua_gettable (L, -2);

					if (lua_type (L, -1) == LUA_TBOOLEAN) {
						if (lua_toboolean (L, -1)) {
							flags |= RSPAMD_SYMBOL_FLAG_ONEPARAM;
						}
					}
					lua_pop (L, 1);

					/*
					 * Do not override the existing symbols (using zero priority),
					 * since we are defining default values here
					 */
					if (!isnan (score)) {
						rspamd_config_add_symbol (cfg, name, score,
								description, group, flags, 0, nshots);
					}
					else if (group) {
						/* Add with zero score */
						rspamd_config_add_symbol (cfg, name, NAN,
								description, group, flags, 0, nshots);
					}

					lua_pushstring (L, "groups");
					lua_gettable (L, -2);

					if (lua_istable (L, -1)) {
						for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
							if (lua_isstring (L, -1)) {
								rspamd_config_add_symbol_group (cfg, name,
										lua_tostring (L, -1));
							}
							else {
								return luaL_error (L, "invalid groups element");
							}
						}
					}

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
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	gboolean ret = FALSE;
	gint condref;

	if (cfg && sym && lua_type (L, 3) == LUA_TFUNCTION) {
		lua_pushvalue (L, 3);
		condref = luaL_ref (L, LUA_REGISTRYINDEX);

		ret = rspamd_symcache_add_condition_delayed (cfg->cache, sym, L,
				condref);

		if (!ret) {
			luaL_unref (L, LUA_REGISTRYINDEX, condref);
		}
	}

	lua_pushboolean (L, ret);
	return 1;
}

static gint
lua_config_set_peak_cb (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	gint condref;

	if (cfg && lua_type (L, 2) == LUA_TFUNCTION) {
		lua_pushvalue (L, 2);
		condref = luaL_ref (L, LUA_REGISTRYINDEX);
		rspamd_symcache_set_peak_callback (cfg->cache,
				condref);
	}

	return 0;
}

static gint
lua_config_enable_symbol (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);

	if (cfg && sym) {
		rspamd_symcache_enable_symbol_perm (cfg->cache, sym);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_config_disable_symbol (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	gboolean disable_parent = TRUE;

	if (cfg && sym) {
		if (lua_isboolean (L, 3)) {
			disable_parent = lua_toboolean (L, 3);
		}

		rspamd_symcache_disable_symbol_perm (cfg->cache, sym, disable_parent);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_config_register_regexp (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_lua_regexp *re = NULL;
	rspamd_regexp_t *cache_re;
	const gchar *type_str = NULL, *header_str = NULL;
	gsize header_len = 0;
	GError *err = NULL;
	enum rspamd_re_type type = RSPAMD_RE_BODY;
	gboolean pcre_only = FALSE;

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
				RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
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
					rspamd_regexp_set_flags (re->re,
							rspamd_regexp_get_flags (re->re) | RSPAMD_REGEXP_FLAG_PCRE_ONLY);
				}

				if (header_str != NULL) {
					/* Include the last \0 */
					header_len = strlen (header_str) + 1;
				}

				cache_re = rspamd_re_cache_add (cfg->re_cache, re->re, type,
						(gpointer) header_str, header_len, -1);

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

					if (pcre_only) {
						rspamd_regexp_set_flags (re->re,
								rspamd_regexp_get_flags (re->re) | RSPAMD_REGEXP_FLAG_PCRE_ONLY);
					}
				}
			}
		}
	}

	return 0;
}

static gint
lua_config_replace_regexp (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_lua_regexp *old_re = NULL, *new_re = NULL;
	gboolean pcre_only = FALSE;
	GError *err = NULL;

	if (cfg != NULL) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
				"*old_re=U{regexp};*new_re=U{regexp};pcre_only=B",
				&old_re, &new_re, &pcre_only)) {
			gint ret = luaL_error (L, "cannot get parameters list: %s",
					err ? err->message : "invalid arguments");

			if (err) {
				g_error_free (err);
			}

			return ret;
		}
		else {

			if (pcre_only) {
				rspamd_regexp_set_flags (new_re->re,
						rspamd_regexp_get_flags (new_re->re) | RSPAMD_REGEXP_FLAG_PCRE_ONLY);
			}

			rspamd_re_cache_replace (cfg->re_cache, old_re->re, new_re->re);
		}
	}

	return 0;
}

static gint
lua_config_register_worker_script (lua_State *L)
{
	LUA_TRACE_POINT;
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
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_config_cfg_lua_script *sc;

	if (cfg == NULL || lua_type (L, 2) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid arguments");
	}

	sc = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*sc));
	lua_pushvalue (L, 2);
	sc->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	DL_APPEND (cfg->on_load_scripts, sc);

	return 0;
}

static inline int
rspamd_post_init_sc_sort (const struct rspamd_config_cfg_lua_script *pra,
				const struct rspamd_config_cfg_lua_script *prb)
{
	/* Inverse sort */
	return prb->priority - pra->priority;
}

static gint
lua_config_add_post_init (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_config_cfg_lua_script *sc;
	guint priority = 0;
	lua_Debug d;
	gchar tmp[256], *p;

	if (cfg == NULL || lua_type (L, 2) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 3) == LUA_TNUMBER) {
		priority = lua_tointeger (L , 3);
	}

	if (lua_getstack (L, 1, &d) == 1) {
		(void) lua_getinfo (L, "Sl", &d);
		if ((p = strrchr (d.short_src, '/')) == NULL) {
			p = d.short_src;
		}
		else {
			p++;
		}

		if (strlen (p) > 200) {
			rspamd_snprintf (tmp, sizeof (tmp), "%10s...]:%d", p,
					d.currentline);
		}
		else {
			rspamd_snprintf (tmp, sizeof (tmp), "%s:%d", p,
					d.currentline);
		}
	}

	sc = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*sc));
	lua_pushvalue (L, 2);
	sc->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	sc->priority = priority;
	sc->lua_src_pos = rspamd_mempool_strdup (cfg->cfg_pool, tmp);
	DL_APPEND (cfg->post_init_scripts, sc);
	DL_SORT (cfg->post_init_scripts, rspamd_post_init_sc_sort);

	return 0;
}

static gint
lua_config_add_config_unload (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_config_cfg_lua_script *sc;
	lua_Debug d;
	gchar tmp[256], *p;

	if (cfg == NULL || lua_type (L, 2) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_getstack (L, 1, &d) == 1) {
		(void) lua_getinfo (L, "Sl", &d);
		if ((p = strrchr (d.short_src, '/')) == NULL) {
			p = d.short_src;
		}
		else {
			p++;
		}

		if (strlen (p) > 20) {
			rspamd_snprintf (tmp, sizeof (tmp), "%10s...]:%d", p,
					d.currentline);
		}
		else {
			rspamd_snprintf (tmp, sizeof (tmp), "%s:%d", p,
					d.currentline);
		}
	}

	sc = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*sc));
	lua_pushvalue (L, 2);
	sc->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	sc->lua_src_pos = rspamd_mempool_strdup (cfg->cfg_pool, tmp);
	DL_APPEND (cfg->config_unload_scripts, sc);

	return 0;
}


static void lua_periodic_callback_finish (struct thread_entry *thread, int ret);
static void lua_periodic_callback_error (struct thread_entry *thread, int ret, const char *msg);

struct rspamd_lua_periodic {
	struct ev_loop *event_loop;
	struct rspamd_config *cfg;
	gchar *lua_src_pos;
	lua_State *L;
	gdouble timeout;
	ev_timer ev;
	gint cbref;
	gboolean need_jitter;
	ref_entry_t ref;
};

static void
lua_periodic_dtor (struct rspamd_lua_periodic *periodic)
{
	luaL_unref (periodic->L, LUA_REGISTRYINDEX, periodic->cbref);
	ev_timer_stop (periodic->event_loop, &periodic->ev);
}

static void
lua_periodic_fin (gpointer p)
{
	struct rspamd_lua_periodic *periodic = (struct rspamd_lua_periodic *)p;

	REF_RELEASE (periodic);
}

static void
lua_periodic_callback (struct ev_loop *loop, ev_timer *w, int revents)
{
	struct rspamd_lua_periodic *periodic = (struct rspamd_lua_periodic *)w->data;
	struct rspamd_config **pcfg, *cfg;
	struct ev_loop **pev_base;
	struct thread_entry *thread;
	lua_State *L;

	REF_RETAIN (periodic);
	thread = lua_thread_pool_get_for_config (periodic->cfg);
	thread->cd = periodic;
	thread->finish_callback = lua_periodic_callback_finish;
	thread->error_callback = lua_periodic_callback_error;

	L = thread->lua_state;

	lua_rawgeti (L, LUA_REGISTRYINDEX, periodic->cbref);
	pcfg = lua_newuserdata (L, sizeof (*pcfg));
	rspamd_lua_setclass (L, "rspamd{config}", -1);
	cfg = periodic->cfg;
	*pcfg = cfg;
	pev_base = lua_newuserdata (L, sizeof (*pev_base));
	rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
	*pev_base = periodic->event_loop;
	lua_pushnumber (L, ev_now (periodic->event_loop));

	lua_thread_call (thread, 3);
}

static void
lua_periodic_callback_finish (struct thread_entry *thread, int ret)
{
	lua_State *L;
	struct rspamd_lua_periodic *periodic = thread->cd;
	gboolean plan_more = FALSE;
	gdouble timeout = 0.0;

	L = thread->lua_state;

	ev_now_update (periodic->event_loop);

	if (ret == 0) {
		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			plan_more = lua_toboolean (L, -1);
			timeout = periodic->timeout;
		}
		else if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1);
			plan_more = timeout > 0 ? TRUE : FALSE;
		}

		lua_pop (L, 1); /* Return value */
	}

	if (periodic->cfg->cur_worker) {
		if (periodic->cfg->cur_worker->state != rspamd_worker_state_running) {
			/* We are terminating, no more periodics */
			plan_more = FALSE;
		}
	}

	if (plan_more) {
		if (periodic->need_jitter) {
			timeout = rspamd_time_jitter (timeout, 0.0);
		}

		periodic->ev.repeat = timeout;
		ev_timer_again (periodic->event_loop, &periodic->ev);
	}
	else {
		ev_timer_stop (periodic->event_loop, &periodic->ev);
	}

	REF_RELEASE (periodic);
}

static void
lua_periodic_callback_error (struct thread_entry *thread, int ret, const char *msg)
{
	struct rspamd_config *cfg;
	struct rspamd_lua_periodic *periodic = thread->cd;
	cfg = periodic->cfg;

	msg_err_config ("call to periodic script (registered at %s) failed: %s",
			periodic->lua_src_pos, msg);

	lua_periodic_callback_finish (thread, ret);
}


static gint
lua_config_add_periodic (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct ev_loop *ev_base = lua_check_ev_base (L, 2);
	gdouble timeout = lua_tonumber (L, 3);
	struct rspamd_lua_periodic *periodic;
	gboolean need_jitter = FALSE;
	lua_Debug d;
	gchar tmp[256], *p;

	if (cfg == NULL || timeout < 0 || lua_type (L, 4) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 5) == LUA_TBOOLEAN) {
		need_jitter = lua_toboolean (L, 5);
	}

	if (lua_getstack (L, 1, &d) == 1) {
		(void) lua_getinfo (L, "Sl", &d);
		if ((p = strrchr (d.short_src, '/')) == NULL) {
			p = d.short_src;
		}
		else {
			p++;
		}

		if (strlen (p) > 20) {
			rspamd_snprintf (tmp, sizeof (tmp), "%10s...]:%d", p,
					d.currentline);
		}
		else {
			rspamd_snprintf (tmp, sizeof (tmp), "%s:%d", p,
					d.currentline);
		}
	}

	periodic = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*periodic));
	periodic->timeout = timeout;
	periodic->L = L;
	periodic->cfg = cfg;
	periodic->event_loop = ev_base;
	periodic->need_jitter = need_jitter;
	periodic->lua_src_pos = rspamd_mempool_strdup (cfg->cfg_pool, tmp);
	lua_pushvalue (L, 4);
	periodic->cbref = luaL_ref (L, LUA_REGISTRYINDEX);

	if (need_jitter) {
		timeout = rspamd_time_jitter (timeout, 0.0);
	}

	ev_timer_init (&periodic->ev, lua_periodic_callback, timeout, 0.0);
	periodic->ev.data = periodic;
	ev_timer_start (ev_base, &periodic->ev);
	REF_INIT_RETAIN (periodic, lua_periodic_dtor);

	rspamd_mempool_add_destructor (cfg->cfg_pool, lua_periodic_fin,
			periodic);

	return 0;
}

static gint
lua_config_get_symbols_count (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	guint res = 0;

	if (cfg != NULL) {
		res = rspamd_symcache_stats_symbols_count (cfg->cache);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushinteger (L, res);

	return 1;
}

static gint
lua_config_get_symbols_cksum (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	guint64 res = 0, *pres;

	if (cfg != NULL) {
		res = rspamd_symcache_get_cksum (cfg->cache);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	pres = lua_newuserdata (L, sizeof (res));
	*pres = res;
	rspamd_lua_setclass (L, "rspamd{int64}", -1);

	return 1;
}

static gint
lua_config_get_symbols_counters (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	ucl_object_t *counters;

	if (cfg != NULL) {
		counters = rspamd_symcache_counters (cfg->cache);
		ucl_object_push_lua (L, counters, true);
		ucl_object_unref (counters);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct lua_metric_symbols_cbdata {
	lua_State *L;
	struct rspamd_config *cfg;
};

static void
lua_metric_symbol_inserter (gpointer k, gpointer v, gpointer ud)
{
	struct lua_metric_symbols_cbdata *cbd = (struct lua_metric_symbols_cbdata *)ud;
	lua_State *L;
	const gchar *sym = k;
	struct rspamd_symbol *s = (struct rspamd_symbol *) v;
	struct rspamd_symbols_group *gr;
	gint i;

	L = cbd->L;

	lua_pushstring (L, sym); /* Symbol name */

	lua_createtable (L, 0, 6);
	lua_pushstring (L, "score");
	lua_pushnumber (L, s->score);
	lua_settable (L, -3);
	lua_pushstring (L, "description");
	lua_pushstring (L, s->description);
	lua_settable (L, -3);

	lua_pushstring (L, "flags");
	lua_createtable (L, 0, 3);

	if (s->flags & RSPAMD_SYMBOL_FLAG_IGNORE_METRIC) {
		lua_pushstring (L, "ignore");
		lua_pushboolean (L, true);
		lua_settable (L, -3);
	}
	if (s->flags & RSPAMD_SYMBOL_FLAG_ONEPARAM) {
		lua_pushstring (L, "oneparam");
		lua_pushboolean (L, true);
		lua_settable (L, -3);
	}
	if (s->flags & RSPAMD_SYMBOL_FLAG_UNGROUPPED) {
		lua_pushstring (L, "ungroupped");
		lua_pushboolean (L, true);
		lua_settable (L, -3);
	}
	if (s->flags & RSPAMD_SYMBOL_FLAG_DISABLED) {
		lua_pushstring (L, "disabled");
		lua_pushboolean (L, true);
		lua_settable (L, -3);
	}

	if (s->cache_item) {
		guint sflags = rspamd_symcache_get_symbol_flags (cbd->cfg->cache, sym);

		lua_push_symbol_flags (L, sflags, LUA_SYMOPT_FLAG_USE_MAP);

		guint nids;
		const guint *allowed_ids = rspamd_symcache_get_allowed_settings_ids (cbd->cfg->cache,
				sym, &nids);

		if (allowed_ids && nids > 0) {
			lua_createtable (L, nids, 0);

			for (i = 0; i < nids; i ++) {
				lua_pushinteger (L, allowed_ids[i]);
				lua_rawseti (L, -2, i + 1);
			}

			lua_setfield (L, -2, "allowed_ids");
		}

		const guint *forbidden_ids = rspamd_symcache_get_forbidden_settings_ids (
				cbd->cfg->cache,
				sym, &nids);

		if (forbidden_ids && nids > 0) {
			lua_createtable (L, nids, 0);

			for (i = 0; i < nids; i ++) {
				lua_pushinteger (L, forbidden_ids[i]);
				lua_rawseti (L, -2, i + 1);
			}

			lua_setfield (L, -2, "forbidden_ids");
		}
	}

	lua_settable (L, -3); /* Flags -> flags_table */

	lua_pushstring (L, "nshots");
	lua_pushinteger (L, s->nshots);
	lua_settable (L, -3);

	if (s->gr) {
		lua_pushstring (L, "group");
		lua_pushstring (L, s->gr->name);
		lua_settable (L, -3);
	}

	if (s->groups && s->groups->len > 0) {
		lua_pushstring (L, "groups");
		lua_createtable (L, s->groups->len, 0);

		PTR_ARRAY_FOREACH (s->groups, i, gr) {
			lua_pushstring (L, gr->name);
			lua_rawseti (L, -2, i + 1); /* Groups[i + 1] = group_name */
		}

		lua_settable (L, -3); /* Groups -> groups_table */
	}
	else {
		lua_createtable (L, 0, 0);
		lua_setfield (L, -2, "groups");
	}

	lua_settable (L, -3); /* Symname -> table */
}

static gint
lua_config_get_symbols (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (cfg != NULL) {
		struct lua_metric_symbols_cbdata cbd;

		cbd.L = L;
		cbd.cfg = cfg;

		lua_createtable (L, 0, g_hash_table_size (cfg->symbols));
		g_hash_table_foreach (cfg->symbols,
				lua_metric_symbol_inserter,
				&cbd);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


static gint
lua_config_get_symbol_callback (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	struct rspamd_abstract_callback_data *abs_cbdata;
	struct lua_callback_data *cbd;

	if (cfg != NULL && sym != NULL) {
		abs_cbdata = rspamd_symcache_get_cbdata (cfg->cache, sym);

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
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	struct rspamd_abstract_callback_data *abs_cbdata;
	struct lua_callback_data *cbd;

	if (cfg != NULL && sym != NULL && lua_type (L, 3) == LUA_TFUNCTION) {
		abs_cbdata = rspamd_symcache_get_cbdata (cfg->cache, sym);

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

static gint
lua_config_get_symbol_stat (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2);
	gdouble freq, stddev, tm;
	guint hits;

	if (cfg != NULL && sym != NULL) {
		if (!rspamd_symcache_stat_symbol (cfg->cache, sym, &freq,
				&stddev, &tm, &hits)) {
			lua_pushnil (L);
		}
		else {
			lua_createtable (L, 0, 4);
			lua_pushstring (L, "frequency");
			lua_pushnumber (L, freq);
			lua_settable (L, -3);
			lua_pushstring (L, "sttdev");
			lua_pushnumber (L, stddev);
			lua_settable (L, -3);
			lua_pushstring (L, "time");
			lua_pushnumber (L, tm);
			lua_settable (L, -3);
			lua_pushstring (L, "hits");
			lua_pushinteger (L, hits);
			lua_settable (L, -3);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_get_symbol_parent (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *sym = luaL_checkstring (L, 2), *parent;

	if (cfg != NULL && sym != NULL) {
		parent = rspamd_symcache_get_parent (cfg->cache, sym);

		if (parent) {
			lua_pushstring (L, parent);
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
lua_config_get_group_symbols (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *gr_name = luaL_checkstring (L, 2);

	if (cfg != NULL && gr_name != NULL) {
		struct rspamd_symbols_group *group;

		group = g_hash_table_lookup (cfg->groups, gr_name);

		if (group == NULL) {
			lua_pushnil (L);
		}
		else {
			guint i = 1;
			gpointer k, v;
			GHashTableIter it;

			lua_createtable (L, g_hash_table_size (group->symbols), 0);
			g_hash_table_iter_init (&it, group->symbols);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				lua_pushstring (L, k);
				lua_rawseti (L, -2, i);
				i ++;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_get_groups (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	gboolean need_private;
	struct rspamd_symbols_group *gr;
	GHashTableIter it;
	gpointer k, v;

	if (cfg) {
		if (lua_isboolean (L, 2)) {
			need_private = lua_toboolean (L, 2);
		}
		else {
			need_private = !(cfg->public_groups_only);
		}

		lua_createtable (L, 0, g_hash_table_size (cfg->groups));
		g_hash_table_iter_init (&it, cfg->groups);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			gr = (struct rspamd_symbols_group *)v;

			if (need_private || (gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC)) {
				lua_createtable (L, 0, 4);

				lua_pushstring (L, gr->description);
				lua_setfield (L, -2, "description");
				lua_pushnumber (L, gr->max_score);
				lua_setfield (L, -2, "max_score");
				lua_pushboolean (L, (gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC) != 0);
				lua_setfield (L, -2, "is_public");
				/* TODO: maybe push symbols as well */

				/* Parent table indexed by group name */
				lua_setfield (L, -2, gr->name);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_register_finish_script (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_config_cfg_lua_script *sc;

	if (cfg != NULL && lua_type (L, 2) == LUA_TFUNCTION) {
		sc = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*sc));
		lua_pushvalue (L, 2);
		sc->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		DL_APPEND (cfg->on_term_scripts, sc);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static inline bool
rspamd_lua_config_check_settings_symbols_object (const ucl_object_t *obj)
{
	if (obj == NULL) {
		/* Semantically valid */
		return true;
	}

	if (ucl_object_type (obj) == UCL_OBJECT) {
		/* Key-value mapping - should be okay */
		return true;
	}

	if (ucl_object_type (obj) == UCL_ARRAY) {
		/* Okay if empty */
		if (obj->len == 0) {
			return true;
		}
	}

	/* Everything else not okay */
	return false;
}

static gint
lua_config_register_settings_id (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *settings_name = luaL_checkstring (L, 2);

	if (cfg != NULL && settings_name) {
		ucl_object_t *sym_enabled, *sym_disabled;
		enum rspamd_config_settings_policy policy = RSPAMD_SETTINGS_POLICY_DEFAULT;

		sym_enabled = ucl_object_lua_import (L, 3);

		if (!rspamd_lua_config_check_settings_symbols_object (sym_enabled)) {
			ucl_object_unref (sym_enabled);

			return luaL_error (L, "invalid symbols enabled");
		}

		sym_disabled = ucl_object_lua_import (L, 4);

		if (!rspamd_lua_config_check_settings_symbols_object (sym_disabled)) {
			ucl_object_unref (sym_enabled);
			ucl_object_unref (sym_disabled);

			return luaL_error (L, "invalid symbols enabled");
		}

		/* Check policy */
		if (lua_isstring (L, 5)) {
			const gchar *policy_str = lua_tostring (L, 5);

			if (strcmp (policy_str, "default") == 0) {
				policy = RSPAMD_SETTINGS_POLICY_DEFAULT;
			}
			else if (strcmp (policy_str, "implicit_allow") == 0) {
				policy = RSPAMD_SETTINGS_POLICY_IMPLICIT_ALLOW;
			}
			else if (strcmp (policy_str, "implicit_deny") == 0) {
				policy = RSPAMD_SETTINGS_POLICY_IMPLICIT_DENY;
			}
			else {
				return luaL_error (L, "invalid settings policy: %s", policy_str);
			}
		}
		else {
			/* Apply heuristic */
			if (!sym_enabled) {
				policy = RSPAMD_SETTINGS_POLICY_IMPLICIT_ALLOW;
			}
		}

		rspamd_config_register_settings_id (cfg, settings_name, sym_enabled,
				sym_disabled, policy);

		if (sym_enabled) {
			ucl_object_unref (sym_enabled);
		}

		if (sym_disabled) {
			ucl_object_unref (sym_disabled);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_config_register_monitored (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_monitored *m, **pm;
	const gchar *url, *type;
	ucl_object_t *params = NULL;

	url = lua_tostring (L, 2);
	type = lua_tostring (L, 3);

	if (cfg != NULL && url != NULL && type != NULL) {
		if (g_ascii_strcasecmp (type, "dns") == 0) {
			lua_Debug ar;

			if (lua_type (L, 4) == LUA_TTABLE) {
				params = ucl_object_lua_import (L, 4);
			}

			/* Get lua line and source */
			lua_getstack (L, 1, &ar);
			lua_getinfo (L, "nSl", &ar);

			m = rspamd_monitored_create_ (cfg->monitored_ctx, url,
					RSPAMD_MONITORED_DNS, RSPAMD_MONITORED_DEFAULT,
					params, ar.short_src);

			if (m) {
				pm = lua_newuserdata (L, sizeof (*pm));
				*pm = m;
				rspamd_lua_setclass (L, "rspamd{monitored}", -1);
			}
			else {
				lua_pushnil (L);
			}

			if (params) {
				ucl_object_unref (params);
			}
		}
		else {
			return luaL_error (L, "invalid monitored type: %s", type);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_add_doc (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg;
	const gchar *path = NULL, *option, *doc_string;
	const gchar *type_str = NULL, *default_value = NULL;
	ucl_type_t type = UCL_NULL;
	gboolean required = FALSE;
	GError *err = NULL;

	cfg = lua_check_config (L, 1);

	if (lua_type (L, 2 ) == LUA_TSTRING) {
		path = luaL_checkstring (L, 2);
	}

	option = luaL_checkstring (L, 3);
	doc_string = luaL_checkstring (L, 4);

	if (cfg && option && doc_string) {
		if (lua_type (L, 5) == LUA_TTABLE) {
			if (!rspamd_lua_parse_table_arguments (L, 5, &err,
					RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
					"type=S;default=S;required=B",
					&type_str, &default_value, &required)) {
				msg_err_config ("cannot get parameters list: %e", err);

				if (err) {
					g_error_free (err);
				}

				if (type_str) {
					if (!ucl_object_string_to_type (type_str, &type)) {
						msg_err_config ("invalid type: %s", type_str);
					}
				}
			}
		}

		rspamd_rcl_add_doc_by_path (cfg, path, doc_string, option,
				type, NULL, 0, default_value, required);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_config_add_example (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg;
	const gchar *path = NULL, *option, *doc_string, *example;
	gsize example_len;

	cfg = lua_check_config (L, 1);

	if (lua_type (L, 2 ) == LUA_TSTRING) {
		path = luaL_checkstring (L, 2);
	}

	option = luaL_checkstring (L, 3);
	doc_string = luaL_checkstring (L, 4);
	example = luaL_checklstring (L, 5, &example_len);

	if (cfg && option && doc_string && example) {

		rspamd_rcl_add_doc_by_example (cfg, path, doc_string, option,
				example, example_len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_config_get_cpu_flags (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_cryptobox_library_ctx *crypto_ctx;

	if (cfg != NULL) {
		crypto_ctx = cfg->libs_ctx->crypto_ctx;
		lua_newtable (L);

		if (crypto_ctx->cpu_config & CPUID_SSSE3) {
			lua_pushstring (L, "ssse3");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (crypto_ctx->cpu_config & CPUID_SSE41) {
			lua_pushstring (L, "sse41");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (crypto_ctx->cpu_config & CPUID_SSE42) {
			lua_pushstring (L, "sse42");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (crypto_ctx->cpu_config & CPUID_SSE2) {
			lua_pushstring (L, "sse2");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (crypto_ctx->cpu_config & CPUID_SSE3) {
			lua_pushstring (L, "sse3");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (crypto_ctx->cpu_config & CPUID_AVX) {
			lua_pushstring (L, "avx");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (crypto_ctx->cpu_config & CPUID_AVX2) {
			lua_pushstring (L, "avx2");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_has_torch (lua_State *L)
{
	msg_warn ("use of the obsoleted `has_torch` function");
	lua_pushboolean (L, false);

	return 1;
}

static gint
lua_config_experimental_enabled (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (cfg != NULL) {
		lua_pushboolean (L, cfg->enable_experimental);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct rspamd_lua_include_trace_cbdata {
	lua_State *L;
	gint cbref;
};

static void
lua_include_trace_cb (struct ucl_parser *parser,
					  const ucl_object_t *parent,
					  const ucl_object_t *args,
					  const char *path,
					  size_t pathlen,
					  void *user_data)
{
	struct rspamd_lua_include_trace_cbdata *cbdata =
			(struct rspamd_lua_include_trace_cbdata *)user_data;
	gint err_idx;
	lua_State *L;

	L = cbdata->L;
	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbdata->cbref);
	/* Current filename */
	lua_pushstring (L, ucl_parser_get_cur_file (parser));
	/* Included filename */
	lua_pushlstring (L, path, pathlen);
	/* Params */
	if (args) {
		ucl_object_push_lua (L, args, true);
	}
	else {
		lua_newtable (L);
	}
	/* Parent */
	if (parent) {
		lua_pushstring (L, ucl_object_key (parent));
	}
	else {
		lua_pushnil (L);
	}

	if (lua_pcall (L, 4, 0, err_idx) != 0) {
		msg_err ("lua call to local include trace failed: %s", lua_tostring (L, -1));
	}

	lua_settop (L, err_idx - 1);
}

#define LUA_TABLE_TO_HASH(htb, idx) do { \
	lua_pushstring (L, (idx)); \
	lua_gettable (L, -2); \
	if (lua_isstring (L, -1)) { \
		g_hash_table_insert ((htb), (idx), g_strdup (lua_tostring (L, -1))); \
	} \
	lua_pop (L, 1); \
} while(0)

static gint
lua_config_load_ucl (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *filename;
	GHashTable *paths = g_hash_table_new_full (rspamd_str_hash, rspamd_str_equal,
			NULL, g_free);
	GError *err = NULL;

	if (cfg) {
		if (lua_isstring (L, 2)) {
			filename = lua_tostring (L, 2);
		}
		else {
			filename = RSPAMD_CONFDIR "/rspamd.conf";
		}

		/* Convert rspamd_paths */
		lua_getglobal (L, "rspamd_paths");

		if (lua_istable (L, -1)) {
			LUA_TABLE_TO_HASH(paths, RSPAMD_CONFDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_LOCAL_CONFDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_RUNDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_DBDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_LOGDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_WWWDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_PLUGINSDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_RULESDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_LUALIBDIR_INDEX);
			LUA_TABLE_TO_HASH(paths, RSPAMD_PREFIX_INDEX);
		}

		lua_pop (L, 1);

		if (lua_isfunction (L, 3)) {
			struct rspamd_lua_include_trace_cbdata cbd;

			lua_pushvalue (L, 3);
			cbd.cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			cbd.L = L;

			if (!rspamd_config_parse_ucl (cfg, filename, paths,
					lua_include_trace_cb, &cbd, lua_toboolean (L, 4), &err)) {
				luaL_unref (L, LUA_REGISTRYINDEX, cbd.cbref);
				lua_pushboolean (L, false);
				lua_pushfstring (L, "failed to load config: %s", err->message);
				g_error_free (err);
				g_hash_table_unref (paths);

				return 2;
			}

			luaL_unref (L, LUA_REGISTRYINDEX, cbd.cbref);
		}
		else {
			if (!rspamd_config_parse_ucl (cfg, filename, paths, NULL, NULL,
					lua_toboolean (L, 3), &err)) {
				lua_pushboolean (L, false);
				lua_pushfstring (L, "failed to load config: %s", err->message);
				g_error_free (err);
				g_hash_table_unref (paths);

				return 2;
			}
		}

		rspamd_rcl_maybe_apply_lua_transform (cfg);
		rspamd_config_calculate_cksum (cfg);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	g_hash_table_unref (paths);
	lua_pushboolean (L, true);

	return 1;
}

#undef IDX_TO_HASH

static gint
lua_config_parse_rcl (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	GHashTable *excluded = g_hash_table_new_full (rspamd_str_hash, rspamd_str_equal,
			g_free, NULL);
	GError *err = NULL;
	struct rspamd_rcl_section *top;

	if (cfg) {
		if (lua_istable (L, 2)) {
			lua_pushvalue (L, 2);

			for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
				g_hash_table_insert (excluded, g_strdup (lua_tostring (L, -1)),
						GINT_TO_POINTER (-1));
			}

			lua_pop (L, 1);
		}

		top = rspamd_rcl_config_init (cfg, excluded);

		if (!rspamd_rcl_parse (top, cfg, cfg, cfg->cfg_pool, cfg->rcl_obj, &err)) {
			lua_pushboolean (L, false);
			lua_pushfstring (L, "failed to load config: %s", err->message);
			g_error_free (err);
			g_hash_table_unref (excluded);
			rspamd_rcl_section_free (top);

			return 2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	g_hash_table_unref (excluded);
	rspamd_rcl_section_free (top);
	lua_pushboolean (L, true);

	return 1;
}

static gint
lua_config_init_modules (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (cfg != NULL) {
		rspamd_lua_post_load_config (cfg);
		lua_pushboolean (L, rspamd_init_filters (cfg, false, false));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_init_subsystem (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *subsystem = luaL_checkstring (L, 2);
	gchar **parts;
	guint nparts, i;

	if (cfg != NULL && subsystem != NULL) {
		parts = g_strsplit_set (subsystem, ";,", -1);
		nparts = g_strv_length (parts);

		for (i = 0; i < nparts; i ++) {
			if (strcmp (parts[i], "filters") == 0) {
				rspamd_lua_post_load_config (cfg);
				rspamd_init_filters (cfg, false, false);
			}
			else if (strcmp (parts[i], "langdet") == 0) {
				if (!cfg->lang_det) {
					cfg->lang_det = rspamd_language_detector_init (cfg);
					rspamd_mempool_add_destructor (cfg->cfg_pool,
							(rspamd_mempool_destruct_t) rspamd_language_detector_unref,
							cfg->lang_det);
				}
			}
			else if (strcmp (parts[i], "stat") == 0) {
				rspamd_stat_init (cfg, NULL);
			}
			else if (strcmp (parts[i], "dns") == 0) {
				struct ev_loop *ev_base = lua_check_ev_base (L, 3);

				if (ev_base) {
					cfg->dns_resolver = rspamd_dns_resolver_init (rspamd_log_default_logger (),
							ev_base,
							cfg);
				}
				else {
					g_strfreev (parts);

					return luaL_error (L, "no event base specified");
				}
			}
			else if (strcmp (parts[i], "symcache") == 0) {
				rspamd_symcache_init (cfg->cache);
			}
			else {
				int ret = luaL_error (L, "invalid param: %s", parts[i]);
				g_strfreev (parts);

				return ret;
			}
		}

		g_strfreev (parts);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_config_register_re_selector (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *name = luaL_checkstring (L, 2);
	const gchar *selector_str = luaL_checkstring (L, 3);
	const gchar *delimiter = "";
	bool flatten = false;
	gint top = lua_gettop (L);
	bool res = false;

	if (cfg && name && selector_str) {
		if (lua_gettop (L) >= 4) {
			delimiter = luaL_checkstring (L, 4);

			if (lua_isboolean (L, 5)) {
				flatten = lua_toboolean (L, 5);
			}
		}

		if (luaL_dostring (L, "return require \"lua_selectors\"") != 0) {
			msg_warn_config ("cannot require lua_selectors: %s",
					lua_tostring (L, -1));
		}
		else {
			if (lua_type (L, -1) != LUA_TTABLE) {
				msg_warn_config ("lua selectors must return "
								 "table and not %s",
						lua_typename (L, lua_type (L, -1)));
			}
			else {
				lua_pushstring (L, "create_selector_closure");
				lua_gettable (L, -2);

				if (lua_type (L, -1) != LUA_TFUNCTION) {
					msg_warn_config ("create_selector_closure must return "
									 "function and not %s",
							lua_typename (L, lua_type (L, -1)));
				}
				else {
					gint err_idx, ret;
					struct rspamd_config **pcfg;

					lua_pushcfunction (L, &rspamd_lua_traceback);
					err_idx = lua_gettop (L);

					/* Push function */
					lua_pushvalue (L, -2);

					pcfg = lua_newuserdata (L, sizeof (*pcfg));
					rspamd_lua_setclass (L, "rspamd{config}", -1);
					*pcfg = cfg;
					lua_pushstring (L, selector_str);
					lua_pushstring (L, delimiter);
					lua_pushboolean (L, flatten);

					if ((ret = lua_pcall (L, 4, 1, err_idx)) != 0) {
						msg_err_config ("call to create_selector_closure lua "
										"script failed (%d): %s", ret,
										lua_tostring (L, -1));
					}
					else {
						if (lua_type (L, -1) != LUA_TFUNCTION) {
							msg_warn_config ("create_selector_closure "
											 "invocation must return "
											 "function and not %s",
									lua_typename (L, lua_type (L, -1)));
						}
						else {
							ret = luaL_ref (L, LUA_REGISTRYINDEX);
							rspamd_re_cache_add_selector (cfg->re_cache,
									name, ret);
							res = true;
						}
					}
				}
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_settop (L, top);
	lua_pushboolean (L, res);

	if (res) {
		msg_info_config ("registered regexp selector %s", name);
	}

	return 1;
}

static gint
lua_config_get_tld_path (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (cfg != NULL) {
		lua_pushstring (L, cfg->tld_file);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_config_get_dns_max_requests (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (cfg != NULL) {
		lua_pushinteger (L, cfg->dns_max_requests);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_monitored_alive (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_monitored *m = lua_check_monitored (L, 1);

	if (m) {
		lua_pushboolean (L, rspamd_monitored_alive (m));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_monitored_offline (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_monitored *m = lua_check_monitored (L, 1);

	if (m) {
		lua_pushnumber (L, rspamd_monitored_offline_time (m));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_monitored_total_offline (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_monitored *m = lua_check_monitored (L, 1);

	if (m) {
		lua_pushnumber (L, rspamd_monitored_total_offline_time (m));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_monitored_latency (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_monitored *m = lua_check_monitored (L, 1);

	if (m) {
		lua_pushnumber (L, rspamd_monitored_latency (m));
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

	rspamd_lua_new_class (L, "rspamd{monitored}", monitoredlib_m);

	lua_pop (L, 1);
}

void
lua_call_finish_script (struct rspamd_config_cfg_lua_script *sc,
		struct rspamd_task *task) {

	struct rspamd_task **ptask;
	struct thread_entry *thread;

	thread = lua_thread_pool_get_for_task (task);
	thread->task = task;

	lua_State *L = thread->lua_state;

	lua_rawgeti (L, LUA_REGISTRYINDEX, sc->cbref);

	ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (L, "rspamd{task}", - 1);
	*ptask = task;

	lua_thread_call (thread, 1);
}
