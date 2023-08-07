--[[
Copyright (c) 2023, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module lua_cfg_utils
-- This module contains utility functions for configuration of Rspamd modules
--]]

local exports = {}

--[[[
-- @function lua_util.disable_module(modname, how[, reason])
-- Disables a plugin
-- @param {string} modname name of plugin to disable
-- @param {string} how 'redis' to disable redis, 'config' to disable startup
-- @param {string} reason optional reason for failure
--]]
exports.disable_module = function(modname, how, reason)
  if rspamd_plugins_state.enabled[modname] then
    rspamd_plugins_state.enabled[modname] = nil
  end

  if how == 'redis' then
    rspamd_plugins_state.disabled_redis[modname] = {}
  elseif how == 'config' then
    rspamd_plugins_state.disabled_unconfigured[modname] = {}
  elseif how == 'experimental' then
    rspamd_plugins_state.disabled_experimental[modname] = {}
  elseif how == 'failed' then
    rspamd_plugins_state.disabled_failed[modname] = { reason = reason }
  else
    rspamd_plugins_state.disabled_unknown[modname] = {}
  end
end

--[[[
-- @function lua_util.push_config_error(module, err)
-- Pushes a configuration error to the state
-- @param {string} module name of module
-- @param {string} err error string
--]]
exports.push_config_error = function(module, err)
  if not rspamd_plugins_state.config_errors then
    rspamd_plugins_state.config_errors = {}
  end

  if not rspamd_plugins_state.config_errors[module] then
    rspamd_plugins_state.config_errors[module] = {}
  end

  table.insert(rspamd_plugins_state.config_errors[module], err)
end

return exports