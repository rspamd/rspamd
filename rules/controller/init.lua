--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Controller endpoints

local local_conf = rspamd_paths['LOCAL_CONFDIR']
local local_rules = rspamd_paths['RULESDIR']
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"

-- Define default controller paths, could be overridden in local.d/controller.lua

local controller_plugin_paths = {
  maps = dofile(local_rules .. "/controller/maps.lua"),
  neural = dofile(local_rules .. "/controller/neural.lua"),
  selectors = dofile(local_rules .. "/controller/selectors.lua"),
}

if rspamd_util.file_exists(local_conf .. '/controller.lua') then
  local controller_overrides = dofile(local_conf .. '/controller.lua')

  if controller_overrides and type(controller_overrides) == 'table' then
    controller_plugin_paths = lua_util.override_defaults(controller_plugin_paths, controller_overrides)
  end
end

for plug,paths in pairs(controller_plugin_paths) do
  if not rspamd_plugins[plug] then
    rspamd_plugins[plug] = {}
  end
  if not rspamd_plugins[plug].webui then
    rspamd_plugins[plug].webui = {}
  end

  local webui = rspamd_plugins[plug].webui

  for path,attrs in pairs(paths) do
    if type(attrs) == 'table' then
      if type(attrs.handler) ~= 'function' then
        rspamd_logger.infox(rspamd_config, 'controller plugin %s; webui path %s has invalid handler: %s; ignore it',
            plug, path, type(attrs.handler))
      else
        webui[path] = lua_util.shallowcopy(attrs)
        rspamd_logger.infox(rspamd_config, 'controller plugin %s; register webui path %s',
            plug, path)
      end
    else
      rspamd_logger.infox(rspamd_config, 'controller plugin %s; webui path %s has invalid type: %s; ignore it',
        plug, path, type(attrs))
    end
  end
end
