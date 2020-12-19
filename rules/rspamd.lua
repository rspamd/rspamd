--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This is main lua config file for rspamd

require "global_functions" ()

config['regexp'] = {}
rspamd_maps = {} -- Global maps

local local_conf = rspamd_paths['LOCAL_CONFDIR']
local local_rules = rspamd_paths['RULESDIR']
local rspamd_util = require "rspamd_util"

dofile(local_rules .. '/regexp/headers.lua')
dofile(local_rules .. '/regexp/misc.lua')
dofile(local_rules .. '/regexp/upstream_spam_filters.lua')
dofile(local_rules .. '/regexp/compromised_hosts.lua')
dofile(local_rules .. '/html.lua')
dofile(local_rules .. '/headers_checks.lua')
dofile(local_rules .. '/subject_checks.lua')
dofile(local_rules .. '/misc.lua')
dofile(local_rules .. '/forwarding.lua')
dofile(local_rules .. '/mid.lua')
dofile(local_rules .. '/bitcoin.lua')
dofile(local_rules .. '/bounce.lua')
dofile(local_rules .. '/content.lua')
dofile(local_rules .. '/controller/init.lua')

if rspamd_util.file_exists(local_conf .. '/rspamd.local.lua') then
  dofile(local_conf .. '/rspamd.local.lua')
else
  -- Legacy lua/rspamd.local.lua
  if rspamd_util.file_exists(local_conf .. '/lua/rspamd.local.lua') then
    dofile(local_conf .. '/lua/rspamd.local.lua')
  end
end

if rspamd_util.file_exists(local_conf .. '/local.d/rspamd.lua') then
  dofile(local_conf .. '/local.d/rspamd.lua')
end

local rmaps =  rspamd_config:get_all_opt("lua_maps")
if rmaps and type(rmaps) == 'table' then
  local rspamd_logger = require "rspamd_logger"
  for k,v in pairs(rmaps) do
    local status,map_or_err = pcall(rspamd_config:add_map(v))

    if not status then
      rspamd_logger.errx(rspamd_config, "cannot add map %s: %s", k, map_or_err)
    else
      rspamd_maps[k] = map_or_err
    end
  end
end
