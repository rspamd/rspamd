--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This plugin implements dynamic updates for rspamd

local ucl = require "ucl"
require "fun" ()
local rspamd_logger = require "rspamd_logger"
local updates_priority = 2
local rspamd_config = rspamd_config
local hash = require "rspamd_cryptobox_hash"
local rspamd_version = rspamd_version
local maps = {}

local function process_symbols(obj, priority)
  each(function(sym, score)
    rspamd_config:set_metric_symbol({
      name = sym,
      score = score,
      priority = priority
    })
  end, obj)
end

local function process_actions(obj, priority)
  each(function(act, score)
    rspamd_config:set_metric_action({
      action = act,
      score = score,
      priority = priority
    })
  end, obj)
end

local function process_rules(obj)
  each(function(key, code)
    local f = loadstring(code)
    if f then
      f()
    else
      rspamd_logger(rspamd_config, 'cannot load rules for %s', key)
    end
  end, obj)
end

local function check_version(obj)
  local ret = true

  if not obj then
    return false
  end

  if obj['min_version'] then
    if rspamd_version('cmp', obj['min_version']) > 0 then
      ret = false
      rspamd_logger.errx(rspamd_config, 'updates require at least %s version of rspamd',
        obj['min_version'])
    end
  end
  if obj['max_version'] then
    if rspamd_version('cmp', obj['max_version']) < 0 then
      ret = false
      rspamd_logger.errx(rspamd_config, 'updates require maximum %s version of rspamd',
        obj['max_version'])
    end
  end

  return ret
end

local function gen_callback(map)

  return function(data)
    local ucl = require "ucl"
    local parser = ucl.parser()
    local res,err = parser:parse_string(data)

    if not res then
      rspamd_logger.warnx(rspamd_config, 'cannot parse updates map: ' .. err)
    else
      local h = hash.create()
      h:update(data)
      local obj = parser:get_object()

      if check_version(obj) then

        local priority = updates_priority

        if obj['priority'] then
          priority = obj['priority']
        end

        if obj['symbols'] then
          process_symbols(obj['symbols'])
        end
        if obj['actions'] then
          process_actions(obj['actions'])
        end
        if obj['rules'] then
          process_rules(obj['rules'])
        end

        rspamd_logger.infox(rspamd_config, 'loaded new rules with hash "%s"',
          h:hex())
      end
    end

    return res
  end
end

-- Configuration part
local section = rspamd_config:get_all_opt("rspamd_update")
if section then
  if section['enabled'] == false then
    rspamd_logger.info('Module is disabled')
    return
  end
  local trusted_key
  each(function(k, elt)
    if k == 'priority' then
      updates_priority = tonumber(elt)
    elseif k == 'key' then
      trusted_key = elt
    else
      local map = rspamd_config:add_map(elt, "rspamd updates map", nil)
      if not map then
        rspamd_logger.errx(rspamd_config, 'cannot load updates from %1', elt)
      else
        map:set_callback(gen_callback(map))
        maps['elt'] = map
      end
    end
  end, section)

  each(function(k, map)
    -- Check sanity for maps
    local proto = map:get_proto()
    if (proto == 'http' or proto == 'https') and not map:get_sign_key() then
      if trusted_key then
        map:set_sign_key(trusted_key)
      else
        rspamd_logger.warnx(rspamd_config, 'Map %s is loaded by HTTP and it is not signed', k)
      end
    end
  end, maps)
else
  rspamd_logger.infox('Module is unconfigured')
end
