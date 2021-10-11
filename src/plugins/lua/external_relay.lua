--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

--[[
external_relay plugin - sets IP/hostname from Received headers
]]--

if confighelp then
  return
end

local lua_maps = require "lua_maps"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local ts = require("tableshape").types

local E = {}
local N = "external_relay"

local settings = {
  rules = {},
}

local config_schema = ts.shape{
  enabled = ts.boolean:is_optional(),
  rules = ts.map_of(
    ts.string, ts.one_of{
      ts.shape{
        priority = ts.number:is_optional(),
        strategy = 'authenticated',
        symbol = ts.string:is_optional(),
        user_map = lua_maps.map_schema:is_optional(),
      },
      ts.shape{
        count = ts.number,
        priority = ts.number:is_optional(),
        strategy = 'count',
        symbol = ts.string:is_optional(),
      },
      ts.shape{
        priority = ts.number:is_optional(),
        strategy = 'local',
        symbol = ts.string:is_optional(),
      },
      ts.shape{
        hostname_map = lua_maps.map_schema,
        priority = ts.number:is_optional(),
        strategy = 'hostname_map',
        symbol = ts.string:is_optional(),
      },
    }
  ),
}

local function set_from_rcvd(task, rcvd)
  local rcvd_ip = rcvd.real_ip
  if not (rcvd_ip and rcvd_ip:is_valid()) then
    rspamd_logger.errx(task, 'no IP in header: %s', rcvd)
    return
  end
  task:set_from_ip(rcvd_ip)
  if rcvd.from_hostname then
    task:set_hostname(rcvd.from_hostname)
    task:set_helo(rcvd.from_hostname) -- use fake value for HELO
  else
    rspamd_logger.warnx(task, "couldn't get hostname from headers")
    local ipstr = string.format('[%s]', rcvd_ip)
    task:set_hostname(ipstr) -- returns nil from task:get_hostname()
    task:set_helo(ipstr)
  end
  return true
end

local strategies = {}

strategies.authenticated = function(rule)
  local user_map
  if rule.user_map then
    user_map = lua_maps.map_add_from_ucl(rule.user_map, 'set', 'external relay usernames')
    if not user_map then
      rspamd_logger.errx(rspamd_config, "couldn't add map %s; won't register symbol %s",
          rule.user_map, rule.symbol)
      return
    end
  end

  return function(task)
    local user = task:get_user()
    if not user then
      lua_util.debugm(N, task, 'sender is unauthenticated')
      return
    end
    if user_map then
      if not user_map:get_key(user) then
        lua_util.debugm(N, task, 'sender (%s) is not in user_map', user)
        return
      end
    end

    local rcvd_hdrs = task:get_received_headers()
    -- Try find end of authentication chain
    for _, rcvd in ipairs(rcvd_hdrs) do
      if not rcvd.flags.authenticated then
        -- Found unauthenticated hop, use this header
        return set_from_rcvd(task, rcvd)
      end
    end

    rspamd_logger.errx(task, 'found nothing useful in Received headers')
  end
end

strategies.count = function(rule)
  return function(task)
    local rcvd_hdrs = task:get_received_headers()
    -- Reduce count by 1 if artificial header is present
    local hdr_count
    if ((rcvd_hdrs[1] or E).flags or E).artificial then
      hdr_count = rule.count - 1
    else
      hdr_count = rule.count
    end

    local rcvd = rcvd_hdrs[hdr_count]
    if not rcvd then
      rspamd_logger.errx(task, 'found no received header #%s', hdr_count)
      return
    end

    return set_from_rcvd(task, rcvd)
  end
end

strategies.hostname_map = function(rule)
  local hostname_map = lua_maps.map_add_from_ucl(rule.hostname_map, 'map', 'external relay hostnames')
  if not hostname_map then
    rspamd_logger.errx(rspamd_config, "couldn't add map %s; won't register symbol %s",
        rule.hostname_map, rule.symbol)
    return
  end

  return function(task)
    local from_hn = task:get_hostname()
    if not from_hn then
      lua_util.debugm(N, task, 'sending hostname is missing')
      return
    end

    if hostname_map:get_key(from_hn) ~= 'direct' then
      lua_util.debugm(N, task, 'sending hostname (%s) is not a direct relay', from_hn)
      return
    end

    local rcvd_hdrs = task:get_received_headers()
    -- Try find sending hostname in Received headers
    for _, rcvd in ipairs(rcvd_hdrs) do
      if rcvd.by_hostname == from_hn and rcvd.real_ip then
        if not hostname_map:get_key(rcvd.from_hostname) then
          -- Remote hostname is not another relay, use this header
          return set_from_rcvd(task, rcvd)
        else
          -- Keep checking with new hostname
          from_hn = rcvd.from_hostname
        end
      end
    end

    rspamd_logger.errx(task, 'found nothing useful in Received headers')
  end
end

strategies['local'] = function(rule)
  return function(task)
    local from_ip = task:get_from_ip()
    if not from_ip then
      lua_util.debugm(N, task, 'sending IP is missing')
      return
    end

    if not from_ip:is_local() then
      lua_util.debugm(N, task, 'sending IP (%s) is non-local', from_ip)
      return
    end

    local rcvd_hdrs = task:get_received_headers()
    local num_rcvd = #rcvd_hdrs
    -- Try find first non-local IP in Received headers
    for i, rcvd in ipairs(rcvd_hdrs) do
      if rcvd.real_ip then
        local rcvd_ip = rcvd.real_ip
        if rcvd_ip and rcvd_ip:is_valid() and (not rcvd_ip:is_local() or i == num_rcvd) then
          return set_from_rcvd(task, rcvd)
        end
      end
    end

    rspamd_logger.errx(task, 'found nothing useful in Received headers')
  end
end

local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)

  local ok, schema_err = config_schema:transform(settings)
  if not ok then
    rspamd_logger.errx(rspamd_config, 'config schema error: %s', schema_err)
    lua_util.disable_module(N, "config")
    return
  end

  for k, rule in pairs(settings.rules) do

    if not rule.symbol then
      rule.symbol = k
    end

    local cb = strategies[rule.strategy](rule)

    if cb then
      rspamd_config:register_symbol({
        name = rule.symbol,
        type = 'prefilter',
        priority = rule.priority or 20,
        group = N,
        callback = cb,
      })
    end
  end
end
