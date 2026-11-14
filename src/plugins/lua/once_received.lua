--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

if confighelp then
  return
end

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local dynconf = require "lua_dynconf"
local fun = require "fun"
local N = 'once_received'

-- 0 or 1 received: = spam
local settings = {
  symbol = 'ONCE_RECEIVED',
  symbol_mx = 'DIRECT_TO_MX',
  -- Symbol for strict checks (no default)
  symbol_strict = nil,
  -- Strings or lists of Lua patterns (normalised to lists after load)
  bad_host = {},
  good_host = {},
  check_local = false,
  check_authed = false,
}

-- Derived runtime object (radix map), not a setting
local whitelist = nil

local function check_quantity_received (task)
  local recvh = task:get_received_headers()

  local nreceived = fun.reduce(function(acc, _)
    return acc + 1
  end, 0, fun.filter(function(h)
    return not h['flags']['artificial']
  end, recvh))

  local task_ip = task:get_ip()

  if ((not settings.check_authed and task:get_user()) or
      (not settings.check_local and task_ip and task_ip:is_local())) then
    rspamd_logger.infox(task, 'Skipping once_received for authenticated user or local network')
    return
  end
  if whitelist and task_ip and whitelist:get_key(task_ip) then
    rspamd_logger.infox(task, 'whitelisted mail from %s',
        task_ip:to_string())
    return
  end

  local hn = task:get_hostname()
  -- Here we don't care about received
  if not hn then
    if nreceived <= 1 then
      task:insert_result(settings.symbol, 1)
      -- Avoid strict symbol inserting as the remaining symbols have already
      -- quote a significant weight, so a message could be rejected by just
      -- this property.
      --task:insert_result(settings.symbol_strict, 1)
      -- Check for MUAs
      local ua = task:get_header('User-Agent')
      local xm = task:get_header('X-Mailer')
      if (ua or xm) then
        task:insert_result(settings.symbol_mx, 1, (ua or xm))
      end
    end
    return
  else
    if settings.good_host then
      for _, gh in ipairs(settings.good_host) do
        if string.find(hn, gh) then
          return
        end
      end
    end

    if nreceived <= 1 then
      task:insert_result(settings.symbol, 1)
      for _, h in ipairs(settings.bad_host) do
        if string.find(hn, h) then
          task:insert_result(settings.symbol_strict, 1, h)
          return
        end
      end
    end
  end

  if nreceived <= 1 then
    local ret = true
    local r = recvh[1]

    if not r then
      return
    end

    if r['real_hostname'] then
      local rhn = string.lower(r['real_hostname'])
      -- Check for good hostname
      if rhn and settings.good_host then
        for _, gh in ipairs(settings.good_host) do
          if string.find(rhn, gh) then
            ret = false
            break
          end
        end
      end
    end

    if ret then
      -- Strict checks
      if settings.symbol_strict then
        -- Unresolved host
        task:insert_result(settings.symbol, 1)

        if not hn then
          return
        end
        for _, h in ipairs(settings.bad_host) do
          if string.find(hn, h) then
            task:insert_result(settings.symbol_strict, 1, h)
            return
          end
        end
      else
        task:insert_result(settings.symbol, 1)
      end
    end
  end
end

local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
    false, false)
settings.check_local = auth_and_local_conf[1]
settings.check_authed = auth_and_local_conf[2]

-- Configuration
local opts = rspamd_config:get_all_opt(N)
if opts then
  local dyn_settings, dyn_err = dynconf.register(N, {
    defaults = settings,
    opts = opts,
    -- No schema: bad_host/good_host accept a string or a list, the rest is
    -- not validated by the plugin
    dynamic = {},
  })
  if not dyn_settings then
    rspamd_logger.errx(rspamd_config, 'invalid %s config: %s', N, dyn_err)
    lua_util.disable_module(N, "config")
    return
  end
  settings = dyn_settings

  -- check_local/check_authed may also come from the `options` section
  if type(settings.check_local) ~= 'boolean' then
    settings.check_local = auth_and_local_conf[1]
  end
  if type(settings.check_authed) ~= 'boolean' then
    settings.check_authed = auth_and_local_conf[2]
  end

  if opts['symbol'] then
    local id = rspamd_config:register_symbol({
      name = settings.symbol,
      callback = check_quantity_received,
    })

    if type(settings.bad_host) == 'string' then
      settings.bad_host = { settings.bad_host }
    end
    if type(settings.good_host) == 'string' then
      settings.good_host = { settings.good_host }
    end
    if opts['whitelist'] ~= nil then
      local lua_maps = require "lua_maps"
      whitelist = lua_maps.map_add('once_received', 'whitelist', 'radix',
          'once received whitelist')
    end

    rspamd_config:register_symbol({
      name = settings.symbol_strict,
      type = 'virtual',
      parent = id
    })
    rspamd_config:register_symbol({
      name = settings.symbol_mx,
      type = 'virtual',
      parent = id
    })
  end
end
