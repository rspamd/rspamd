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

-- 0 or 1 received: = spam
local symbol = 'ONCE_RECEIVED'
local symbol_mx = 'DIRECT_TO_MX'
-- Symbol for strict checks
local symbol_strict = nil
local bad_hosts = {}
local good_hosts = {}
local whitelist = nil

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local fun = require "fun"
local N = 'once_received'

local check_local = false
local check_authed = false

local function check_quantity_received (task)
  local recvh = task:get_received_headers()

  local nreceived = fun.reduce(function(acc, _)
    return acc + 1
  end, 0, fun.filter(function(h)
    return not h['flags']['artificial']
  end, recvh))

  local task_ip = task:get_ip()

  if ((not check_authed and task:get_user()) or
      (not check_local and task_ip and task_ip:is_local())) then
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
      task:insert_result(symbol, 1)
      -- Avoid strict symbol inserting as the remaining symbols have already
      -- quote a significant weight, so a message could be rejected by just
      -- this property.
      --task:insert_result(symbol_strict, 1)
      -- Check for MUAs
      local ua = task:get_header('User-Agent')
      local xm = task:get_header('X-Mailer')
      if (ua or xm) then
        task:insert_result(symbol_mx, 1, (ua or xm))
      end
    end
    return
  else
    if good_hosts then
      for _, gh in ipairs(good_hosts) do
        if string.find(hn, gh) then
          return
        end
      end
    end

    if nreceived <= 1 then
      task:insert_result(symbol, 1)
      for _, h in ipairs(bad_hosts) do
        if string.find(hn, h) then
          task:insert_result(symbol_strict, 1, h)
          break
        end
      end
    end
    return
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
      if rhn and good_hosts then
        for _, gh in ipairs(good_hosts) do
          if string.find(rhn, gh) then
            ret = false
            break
          end
        end
      end
    end

    if ret then
      -- Strict checks
      if symbol_strict then
        -- Unresolved host
        task:insert_result(symbol, 1)
      else
        task:insert_result(symbol, 1)
      end
    end
  end
end

local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
    false, false)
check_local = auth_and_local_conf[1]
check_authed = auth_and_local_conf[2]

-- Configuration
local opts = rspamd_config:get_all_opt(N)
if opts then
  if opts['symbol'] then
    symbol = opts['symbol']

    local id = rspamd_config:register_symbol({
      name = symbol,
      callback = check_quantity_received,
    })

    for n, v in pairs(opts) do
      if n == 'symbol_strict' then
        symbol_strict = v
      elseif n == 'bad_host' then
        if type(v) == 'string' then
          bad_hosts[1] = v
        else
          bad_hosts = v
        end
      elseif n == 'good_host' then
        if type(v) == 'string' then
          good_hosts[1] = v
        else
          good_hosts = v
        end
      elseif n == 'whitelist' then
        local lua_maps = require "lua_maps"
        whitelist = lua_maps.map_add('once_received', 'whitelist', 'radix',
            'once received whitelist')
      elseif n == 'symbol_mx' then
        symbol_mx = v
      end
    end

    rspamd_config:register_symbol({
      name = symbol_strict,
      type = 'virtual',
      parent = id
    })
    rspamd_config:register_symbol({
      name = symbol_mx,
      type = 'virtual',
      parent = id
    })
  end
end
