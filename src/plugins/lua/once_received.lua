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

if confighelp then
  return
end

-- 0 or 1 received: = spam

local symbol = 'ONCE_RECEIVED'
local symbol_rdns = 'RDNS_NONE'
local symbol_rdns_dnsfail = 'RDNS_DNSFAIL'
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

  local nreceived = fun.reduce(function(acc, rcvd)
    return acc + 1
  end, 0, fun.filter(function(h)
    return not h['artificial']
  end, recvh))

  local function recv_dns_cb(_, to_resolve, results, err)
    if err and (err ~= 'requested record is not found' and err ~= 'no records with this name') then
      rspamd_logger.errx(task, 'error looking up %s: %s', to_resolve, err)
      task:insert_result(symbol_rdns_dnsfail, 1.0)
    end

    if not results then
      if nreceived <= 1 then
        task:insert_result(symbol, 1)
        task:insert_result(symbol_strict, 1)
        -- Check for MUAs
        local ua = task:get_header('User-Agent')
        local xm = task:get_header('X-Mailer')
        if (ua or xm) then
          task:insert_result(symbol_mx, 1, (ua or xm))
        end
      end
      task:insert_result(symbol_rdns, 1)
    else
      rspamd_logger.infox(task, 'source hostname has not been passed to Rspamd from MTA, ' ..
          'but we could resolve source IP address PTR %s as "%s"',
        to_resolve, results[1])
      task:set_hostname(results[1])

      if good_hosts then
        for _,gh in ipairs(good_hosts) do
          if string.find(results[1], gh) then
            return
          end
        end
      end

      if nreceived <= 1 then
        task:insert_result(symbol, 1)
        for _,h in ipairs(bad_hosts) do
          if string.find(results[1], h) then

            task:insert_result(symbol_strict, 1, h)
            return
          end
        end
      end
    end
  end

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
  if (not hn) and task_ip and task_ip:is_valid() then
    task:get_resolver():resolve_ptr({task = task,
      name = task_ip:to_string(),
      callback = recv_dns_cb,
      forced = true
    })
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
        for _,gh in ipairs(good_hosts) do
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

        if not hn then return end
        for _,h in ipairs(bad_hosts) do
          if string.find(hn, h) then
            task:insert_result(symbol_strict, 1, h)
            return
          end
        end
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

    for n,v in pairs(opts) do
      if n == 'symbol_strict' then
        symbol_strict = v
      elseif n == 'symbol_rdns' then
        symbol_rdns = v
      elseif n == 'symbol_rdns_dnsfail' then
        symbol_rdns_dnsfail = v
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
        whitelist = rspamd_map_add('once_received', 'whitelist', 'radix',
          'once received whitelist')
      elseif n == 'symbol_mx' then
        symbol_mx = v
      end
    end

    rspamd_config:register_symbol({
      name = symbol_rdns,
      type = 'virtual',
      parent = id
    })
    rspamd_config:register_symbol({
      name = symbol_rdns_dnsfail,
      type = 'virtual',
      parent = id
    })
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
