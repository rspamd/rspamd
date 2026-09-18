--[[
Copyright (c) 2016-2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"
local lua_util = require "lua_util"
local N = "asn"

if confighelp then
  return
end

local options = {
  provider_type = 'rspamd',
  provider_info = {
    ip4 = 'asn.rspamd.com',
    ip6 = 'asn6.rspamd.com',
  },
  symbol = 'ASN',
  check_local = false,
}

local rspamd_re = rspamd_regexp.create_cached("[\\|\\s]")

local function asn_identity(task)
  local ip = task:get_from_ip()
  local valid = ip and ip:is_valid()

  return {
    ip = valid and ip:to_string() or false,
    provider = valid and options.provider_info['ip' .. ip:get_version()] or false,
    skip = not valid or (not options.check_local and ip:is_local()),
    status = 'pending',
    asn = false,
    ipnet = false,
    country = false,
  }
end

local function asn_restore(task, result)
  local mempool = task:get_mempool()

  for _, name in ipairs({ 'asn', 'ipnet', 'country' }) do
    if result[name] then
      mempool:set_variable(name, result[name])
    end
  end
end

local function asn_replay(task, facts)
  local saved = facts.asn

  if type(saved) ~= 'table' or
      (saved.status ~= 'ok' and saved.status ~= 'none' and saved.status ~= 'skip') then
    return false
  end

  local current = asn_identity(task)

  for _, name in ipairs({ 'ip', 'provider', 'skip' }) do
    if saved[name] ~= current[name] then
      return false
    end
  end

  if (saved.status == 'skip') ~= current.skip then
    return false
  end

  for _, name in ipairs({ 'asn', 'ipnet', 'country' }) do
    local value = saved[name]

    if value ~= false and (type(value) ~= 'string' or #value > 256 or value:find('%z')) then
      return false
    end

    if saved.status ~= 'ok' and value ~= false then
      return false
    end
  end

  if saved.asn and not tonumber(saved.asn) then
    return false
  end

  asn_restore(task, saved)
  return true
end

local function asn_check(task)
  local result = asn_identity(task)

  local function complete(status)
    result.status = status
    task:set_check_fact('asn', result)
  end

  local function asn_set(asn, ipnet, country)
    local descr_t = {}

    if asn then
      if tonumber(asn) ~= nil then
        result.asn = asn
        table.insert(descr_t, 'asn:' .. asn)
      else
        rspamd_logger.errx(task, 'malformed ASN "%s" for ip %s', asn, task:get_from_ip())
      end
    end

    if ipnet then
      result.ipnet = ipnet
      table.insert(descr_t, 'ipnet:' .. ipnet)
    end

    if country then
      result.country = country
      table.insert(descr_t, 'country:' .. country)
    end

    asn_restore(task, result)
    complete('ok')

    if options.symbol then
      task:insert_result(options.symbol, 0.0, table.concat(descr_t, ', '))
    end
  end

  local asn_check_func = {}
  asn_check_func.rspamd = function(ip)
    local dnsbl = options['provider_info']['ip' .. ip:get_version()]
    local req_name = string.format("%s.%s",
        table.concat(ip:inversed_str_octets(), '.'), dnsbl)
    local function rspamd_dns_cb(_, _, results, dns_err, _, _, serv)
      if dns_err and (dns_err ~= 'requested record is not found' and dns_err ~= 'no records with this name') then
        complete('error')
        rspamd_logger.errx(task, 'error querying dns "%s" on %s: %s',
            req_name, serv, dns_err)
        task:insert_result(options['symbol_fail'], 0, string.format('%s:%s', req_name, dns_err))
        return
      end

      if not results or not results[1] then
        complete('none')
        rspamd_logger.infox(task, 'no ASN information is available for the IP address "%s" on %s',
            req_name, serv)
        return
      end

      lua_util.debugm(N, task, 'got reply from %s when requesting %s: %s',
          serv, req_name, results[1])

      local parts = rspamd_re:split(results[1])
      -- "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
      asn_set(parts[1], parts[2], parts[3])
    end

    local submitted = task:get_resolver():resolve_txt({
      task = task,
      name = req_name,
      callback = rspamd_dns_cb
    })

    if not submitted then
      complete('error')
    end
  end

  if result.skip then
    complete('skip')
    return
  end

  asn_check_func[options['provider_type']](task:get_from_ip())
end

-- Configuration options
local configure_asn_module = function()
  local opts = rspamd_config:get_all_opt('asn')
  if opts then
    for k, v in pairs(opts) do
      options[k] = v
    end
  end

  local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
      false, true)
  options.check_local = auth_and_local_conf[1]
  options.check_authed = auth_and_local_conf[2]

  if options['provider_type'] == 'rspamd' then
    if not options['provider_info'] and options['provider_info']['ip4'] and
        options['provider_info']['ip6'] then
      rspamd_logger.errx(rspamd_config, "Missing required provider_info for rspamd")
      return false
    end
  else
    rspamd_logger.errx(rspamd_config, "Unknown provider_type: %s", options['provider_type'])
    return false
  end

  if options['symbol'] then
    options['symbol_fail'] = options['symbol'] .. '_FAIL'
  else
    options['symbol_fail'] = 'ASN_FAIL'
  end

  return true
end

if configure_asn_module() then
  local id = rspamd_config:register_symbol({
    name = 'ASN_CHECK',
    type = 'prefilter',
    callback = asn_check,
    priority = lua_util.symbols_priorities.high,
    flags = 'empty,nostat',
    required_inputs = { 'connection' },
    replay_version = 1,
    replay_callback = asn_replay,
    augmentations = { lua_util.dns_timeout_augmentation(rspamd_config) },
  })

  require('lua_multistage').register_connection_consumer(rspamd_config, 'ASN_CHECK')

  if options['symbol'] then
    rspamd_config:register_symbol({
      name = options['symbol'],
      parent = id,
      type = 'virtual',
      flags = 'empty,nostat',
      score = 0,
    })
  end
  rspamd_config:register_symbol {
    name = options['symbol_fail'],
    parent = id,
    type = 'virtual',
    flags = 'empty,nostat',
    score = 0,
  }
else
  lua_util.disable_module(N, 'config')
end
