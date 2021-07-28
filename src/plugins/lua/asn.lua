--[[
Copyright (c) 2011-2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>

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

local function asn_check(task)

  local function asn_set(asn, ipnet, country)
    local descr_t = {}
    local mempool = task:get_mempool()
    if asn then
      if tonumber(asn) ~= nil then
        mempool:set_variable("asn", asn)
        table.insert(descr_t, "asn:" .. asn)
      else
        rspamd_logger.errx(task, 'malformed ASN "%s" for ip %s', asn, task:get_from_ip())
      end
    end
    if ipnet then
      mempool:set_variable("ipnet", ipnet)
      table.insert(descr_t, "ipnet:" .. ipnet)
    end
    if country then
      mempool:set_variable("country", country)
      table.insert(descr_t, "country:" .. country)
    end
    if options['symbol'] then
      task:insert_result(options['symbol'], 0.0, table.concat(descr_t, ', '))
    end
  end

  local asn_check_func = {}
  asn_check_func.rspamd = function(ip)
    local dnsbl = options['provider_info']['ip' .. ip:get_version()]
    local req_name = string.format("%s.%s",
        table.concat(ip:inversed_str_octets(), '.'), dnsbl)
    local function rspamd_dns_cb(_, _, results, dns_err, _, _, serv)
      if dns_err and (dns_err ~= 'requested record is not found' and dns_err ~= 'no records with this name') then
        rspamd_logger.errx(task, 'error querying dns "%s" on %s: %s',
            req_name, serv, dns_err)
        task:insert_result(options['symbol_fail'], 0, string.format('%s:%s', req_name, dns_err))
        return
      end
      if not results or not results[1] then
        rspamd_logger.infox(task, 'cannot query ip %s on %s: no results',
            req_name, serv)
        return
      end

      lua_util.debugm(N, task, 'got reply from %s when requesting %s: %s',
        serv, req_name, results[1])

      local parts = rspamd_re:split(results[1])
      -- "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
      asn_set(parts[1], parts[2], parts[3])
    end

    task:get_resolver():resolve_txt({
      task = task,
      name = req_name,
      callback = rspamd_dns_cb
    })
  end

  local ip = task:get_from_ip()
  if not (ip and ip:is_valid()) or
      (not options.check_local and ip:is_local()) then
    return
  end

  asn_check_func[options['provider_type']](ip)
end

-- Configuration options
local configure_asn_module = function()
  local opts =  rspamd_config:get_all_opt('asn')
  if opts then
    for k,v in pairs(opts) do
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
      rspamd_logger.errx("Missing required provider_info for rspamd")
      return false
    end
  else
    rspamd_logger.errx("Unknown provider_type: %s", options['provider_type'])
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
    priority = 8,
    flags = 'empty,nostat',
  })
  if options['symbol'] then
    rspamd_config:register_symbol({
      name = options['symbol'],
      parent = id,
      type = 'virtual',
      flags = 'empty,nostat',
      score = 0,
    })
  end
  rspamd_config:register_symbol{
    name = options['symbol_fail'],
    parent = id,
    type = 'virtual',
    flags = 'empty,nostat',
    score = 0,
  }
else
  lua_util.disable_module(N, 'config')
end
