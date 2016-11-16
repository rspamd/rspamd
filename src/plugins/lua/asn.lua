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

local options = {
  provider_type = 'rspamd',
  provider_info = {
    ip4 = 'asn.rspamd.com',
    ip6 = 'asn6.rspamd.com',
  },
  symbol = 'ASN',
  expire = 86400, -- 1 day by default
  key_prefix = 'rasn',
}
local redis_params

local rspamd_re = rspamd_regexp.create_cached("[\\|\\s]")

local function asn_check(task)

  local function asn_set(asn, ipnet, country)
    local descr_t = {}
    if asn then
      task:get_mempool():set_variable("asn", asn)
      table.insert(descr_t, "asn:" .. asn)
    end
    if ipnet then
      task:get_mempool():set_variable("ipnet", ipnet)
      table.insert(descr_t, "ipnet:" .. ipnet)
    end
    if country then
      task:get_mempool():set_variable("country", country)
      table.insert(descr_t, "country:" .. country)
    end
    if options['symbol'] then
      task:insert_result(options['symbol'], 0.0, table.concat(descr_t, ', '))
    end
  end

  local asn_check_func = {}
  function asn_check_func.rspamd(ip)
    local function rspamd_dns_cb(_, _, results, dns_err)
      if dns_err then
        rspamd_logger.errx(task, 'error querying dns: %s', dns_err)
      end
      if not (results and results[1]) then return end
      local parts = rspamd_re:split(results[1])
      -- "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
      asn_set(parts[1], parts[2], parts[3])

      if redis_params then
        local redis_key = options.key_prefix .. ip:to_string()
        local ret,conn,upstream
        local function redis_asn_set_cb(redis_err)
          if redis_err then
            rspamd_logger.errx(task, 'got error %s when setting asn record on server %s',
              redis_err, upstream:get_addr())
          end
        end
        ret,conn,upstream = rspamd_redis_make_request(task,
          redis_params, -- connect params
          redis_key, -- hash key
          true, -- is write
          redis_asn_set_cb, --callback
          'HMSET', -- command
          {redis_key, "asn", parts[1], "net", parts[2], "country", parts[3]} -- arguments
        )
        if ret then
          conn:add_cmd('EXPIRE', {
            redis_key, tostring(options['expire'])
          })
        else
          rspamd_logger.err(task, 'got error while connecting to redis')
        end
      end
    end
    local dnsbl = options['provider_info']['ip' .. ip:get_version()]
    local req_name = rspamd_logger.slog("%1.%2",
        table.concat(ip:inversed_str_octets(), '.'), dnsbl)
    task:get_resolver():resolve_txt(task:get_session(), task:get_mempool(),
        req_name, rspamd_dns_cb)
  end

  local function asn_check_cache(ip, continuation_func)
    local key = options.key_prefix .. ip:to_string()

    local function redis_asn_get_cb(err, data)
      if err or not data or type(data[1]) ~= 'string' then
        continuation_func(ip)
      else
        asn_set(data[1], data[2], data[3])
        -- Refresh key
        local function redis_asn_expire_cb(redis_err)
          if redis_err then
            rspamd_logger.errx(task, 'Error setting expire: %s',
                redis_err)
          end
        end

        local ret = rspamd_redis_make_request(task,
          redis_params, -- connect params
          key, -- hash key
          true, -- is write
          redis_asn_expire_cb, --callback
          'EXPIRE', -- command
          {key, tostring(options.expire)} -- arguments
        )
        if not ret then
          rspamd_logger.err('got error connecting to redis')
        end
      end
    end

    local ret = rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_asn_get_cb, --callback
      'HMGET', -- command
      {key, "asn", "net", "country"} -- arguments
    )

    if not ret then
      continuation_func(ip)
    end
  end

  local ip = task:get_from_ip()
  if not (ip and ip:is_valid()) then return end

  if not redis_params then
    asn_check_func[options['provider_type']](ip)
  else
    asn_check_cache(ip, asn_check_func[options['provider_type']])
  end
end

-- Configuration options
local configure_asn_module = function()
  local opts =  rspamd_config:get_all_opt('asn')
  if opts then
    for k,v in pairs(opts) do
      options[k] = v
    end
  end
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
  redis_params = rspamd_parse_redis_server('asn')
  return true
end

if configure_asn_module() then
  rspamd_config:register_symbol({
    name = 'ASN_CHECK',
    type = 'prefilter',
    callback = asn_check,
    priority = 10,
  })
end
