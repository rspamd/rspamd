--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2019, Denis Paavilainen <denpa@denpa.pro>

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

--[[[
-- @module p0f
-- This module contains p0f access functions
--]]

local tcp = require "rspamd_tcp"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local common = require "lua_scanners/common"

-- SEE: https://github.com/p0f/p0f/blob/v3.06b/docs/README#L317
local S = {
  BAD_QUERY = 0x0,
  OK        = 0x10,
  NO_MATCH  = 0x20
}

local N = 'p0f'

local function p0f_check(task, ip, rule)

  local function ip2bin(addr)
    addr = addr:to_table()

    for k, v in ipairs(addr) do
      addr[k] = rspamd_util.pack('B', v)
    end

    return table.concat(addr)
  end

  local function trim(...)
    local vars = {...}

    for k, v in ipairs(vars) do
      -- skip numbers, trim only strings
      if tonumber(vars[k]) == nil then
        vars[k] = string.gsub(v, '[^%w-_\\.\\(\\) ]', '')
      end
    end

    return lua_util.unpack(vars)
  end

  local function parse_p0f_response(data)
    --[[
      p0f_api_response[232]: magic, status, first_seen, last_seen, total_conn,
      uptime_min, up_mod_days, last_nat, last_chg, distance, bad_sw, os_match_q,
      os_name, os_flavor, http_name, http_flavor, link_type, language
    ]]--

    data = tostring(data)

    -- API response must be 232 bytes long
    if #data ~= 232 then
      rspamd_logger.errx(task, 'malformed response from p0f on %s, %s bytes',
        rule.socket, #data)

      common.yield_result(task, rule, 'Malformed Response: ' .. rule.socket,
        0.0, 'fail')
      return
    end

    local _, status, _, _, _, uptime_min, _, _, _, distance, _, _, os_name,
      os_flavor, _, _, link_type, _ = trim(rspamd_util.unpack(
        'I4I4I4I4I4I4I4I4I4hbbc32c32c32c32c32c32', data))

    if status ~= S.OK then
      if status == S.BAD_QUERY then
        rspamd_logger.errx(task, 'malformed p0f query on %s', rule.socket)
        common.yield_result(task, rule, 'Malformed Query: ' .. rule.socket,
          0.0, 'fail')
      end

      return
    end

    local os_string = #os_name == 0 and 'unknown' or os_name .. ' ' .. os_flavor

    task:get_mempool():set_variable('os_fingerprint', os_string, link_type,
      uptime_min, distance)

    if link_type and #link_type > 0 then
      common.yield_result(task, rule, {
        os_string,
        'link=' .. link_type,
        'distance=' .. distance},
          0.0)
    else
      common.yield_result(task, rule, {
        os_string,
        'link=unknown',
        'distance=' .. distance},
          0.0)
    end

    return data
  end

  local function make_p0f_request()

    local function check_p0f_cb(err, data)

      local function redis_set_cb(redis_set_err)
        if redis_set_err then
          rspamd_logger.errx(task, 'redis received an error: %s', redis_set_err)
        end
      end

      if err then
        rspamd_logger.errx(task, 'p0f received an error: %s', err)
        common.yield_result(task, rule, 'Error getting result: ' .. err,
            0.0, 'fail')
        return
      end

      data = parse_p0f_response(data)

      if rule.redis_params and data then
        local key = rule.prefix .. ip:to_string()
        local ret = lua_redis.redis_make_request(task,
            rule.redis_params,
            key,
            true,
            redis_set_cb,
            'SETEX',
            { key, tostring(rule.expire), data }
        )

        if not ret then
          rspamd_logger.warnx(task, 'error connecting to redis')
        end
      end
    end

    local query = rspamd_util.pack('I4 I1 c16', 0x50304601,
      ip:get_version(), ip2bin(ip))

    tcp.request({
      host = rule.socket,
      callback = check_p0f_cb,
      data = { query },
      task = task,
      timeout = rule.timeout
    })
  end

  local function redis_get_cb(err, data)
    if err or type(data) ~= 'string' then
      make_p0f_request()
    else
      parse_p0f_response(data)
    end
  end

  local ret = nil
  if rule.redis_params then
    local key = rule.prefix .. ip:to_string()
    ret = lua_redis.redis_make_request(task,
      rule.redis_params,
      key,
      false,
      redis_get_cb,
      'GET',
      { key }
    )
  end

  if not ret then
    make_p0f_request() -- fallback to directly querying p0f
  end
end

local function p0f_config(opts)
  local p0f_conf = {
    name = N,
    timeout = 5,
    symbol = 'P0F',
    symbol_fail = 'P0F_FAIL',
    patterns = {},
    expire = 7200,
    prefix = 'p0f',
    detection_category = 'fingerprint',
    message = '${SCANNER}: fingerprint matched: "${VIRUS}"'
  }

  p0f_conf = lua_util.override_defaults(p0f_conf, opts)
  p0f_conf.patterns = common.create_regex_table(p0f_conf.patterns)

  if not p0f_conf.log_prefix then
    p0f_conf.log_prefix = p0f_conf.name
  end

  if not p0f_conf.socket then
    rspamd_logger.errx(rspamd_config, 'no servers defined')
    return nil
  end

  return p0f_conf
end

return {
  type = {N, 'fingerprint', 'scanner'},
  description = 'passive OS fingerprinter',
  configure = p0f_config,
  check = p0f_check,
  name = N
}
