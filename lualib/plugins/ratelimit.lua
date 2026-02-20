--[[
Copyright (c) 2024, Vsevolod Stakhov <vsevolod@rspamd.com>

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
local lua_util = require "lua_util"
local T = require "lua_shape.core"

local exports = {}

local limit_parser
local function parse_string_limit(lim, no_error)
  local function parse_time_suffix(s)
    if s == 's' then
      return 1
    elseif s == 'm' then
      return 60
    elseif s == 'h' then
      return 3600
    elseif s == 'd' then
      return 86400
    end
  end
  local function parse_num_suffix(s)
    if s == '' then
      return 1
    elseif s == 'k' then
      return 1000
    elseif s == 'm' then
      return 1000000
    elseif s == 'g' then
      return 1000000000
    end
  end
  local lpeg = require "lpeg"

  if not limit_parser then
    local digit = lpeg.R("09")
    limit_parser = {}
    limit_parser.integer = (lpeg.S("+-") ^ -1) *
        (digit ^ 1)
    limit_parser.fractional = (lpeg.P(".")) *
        (digit ^ 1)
    limit_parser.number = (limit_parser.integer *
        (limit_parser.fractional ^ -1)) +
        (lpeg.S("+-") * limit_parser.fractional)
    limit_parser.time = lpeg.Cf(lpeg.Cc(1) *
        (limit_parser.number / tonumber) *
        ((lpeg.S("smhd") / parse_time_suffix) ^ -1),
        function(acc, val)
          return acc * val
        end)
    limit_parser.suffixed_number = lpeg.Cf(lpeg.Cc(1) *
        (limit_parser.number / tonumber) *
        ((lpeg.S("kmg") / parse_num_suffix) ^ -1),
        function(acc, val)
          return acc * val
        end)
    limit_parser.limit = lpeg.Ct(limit_parser.suffixed_number *
        (lpeg.S(" ") ^ 0) * lpeg.S("/") * (lpeg.S(" ") ^ 0) *
        limit_parser.time)
  end
  local t = lpeg.match(limit_parser.limit, lim)

  if t and t[1] and t[2] and t[2] ~= 0 then
    return t[2], t[1]
  end

  if not no_error then
    rspamd_logger.errx(rspamd_config, 'bad limit: %s', lim)
  end

  return nil
end

local function str_to_rate(str)
  local divider, divisor = parse_string_limit(str, false)

  if not divisor then
    rspamd_logger.errx(rspamd_config, 'bad rate string: %s', str)

    return nil
  end

  return divisor / divider
end

local bucket_schema = T.table({
  burst = T.one_of({
    T.number(),
    T.transform(T.string(), lua_util.dehumanize_number)
  }):doc({ summary = "Burst size (number of messages)" }),
  rate = T.one_of({
    T.number(),
    T.transform(T.string(), str_to_rate)
  }):doc({ summary = "Rate limit (messages per time unit)" }),
  skip_recipients = T.boolean():optional():doc({ summary = "Skip per-recipient limits" }),
  symbol = T.string():optional():doc({ summary = "Custom symbol name" }),
  message = T.string():optional():doc({ summary = "Custom reject message" }),
  skip_soft_reject = T.boolean():optional():doc({ summary = "Skip soft reject" }),
  ham_factor_rate = T.number():optional():doc({ summary = "Bucket-specific ham_factor_rate"}),
  spam_factor_rate = T.number():optional():doc({ summary = "Bucket-specific spam_factor_rate"}),
  ham_factor_burst = T.number():optional():doc({ summary = "Bucket-specific ham_factor_burst"}),
  spam_factor_burst = T.number():optional():doc({ summary = "Bucket-specific spam_factor_burst"}),
  max_rate_mult = T.number():optional():doc({ summary = "Bucket-specific rate multiplicator limit"}),
  max_bucket_mult = T.number():optional():doc({ summary = "Bucket-specific bucket multiplicator limit"}),
}):doc({ summary = "Ratelimit bucket configuration" })

exports.parse_limit = function(name, data)
  if type(data) == 'table' then
    -- 2 cases here:
    --  * old limit in format [burst, rate]
    --  * vector of strings in Andrew's string format (removed from 1.8.2)
    --  * proper bucket table
    if #data == 2 and tonumber(data[1]) and tonumber(data[2]) then
      -- Old style ratelimit
      rspamd_logger.warnx(rspamd_config, 'old style ratelimit for %s', name)
      if tonumber(data[1]) > 0 and tonumber(data[2]) > 0 then
        return {
          burst = data[1],
          rate = data[2]
        }
      elseif data[1] ~= 0 then
        rspamd_logger.warnx(rspamd_config, 'invalid numbers for %s', name)
      else
        rspamd_logger.infox(rspamd_config, 'disable limit %s, burst is zero', name)
      end

      return nil
    else
      local parsed_bucket, err = bucket_schema:transform(data)

      if not parsed_bucket or err then
        rspamd_logger.errx(rspamd_config, 'cannot parse bucket for %s: %s; original value: %s',
            name, err, data)
      else
        return parsed_bucket
      end
    end
  elseif type(data) == 'string' then
    local rep_rate, burst = parse_string_limit(data)
    rspamd_logger.warnx(rspamd_config, 'old style rate bucket config detected for %s: %s',
        name, data)
    if rep_rate and burst then
      return {
        burst = burst,
        rate = burst / rep_rate -- reciprocal
      }
    end
  end

  return nil
end

return exports