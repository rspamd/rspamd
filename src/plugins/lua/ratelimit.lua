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

-- A plugin that implements ratelimits using redis or kvstorage server

-- Default settings for limits, 1-st member is burst, second is rate and the third is numeric type
local settings = {
  -- Limit for all mail per recipient (burst 100, rate 2 per minute)
  to = {0, 0.033333333},
  -- Limit for all mail per one source ip (burst 30, rate 1.5 per minute)
  to_ip = {0, 0.025},
  -- Limit for all mail per one source ip and from address (burst 20, rate 1 per minute)
  to_ip_from = {0, 0.01666666667},

  -- Limit for all bounce mail (burst 10, rate 2 per hour)
  bounce_to = {0, 0.000555556},
  -- Limit for bounce mail per one source ip (burst 5, rate 1 per hour)
  bounce_to_ip = {0, 0.000277778},

  -- Limit for all mail per user (authuser) (burst 20, rate 1 per minute)
  user = {0, 0.01666666667}
}
-- Senders that are considered as bounce
local bounce_senders = {'postmaster', 'mailer-daemon', '', 'null', 'fetchmail-daemon', 'mdaemon'}
-- Do not check ratelimits for these senders
local whitelisted_rcpts = {'postmaster', 'mailer-daemon'}
local whitelisted_ip
local max_rcpt = 5
local redis_params
local ratelimit_symbol
-- Do not delay mail after 1 day
local max_delay = 24 * 3600

local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local fun = require "fun"
--local dumper = require 'pl.pretty'.dump

--- Parse atime and bucket of limit
local function parse_limits(data)
  local function parse_limit_elt(str)
    local elts = rspamd_str_split(str, ':')
    if not elts or #elts < 2 then
      return {0, 0, 0}
    else
      local atime = tonumber(elts[1])
      local bucket = tonumber(elts[2])
      local ctime = atime

      if elts[3] then
        ctime = tonumber(elts[3])
      end

      if not ctime then
        ctime = atime
      end

      return {atime,bucket,ctime}
    end
  end

  return fun.iter(data):map(function(e)
    if type(e) == 'string' then
      return parse_limit_elt(e)
    else
      return {0, 0, 0}
    end
  end):totable()
end

local function generate_format_string(args, is_set)
  if is_set then
    return 'MSET'
    --return fun.foldl(function(acc, k) return acc .. ' %s %s' end, 'MSET', args)
  end
  return 'MGET'
  --return fun.foldl(function(acc, k) return acc .. ' %s' end, 'MGET', args)
end

--- Check specific limit inside redis
local function check_limits(task, args)

  local key = fun.foldl(function(acc, k) return acc .. k[2] end, '', args)
  local ret,upstream
  --- Called when value is got from server
  local function rate_get_cb(task, err, data)
    if data then
      local ntime = rspamd_util.get_time()

      fun.each(function(elt, limit)
        local bucket = elt[2]
        local rate = limit[2]
        local threshold = limit[1]
        local atime = elt[1]
        local ctime = elt[3]

        if atime == 0 then return end

        if atime - ctime > max_delay then
          rspamd_logger.infox(task, 'limit is too old: %1 seconds; ignore it',
            atime - ctime)
        else
          bucket = bucket - rate * (ntime - atime);
          if bucket > 0 then
            if ratelimit_symbol then
              local mult = 2 * rspamd_util.tanh(bucket / (threshold * 2))

              if mult > 0.5 then
                task:insert_result(ratelimit_symbol, mult,
                  tostring(mult))
              end
            else
              if bucket > threshold then
                task:set_pre_result('soft reject', 'Ratelimit exceeded')
              end
            end
          end
        end
      end, fun.zip(parse_limits(data), fun.map(function(a) return a[1] end, args)))
    elseif err then
      rspamd_logger.infox(task, 'got error while getting limit: %1', err)
      upstream:fail()
    end
  end

  local cmd = generate_format_string(args, false)
  ret,_,upstream = rspamd_redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    false, -- is write
    rate_get_cb, --callback
    cmd, -- command
    fun.totable(fun.map(function(l) return l[2] end, args)) -- arguments
  )
end

--- Set specific limit inside redis
local function set_limits(task, args)
  local key = fun.foldl(function(acc, k) return acc .. k[2] end, '', args)
  local ret, upstream

  local function rate_set_cb(task, err, data)
    if not err then
      upstream:ok()
    else
      rspamd_logger.infox(task, 'got error %s when setting ratelimit record on server %s',
        err, upstream:get_addr())
    end
  end
  local function rate_get_cb(task, err, data)
    if data then
      local ntime = rspamd_util.get_time()
      local values = {}
      fun.each(function(elt, limit)
        local bucket = elt[2]
        local rate = limit[1][2]
        local threshold = limit[1][1]
        local atime = elt[1]
        local ctime = elt[3]

        if atime - ctime > max_delay then
          rspamd_logger.infox(task, 'limit is too old: %1 seconds; start it over',
            atime - ctime)
          bucket = 1
          ctime = ntime
          atime = ntime
        else
          if bucket > 0 then
            bucket = bucket - rate * (ntime - atime) + 1;
            if bucket < 0 then
              bucket = 1
            end
          else
            bucket = 1
          end
        end

        if ctime == 0 then ctime = ntime end

        local lstr = string.format('%.3f:%.3f:%.3f', ntime, bucket, ctime)
        table.insert(values, {limit[2], max_delay, lstr})
      end, fun.zip(parse_limits(data), fun.iter(args)))

      local conn
      ret,conn,upstream = rspamd_redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        true, -- is write
        rate_set_cb, --callback
        'setex', -- command
        values[1] -- arguments
      )

      if conn then
        fun.each(function(v)
          conn:add_cmd('setex', v)
        end, fun.drop_n(1, values))
      else
        rspamd_logger.infox(task, 'got error while connecting to redis: %1', addr)
        upstream:fail()
      end
    elseif err then
      rspamd_logger.infox(task, 'got error while setting limit: %1', err)
      upstream:fail()
    end
  end

  local cmd = generate_format_string(args, false)
  ret,_,upstream = rspamd_redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    false, -- is write
    rate_get_cb, --callback
    cmd, -- command
    fun.totable(fun.map(function(l) return l[2] end, args)) -- arguments
  )
end

--- Make rate key
local function make_rate_key(from, to, ip)
  if from and ip and ip:is_valid() then
    return string.format('%s:%s:%s', from, to, ip:to_string())
  elseif from then
    return string.format('%s:%s', from, to)
  elseif ip and ip:is_valid() then
    return string.format('%s:%s', to, ip:to_string())
  elseif to then
    return to
  else
    return nil
  end
end

--- Check whether this addr is bounce
local function check_bounce(from)
  return fun.any(function(b) return b == from end, bounce_senders)
end

--- Check or update ratelimit
local function rate_test_set(task, func)
  local args = {}
  -- Get initial task data
  local ip = task:get_from_ip()
  if ip and ip:is_valid() and whitelisted_ip then
    if whitelisted_ip:get_key(ip) then
      -- Do not check whitelisted ip
      rspamd_logger.infox(task, 'skip ratelimit for whitelisted IP')
      return
    end
  end
  -- Parse all rcpts
  local rcpts = task:get_recipients()
  local rcpts_user = {}
  if rcpts then
    fun.each(function(r) table.insert(rcpts_user, r['user']) end, rcpts)
    if fun.any(function(r)
      fun.any(function(w) return r == w end, whitelisted_rcpts) end,
      rcpts_user) then

      rspamd_logger.infox(task, 'skip ratelimit for whitelisted recipient')
      return
    end
  end
  -- Parse from
  local from = task:get_from()
  local from_user = '<>'
  local from_addr = '<>'
  if from and from[1] and from[1]['addr'] then
    from_user = from[1]['user']
    from_addr = from[1]['addr']
  end
  -- Get user (authuser)
  local auser = task:get_user()
  if auser and settings['user'][1] > 0 then
    table.insert(args, {settings['user'], make_rate_key (auser, '<auth>', nil)})
  end

  local is_bounce = check_bounce(from_user)

  if rcpts and not auser then
    fun.each(function(r)
      if is_bounce then
        if settings['bounce_to'][1] > 0 then
          table.insert(args, { settings['bounce_to'], make_rate_key('<>', r['addr'], nil) })
        end
        if ip and settings['bounce_to_ip'][1] > 0 then
          table.insert(args, { settings['bounce_to_ip'], make_rate_key('<>', r['addr'], ip) })
        end
      end
      if settings['to'][1] > 0 then
        table.insert(args, { settings['to'], make_rate_key(nil, r['addr'], nil) })
      end
      if ip then
        if settings['to_ip'][1] > 0 then
          table.insert(args, { settings['to_ip'], make_rate_key(nil, r['addr'], ip) })
        end
        if settings['to_ip_from'][1] > 0 then
          table.insert(args, { settings['to_ip_from'], make_rate_key(from_addr, r['addr'], ip) })
        end
      end
    end, rcpts)
  end

  if #args > 0 then
    func(task, args)
  end
end

--- Check limit
local function rate_test(task)
  rate_test_set(task, check_limits)
end
--- Update limit
local function rate_set(task)
  rate_test_set(task, set_limits)
end


--- Parse a single limit description
local function parse_limit(str)
  local params = rspamd_str_split(str, ':')

  local function set_limit(limit, burst, rate)
    limit[1] = tonumber(burst)
    limit[2] = tonumber(rate)
  end

  if table.maxn(params) ~= 3 then
    rspamd_logger.errx(rspamd_config, 'invalid limit definition: ' .. str)
    return
  end

  if params[1] == 'to' then
    set_limit(settings['to'], params[2], params[3])
  elseif params[1] == 'to_ip' then
    set_limit(settings['to_ip'], params[2], params[3])
  elseif params[1] == 'to_ip_from' then
    set_limit(settings['to_ip_from'], params[2], params[3])
  elseif params[1] == 'bounce_to' then
    set_limit(settings['bounce_to'], params[2], params[3])
  elseif params[1] == 'bounce_to_ip' then
    set_limit(settings['bounce_to_ip'], params[2], params[3])
  elseif params[1] == 'user' then
    set_limit(settings['user'], params[2], params[3])
  else
    rspamd_logger.errx(rspamd_config, 'invalid limit type: ' .. params[1])
  end
end

local opts =  rspamd_config:get_all_opt('ratelimit')
if opts then
  local rates = opts['limit']
  if rates and type(rates) == 'table' then
    fun.each(parse_limit, rates)
  elseif rates and type(rates) == 'string' then
    parse_limit(rates)
  end

  if opts['rates'] and type(opts['rates']) == 'table' then
    -- new way of setting limits
    fun.each(function(t, lim)
      if type(lim) == 'table' and settings[t] then
        settings[t] = lim
      else
        rspamd_logger.errx(rspamd_config, 'bad rate: %s: %s', t, lim)
      end
    end, opts['rates'])
  end

  local enabled_limits = fun.totable(fun.map(function(t, lim)
    return t
  end, fun.filter(function(t, lim) return lim[1] > 0 end, settings)))
  rspamd_logger.infox(rspamd_config, 'enabled rate buckets: %s', enabled_limits)

  if opts['whitelisted_rcpts'] and type(opts['whitelisted_rcpts']) == 'string' then
    whitelisted_rcpts = rspamd_str_split(opts['whitelisted_rcpts'], ',')
  elseif type(opts['whitelisted_rcpts']) == 'table' then
    whitelisted_rcpts = opts['whitelisted_rcpts']
  end

  if opts['whitelisted_ip'] then
    whitelisted_ip = rspamd_config:add_radix_map(opts['whitelisted_ip'], 'Ratelimit whitelist ip map')
  end

  if opts['symbol'] then
    -- We want symbol instead of pre-result
    ratelimit_symbol = opts['symbol']
  end

  if opts['max_rcpt'] then
    max_rcpt = tonumber(opts['max_rcpt'])
  end

  if opts['max_delay'] then
    max_rcpt = tonumber(opts['max_delay'])
  end

  redis_params = rspamd_parse_redis_server('ratelimit')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
  else
    if not ratelimit_symbol then
      rspamd_config:register_pre_filter(rate_test)
    else
      rspamd_config:register_symbol({
        name = ratelimit_symbol,
        callback = rate_test,
        flags = 'empty'
      })
    end

    rspamd_config:register_post_filter(rate_set)
  end
end

