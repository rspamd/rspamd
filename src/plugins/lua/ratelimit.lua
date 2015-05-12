--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

-- A plugin that implements ratelimits using redis or kvstorage server

-- Default port for redis upstreams
local default_port = 6379
-- Default settings for limits, 1-st member is burst, second is rate and the third is numeric type
local settings = {
  -- Limit for all mail per recipient (burst 100, rate 2 per minute)
  to = {[1] = 100, [2] = 0.033333333, [3] = 1},
  -- Limit for all mail per one source ip (burst 30, rate 1.5 per minute)
  to_ip = {[1] = 30, [2] = 0.025, [3] = 2},
  -- Limit for all mail per one source ip and from address (burst 20, rate 1 per minute)
  to_ip_from = {[1] = 20, [2] = 0.01666666667, [3] = 3},

  -- Limit for all bounce mail (burst 10, rate 2 per hour)
  bounce_to = {[1] = 10, [2] = 0.000555556, [3] = 4},
  -- Limit for bounce mail per one source ip (burst 5, rate 1 per hour)
  bounce_to_ip = {[1] = 5 , [2] = 0.000277778, [3] = 5},

  -- Limit for all mail per user (authuser) (burst 20, rate 1 per minute)
  user = {[1] = 20, [2] = 0.01666666667, [3] = 6}

}
-- Senders that are considered as bounce
local bounce_senders = {'postmaster', 'mailer-daemon', '', 'null', 'fetchmail-daemon', 'mdaemon'}
-- Do not check ratelimits for these senders
local whitelisted_rcpts = {'postmaster', 'mailer-daemon'}
local whitelisted_ip = nil
local max_rcpt = 5
local upstreams = nil

local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"
local _ = require "fun"
--local dumper = require 'pl.pretty'.dump

--- Parse atime and bucket of limit
local function parse_limits(data)
  local function parse_limit_elt(str)
    local pos,_ = string.find(str, ':')
    if not pos then
      return {0, 0}
    else
      local atime = tonumber(string.sub(str, 1, pos - 1))
      local bucket = tonumber(string.sub(str, pos + 1))
      return {atime,bucket}
    end
  end
  
  return _.iter(data):map(function(e) 
    if type(e) == 'string' then 
      return parse_limit_elt(e)
    else
      return {0, 0}
    end
    end):totable()
end

local function generate_format_string(args, is_set)
  if is_set then
    return 'MSET'
    --return _.foldl(function(acc, k) return acc .. ' %s %s' end, 'MSET', args)
  end
  return 'MGET'
  --return _.foldl(function(acc, k) return acc .. ' %s' end, 'MGET', args)
end

--- Check specific limit inside redis
local function check_limits(task, args)

  local key = _.foldl(function(acc, k) return acc .. k[2] end, '', args)
  local upstream = upstreams:get_upstream_by_hash(key)
  local addr = upstream:get_addr()
  --- Called when value was set on server
  local function rate_set_key_cb(task, err, data)
    if err then
      rspamd_logger.info('got error while getting limit: ' .. err)
      upstream:fail()
    else
      upstream:ok()
    end
  end
  --- Called when value is got from server
  local function rate_get_cb(task, err, data)
    if data then
      local tv = task:get_timeval()
      local ntime = tv['tv_usec'] / 1000000. + tv['tv_sec']
      
      _.each(function(elt, limit)
        local bucket = elt[2]
        local rate = limit[2]
        local threshold = limit[1]
        local atime = elt[1]
        
        bucket = bucket - rate * (ntime - atime);
        if bucket > 0 then
          if bucket > threshold then
            task:set_pre_result('soft reject', 'Ratelimit exceeded')
          end
        end
      end, _.zip(parse_limits(data), _.map(function(a) return a[1] end, args)))
    elseif err then
      rspamd_logger.info('got error while getting limit: ' .. err)
      upstream:fail()
    end
  end
  
  if upstream then
    local cmd = generate_format_string(args, false)
    
    rspamd_redis.make_request(task, addr, rate_get_cb, cmd, 
      _.totable(_.map(function(l) return l[2] end, args)))
  end
end

--- Set specific limit inside redis
local function set_limits(task, args)
  local key = _.foldl(function(acc, k) return acc .. k[2] end, '', args)
  local upstream = upstreams:get_upstream_by_hash(key)
  local addr = upstream:get_addr()

  local function rate_set_key_cb(task, err, data)
    if err then
      rspamd_logger.info('got error while setting limit: ' .. err)
      upstream:fail()
    else
      upstream:ok()
    end
  end
 
  local function rate_set_cb(task, err, data)
    if data then
      local tv = task:get_timeval()
      local ntime = tv['tv_usec'] / 1000000. + tv['tv_sec']
      local values = {}
      _.each(function(elt, limit)
        local bucket = elt[2]
        local rate = limit[1][2]
        local threshold = limit[1][1]
        local atime = elt[1]
        
        if bucket > 0 then
          bucket = bucket - rate * (ntime - atime) + 1;
          if bucket < 0 then
            bucket = 1
          end
        else
          bucket = 1
        end
        local lstr = string.format('%.3f:%.3f', ntime, bucket)
        table.insert(values, limit[2])
        table.insert(values, lstr)
      end, _.zip(parse_limits(data), _.iter(args)))
      
      local cmd = generate_format_string(values, true)
      rspamd_redis.make_request(task, addr, rate_set_key_cb, cmd, values)
    elseif err then
      rspamd_logger.info('got error while setting limit: ' .. err)
      upstream:fail()
    end
  end
  if upstream then
    local cmd = generate_format_string(args, false)
    
    rspamd_redis.make_request(task, addr, rate_set_cb, cmd,
      _.totable(_.map(function(l) return l[2] end, args)))
  end
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
  return _.any(function(b) return b == from end, bounce_senders)
end

--- Check or update ratelimit
local function rate_test_set(task, func)
  local args = {}
  -- Get initial task data
  local ip = task:get_from_ip()
  if ip and ip:is_valid() and whitelisted_ip then
    if whitelisted_ip:get_key(ip) then
      -- Do not check whitelisted ip
      rspamd_logger.info('skip ratelimit for whitelisted IP')
      return
    end
  end
  -- Parse all rcpts
  local rcpts = task:get_recipients()
  local rcpts_user = {}
  if rcpts then
    _.each(function(r) table.insert(rcpts_user, r['user']) end, rcpts)
    if _.any(function(r) 
      _.any(function(w) return r == w end, whitelisted_rcpts) end, 
      rcpts_user) then
      
      rspamd_logger.info('skip ratelimit for whitelisted recipient')
      return
    end
  end
  -- Parse from
  local from = task:get_from()
  local from_user = '<>'
  local from_addr = '<>'
  if from then
    from_user = from[1]['user']
    from_addr = from[1]['addr']
  end
  -- Get user (authuser)
  local auser = task:get_user()
  if auser then
    table.insert(args, {settings['user'], make_rate_key (auser, '<auth>', nil)})
  end

  local is_bounce = check_bounce(from_user)

  if rcpts then
    _.each(function(r)
      if is_bounce then
        table.insert(args, {settings['bounce_to'], make_rate_key ('<>', r['addr'], nil)})
        if ip then
          table.insert(args, {settings['bounce_to_ip'], make_rate_key ('<>', r['addr'], ip)})
        end
      end
      table.insert(args, {settings['to'], make_rate_key (nil, r['addr'], nil)})
      if ip then
        table.insert(args, {settings['to_ip'], make_rate_key (nil, r['addr'], ip)})
        table.insert(args, {settings['to_ip_from'], make_rate_key (from_addr, r['addr'], ip)})
      end
    end, rcpts)
  end
  
  func(task, args)
end

--- Check limit
local function rate_test(task)
  rate_test_set(task, check_limits)
end
--- Update limit
local function rate_set(task)
  rate_test_set(task, set_limits)
end


--- Utility function for split string to table
local function split(str, delim, maxNb)
  -- Eliminate bad cases...
  if string.find(str, delim) == nil then
    return { str }
  end
  if maxNb == nil or maxNb < 1 then
    maxNb = 0    -- No limit
  end
  local result = {}
  local pat = "(.-)" .. delim .. "()"
  local nb = 0
  local lastPos
  for part, pos in string.gmatch(str, pat) do
    nb = nb + 1
    result[nb] = part
    lastPos = pos
    if nb == maxNb then break end
  end
  -- Handle the last field
  if nb ~= maxNb then
    result[nb + 1] = string.sub(str, lastPos)
  end
  return result
end

--- Parse a single limit description
local function parse_limit(str)
  local params = split(str, ':', 0)

  local function set_limit(limit, burst, rate)
    limit[1] = tonumber(burst)
    limit[2] = tonumber(rate)
  end

  if table.maxn(params) ~= 3 then
    rspamd_logger.err('invalid limit definition: ' .. str)
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
    rspamd_logger.err('invalid limit type: ' .. params[1])
  end
end

-- Registration
if rspamd_config:get_api_version() >= 9 then
  rspamd_config:register_module_option('ratelimit', 'servers', 'string')
  rspamd_config:register_module_option('ratelimit', 'bounce_senders', 'string')
  rspamd_config:register_module_option('ratelimit', 'whitelisted_rcpts', 'string')
  rspamd_config:register_module_option('ratelimit', 'whitelisted_ip', 'map')
  rspamd_config:register_module_option('ratelimit', 'limit', 'string')
  rspamd_config:register_module_option('ratelimit', 'max_rcpt', 'uint')
end

local function parse_whitelisted_rcpts(str)

end

local opts =  rspamd_config:get_all_opt('ratelimit')
if opts then
  local rates = opts['limit']
  if rates and type(rates) == 'table' then
    _.each(parse_limit, rates)
  elseif rates and type(rates) == 'string' then
    parse_limit(rates)
  end

  if opts['whitelisted_rcpts'] and type(opts['whitelisted_rcpts']) == 'string' then
    whitelisted_rcpts = split(opts['whitelisted_rcpts'], ',')
  end

  if opts['whitelisted_ip'] then
    whitelisted_ip = rspamd_config:add_radix_map(opts['whitelisted_ip'], 'Ratelimit whitelist ip map')
  end

  if opts['max_rcpt'] then
    max_rcpt = tonumber(opts['max_rcpt'])
  end

  if not opts['servers'] then
    rspamd_logger.err('no servers are specified')
  else
    upstreams = upstream_list.create(opts['servers'], default_port)
    if not upstreams then
      rspamd_logger.err('no servers are specified')
    else
      rspamd_config:register_pre_filter(rate_test)
      rspamd_config:register_post_filter(rate_set)
    end
  end
end

