--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- A plugin that implements greylisting using redis

local redis_params
local whitelisted_ip
local settings = {
  expire = 86400, -- 1 day by default
  timeout = 300, -- 5 minutes by default
  key_prefix = 'rg', -- default hash name
  max_data_len = 10240, -- default data limit to hash
  message = 'Try again later', -- default greylisted message
  symbol = 'GREYLIST',
  ipv4_mask = 19, -- Mask bits for ipv4
  ipv6_mask = 64, -- Mask bits for ipv6
}

local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local fun = require "fun"
local rspamd_cryptobox = require "rspamd_cryptobox"
local hash = require "rspamd_cryptobox_hash"

local function data_key(task)
  local cached = task:get_mempool():get_variable("grey_bodyhash")
  if cached then
    return cached
  end

  local body = task:get_rawbody()

  if not body then return nil end

  local len = body:len()
  if len > settings['max_data_len'] then
    len = settings['max_data_len']
  end

  local h = hash.create()
  h:update(body, len)

  local b32 = settings['key_prefix'] .. 'b' .. h:base32():sub(1, 20)
  task:get_mempool():set_variable("grey_bodyhash", b32)
  return b32
end

local function envelope_key(task)
  local cached = task:get_mempool():get_variable("grey_metahash")
  if cached then
    return cached
  end

  local from = task:get_from('smtp')
  local h = hash.create()

  local addr = '<>'
  if from and from[1] then
    addr = from[1]['addr']
  end

  h:update(addr)
  local rcpt = task:get_recipients('smtp')
  if rcpt then
    table.sort(rcpt, function(r1, r2)
      return r1['addr'] < r2['addr']
    end)

    fun.each(function(r)
      h:update(r['addr'])
    end, rcpt)
  end

  local ip = task:get_from_ip()

  if ip and ip:is_valid() then
    local s
    if ip:get_version() == 4 then
      s = tostring(ip:apply_mask(settings['ipv4_mask']))
    else
      s = tostring(ip:apply_mask(settings['ipv6_mask']))
    end
    h:update(s)
  end

  local b32 = settings['key_prefix'] .. 'm' .. h:base32():sub(1, 20)
  task:get_mempool():set_variable("grey_metahash", b32)
  return b32
end

-- Returns pair of booleans: found,greylisted
local function check_time(task, tm, type)
  local t = tonumber(tm)

  if not t then
    rspamd_logger.infox(task, 'not a valid number: %s', tm)
    return false,false
  end

  local now = rspamd_util.get_time()
  if now - t < settings['timeout'] then
    return true,true
  else
    -- We just set variable to pass when in post-filter stage
    task:get_mempool():set_variable("grey_whitelisted", type)

    return true,false
  end

  return false,false
end

local function greylist_check(task)
  local body_key = data_key(task)
  local meta_key = envelope_key(task)
  local hash_key = body_key .. meta_key
  local upstream

  local function redis_set_cb(task, err, data)
    if not err then
      upstream:ok()
    else
      rspamd_logger.infox(task, 'got error %s when setting greylisting record on server %s',
          err, upstream:get_addr())
    end
  end

  local function redis_get_cb(task, err, data)
    local ret_body = false
    local greylisted_body = false
    local ret_meta = false
    local greylisted_meta = false
    local greylist_type

    if data then
      if data[1] and type(data[1]) ~= 'userdata' then
        ret_body,greylisted_body = check_time(task, data[1], 'body')
        if greylisted_body then
          local end_time = rspamd_util.time_to_string(rspamd_util.get_time()
            + settings['timeout'])
          task:get_mempool():set_variable("grey_greylisted_body", end_time)
        end
      end
      if data[2] and type(data[2]) ~= 'userdata' then
        if not ret_body or greylisted_body then
          ret_meta,greylisted_meta = check_time(task, data[2], 'meta')

          if greylisted_meta then
            local end_time = rspamd_util.time_to_string(rspamd_util.get_time()
               + settings['timeout'])
            task:get_mempool():set_variable("grey_greylisted_meta", end_time)
          end
        end
      end

      upstream:ok()

      if not ret_body and not ret_meta then
        local end_time = rspamd_util.time_to_string(rspamd_util.get_time()
          + settings['timeout'])
        task:get_mempool():set_variable("grey_greylisted", end_time)
      elseif greylisted_body and greylisted_meta then
        local end_time = rspamd_util.time_to_string(rspamd_util.get_time() +
          settings['timeout'])
        rspamd_logger.infox(task, 'greylisted until "%s" using %s key',
          end_time, type)
        task:insert_result(settings['symbol'], 0.0, 'greylisted', end_time,
          greylist_type)
        task:set_pre_result('soft reject', settings['message'])
      end
    elseif err then
      rspamd_logger.infox(task, 'got error while getting greylisting keys: %1', err)
      upstream:fail()
    end
  end

  local ret
  ret,_,upstream = rspamd_redis_make_request(task,
    redis_params, -- connect params
    hash_key, -- hash key
    false, -- is write
    redis_get_cb, --callback
    'MGET', -- command
    {body_key, meta_key} -- arguments
  )
  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to check results')
  end
end

local function greylist_set(task)
  local is_whitelisted = task:get_mempool():get_variable("grey_whitelisted")
  local do_greylisting = task:get_mempool():get_variable("grey_greylisted")

  local action = task:get_metric_action('default')
  if action == 'no action' or action == 'reject' then return end
  local body_key = data_key(task)
  local meta_key = envelope_key(task)
  local upstream, ret, conn
  local hash_key = body_key .. meta_key

  local function redis_set_cb(task, err, data)
    if not err then
      upstream:ok()
    else
      rspamd_logger.infox(task, 'got error %s when setting greylisting record on server %s',
          err, upstream:get_addr())
    end
  end

  if is_whitelisted then
    if action == 'greylist' then
      -- We are going to accept message
      task:set_metric_action('default', 'no action')
    end

    task:insert_result(settings['symbol'], 0.0, 'pass', is_whitelisted)
    rspamd_logger.infox(task, 'greylisting pass (%s) until %s',
      is_whitelisted,
      rspamd_util.time_to_string(rspamd_util.get_time() + settings['expire']))

    ret,conn,upstream = rspamd_redis_make_request(task,
      redis_params, -- connect params
      hash_key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'EXPIRE', -- command
      {body_key, tostring(settings['expire'])} -- arguments
    )
    -- Update greylisting record expire
    if conn then
      conn:add_cmd('EXPIRE', {
        meta_key, tostring(settings['expire'])
      })
    else
     rspamd_logger.infox(task, 'got error while connecting to redis: %1', addr)
     upstream:fail()
    end
  elseif do_greylisting then
    local t = tostring(math.floor(rspamd_util.get_time()))
    local end_time = rspamd_util.time_to_string(t + settings['timeout'])
    rspamd_logger.infox(task, 'greylisted until "%s", new record', end_time)
    task:insert_result(settings['symbol'], 0.0, 'greylisted', end_time,
      'new record')
    task:set_pre_result('soft reject', settings['message'])
    -- Create new record
    local ret, conn
    ret,conn,upstream = rspamd_redis_make_request(task,
      redis_params, -- connect params
      hash_key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'SETEX', -- command
      {body_key, tostring(settings['expire']), t} -- arguments
    )

    if conn then
      conn:add_cmd('SETEX', {
        meta_key, tostring(settings['expire']), t
      })
      local end_time = rspamd_util.time_to_string(rspamd_util.get_time()
        + settings['timeout'])
    else
      rspamd_logger.infox(task, 'got error while connecting to redis: %s',
      upstream:get_addr())
      upstream:fail()
    end
  else
    if action ~= 'no action' and action ~= 'reject' then
      local grey_res = task:get_mempool():get_variable("grey_greylisted_body")

      if grey_res then
        -- We need to delay message, hence set a temporary result
        task:insert_result(settings['symbol'], 0.0, grey_res, 'body')
        rspamd_logger.infox(task, 'greylisting delayed until "%s": body', grey_res)
      else
        grey_res = task:get_mempool():get_variable("grey_greylisted_meta")

        if grey_res then
          task:insert_result(settings['symbol'], 0.0, grey_res, 'meta')
          rspamd_logger.infox(task, 'greylisting delayed until "%s": meta', grey_res)
        else
          task:insert_result(settings['symbol'], 0.0, 'greylisted', 'redis fail')
          return
        end
      end
      task:set_metric_action('default', 'soft reject')
      task:set_pre_result('soft reject', settings['message'])
    else
      task:insert_result(settings['symbol'], 0.0, 'greylisted', 'passed')
    end
  end
end

local opts =  rspamd_config:get_all_opt('greylist')
if opts then
  if opts['whitelisted_ip'] then
    whitelisted_ip = rspamd_config:add_radix_map(opts['whitelisted_ip'],
      'Greylist whitelist ip map')
  end

  redis_params = rspamd_parse_redis_server('greylist')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
  else
    rspamd_config:register_symbol({
      name = 'GREYLIST_SAVE',
      type = 'postfilter',
      callback = greylist_set,
      priority = 10
    })
    rspamd_config:register_symbol({
      name = 'GREYLIST_CHECK',
      type = 'prefilter',
      callback = greylist_check,
    })
  end

  for k,v in pairs(opts) do
    settings[k] = v
  end
end
