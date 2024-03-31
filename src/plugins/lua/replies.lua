--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>
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

if confighelp then
  return
end

local rspamd_logger = require 'rspamd_logger'
local hash = require 'rspamd_cryptobox_hash'
local lua_util = require 'lua_util'
local lua_redis = require 'lua_redis'
local fun = require "fun"

-- A plugin that implements replies check using redis

-- Default port for redis upstreams
local redis_params
local settings = {
  action = nil,
  expire = 86400, -- 1 day by default
  key_prefix = 'rr',
  key_size = 20,
  sender_prefix = 'rsrk',
  message = 'Message is reply to one we originated',
  symbol = 'REPLY',
  score = -4, -- Default score
  use_auth = true,
  use_local = true,
  cookie = nil,
  cookie_key = nil,
  cookie_is_pattern = false,
  cookie_valid_time = '2w', -- 2 weeks by default
  min_message_id = 2, -- minimum length of the message-id header
  reply_sender_privacy = false,
  reply_sender_privacy_alg = 'blake2',
  reply_sender_privacy_prefix = 'obf',
  reply_sender_privacy_length = 16,
}

local N = "replies"

local function make_key(goop, sz, prefix)
  local h = hash.create()
  h:update(goop)
  local key = (prefix or '') .. h:base32():sub(1, sz)
  return key
end

local function replies_check(task)
  local in_reply_to
  local function check_recipient(stored_rcpt)
    local rcpts = task:get_recipients('mime')
    lua_util.debugm(N, task, 'recipients: %s', rcpts)
    if rcpts then
      local filter_predicate = function(input_rcpt)
        local real_rcpt_h = make_key(input_rcpt:lower(), 8)

        return real_rcpt_h == stored_rcpt
      end

      if fun.any(filter_predicate, fun.map(function(rcpt)
        return rcpt.addr or ''
      end, rcpts)) then
        lua_util.debugm(N, task, 'reply to %s validated', in_reply_to)

        --storing only addr of rcpt
        for i = 1, #rcpts do
          rcpts[i] = rcpts[i].addr
        end
        return rcpts
      end

      rspamd_logger.infox(task, 'ignoring reply to %s as no recipients are matching hash %s',
          in_reply_to, stored_rcpt)
    else
      rspamd_logger.infox(task, 'ignoring reply to %s as recipient cannot be detected for hash %s',
          in_reply_to, stored_rcpt)
    end

    return nil
  end

  local function add_to_global_replies_set(params, sender_key)
    lua_util.debugm(N, task, 'Adding recipients %s to global replies set', params)

    local function zadd_global_set_cb(err, data)
      if err ~= nil then
        rspamd_logger.errx(task, 'failed to add sender %s to global replies set with error: %s', sender_key, err)
        return
      end
      rspamd_logger.infox(task, 'added sender %s to global set with code: %s', sender_key, data)
    end

    table.insert(params, 1, 'rsrk_verified_recipients')

    lua_redis.redis_make_request(task, -- making global replies set for verified recipients
            redis_params, -- connect params
            sender_key, -- hash key
            true, -- is write
            zadd_global_set_cb, --callback
            'ZADD', -- command
            params -- arguments
    )

  end

  local function update_global_replies_set(params, sender_key)
    local last_score = -1

    -- getting last score of recipients
    local function redis_zrange_cb(err, data)
      if err ~= nil then
        rspamd_logger.errx(task,
                'redis_zrange_cb error when reading zrange withscores from global replies set with error: %s', err)
        return
      end
      last_score = tonumber(data[#data])
      lua_util.debugm(N, task, 'last score %s of global replies set was received', last_score)

      -- if last score wasn't found
      if last_score == -1 or last_score == nil then
        lua_util.debugm(N,
                task, 'have not found any senders in global replies set, considering last score as 0')
        last_score = 0
      end

      -- updating params considering last score of existing sender
      for i = 1, #params, 2 do
        params[i] = params[i] + last_score
      end

      add_to_global_replies_set(params, sender_key)
    end

    lua_util.debugm(N, task, 'Getting recipients withscores from global replies set to get last score')

    -- getting scores of recipients connected to sender
    lua_redis.redis_make_request(task,
            redis_params,
            sender_key,
            false,
            redis_zrange_cb,
            'ZRANGE',
            {'rsrk_verified_recipients', '0', '-1', 'WITHSCORES'}
    )
  end

  local function add_to_replies_set(recipients)
    local sender = task:get_reply_sender()

    local task_time = task:get_timeval(true)

    local params = {}
    -- making params out of recipients list for replies set
    local task_time_str = tostring(task_time)
    for _, rcpt in ipairs(recipients) do
      table.insert(params, task_time_str)
      table.insert(params, tostring(rcpt))
    end

    local sender_string = lua_util.maybe_obfuscate_string(tostring(sender), settings, settings.sender_prefix)
    local sender_key = make_key(sender_string:lower(), 8)

    lua_util.debugm(N, task,
            'Adding recipients %s to sender %s local replies set', recipients, sender_key)

    table.insert(params, 1, sender_key)

    local function zadd_cb(err, data)
      if err ~= nil then
        rspamd_logger.errx(task, 'adding to %s failed with error: %s', sender_key, err)
        return
      end
      table.remove(params, 1)

      lua_util.debugm(N, task, 'added data: %s to sender: %s with code: %s', params, sender_key, data)
      update_global_replies_set(params, sender_key)
    end

    local _, conn, _ = lua_redis.redis_make_request(task, -- making local replies set (sender - recipients)
            redis_params, -- connect params
            sender_key, -- hash key
            true, -- is write
            zadd_cb, --callback
            'ZADD', -- command
            params -- arguments
    )
    -- adding expiration to the local replies set
    conn:add_cmd('EXPIRE', { sender_key, tostring(math.floor(settings['expire'])) })
  end

  local function redis_get_cb(err, data, addr)
    if err ~= nil then
      rspamd_logger.errx(task, 'redis_get_cb error when reading data from %s: %s', addr:get_addr(), err)
      return
    end
    local recipients = check_recipient(data)
    if type(data) == 'string' and recipients then
      -- Hash was found
      add_to_replies_set(recipients)
      task:insert_result(settings['symbol'], 1.0)
      if settings['action'] ~= nil then
        local ip_addr = task:get_ip()
        if (settings.use_auth and
            task:get_user()) or
            (settings.use_local and ip_addr and ip_addr:is_local()) then
          rspamd_logger.infox(task, "not forcing action for local network or authorized user");
        else
          task:set_pre_result(settings['action'], settings['message'], N)
        end
      end
    end
  end
  -- If in-reply-to header not present return
  in_reply_to = task:get_header_raw('in-reply-to')
  if not in_reply_to then
    return
  end
  -- Create hash of in-reply-to and query redis
  local key = make_key(in_reply_to, settings.key_size, settings.key_prefix)

  local ret = lua_redis.redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_get_cb, --callback
      'GET', -- command
      { key } -- arguments
  )

  if not ret then
    rspamd_logger.errx(task, "redis request wasn't scheduled")
  end


end

local function replies_set(task)
  local function redis_set_cb(err, _, addr)
    if err ~= nil then
      rspamd_logger.errx(task, 'redis_set_cb error when writing data to %s: %s', addr:get_addr(), err)
    end
  end
  -- If sender is unauthenticated return
  local ip = task:get_ip()
  if settings.use_auth and task:get_user() then
    lua_util.debugm(N, task, 'sender is authenticated')
  elseif settings.use_local and (ip and ip:is_local()) then
    lua_util.debugm(N, task, 'sender is from local network')
  else
    return
  end
  -- If no message-id present return
  local msg_id = task:get_header_raw('message-id')
  if msg_id == nil or msg_id:len() <= (settings.min_message_id or 2) then
    return
  end
  -- Create hash of message-id and store to redis
  local key = make_key(msg_id, settings.key_size, settings.key_prefix)

  local sender = task:get_reply_sender()

  if sender then
    local sender_hash = make_key(sender:lower(), 8)
    lua_util.debugm(N, task, 'storing id: %s (%s), reply-to: %s (%s) for replies check',
        msg_id, key, sender, sender_hash)
    local ret = lua_redis.redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        true, -- is write
        redis_set_cb, --callback
        'PSETEX', -- command
        { key, tostring(math.floor(settings['expire'] * 1000)), sender_hash } -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, "redis request wasn't scheduled")
    end
  else
    rspamd_logger.infox(task, "cannot find reply sender address")
  end
end

local function replies_check_cookie(task)
  local function cookie_matched(extra, ts)
    local dt = task:get_date { format = 'connect', gmt = true }

    if dt < ts then
      rspamd_logger.infox(task, 'ignore cookie as its date is in future')

      return
    end

    if settings.cookie_valid_time then
      if dt - ts > settings.cookie_valid_time then
        rspamd_logger.infox(task,
            'ignore cookie as its timestamp is too old: %s (%s current time)',
            ts, dt)

        return
      end
    end

    if extra then
      task:insert_result(settings['symbol'], 1.0,
          string.format('cookie:%s:%s', extra, ts))
    else
      task:insert_result(settings['symbol'], 1.0,
          string.format('cookie:%s', ts))
    end
    if settings['action'] ~= nil then
      local ip_addr = task:get_ip()
      if (settings.use_auth and
          task:get_user()) or
          (settings.use_local and ip_addr and ip_addr:is_local()) then
        rspamd_logger.infox(task, "not forcing action for local network or authorized user");
      else
        task:set_pre_result(settings['action'], settings['message'], N)
      end
    end
  end

  -- If in-reply-to header not present return
  local irt = task:get_header('in-reply-to')
  if irt == nil then
    return
  end
  local cr = require "rspamd_cryptobox"
  -- Extract user part if needed
  local extracted_cookie = irt:match('^%<?([^@]+)@.*$')
  if not extracted_cookie then
    -- Assume full message id as a cookie
    extracted_cookie = irt
  end

  local dec_cookie, ts = cr.decrypt_cookie(settings.cookie_key, extracted_cookie)

  if dec_cookie then
    -- We have something that looks like a cookie
    if settings.cookie_is_pattern then
      local m = dec_cookie:match(settings.cookie)

      if m then
        cookie_matched(m, ts)
      end
    else
      -- Direct match
      if dec_cookie == settings.cookie then
        cookie_matched(nil, ts)
      end
    end
  end
end

local opts = rspamd_config:get_all_opt('replies')
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'module is unconfigured')
  return
end
if opts then
  settings = lua_util.override_defaults(settings, opts)
  redis_params = lua_redis.parse_redis_server('replies')
  if not redis_params then
    if not (settings.cookie and settings.cookie_key) then
      rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
      lua_util.disable_module(N, "redis")
    else
      -- Cookies mode
      -- Check key sanity:
      local pattern = { '^' }
      for i = 1, 32 do
        pattern[i + 1] = '[a-zA-Z0-9]'
      end
      pattern[34] = '$'
      if not settings.cookie_key:match(table.concat(pattern, '')) then
        rspamd_logger.errx(rspamd_config,
            'invalid cookies key: %s, must be 32 hex digits', settings.cookie_key)
        lua_util.disable_module(N, "config")

        return
      end

      if settings.cookie_valid_time then
        settings.cookie_valid_time = lua_util.parse_time_interval(settings.cookie_valid_time)
      end

      lua_redis.register_prefix(settings.sender_prefix, N,
              'Prefix to identify replies sets')

      local id = rspamd_config:register_symbol({
        name = 'REPLIES_CHECK',
        type = 'prefilter',
        callback = replies_check_cookie,
        flags = 'nostat',
        priority = lua_util.symbols_priorities.medium,
        group = "replies"
      })
      rspamd_config:register_symbol({
        name = settings['symbol'],
        parent = id,
        type = 'virtual',
        score = settings.score,
        group = "replies",
      })
    end
  else
    rspamd_config:register_symbol({
      name = 'REPLIES_SET',
      type = 'idempotent',
      callback = replies_set,
      group = 'replies',
      flags = 'explicit_disable,ignore_passthrough',
    })
    local id = rspamd_config:register_symbol({
      name = 'REPLIES_CHECK',
      type = 'prefilter',
      flags = 'nostat',
      callback = replies_check,
      priority = lua_util.symbols_priorities.medium,
      group = "replies"
    })
    rspamd_config:register_symbol({
      name = settings['symbol'],
      parent = id,
      type = 'virtual',
      score = settings.score,
      group = "replies",
    })
  end
end
