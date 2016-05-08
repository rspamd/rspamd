--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
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

-- A plugin that implements replies check using redis

-- Default port for redis upstreams
local default_port = 6379
local upstreams
local whitelisted_ip
local settings = {
  action = nil,
  expire = 86400, -- 1 day by default
  key_prefix = 'rr',
  message = 'Message is reply to one we originated',
  symbol = 'REPLY',
}

local rspamd_logger = require 'rspamd_logger'
local rspamd_redis = require 'rspamd_redis'
local upstream_list = require 'rspamd_upstream_list'
local hash = require 'rspamd_cryptobox_hash'

local function make_key(goop)
  local h = hash.create()
  h:update(goop)
  local key = h:base32():sub(1, 20)
  key = settings['key_prefix'] .. key
  return key
end

local function replies_check(task)
  local function redis_get_cb(task, err, data)
    if err ~= nil then
      rspamd_logger.errx('redis_get_cb received error: %1', err)
      return
    end
    if data == '1' then
      -- Hash was found
      task:insert_result(settings['symbol'], 0.0)
      if settings['action'] ~= nil then
        task:set_pre_result(settings['action'], settings['message'])
      end
    end
  end
  -- If in-reply-to header not present return
  local irt = task:get_header_raw('in-reply-to')
  if irt == nil then
    return
  end
  -- Create hash of in-reply-to and query redis
  local key = make_key(irt)
  local upstream = upstreams:get_upstream_by_hash(key)
  local addr = upstream:get_addr()
  if not rspamd_redis.make_request({task = task, host = addr, callback = redis_get_cb,
      cmd = 'GET', args = {key}}) then
    rspamd_logger.errx("redis request wasn't scheduled")
  end
end

local function replies_set(task)
  local function redis_set_cb(task, err, data)
    if err ~=nil then
      rspamd_logger.errx('redis_set_cb received error: %1', err)
    end
  end
  -- If sender is unauthenticated return
  if task:get_user() == nil then
    return
  end
  -- If no message-id present return
  local msg_id = task:get_header_raw('message-id')
  if msg_id == nil then
    return
  end
  -- Create hash of message-id and store to redis
  local key = make_key(msg_id)
  local upstream = upstreams:get_upstream_by_hash(key)
  local addr = upstream:get_addr()
  if not addr then
    rspamd_logger.errx("couldn't get address for upstream")
    return
  end
  if not rspamd_redis.make_request({task = task, host = addr, callback = redis_set_cb,
      cmd = 'SET', args = {key, 1, "ex", settings['expire']}}) then
    rspamd_logger.errx("redis request wasn't scheduled")
  end
end

local opts = rspamd_config:get_all_opt('replies')
if opts then
  if not opts['servers'] then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
  else
    upstreams = upstream_list.create(rspamd_config, opts['servers'], default_port)
    if not upstreams then
      rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    else
      rspamd_config:register_pre_filter(replies_check)
      rspamd_config:register_post_filter(replies_set, 10)
    end
  end

  for k,v in pairs(opts) do
    settings[k] = v
  end
end
