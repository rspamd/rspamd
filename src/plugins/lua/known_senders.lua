--[[
Copyright (c) 2023, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- This plugin implements known senders logic for Rspamd

local rspamd_logger = require "rspamd_logger"
local ts = (require "tableshape").types
local N = 'known_senders'
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local lua_maps = require "lua_maps"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"

if confighelp then
  rspamd_config:add_example(nil, 'known_senders',
      "Maintain a list of known senders using Redis",
      [[
known_senders {
  # Domains to track senders
  domains = "https://maps.rspamd.com/freemail/free.txt.zst";
  # Maximum number of elements
  max_senders = 100000;
  # Maximum time to live (when not using bloom filters)
  max_ttl = 30d;
  # Use bloom filters (must be enabled in Redis as a plugin)
  use_bloom = false;
  # Insert symbol for new senders from the specific domains
  symbol_unknown = 'UNKNOWN_SENDER';
}
  ]])
  return
end

local redis_params
local settings = {
  domains = {},
  max_senders = 100000,
  max_ttl = 30 * 86400,
  use_bloom = false,
  symbol = 'KNOWN_SENDER',
  symbol_unknown = 'UNKNOWN_SENDER',
  symbol_check_mail = 'INC_MAIL_KNOWN',
  redis_key = 'rs_known_senders',
  sender_prefix = 'rsrk',
  sender_key_global = 'verified_senders',
  sender_key_size = 20,
  reply_sender_privacy = false,
  reply_sender_privacy_alg = 'blake2',
  reply_sender_privacy_prefix = 'obf',
  reply_sender_privacy_length = 16,
}

local settings_schema = lua_redis.enrich_schema({
  domains = lua_maps.map_schema,
  enabled = ts.boolean:is_optional(),
  max_senders = (ts.integer + ts.string / tonumber):is_optional(),
  max_ttl = (ts.integer + ts.string / tonumber):is_optional(),
  use_bloom = ts.boolean:is_optional(),
  redis_key = ts.string:is_optional(),
  symbol = ts.string:is_optional(),
  symbol_unknown = ts.string:is_optional(),
})

local function make_key(input)
  local hash = rspamd_cryptobox_hash.create_specific('md5')
  hash:update(input.addr)
  return hash:hex()
end

local function make_key_replies(goop, sz, prefix)
  local h = rspamd_cryptobox_hash.create()
  h:update(goop)
  local key = (prefix or '') .. h:base32():sub(1, sz)
  return key
end

local function check_redis_key(task, key, key_ty)
  lua_util.debugm(N, task, 'check key %s, type: %s', key, key_ty)
  local function redis_zset_callback(err, data)
    lua_util.debugm(N, task, 'got data: %s', data)
    if err then
      rspamd_logger.errx(task, 'redis error: %s', err)
    elseif data then
      if type(data) ~= 'userdata' then
        -- non-null reply
        task:insert_result(settings.symbol, 1.0, string.format("%s:%s", key_ty, key))
      else
        if settings.symbol_unknown then
          task:insert_result(settings.symbol_unknown, 1.0, string.format("%s:%s", key_ty, key))
        end
        lua_util.debugm(N, task, 'insert key %s, type: %s', key, key_ty)
        -- Insert key to zset and trim it's cardinality
        lua_redis.redis_make_request(task,
            redis_params, -- connect params
            key, -- hash key
            true, -- is write
            nil, --callback
            'ZADD', -- command
            { settings.redis_key, tostring(task:get_timeval(true)), key } -- arguments
        )
        lua_redis.redis_make_request(task,
            redis_params, -- connect params
            key, -- hash key
            true, -- is write
            nil, --callback
            'ZREMRANGEBYRANK', -- command
            { settings.redis_key, '0',
              tostring(-(settings.max_senders + 1)) } -- arguments
        )
      end
    end
  end

  local function redis_bloom_callback(err, data)
    lua_util.debugm(N, task, 'got data: %s', data)
    if err then
      rspamd_logger.errx(task, 'redis error: %s', err)
    elseif data then
      if type(data) ~= 'userdata' and data == 1 then
        -- non-null reply equal to `1`
        task:insert_result(settings.symbol, 1.0, string.format("%s:%s", key_ty, key))
      else
        if settings.symbol_unknown then
          task:insert_result(settings.symbol_unknown, 1.0, string.format("%s:%s", key_ty, key))
        end
        lua_util.debugm(N, task, 'insert key %s, type: %s', key, key_ty)
        -- Reserve bloom filter space
        lua_redis.redis_make_request(task,
            redis_params, -- connect params
            key, -- hash key
            true, -- is write
            nil, --callback
            'BF.RESERVE', -- command
            { settings.redis_key, tostring(settings.max_senders), '0.01', '1000', 'NONSCALING' } -- arguments
        )
        -- Insert key and adjust bloom filter
        lua_redis.redis_make_request(task,
            redis_params, -- connect params
            key, -- hash key
            true, -- is write
            nil, --callback
            'BF.ADD', -- command
            { settings.redis_key, key } -- arguments
        )
      end
    end
  end

  if settings.use_bloom then
    lua_redis.redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_bloom_callback, --callback
        'BF.EXISTS', -- command
        { settings.redis_key, key } -- arguments
    )
  else
    lua_redis.redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_zset_callback, --callback
        'ZSCORE', -- command
        { settings.redis_key, key } -- arguments
    )
  end
end

local function known_senders_callback(task)
  local mime_from = (task:get_from('mime') or {})[1]
  local smtp_from = (task:get_from('smtp') or {})[1]
  local mime_key, smtp_key
  if mime_from and mime_from.addr then
    if settings.domains:get_key(mime_from.domain) then
      mime_key = make_key(mime_from)
    else
      lua_util.debugm(N, task, 'skip mime from domain %s', mime_from.domain)
    end
  end
  if smtp_from and smtp_from.addr then
    if settings.domains:get_key(smtp_from.domain) then
      smtp_key = make_key(smtp_from)
    else
      lua_util.debugm(N, task, 'skip smtp from domain %s', smtp_from.domain)
    end
  end

  if mime_key and smtp_key and mime_key ~= smtp_key then
    -- Check both keys
    check_redis_key(task, mime_key, 'mime')
    check_redis_key(task, smtp_key, 'smtp')
  elseif mime_key then
    -- Check mime key
    check_redis_key(task, mime_key, 'mime')
  elseif smtp_key then
    -- Check smtp key
    check_redis_key(task, smtp_key, 'smtp')
  end
end

local function check_known_incoming_mail_callback(task)
  local sender = task:get_reply_sender()
  if not sender then
    lua_util.debugm(N, task, 'Could not get sender')
    return nil
  end

  -- making sender key
  lua_util.debugm(N, task, 'Sender: %s', sender)

  local sender_string = lua_util.maybe_obfuscate_string(tostring(sender), settings, settings.sender_prefix)
  local sender_key = make_key_replies(sender_string:lower(), 8)

  lua_util.debugm(N, task, 'Sender key: %s', sender_key)


  local function redis_zrange_cb(err, data)
    if err ~= nil then
      rspamd_logger.errx(task, 'Couldn\'t get data from global replies set. Ended with error: %s', err)
      return
    end

    rspamd_logger.infox(task, 'Successfully got list: %s of verified senders', data)

    -- searching for sender in global replies set
    if data then
      for _, sndr in ipairs(data) do
        if sndr == sender then
          task:insert_result(settings.symbol_check_mail, 1.0, sndr)
        end
      end
    end
  end

  -- key for global replies set
  local global_key = make_key_replies(settings.sender_key_global, settings.sender_key_size, settings.sender_prefix)

  lua_util.debugm(N, task, 'Making redis request to global replies set')
  lua_redis.redis_make_request(task,
          redis_params, -- connect params
          sender_key, -- hash key
          false, -- is write
          redis_zrange_cb, --callback
          'ZRANGE', -- command
          { global_key, '0', '-1' } -- arguments
  )

end

local opts = rspamd_config:get_all_opt('known_senders')
if opts then
  settings = lua_util.override_defaults(settings, opts)
  local res, err = settings_schema:transform(settings)
  if not res then
    rspamd_logger.errx(rspamd_config, 'cannot parse known_senders options: %1', err)
  else
    settings = res
  end
  redis_params = lua_redis.parse_redis_server(N, opts)

  if redis_params then
    local map_conf = settings.domains
    settings.domains = lua_maps.map_add_from_ucl(settings.domains,
            'set', 'domains to track senders from')
    if not settings.domains then
      rspamd_logger.errx(rspamd_config, "couldn't add map %s, disable module",
          map_conf)
      lua_util.disable_module(N, "config")
      return
    end
    lua_redis.register_prefix(settings.redis_key, N,
        'Known elements redis key', {
          type = 'zset/bloom filter',
        })
    lua_redis.register_prefix(settings.sender_prefix, N,
        'Prefix to identify replies sets')
    local id = rspamd_config:register_symbol({
      name = settings.symbol,
      type = 'normal',
      callback = known_senders_callback,
      one_shot = true,
      score = -1.0,
      augmentations = { string.format("timeout=%f", redis_params.timeout or 0.0) }
    })

    rspamd_config:register_symbol({
      name = settings.symbol_check_mail,
      type = 'normal',
      callback = check_known_incoming_mail_callback,
      score = 1.0
    })

    if settings.symbol_unknown and #settings.symbol_unknown > 0 then
      rspamd_config:register_symbol({
        name = settings.symbol_unknown,
        type = 'virtual',
        parent = id,
        one_shot = true,
        score = 0.5,
      })
    end
  else
    lua_util.disable_module(N, "redis")
  end
end
