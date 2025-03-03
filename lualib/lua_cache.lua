--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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

--[[
Cache API implementation for Rspamd using Redis
]]--

local logger = require "rspamd_logger"
local ucl = require "ucl"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local lua_redis = require "lua_redis"

local N = "lua_cache"
local exports = {}

-- Default options
local default_opts = {
  cache_prefix = "rspamd_cache",
  cache_ttl = 3600, -- 1 hour
  cache_probes = 5, -- Number of times to check a pending key
  cache_format = "json", -- Serialization format
}

-- Create a caching context with the provided options
local function create_cache_context(redis_params, opts)
  if not redis_params then
    return nil, "Redis parameters must be provided"
  end

  local cache_context = {}
  cache_context.redis_params = redis_params

  -- Process and merge configuration options
  cache_context.opts = lua_util.override_defaults(default_opts, opts)

  -- Register Redis prefix
  lua_redis.register_prefix(cache_context.opts.cache_prefix,
      "caching",
      "Cache API prefix")

  lua_util.debugm(N, rspamd_config, "registered redis prefix: %s", cache_context.opts.cache_prefix)

  -- Remove cache related options from opts table
  if opts then
    lua_util.debugm(N, rspamd_config, "removing cache options from original opts table")
    opts.cache_prefix = nil
    opts.cache_ttl = nil
    opts.cache_probes = nil
    opts.cache_format = nil
  end

  -- Set serialization and deserialization functions
  if cache_context.opts.cache_format == "messagepack" then
    lua_util.debugm(N, rspamd_config, "using messagepack for serialization")

    cache_context.encode = function(data)
      return ucl.to_format(data, 'msgpack')
    end

    cache_context.decode = function(raw_data)
      local ucl_parser = ucl.parser()
      local ok, ucl_err = ucl_parser:parse_text(raw_data, 'messagepack')
      if not ok then
        lua_util.debugm(N, rspamd_config, "failed to parse messagepack data: %s", ucl_err)
        return nil
      end
      return ucl_parser:get_object()
    end
  else
    -- Default to JSON
    lua_util.debugm(N, rspamd_config, "using json for serialization")

    cache_context.encode = function(data)
      return ucl.to_format(data, 'json')
    end

    cache_context.decode = function(raw_data)
      local ucl_parser = ucl.parser()
      local ok, ucl_err = ucl_parser:parse_text(raw_data)
      if not ok then
        lua_util.debugm(N, rspamd_config, "failed to parse json data: %s", ucl_err)
        return nil
      end
      return ucl_parser:get_object()
    end
  end

  lua_util.debugm(N, rspamd_config, "cache context created: %s", cache_context.opts)
  return cache_context
end

-- Encode data for storage in Redis with proper formatting
local function encode_data(data, cache_context)
  lua_util.debugm(N, rspamd_config, "encoding data using %s format", cache_context.opts.cache_format)
  return cache_context.encode(data)
end

-- Decode data from Redis with proper formatting
local function decode_data(data, cache_context)
  if not data then
    lua_util.debugm(N, rspamd_config, "cannot decode nil data")
    return nil
  end
  lua_util.debugm(N, rspamd_config, "decoding data using %s format", cache_context.opts.cache_format)
  return cache_context.decode(data)
end

-- Check if a value is a PENDING marker and extract its details
local function parse_pending_value(value, cache_context)
  if type(value) ~= 'string' then
    lua_util.debugm(N, rspamd_config, "value is not a string, cannot be a pending marker")
    return nil
  end

  -- Check if the value starts with PENDING:
  if string.sub(value, 1, 8) ~= "PENDING:" then
    lua_util.debugm(N, rspamd_config, "value doesn't start with PENDING: prefix")
    return nil
  end

  lua_util.debugm(N, rspamd_config, "found PENDING marker, extracting data")
  local pending_data = string.sub(value, 9)
  return decode_data(pending_data, cache_context)
end

-- Create a pending marker with hostname and timeout
local function create_pending_marker(timeout, cache_context)
  local hostname = rspamd_util.get_hostname()
  local pending_data = {
    hostname = hostname,
    timeout = timeout,
    timestamp = os.time()
  }

  lua_util.debugm(N, rspamd_config, "creating PENDING marker for host %s, timeout %s",
      hostname, timeout)

  return "PENDING:" .. encode_data(pending_data, cache_context)
end

-- Check cache and handle the result appropriately
local function cache_get(task, key, cache_context, timeout, callback_uncached, callback_data)
  if not task or not key or not cache_context or not callback_uncached or not callback_data then
    logger.errx(task, "missing required parameters for cache_get")
    return false
  end

  local full_key = cache_context.opts.cache_prefix .. ":" .. key
  lua_util.debugm(N, task, "cache lookup for key: %s", full_key)

  -- Function to check a pending key
  local function check_pending(pending_info)
    local probe_count = 0
    local probe_interval = timeout / (cache_context.opts.cache_probes or 5)

    lua_util.debugm(N, task, "setting up probes for pending key %s, interval: %s seconds",
        full_key, probe_interval)

    -- Set up a timer to probe the key
    local function probe_key()
      probe_count = probe_count + 1
      lua_util.debugm(N, task, "probe #%d/%d for pending key %s",
          probe_count, cache_context.opts.cache_probes, full_key)

      if probe_count >= cache_context.opts.cache_probes then
        logger.infox(task, "maximum probes reached for key %s, considering it failed", full_key)
        lua_util.debugm(N, task, "maximum probes reached for key %s, giving up", full_key)
        callback_data(task, "timeout waiting for pending key", nil)
        return
      end

      lua_util.debugm(N, task, "probing redis for key %s", full_key)
      lua_redis.redis_make_request(task, cache_context.redis_params, key, false,
          function(err, data)
            if err then
              logger.errx(task, "redis error while probing key %s: %s", full_key, err)
              lua_util.debugm(N, task, "redis error during probe: %s, retrying later", err)
              task:add_timer(probe_interval, probe_key)
              return
            end

            if not data or type(data) == 'userdata' then
              lua_util.debugm(N, task, "pending key %s disappeared, calling uncached handler", full_key)
              callback_uncached(task)
              return
            end

            local pending = parse_pending_value(data, cache_context)
            if pending then
              lua_util.debugm(N, task, "key %s still pending (host: %s), retrying later",
                  full_key, pending.hostname)
              task:add_timer(probe_interval, probe_key)
            else
              lua_util.debugm(N, task, "pending key %s resolved to actual data", full_key)
              callback_data(task, nil, decode_data(data, cache_context))
            end
          end,
          'GET', { full_key }
      )
    end

    -- Start the first probe after the initial probe interval
    lua_util.debugm(N, task, "scheduling first probe for %s in %s seconds",
        full_key, probe_interval)
    task:add_timer(probe_interval, probe_key)
  end

  -- Initial cache lookup
  lua_util.debugm(N, task, "making initial redis GET request for key: %s", full_key)
  lua_redis.redis_make_request(task, cache_context.redis_params, key, false,
      function(err, data)
        if err then
          logger.errx(task, "redis error looking up key %s: %s", full_key, err)
          lua_util.debugm(N, task, "redis error: %s, calling uncached handler", err)
          callback_uncached(task)
          return
        end

        if not data or type(data) == 'userdata' then
          -- Key not found, set pending and call the uncached callback
          lua_util.debugm(N, task, "key %s not found in cache, creating pending marker", full_key)
          local pending_marker = create_pending_marker(timeout, cache_context)

          lua_util.debugm(N, task, "setting pending marker for key %s with TTL %s",
              full_key, timeout * 2)
          lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
              function(set_err, set_data)
                if set_err then
                  logger.errx(task, "redis error setting pending marker for %s: %s", full_key, set_err)
                  lua_util.debugm(N, task, "failed to set pending marker: %s", set_err)
                else
                  lua_util.debugm(N, task, "successfully set pending marker for %s", full_key)
                end
                lua_util.debugm(N, task, "calling uncached handler for %s", full_key)
                callback_uncached(task)
              end,
              'SETEX', { full_key, tostring(timeout * 2), pending_marker }
          )
        else
          -- Key found, check if it's a pending marker or actual data
          local pending = parse_pending_value(data, cache_context)

          if pending then
            -- Key is being processed by another worker
            lua_util.debugm(N, task, "key %s is pending on host %s, waiting for result",
                full_key, pending.hostname)
            check_pending(pending)
          else
            -- Extend TTL and return data
            lua_util.debugm(N, task, "found cached data for key %s, extending TTL to %s",
                full_key, cache_context.opts.cache_ttl)
            lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
                function(expire_err, _)
                  if expire_err then
                    logger.errx(task, "redis error extending TTL for %s: %s", full_key, expire_err)
                    lua_util.debugm(N, task, "failed to extend TTL: %s", expire_err)
                  else
                    lua_util.debugm(N, task, "successfully extended TTL for %s", full_key)
                  end
                end,
                'EXPIRE', { full_key, tostring(cache_context.opts.cache_ttl) }
            )

            lua_util.debugm(N, task, "returning cached data for key %s", full_key)
            callback_data(task, nil, decode_data(data, cache_context))
          end
        end
      end,
      'GET', { full_key }
  )

  return true
end

-- Save data to the cache
local function cache_set(task, key, data, cache_context)
  if not task or not key or not data or not cache_context then
    logger.errx(task, "missing required parameters for cache_set")
    return false
  end

  local full_key = cache_context.opts.cache_prefix .. ":" .. key
  lua_util.debugm(N, task, "caching data for key: %s with TTL: %s",
      full_key, cache_context.opts.cache_ttl)

  local encoded_data = encode_data(data, cache_context)

  -- Store the data with expiration
  lua_util.debugm(N, task, "making redis SETEX request for key: %s", full_key)
  return lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
      function(err, result)
        if err then
          logger.errx(task, "redis error setting cached data for %s: %s", full_key, err)
          lua_util.debugm(N, task, "failed to cache data: %s", err)
        else
          lua_util.debugm(N, task, "successfully cached data for key %s", full_key)
        end
      end,
      'SETEX', { full_key, tostring(cache_context.opts.cache_ttl), encoded_data }
  )
end

-- Delete a cache entry
local function cache_del(task, key, cache_context)
  if not task or not key or not cache_context then
    logger.errx(task, "missing required parameters for cache_del")
    return false
  end

  local full_key = cache_context.opts.cache_prefix .. ":" .. key
  lua_util.debugm(N, task, "deleting cache key: %s", full_key)

  return lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
      function(err, result)
        if err then
          logger.errx(task, "redis error deleting cache key %s: %s", full_key, err)
          lua_util.debugm(N, task, "failed to delete cache key: %s", err)
        else
          local count = tonumber(result) or 0
          lua_util.debugm(N, task, "successfully deleted cache key %s (%d keys removed)",
              full_key, count)
        end
      end,
      'DEL', { full_key }
  )
end

-- Export the API functions
exports.create_cache_context = create_cache_context
exports.cache_get = cache_get
exports.cache_set = cache_set
exports.cache_del = cache_del

return exports
