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
]] --

--[[[
-- @module lua_cache
-- This module provides a Redis-based caching API for Rspamd with support for
-- concurrent operations across multiple workers. It includes features like
-- distributed locking via PENDING markers, automatic key hashing,
-- configurable serialization formats, and TTL management.
--
@example
local redis_cache = require "lua_cache"
local redis_params = redis_lib.parse_redis_server('reputation')

-- Create cache context
local cache_context = redis_cache.create_cache_context(redis_params, {
  cache_prefix = "rspamd_reputation",
  cache_ttl = 86400, -- 1 day
  cache_format = "json",
  cache_hash_len = 16,
  cache_use_hashing = true
})

-- Example usage in a task
local function process_url_reputation(task, url)
  local cache_key = url:get_tld()

  -- Try to get data from cache first
  redis_cache.cache_get(task, cache_key, cache_context, 5.0,
    -- This callback is called on cache miss
    function(task)
      -- Perform expensive reputation lookup
      local reputation = calculate_reputation(task, url)

      -- Store result in cache for future use
      redis_cache.cache_set(task, cache_key, {
        score = reputation.score,
        categories = reputation.categories,
        timestamp = os.time()
      }, cache_context)

      -- Use the result
      apply_reputation_rules(task, url, reputation)
    end,
    -- This callback is called when cache data is available
    function(task, err, data)
      if err then
        logger.errx(task, "Cache error for %s: %s", cache_key, err)
        return
      end

      -- Use the cached data
      apply_reputation_rules(task, url, data)
    end
  )
end
--]]

local logger = require "rspamd_logger"
local ucl = require "ucl"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local lua_redis = require "lua_redis"
local hasher = require "rspamd_cryptobox_hash"

local N = "lua_cache"
local exports = {}

-- Default options
local default_opts = {
  cache_prefix = "rspamd_cache",
  cache_ttl = 3600,         -- 1 hour
  cache_probes = 5,         -- Number of times to check a pending key
  cache_format = "json",    -- Serialization format
  cache_hash_len = 16,      -- Number of hex symbols to use for hashed keys
  cache_use_hashing = false -- Whether to hash keys by default
}

-- Create a hash of the key using the configured length
local function hash_key(key, hash_len)
  local h = hasher.create(key)
  local hex = h:hex()

  if hash_len and hash_len > 0 and hash_len < #hex then
    return string.sub(hex, 1, hash_len)
  end

  return hex
end

-- Get the appropriate key based on hashing configuration
local function get_cache_key(raw_key, cache_context, force_hashing)
  -- Determine whether to hash based on context settings and force parameter
  local should_hash = force_hashing
  if should_hash == nil then
    should_hash = cache_context.opts.cache_use_hashing
  end

  if should_hash then
    local raw_len = (type(raw_key) == 'string') and #raw_key or -1
    lua_util.debugm(N, rspamd_config, "hashing cache key (len=%s) with hash length %s",
      raw_len, cache_context.opts.cache_hash_len)
    return hash_key(raw_key, cache_context.opts.cache_hash_len)
  else
    return raw_key
  end
end

-- Create a caching context with the provided options
local function create_cache_context(redis_params, opts, module_name)
  if not redis_params then
    return nil, "Redis parameters must be provided"
  end

  local cache_context = {}
  cache_context.redis_params = redis_params

  -- Process and merge configuration options
  cache_context.opts = lua_util.override_defaults(default_opts, opts)
  cache_context.N = module_name or N

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
    opts.cache_hash_len = nil
    opts.cache_use_hashing = nil
  end

  -- Set serialization and deserialization functions
  if cache_context.opts.cache_format == "messagepack" then
    lua_util.debugm(cache_context.N, rspamd_config, "using messagepack for serialization")

    cache_context.encode = function(data)
      return ucl.to_format(data, 'msgpack')
    end

    cache_context.decode = function(raw_data)
      local ucl_parser = ucl.parser()
      local ok, ucl_err = ucl_parser:parse_text(raw_data, 'messagepack')
      if not ok then
        lua_util.debugm(cache_context.N, rspamd_config, "failed to parse messagepack data: %s", ucl_err)
        return nil
      end
      return ucl_parser:get_object()
    end
  else
    -- Default to JSON
    lua_util.debugm(cache_context.N, rspamd_config, "using json for serialization")

    cache_context.encode = function(data)
      return ucl.to_format(data, 'json')
    end

    cache_context.decode = function(raw_data)
      local ucl_parser = ucl.parser()
      local ok, ucl_err = ucl_parser:parse_text(raw_data)
      if not ok then
        lua_util.debugm(cache_context.N, rspamd_config, "failed to parse json data: %s", ucl_err)
        return nil
      end
      return ucl_parser:get_object()
    end
  end

  lua_util.debugm(cache_context.N, rspamd_config, "cache context created: %s", cache_context.opts)
  return cache_context
end

-- Encode data for storage in Redis with proper formatting
local function encode_data(data, cache_context)
  lua_util.debugm(cache_context.N, rspamd_config, "encoding data using %s format", cache_context.opts.cache_format)
  return cache_context.encode(data)
end

-- Decode data from Redis with proper formatting
local function decode_data(data, cache_context)
  if not data then
    lua_util.debugm(cache_context.N, rspamd_config, "cannot decode nil data")
    return nil
  end
  lua_util.debugm(cache_context.N, rspamd_config, "decoding data using %s format", cache_context.opts.cache_format)
  return cache_context.decode(data)
end

-- Check if a value is a PENDING marker and extract its details
local function parse_pending_value(value, cache_context)
  if type(value) ~= 'string' then
    lua_util.debugm(cache_context.N, rspamd_config, "value is not a string, cannot be a pending marker")
    return nil
  end

  -- Check if the value starts with PENDING:
  if string.sub(value, 1, 8) ~= "PENDING:" then
    lua_util.debugm(cache_context.N, rspamd_config, "value doesn't start with PENDING: prefix")
    return nil
  end

  lua_util.debugm(cache_context.N, rspamd_config, "found PENDING marker, extracting data")
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

  lua_util.debugm(cache_context.N, rspamd_config, "creating PENDING marker for host %s, timeout %s",
    hostname, timeout)

  return "PENDING:" .. encode_data(pending_data, cache_context)
end

-- Check cache and handle the result appropriately
local function cache_get(task, key, cache_context, timeout, callback_uncached, callback_data)
  if not task or not key or not cache_context or not callback_uncached or not callback_data then
    logger.errx(task, "missing required parameters for cache_get")
    return false
  end

  local full_key = cache_context.opts.cache_prefix .. "_" .. get_cache_key(key, cache_context, nil)
  lua_util.debugm(cache_context.N, task, "cache lookup for key: %s", full_key)

  -- Function to check a pending key
  local function check_pending(pending_info)
    local probe_count = 0
    local probe_interval = timeout / (cache_context.opts.cache_probes or 5)

    lua_util.debugm(cache_context.N, task, "setting up probes for pending key %s, interval: %s seconds",
      full_key, probe_interval)

    -- Set up a timer to probe the key
    local function probe_key()
      probe_count = probe_count + 1
      lua_util.debugm(cache_context.N, task, "probe #%s/%s for pending key %s",
        probe_count, cache_context.opts.cache_probes, full_key)

      if probe_count >= cache_context.opts.cache_probes then
        logger.infox(task, "maximum probes reached for key %s, considering it failed", full_key)
        lua_util.debugm(cache_context.N, task, "maximum probes reached for key %s, giving up", full_key)
        callback_data(task, "timeout waiting for pending key", nil)
        return
      end

      lua_util.debugm(cache_context.N, task, "probing redis for key %s", full_key)
      lua_redis.redis_make_request(task, cache_context.redis_params, key, false,
        function(err, data)
          if err then
            logger.errx(task, "redis error while probing key %s: %s", full_key, err)
            lua_util.debugm(cache_context.N, task, "redis error during probe: %s, retrying later", err)
            task:add_timer(probe_interval, probe_key)
            return
          end

          if not data or type(data) == 'userdata' then
            lua_util.debugm(cache_context.N, task, "pending key %s disappeared, calling uncached handler", full_key)
            callback_uncached(task)
            return
          end

          local pending = parse_pending_value(data, cache_context)
          if pending then
            lua_util.debugm(cache_context.N, task, "key %s still pending (host: %s), retrying later",
              full_key, pending.hostname)
            task:add_timer(probe_interval, probe_key)
          else
            lua_util.debugm(cache_context.N, task, "pending key %s resolved to actual data", full_key)
            callback_data(task, nil, decode_data(data, cache_context))
          end
        end,
        'GET', { full_key }
      )
    end

    -- Start the first probe after the initial probe interval
    lua_util.debugm(cache_context.N, task, "scheduling first probe for %s in %s seconds",
      full_key, probe_interval)
    task:add_timer(probe_interval, probe_key)
  end

  -- Initial cache lookup
  lua_util.debugm(cache_context.N, task, "making initial redis GET request for key: %s", full_key)
  lua_redis.redis_make_request(task, cache_context.redis_params, key, false,
    function(err, data)
      if err then
        logger.errx(task, "redis error looking up key %s: %s", full_key, err)
        lua_util.debugm(cache_context.N, task, "redis error: %s, calling uncached handler", err)
        callback_uncached(task)
        return
      end

      if not data or type(data) == 'userdata' then
        -- Key not found, set pending and call the uncached callback
        lua_util.debugm(cache_context.N, task, "key %s not found in cache, creating pending marker", full_key)
        local pending_marker = create_pending_marker(timeout, cache_context)

        lua_util.debugm(cache_context.N, task, "setting pending marker for key %s with TTL %s",
          full_key, timeout * 2)
        lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
          function(set_err, set_data)
            if set_err then
              logger.errx(task, "redis error setting pending marker for %s: %s", full_key, set_err)
              lua_util.debugm(cache_context.N, task, "failed to set pending marker: %s", set_err)
            else
              lua_util.debugm(cache_context.N, task, "successfully set pending marker for %s", full_key)
            end
            lua_util.debugm(cache_context.N, task, "calling uncached handler for %s", full_key)
            callback_uncached(task)
          end,
          'SETEX', { full_key, tostring(timeout * 2), pending_marker }
        )
      else
        -- Key found, check if it's a pending marker or actual data
        local pending = parse_pending_value(data, cache_context)

        if pending then
          -- Key is being processed by another worker
          lua_util.debugm(cache_context.N, task, "key %s is pending on host %s, waiting for result",
            full_key, pending.hostname)
          check_pending(pending)
        else
          -- Extend TTL and return data
          lua_util.debugm(cache_context.N, task, "found cached data for key %s, extending TTL to %s",
            full_key, cache_context.opts.cache_ttl)
          lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
            function(expire_err, _)
              if expire_err then
                logger.errx(task, "redis error extending TTL for %s: %s", full_key, expire_err)
                lua_util.debugm(cache_context.N, task, "failed to extend TTL: %s", expire_err)
              else
                lua_util.debugm(cache_context.N, task, "successfully extended TTL for %s", full_key)
              end
            end,
            'EXPIRE', { full_key, tostring(cache_context.opts.cache_ttl) }
          )

          lua_util.debugm(cache_context.N, task, "returning cached data for key %s", full_key)
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

  local full_key = cache_context.opts.cache_prefix .. "_" .. get_cache_key(key, cache_context, nil)
  local ttl = cache_context.opts.cache_ttl
  local expire_at = os.time() + ttl
  lua_util.debugm(cache_context.N, task, "caching data for key: %s with TTL: %s (expiring at: %s)",
    full_key, ttl, os.date('%Y-%m-%d %H:%M:%S', expire_at))

  local encoded_data = encode_data(data, cache_context)

  -- Store the data with expiration
  lua_util.debugm(cache_context.N, task, "making redis SETEX request for key: %s", full_key)
  return lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
    function(err, result)
      if err then
        logger.errx(task, "redis error setting cached data for %s: %s", full_key, err)
        lua_util.debugm(cache_context.N, task, "failed to cache data: %s", err)
      else
        lua_util.debugm(cache_context.N, task, "successfully cached data for key %s, expiring at %s",
          full_key, os.date('%Y-%m-%d %H:%M:%S', expire_at))
      end
    end,
    'SETEX', { full_key, tostring(ttl), encoded_data }
  )
end

-- Delete a cache entry
local function cache_del(task, key, cache_context)
  if not task or not key or not cache_context then
    logger.errx(task, "missing required parameters for cache_del")
    return false
  end

  local full_key = cache_context.opts.cache_prefix .. "_" .. get_cache_key(key, cache_context, nil)
  lua_util.debugm(cache_context.N, task, "deleting cache key: %s", full_key)

  return lua_redis.redis_make_request(task, cache_context.redis_params, key, true,
    function(err, result)
      if err then
        logger.errx(task, "redis error deleting cache key %s: %s", full_key, err)
        lua_util.debugm(cache_context.N, task, "failed to delete cache key: %s", err)
      else
        local count = tonumber(result) or 0
        lua_util.debugm(cache_context.N, task, "successfully deleted cache key %s (%s keys removed)",
          full_key, count)
      end
    end,
    'DEL', { full_key }
  )
end

-- Export the API functions
---[[[
-- @function lua_cache.create_cache_context(redis_params, opts, module_name)
-- Creates a Redis caching context with specified parameters and options
-- @param {table} redis_params Redis connection parameters (required)
-- @param {table} opts Optional configuration parameters:
--   * `cache_prefix`: Key prefix for Redis (default: "rspamd_cache")
--   * `cache_ttl`: TTL in seconds for cached entries (default: 3600)
--   * `cache_probes`: Number of times to check pending keys (default: 5)
--   * `cache_format`: Serialization format - "json" or "messagepack" (default: "json")
--   * `cache_hash_len`: Number of hex symbols for hashed keys (default: 16)
--   * `cache_use_hashing`: Whether to hash keys by default (default: true)
-- @return {table} Cache context or nil + error message on failure
--]]
exports.create_cache_context = create_cache_context
---[[[
-- @function ç.cache_get(task, key, cache_context, timeout, callback_uncached, callback_data)
-- Retrieves data from cache, handling pending states and cache misses appropriately
-- @param {rspamd_task} task Current task (required)
-- @param {string} key Cache key (required)
-- @param {table} cache_context Redis cache context from create_cache_context (required)
-- @param {number} timeout Timeout for pending operations in seconds (required)
-- @param {function} callback_uncached Function to call on cache miss: callback_uncached(task) (required)
-- @param {function} callback_data Function to call when data is available: callback_data(task, err, data) (required)
-- @return {boolean} true if request was initiated successfully, false otherwise
--]]
exports.cache_get = cache_get
---[[[
-- @function lua_cache.cache_set(task, key, data, cache_context)
-- Stores data in the cache with the configured TTL
-- @param {rspamd_task} task Current task (required)
-- @param {string} key Cache key (required)
-- @param {table} data Data to store in the cache (required)
-- @param {table} cache_context Redis cache context from create_cache_context (required)
-- @return {boolean} true if request was initiated successfully, false otherwise
--]]
exports.cache_set = cache_set
---[[[
-- @function lua_cache.cache_del(task, key, cache_context)
-- Deletes data from the cache
-- @param {rspamd_task} task Current task (required)
-- @param {string} key Cache key (required)
-- @param {table} cache_context Redis cache context from create_cache_context (required)
-- @return {boolean} true if request was initiated successfully, false otherwise
--]]
exports.cache_del = cache_del

return exports
