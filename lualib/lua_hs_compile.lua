--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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
Unified Hyperscan compilation service.

This module provides a single interface for compiling Hyperscan databases
with pluggable cache backends. It unifies the compilation paths used by
multipattern and re_cache.

Usage:
  local hs_compile = require "lua_hs_compile"

  -- Compile with caching (async)
  hs_compile.compile({
    patterns = {"pat1", "pat2"},
    flags = {0, 0},
    ids = {1, 2},
    cache_key = "my_patterns_hash",
    backend = backend_instance,  -- from lua_hs_cache
    callback = function(err, db) ... end
  })

  -- Compile with caching (sync, for initialization)
  local db, err = hs_compile.compile_sync({
    patterns = {"pat1", "pat2"},
    cache_key = "my_patterns_hash",
    backend = backend_instance,
  })
]]--

local rspamd_hyperscan = require "rspamd_hyperscan"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local logger = require "rspamd_logger"

local exports = {}
local N = "lua_hs_compile"

-- Check if hyperscan is available
exports.has_hyperscan = rspamd_hyperscan.has_hyperscan

-- Get platform identifier
exports.platform_id = rspamd_hyperscan.platform_id

-- Hyperscan flags (re-exported for convenience)
exports.flags = rspamd_hyperscan.flags or {}

--[[
Generate a cache key from patterns and flags.
@param patterns table of pattern strings
@param flags table of flag values (optional)
@return string cache key (hex hash)
]]--
function exports.generate_cache_key(patterns, flags)
  local h = rspamd_cryptobox_hash.create()

  for i, pat in ipairs(patterns) do
    h:update(pat)
    if flags and flags[i] then
      h:update(tostring(flags[i]))
    end
  end

  return h:hex():sub(1, 16)
end

--[[
Compile patterns into a hyperscan database with optional caching.
This is the async version suitable for use in workers with event loops.

@param opts table with:
  - patterns: table of pattern strings (required)
  - flags: table of HS_FLAG_* values (optional, default 0 for each)
  - ids: table of pattern IDs (optional, defaults to 1..n)
  - cache_key: string cache key (optional, auto-generated if not provided)
  - backend: cache backend instance from lua_hs_cache (optional)
  - ttl: cache TTL in seconds (optional)
  - callback: function(err, db) called on completion (required)
]]--
function exports.compile(opts)
  local callback = opts.callback
  if not callback then
    error("callback is required for async compile")
  end

  local patterns = opts.patterns
  if not patterns or #patterns == 0 then
    callback("no patterns provided", nil)
    return
  end

  if not rspamd_hyperscan.has_hyperscan() then
    callback("hyperscan not available", nil)
    return
  end

  local flags = opts.flags or {}
  local ids = opts.ids or {}
  local cache_key = opts.cache_key or exports.generate_cache_key(patterns, flags)
  local backend = opts.backend
  local ttl = opts.ttl
  local platform_id = rspamd_hyperscan.platform_id()

  -- Fill in default IDs if not provided
  if #ids == 0 then
    for i = 1, #patterns do
      ids[i] = i
    end
  end

  -- If no backend, compile directly
  if not backend then
    local db, err = rspamd_hyperscan.compile(patterns, flags, ids)
    if db then
      callback(nil, db)
    else
      callback(err or "compile failed", nil)
    end
    return
  end

  -- Try to load from cache first
  backend:load(cache_key, platform_id, function(load_err, data)
    if data then
      -- Validate the cached data
      local valid, valid_err = rspamd_hyperscan.validate(data)
      if valid then
        -- Deserialize
        local db, deser_err = rspamd_hyperscan.deserialize(data)
        if db then
          logger.debugx(N, "loaded cached hyperscan db for key %s", cache_key)
          callback(nil, db)
          return
        else
          logger.warnx(N, "failed to deserialize cached db for key %s: %s",
                       cache_key, deser_err)
        end
      else
        logger.debugx(N, "cached db for key %s is invalid: %s", cache_key, valid_err)
      end
    end

    -- Cache miss or invalid - compile
    local db, compile_err = rspamd_hyperscan.compile(patterns, flags, ids)
    if not db then
      callback(compile_err or "compile failed", nil)
      return
    end

    -- Serialize and store
    local blob = rspamd_hyperscan.serialize(db, ids, flags)
    if blob then
      backend:store(cache_key, platform_id, blob, ttl, function(store_err)
        if store_err then
          logger.warnx(N, "failed to store compiled db for key %s: %s",
                       cache_key, store_err)
        else
          logger.debugx(N, "stored compiled db for key %s (%d bytes)",
                        cache_key, #blob)
        end
      end)
    end

    callback(nil, db)
  end)
end

--[[
Compile patterns synchronously with optional caching.
This is suitable for use during initialization before event loops start.

@param opts table with same options as compile() except callback
@return db, err - database object or nil and error message
]]--
function exports.compile_sync(opts)
  local patterns = opts.patterns
  if not patterns or #patterns == 0 then
    return nil, "no patterns provided"
  end

  if not rspamd_hyperscan.has_hyperscan() then
    return nil, "hyperscan not available"
  end

  local flags = opts.flags or {}
  local ids = opts.ids or {}
  local cache_key = opts.cache_key or exports.generate_cache_key(patterns, flags)
  local backend = opts.backend
  local ttl = opts.ttl
  local platform_id = rspamd_hyperscan.platform_id()

  -- Fill in default IDs if not provided
  if #ids == 0 then
    for i = 1, #patterns do
      ids[i] = i
    end
  end

  -- If no backend, compile directly
  if not backend then
    return rspamd_hyperscan.compile(patterns, flags, ids)
  end

  -- For sync mode with backend, check if backend supports sync operations
  if backend.load_sync then
    local data = backend:load_sync(cache_key, platform_id)
    if data then
      local valid = rspamd_hyperscan.validate(data)
      if valid then
        local db = rspamd_hyperscan.deserialize(data)
        if db then
          logger.debugx(N, "loaded cached hyperscan db for key %s (sync)", cache_key)
          return db, nil
        end
      end
    end
  end

  -- Compile
  local db, compile_err = rspamd_hyperscan.compile(patterns, flags, ids)
  if not db then
    return nil, compile_err or "compile failed"
  end

  -- Try to store (best effort for sync mode)
  if backend.store_sync then
    local blob = rspamd_hyperscan.serialize(db, ids, flags)
    if blob then
      local ok = backend:store_sync(cache_key, platform_id, blob, ttl)
      if ok then
        logger.debugx(N, "stored compiled db for key %s (sync)", cache_key)
      end
    end
  end

  return db, nil
end

--[[
Validate a serialized hyperscan blob.
@param blob string or text containing serialized database
@return boolean, error_message
]]--
exports.validate = rspamd_hyperscan.validate

--[[
Deserialize a hyperscan database from blob.
@param blob string or text containing serialized database
@return db, error_message
]]--
exports.deserialize = rspamd_hyperscan.deserialize

--[[
Serialize a hyperscan database to blob.
@param db database object
@param ids optional table of pattern IDs
@param flags optional table of pattern flags
@return blob as rspamd_text or nil
]]--
exports.serialize = rspamd_hyperscan.serialize

--[[
Direct compilation without caching.
@param patterns table of pattern strings
@param flags table of flag values (optional)
@param ids table of pattern IDs (optional)
@return db, error_message
]]--
exports.compile_direct = rspamd_hyperscan.compile

return exports
