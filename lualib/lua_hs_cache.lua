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

local logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"

local exports = {}
-- Use "hyperscan" module name so debug output is enabled together with C code
local N = "hyperscan"

-- File backend
local file_backend = {}
file_backend.__index = file_backend

-- Zstd magic number: 0xFD2FB528 (little-endian bytes: 28 B5 2F FD)
local ZSTD_MAGIC = string.char(0x28, 0xB5, 0x2F, 0xFD)

function file_backend.new(config)
  local self = setmetatable({}, file_backend)
  -- Store config for logging context
  self.config = config.rspamd_config or config
  -- Remove trailing slashes from cache_dir
  local cache_dir = config.cache_dir or '/var/lib/rspamd/hs_cache'
  self.cache_dir = cache_dir:gsub("/+$", "")
  -- Default to flat directory structure for backward compatibility
  self.platform_dirs = config.platform_dirs == true
  -- Enable compression by default (consistent with redis/http backends)
  local opts = config.file or config
  self.use_compression = (opts.compression ~= false) and (config.compression ~= false)
  lua_util.debugm(N, self.config, "file backend config: cache_dir=%s, platform_dirs=%s, compression=%s",
      self.cache_dir, self.platform_dirs and "yes" or "no",
      self.use_compression and "enabled" or "disabled")
  return self
end

-- Get file extension based on compression setting
function file_backend:_get_extension()
  return self.use_compression and '.hs.zst' or '.hs'
end

-- Get the path for a cache file
-- @param cache_key string cache key (hash that already includes platform info)
-- @param platform_id string platform identifier (unused in flat mode for backward compat)
-- @param ext string optional extension override (e.g., '.hs' or '.hs.zst')
function file_backend:_get_path(cache_key, platform_id, ext)
  local extension = ext or self:_get_extension()
  if self.platform_dirs then
    -- Optional: use platform subdirectories (not default)
    return string.format("%s/%s/%s%s", self.cache_dir, platform_id, cache_key, extension)
  else
    -- Default: flat structure matching original C code behavior
    -- Platform info is already embedded in cache_key hash
    return string.format("%s/%s%s", self.cache_dir, cache_key, extension)
  end
end

-- Check if data starts with zstd magic bytes
function file_backend:_is_zstd(data)
  if not data or #data < 4 then
    return false
  end
  return data:sub(1, 4) == ZSTD_MAGIC
end

-- Find existing cache file, trying both compressed and uncompressed extensions
-- Returns: path, is_compressed (or nil if not found)
function file_backend:_find_existing_path(cache_key, platform_id)
  -- Try compressed first if compression is enabled, otherwise try uncompressed first
  local primary_ext = self:_get_extension()
  local secondary_ext = self.use_compression and '.hs' or '.hs.zst'

  local primary_path = self:_get_path(cache_key, platform_id, primary_ext)
  -- rspamd_util.stat returns (err, stat_table) - check for no error AND valid stat
  local err, stat = rspamd_util.stat(primary_path)
  if not err and stat then
    return primary_path, primary_ext == '.hs.zst'
  end

  local secondary_path = self:_get_path(cache_key, platform_id, secondary_ext)
  err, stat = rspamd_util.stat(secondary_path)
  if not err and stat then
    return secondary_path, secondary_ext == '.hs.zst'
  end

  return nil, nil
end

function file_backend:_ensure_dir(path)
  local dir = path:match("(.*/)")
  if dir then
    local ok, err = rspamd_util.mkdir(dir, true)
    if not ok and err then
      logger.warnx(N, "failed to create directory %s: %s", dir, err)
    end
  end
end

function file_backend:exists(cache_key, platform_id, callback)
  local path, is_compressed = self:_find_existing_path(cache_key, platform_id)

  if path then
    local err, stat = rspamd_util.stat(path)
    if not err and stat then
      lua_util.debugm(N, self.config, "file exists check: %s found, size: %d, compressed: %s",
          path, stat.size, is_compressed and "yes" or "no")
      callback(nil, true, { size = stat.size, mtime = stat.mtime, compressed = is_compressed })
    else
      -- Race condition: file disappeared between _find_existing_path and stat
      lua_util.debugm(N, self.config, "file exists check: %s disappeared (race)", path)
      callback(nil, false, nil)
    end
  else
    local expected_path = self:_get_path(cache_key, platform_id)
    lua_util.debugm(N, self.config, "file exists check: %s not found (checked both extensions)", expected_path)
    callback(nil, false, nil)
  end
end

function file_backend:load(cache_key, platform_id, callback)
  local path, expected_compressed = self:_find_existing_path(cache_key, platform_id)

  if not path then
    local expected_path = self:_get_path(cache_key, platform_id)
    lua_util.debugm(N, self.config, "file load failed: %s not found (checked both extensions)", expected_path)
    callback("file not found", nil)
    return
  end

  lua_util.debugm(N, self.config, "file load from: %s (expected compressed: %s)", path, expected_compressed and "yes" or "no")

  local f, err = io.open(path, "rb")
  if not f then
    lua_util.debugm(N, self.config, "file load failed from %s: %s", path, err or "open error")
    callback(err or "open error", nil)
    return
  end
  local data = f:read("*a")
  f:close()
  if not data then
    lua_util.debugm(N, self.config, "file read failed from %s", path)
    callback("read error", nil)
    return
  end

  -- Check if data is actually zstd compressed (magic byte verification)
  local is_zstd = self:_is_zstd(data)
  lua_util.debugm(N, self.config, "file loaded %d bytes from %s, zstd magic: %s",
      #data, path, is_zstd and "yes" or "no")

  -- Notify hyperscan cache that this file is known (for cleanup tracking)
  rspamd_util.hyperscan_notice_known(path)

  if is_zstd then
    -- Decompress the data
    local decompress_err, decompressed = rspamd_util.zstd_decompress(data)
    if not decompress_err and decompressed then
      lua_util.debugm(N, self.config, "file decompressed %d -> %d bytes from %s (compression ratio: %.1f%%)",
          #data, #decompressed, path, (1 - #data / #decompressed) * 100)
      callback(nil, decompressed)
    else
      lua_util.debugm(N, self.config, "file decompression failed for %s: %s", path, decompress_err or "unknown error")
      callback(decompress_err or "decompression failed", nil)
    end
  else
    -- Data is not compressed, return as-is
    if expected_compressed then
      lua_util.debugm(N, self.config, "file %s has .zst extension but no zstd magic - treating as uncompressed", path)
    end
    callback(nil, data)
  end
end

function file_backend:store(cache_key, platform_id, data, _ttl, callback)
  local path = self:_get_path(cache_key, platform_id)

  lua_util.debugm(N, self.config, "file store to: %s, original size: %d bytes, compression: %s",
      path, #data, self.use_compression and "enabled" or "disabled")

  self:_ensure_dir(path)

  local store_data = data
  -- Compress if enabled
  if self.use_compression then
    local compressed, compress_err = rspamd_util.zstd_compress(data)
    if compressed then
      lua_util.debugm(N, self.config, "file compressed %d -> %d bytes (%.1f%% size reduction) for %s",
          #data, #compressed, (1 - #compressed / #data) * 100, path)
      store_data = compressed
    else
      logger.warnx(N, "compression failed: %s, storing uncompressed to %s", compress_err, path)
    end
  end

  -- Write to temp file first, then rename atomically
  local tmp_path = path .. ".tmp." .. rspamd_util.random_hex(8)
  -- store_data can be string or rspamd_text userdata
  local ok, write_err
  if type(store_data) == "userdata" and store_data.save_in_file then
    ok, write_err = store_data:save_in_file(tmp_path)
  else
    local f, err = io.open(tmp_path, "wb")
    if not f then
      callback(err or "open failed")
      return
    end
    ok, write_err = f:write(store_data)
    f:close()
  end
  if not ok then
    os.remove(tmp_path)
    callback(write_err or "write failed")
    return
  end

  do
    local renamed, rename_err = os.rename(tmp_path, path)
    if renamed then
      lua_util.debugm(N, self.config, "stored %d bytes to %s", #store_data, path)
      -- Notify hyperscan cache that this file is known (for cleanup tracking)
      rspamd_util.hyperscan_notice_known(path)
      -- Remove old file with opposite extension if it exists (migration cleanup)
      local old_ext = self.use_compression and '.hs' or '.hs.zst'
      local old_path = self:_get_path(cache_key, platform_id, old_ext)
      local old_err, old_stat = rspamd_util.stat(old_path)
      if not old_err and old_stat then
        local removed = os.remove(old_path)
        if removed then
          lua_util.debugm(N, self.config, "removed old cache file %s (migrated to %s)", old_path, path)
        end
      end
      callback(nil)
    else
      os.remove(tmp_path)
      callback(rename_err or "rename failed")
    end
  end
end

function file_backend:delete(cache_key, platform_id, callback)
  -- Try to delete both compressed and uncompressed versions
  local deleted_any = false
  local last_err = nil

  for _, ext in ipairs({'.hs', '.hs.zst'}) do
    local path = self:_get_path(cache_key, platform_id, ext)
    local stat_err, stat = rspamd_util.stat(path)
    if not stat_err and stat then
      local ok, err = os.remove(path)
      if ok then
        lua_util.debugm(N, self.config, "deleted %s", path)
        deleted_any = true
      else
        last_err = err
      end
    end
  end

  if deleted_any then
    callback(nil)
  else
    callback(last_err or "file not found")
  end
end

function file_backend:exists_sync(cache_key, platform_id)
  local path, is_compressed = self:_find_existing_path(cache_key, platform_id)
  if path then
    lua_util.debugm(N, self.config, "file sync exists check: %s found (compressed: %s)",
        path, is_compressed and "yes" or "no")
    return true, nil
  else
    local expected_path = self:_get_path(cache_key, platform_id)
    lua_util.debugm(N, self.config, "file sync exists check: %s not found (checked both extensions)", expected_path)
    return false, nil
  end
end

function file_backend:save_async(cache_key, platform_id, data, callback)
  self:store(cache_key, platform_id, data, nil, callback)
end

function file_backend:load_async(cache_key, platform_id, callback)
  self:load(cache_key, platform_id, callback)
end

function file_backend:exists_async(cache_key, platform_id, callback)
  local exists, err = self:exists_sync(cache_key, platform_id)
  callback(err, exists)
end

function file_backend:load_sync(cache_key, platform_id)
  local path, expected_compressed = self:_find_existing_path(cache_key, platform_id)

  if not path then
    local expected_path = self:_get_path(cache_key, platform_id)
    lua_util.debugm(N, self.config, "file sync load failed: %s not found (checked both extensions)", expected_path)
    return nil, "file not found"
  end

  lua_util.debugm(N, self.config, "file sync load from: %s (expected compressed: %s)",
      path, expected_compressed and "yes" or "no")

  local f, err = io.open(path, "rb")
  if not f then
    lua_util.debugm(N, self.config, "file sync load failed from %s: %s", path, err or "open error")
    return nil, err or "open error"
  end
  local data = f:read("*a")
  f:close()
  if not data then
    lua_util.debugm(N, self.config, "file sync read failed from %s", path)
    return nil, "read error"
  end

  -- Check if data is actually zstd compressed (magic byte verification)
  local is_zstd = self:_is_zstd(data)
  lua_util.debugm(N, self.config, "file sync loaded %d bytes from %s, zstd magic: %s",
      #data, path, is_zstd and "yes" or "no")

  -- Notify hyperscan cache that this file is known (for cleanup tracking)
  rspamd_util.hyperscan_notice_known(path)

  if is_zstd then
    -- Decompress the data
    local decompress_err, decompressed = rspamd_util.zstd_decompress(data)
    if not decompress_err and decompressed then
      lua_util.debugm(N, self.config, "file sync decompressed %d -> %d bytes from %s (compression ratio: %.1f%%)",
          #data, #decompressed, path, (1 - #data / #decompressed) * 100)
      return decompressed, nil
    else
      lua_util.debugm(N, self.config, "file sync decompression failed for %s: %s", path, decompress_err or "unknown error")
      return nil, decompress_err or "decompression failed"
    end
  else
    -- Data is not compressed, return as-is
    if expected_compressed then
      lua_util.debugm(N, self.config, "file %s has .zst extension but no zstd magic - treating as uncompressed", path)
    end
    return data, nil
  end
end

function file_backend:save_sync(cache_key, platform_id, data)
  local path = self:_get_path(cache_key, platform_id)
  lua_util.debugm(N, self.config, "file sync save to: %s, original size: %d bytes, compression: %s",
      path, #data, self.use_compression and "enabled" or "disabled")
  self:_ensure_dir(path)

  local store_data = data
  -- Compress if enabled
  if self.use_compression then
    local compressed, compress_err = rspamd_util.zstd_compress(data)
    if compressed then
      lua_util.debugm(N, self.config, "file sync compressed %d -> %d bytes (%.1f%% size reduction) for %s",
          #data, #compressed, (1 - #compressed / #data) * 100, path)
      store_data = compressed
    else
      logger.warnx(N, "compression failed: %s, storing uncompressed to %s", compress_err, path)
    end
  end

  local tmp_path = path .. ".tmp." .. rspamd_util.random_hex(8)
  -- store_data can be string or rspamd_text userdata
  local ok, write_err
  if type(store_data) == "userdata" and store_data.save_in_file then
    ok, write_err = store_data:save_in_file(tmp_path)
  else
    local f, err = io.open(tmp_path, "wb")
    if not f then
      lua_util.debugm(N, self.config, "file sync open failed for %s: %s", tmp_path, err)
      return false, err
    end
    ok, write_err = f:write(store_data)
    f:close()
  end
  if not ok then
    lua_util.debugm(N, self.config, "file sync write failed to %s: %s", tmp_path, write_err)
    os.remove(tmp_path)
    return false, write_err
  end

  local renamed, rename_err = os.rename(tmp_path, path)
  if not renamed then
    lua_util.debugm(N, self.config, "file sync rename failed %s -> %s: %s", tmp_path, path, rename_err)
    os.remove(tmp_path)
    return false, rename_err
  end

  lua_util.debugm(N, self.config, "file sync stored %d bytes to %s", #store_data, path)

  -- Notify hyperscan cache that this file is known (for cleanup tracking)
  rspamd_util.hyperscan_notice_known(path)

  -- Remove old file with opposite extension if it exists (migration cleanup)
  local old_ext = self.use_compression and '.hs' or '.hs.zst'
  local old_path = self:_get_path(cache_key, platform_id, old_ext)
  local old_err, old_stat = rspamd_util.stat(old_path)
  if not old_err and old_stat then
    local removed = os.remove(old_path)
    if removed then
      lua_util.debugm(N, self.config, "removed old cache file %s (migrated to %s)", old_path, path)
    end
  end

  return true, nil
end

-- Redis backend
local redis_backend = {}
redis_backend.__index = redis_backend

function redis_backend.new(config)
  local self = setmetatable({}, redis_backend)

  -- Redis config can be:
  -- 1. In a 'redis' sub-section of hs_helper worker options
  -- 2. Directly in the hs_helper worker options (servers, write_servers, etc.)
  -- 3. Fallback to global 'redis' configuration section
  local redis_opts = config.redis or config
  self.redis_params = lua_redis.parse_redis_server(nil, redis_opts, true)
  if not self.redis_params then
    -- Fallback to global redis config
    self.redis_params = lua_redis.parse_redis_server('redis')
  end

  if not self.redis_params then
    logger.warnx(N, "redis backend: no redis configuration found in hs_helper worker or global redis section")
  end

  if config.ev_base and self.redis_params then
    self.redis_params.ev_base = config.ev_base
  end

  if config.rspamd_config then
    self.config = config.rspamd_config
  else
    self.config = config
  end

  -- Config options can be in redis sub-section or at top level
  local opts = config.redis or config
  self.default_ttl = opts.ttl or config.ttl or (86400 * 30) -- 30 days default
  self.refresh_ttl = (opts.refresh_ttl ~= false) and (config.refresh_ttl ~= false)
  self.use_compression = (opts.compression ~= false) and (config.compression ~= false)
  -- Use different default prefix for compressed (rspamd_zhs) vs uncompressed (rspamd_hs)
  local default_prefix = self.use_compression and 'rspamd_zhs' or 'rspamd_hs'
  self.prefix = opts.prefix or config.prefix or default_prefix

  lua_util.debugm(N, self.config, "redis backend config: prefix=%s, ttl=%s, refresh_ttl=%s, compression=%s",
      self.prefix, self.default_ttl, self.refresh_ttl, self.use_compression)

  return self
end

function redis_backend:_get_key(cache_key, platform_id)
  return string.format("%s:%s:%s", self.prefix, platform_id, cache_key)
end

function redis_backend:exists(cache_key, platform_id, callback)
  local key = self:_get_key(cache_key, platform_id)

  if not self.redis_params then
    callback("redis not configured", false, nil)
    return
  end

  lua_util.debugm(N, self.config, "redis EXISTS check for key: %s", key)

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err, data)
      if err then
        lua_util.debugm(N, self.config, "redis EXISTS failed for key %s: %s", key, err)
        callback(err, false, nil)
      else
        lua_util.debugm(N, self.config, "redis EXISTS result for key %s: %s", key, data == 1 and "found" or "not found")
        callback(nil, data == 1, nil)
      end
    end
  }

  local req = {'EXISTS', key}
  lua_redis.request(self.redis_params, attrs, req)
end

function redis_backend:load(cache_key, platform_id, callback)
  local key = self:_get_key(cache_key, platform_id)

  if not self.redis_params then
    callback("redis not configured", nil)
    return
  end

  -- Use GETEX to refresh TTL on read if enabled
  local req
  if self.refresh_ttl then
    lua_util.debugm(N, self.config, "redis GETEX (with TTL refresh %d) for key: %s", self.default_ttl, key)
    req = {'GETEX', key, 'EX', tostring(self.default_ttl)}
  else
    lua_util.debugm(N, self.config, "redis GET for key: %s", key)
    req = {'GET', key}
  end

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err, data)
      if err then
        lua_util.debugm(N, self.config, "redis GET failed for key %s: %s", key, err)
        callback(err, nil)
      elseif not data then
        lua_util.debugm(N, self.config, "redis cache miss for key %s", key)
        callback("not found", nil)
      else
        -- Decompress if needed
        if self.use_compression then
          local decompress_err, decompressed = rspamd_util.zstd_decompress(data)
          if not decompress_err and decompressed then
            lua_util.debugm(N, self.config, "redis loaded and decompressed %d -> %d bytes from key %s (compression ratio: %.1f%%)",
                #data, #decompressed, key, (1 - #data / #decompressed) * 100)
            callback(nil, decompressed)
          else
            lua_util.debugm(N, self.config, "redis decompression failed for key %s: %s", key, decompress_err)
            callback(decompress_err or "decompression failed", nil)
          end
        else
          lua_util.debugm(N, self.config, "redis loaded %d bytes (uncompressed) from key %s", #data, key)
          callback(nil, data)
        end
      end
    end
  }

  lua_redis.request(self.redis_params, attrs, req)
end

function redis_backend:store(cache_key, platform_id, data, ttl, callback)
  local key = self:_get_key(cache_key, platform_id)
  local actual_ttl = ttl or self.default_ttl

  if not self.redis_params then
    callback("redis not configured")
    return
  end

  lua_util.debugm(N, self.config, "redis SETEX for key: %s, original size: %d bytes, TTL: %d, compression: %s",
      key, #data, actual_ttl, self.use_compression and "enabled" or "disabled")

  local store_data = data
  -- Compress if enabled
  if self.use_compression then
    local compressed, compress_err = rspamd_util.zstd_compress(data)
    if compressed then
      lua_util.debugm(N, self.config, "redis compressed %d -> %d bytes (%.1f%% size reduction) for key %s",
          #data, #compressed, (1 - #compressed / #data) * 100, key)
      store_data = compressed
    else
      logger.warnx(N, "compression failed: %s, storing uncompressed", compress_err)
    end
  end

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    is_write = true,
    callback = function(err)
      if err then
        lua_util.debugm(N, self.config, "redis SETEX failed for key %s: %s", key, err)
        callback(err)
      else
        lua_util.debugm(N, self.config, "redis stored %d bytes to key %s with TTL %d",
            #store_data, key, actual_ttl)
        callback(nil)
      end
    end
  }

  local req = {'SETEX', key, tostring(actual_ttl), store_data}
  lua_redis.request(self.redis_params, attrs, req)
end

function redis_backend:delete(cache_key, platform_id, callback)
  local key = self:_get_key(cache_key, platform_id)

  if not self.redis_params then
    callback("redis not configured")
    return
  end

  lua_util.debugm(N, self.config, "redis DEL for key: %s", key)

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    is_write = true,
    callback = function(err)
      if err then
        lua_util.debugm(N, self.config, "redis DEL failed for key %s: %s", key, err)
        callback(err)
      else
        lua_util.debugm(N, self.config, "redis deleted key %s", key)
        callback(nil)
      end
    end
  }

  local req = {'DEL', key}
  lua_redis.request(self.redis_params, attrs, req)
end

function redis_backend:save_async(cache_key, platform_id, data, callback)
  self:store(cache_key, platform_id, data, nil, callback)
end

function redis_backend:load_async(cache_key, platform_id, callback)
  self:load(cache_key, platform_id, callback)
end

function redis_backend:exists_async(cache_key, platform_id, callback)
  self:exists(cache_key, platform_id, callback)
end

-- HTTP backend
local http_backend = {}
http_backend.__index = http_backend

function http_backend.new(config)
  local self = setmetatable({}, http_backend)
  -- Store config for logging context
  self.config = config.rspamd_config or config

  -- HTTP config can be in 'http' sub-section or at top level
  local opts = config.http or config
  self.base_url = opts.base_url or opts.url
  self.timeout = opts.timeout or config.timeout or 30
  self.auth_header = opts.auth_header or config.auth_header
  self.auth_value = opts.auth_value or config.auth_value
  self.use_compression = (opts.compression ~= false) and (config.compression ~= false)
  return self
end

function http_backend:_get_url(cache_key, platform_id)
  return string.format("%s/%s/%s", self.base_url, platform_id, cache_key)
end

function http_backend:_get_headers()
  local headers = {}
  if self.auth_header and self.auth_value then
    headers[self.auth_header] = self.auth_value
  end
  return headers
end

function http_backend:exists(cache_key, platform_id, callback)
  local url = self:_get_url(cache_key, platform_id)

  lua_util.debugm(N, self.config, "http HEAD check for url: %s", url)

  rspamd_http.request({
    url = url,
    method = 'HEAD',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code, _, headers)
      if err then
        lua_util.debugm(N, self.config, "http HEAD failed for %s: %s", url, err)
        callback(err, false, nil)
      elseif code == 200 then
        local size = headers and headers['content-length']
        lua_util.debugm(N, self.config, "http HEAD found %s, size: %s", url, size or "unknown")
        callback(nil, true, { size = tonumber(size) })
      else
        lua_util.debugm(N, self.config, "http HEAD not found %s (code: %d)", url, code)
        callback(nil, false, nil)
      end
    end
  })
end

function http_backend:load(cache_key, platform_id, callback)
  local url = self:_get_url(cache_key, platform_id)

  lua_util.debugm(N, self.config, "http GET for url: %s", url)

  rspamd_http.request({
    url = url,
    method = 'GET',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code, body, headers)
      if err then
        lua_util.debugm(N, self.config, "http GET failed for %s: %s", url, err)
        callback(err, nil)
      elseif code == 200 and body then
        -- Check if content is compressed
        local content_encoding = headers and headers['content-encoding']
        if content_encoding == 'zstd' or self.use_compression then
          local decompress_err, decompressed = rspamd_util.zstd_decompress(body)
          if not decompress_err and decompressed then
            lua_util.debugm(N, self.config, "http loaded and decompressed %d -> %d bytes from %s",
                #body, #decompressed, url)
            callback(nil, decompressed)
          else
            lua_util.debugm(N, self.config, "http loaded %d bytes (no decompression) from %s", #body, url)
            callback(nil, body)
          end
        else
          lua_util.debugm(N, self.config, "http loaded %d bytes from %s", #body, url)
          callback(nil, body)
        end
      elseif code == 404 then
        lua_util.debugm(N, self.config, "http cache miss (404) for %s", url)
        callback("not found", nil)
      else
        lua_util.debugm(N, self.config, "http GET failed for %s: HTTP %d", url, code)
        callback(string.format("HTTP %d", code), nil)
      end
    end
  })
end

function http_backend:store(cache_key, platform_id, data, ttl, callback)
  local url = self:_get_url(cache_key, platform_id)
  local headers = self:_get_headers()

  lua_util.debugm(N, self.config, "http PUT for url: %s, original size: %d bytes, compression: %s",
      url, #data, self.use_compression and "enabled" or "disabled")

  local store_data = data
  if self.use_compression then
    local compressed = rspamd_util.zstd_compress(data)
    if compressed then
      lua_util.debugm(N, self.config, "http compressed %d -> %d bytes (%.1f%% size reduction) for %s",
          #data, #compressed, (1 - #compressed / #data) * 100, url)
      store_data = compressed
      headers['Content-Encoding'] = 'zstd'
    end
  end

  if ttl then
    headers['X-TTL'] = tostring(ttl)
  end

  rspamd_http.request({
    url = url,
    method = 'PUT',
    headers = headers,
    body = store_data,
    timeout = self.timeout,
    callback = function(err, code)
      if err then
        lua_util.debugm(N, self.config, "http PUT failed for %s: %s", url, err)
        callback(err)
      elseif code >= 200 and code < 300 then
        lua_util.debugm(N, self.config, "http stored %d bytes to %s", #store_data, url)
        callback(nil)
      else
        lua_util.debugm(N, self.config, "http PUT failed for %s: HTTP %d", url, code)
        callback(string.format("HTTP %d", code))
      end
    end
  })
end

function http_backend:delete(cache_key, platform_id, callback)
  local url = self:_get_url(cache_key, platform_id)

  lua_util.debugm(N, self.config, "http DELETE for url: %s", url)

  rspamd_http.request({
    url = url,
    method = 'DELETE',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code)
      if err then
        lua_util.debugm(N, self.config, "http DELETE failed for %s: %s", url, err)
        callback(err)
      elseif code >= 200 and code < 300 or code == 404 then
        lua_util.debugm(N, self.config, "http deleted %s", url)
        callback(nil)
      else
        lua_util.debugm(N, self.config, "http DELETE failed for %s: HTTP %d", url, code)
        callback(string.format("HTTP %d", code))
      end
    end
  })
end

-- Backend factory

-- Create a backend instance based on configuration
-- @param config table with:
--   - backend: "file"|"redis"|"http" (default: "file")
--   - cache_dir: directory for file backend
--   - redis: redis configuration table
--   - http: http configuration table
-- @return backend instance
function exports.create_backend(config)
  local backend_type = config.backend or config.cache_backend or 'file'

  local cfg = config.rspamd_config or config
  lua_util.debugm(N, cfg, "creating hyperscan cache backend: %s", backend_type)

  -- Always pass full config - backends will extract what they need
  -- (config contains ev_base, rspamd_config at top level, plus optional
  -- redis/http sub-sections for backend-specific settings)
  if backend_type == 'file' then
    local be = file_backend.new(config)
    lua_util.debugm(N, be.config, "file backend created, cache_dir: %s, compression: %s",
        be.cache_dir or "not set", be.use_compression and "enabled" or "disabled")
    return be
  elseif backend_type == 'redis' then
    local be = redis_backend.new(config)
    if be.redis_params then
      lua_util.debugm(N, be.config, "redis backend created, prefix: %s, compression: %s",
          be.prefix, be.use_compression and "enabled" or "disabled")
    else
      logger.errx(N, "redis backend created but no redis params - operations will fail!")
    end
    return be
  elseif backend_type == 'http' then
    local be = http_backend.new(config)
    lua_util.debugm(N, be.config, "http backend created, base_url: %s", be.base_url or "not set")
    return be
  else
    logger.errx(N, "unknown hyperscan cache backend: %s, falling back to file", backend_type)
    return file_backend.new(config)
  end
end

-- Export individual backend constructors for direct use
exports.file_backend = file_backend
exports.redis_backend = redis_backend
exports.http_backend = http_backend

return exports
