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

function file_backend.new(config)
  local self = setmetatable({}, file_backend)
  self.cache_dir = config.cache_dir or '/var/lib/rspamd/hs_cache'
  self.platform_dirs = config.platform_dirs ~= false
  return self
end

function file_backend:_get_path(cache_key, platform_id)
  if self.platform_dirs then
    return string.format("%s/%s/%s.hs", self.cache_dir, platform_id, cache_key)
  else
    return string.format("%s/%s_%s.hs", self.cache_dir, platform_id, cache_key)
  end
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
  local path = self:_get_path(cache_key, platform_id)
  local stat = rspamd_util.stat(path)

  if stat then
    lua_util.debugm(N, "file exists check: %s found, size: %d", path, stat.size)
    callback(nil, true, { size = stat.size, mtime = stat.mtime })
  else
    lua_util.debugm(N, "file exists check: %s not found", path)
    callback(nil, false, nil)
  end
end

function file_backend:load(cache_key, platform_id, callback)
  local path = self:_get_path(cache_key, platform_id)

  lua_util.debugm(N, "file load from: %s", path)

  local data, err = rspamd_util.read_file(path)
  if data then
    lua_util.debugm(N, "file loaded %d bytes from %s", #data, path)
    callback(nil, data)
  else
    lua_util.debugm(N, "file load failed from %s: %s", path, err or "file not found")
    callback(err or "file not found", nil)
  end
end

function file_backend:store(cache_key, platform_id, data, _ttl, callback)
  local path = self:_get_path(cache_key, platform_id)

  self:_ensure_dir(path)

  -- Write to temp file first, then rename atomically
  local tmp_path = path .. ".tmp." .. rspamd_util.random_hex(8)
  local ok, err = rspamd_util.write_file(tmp_path, data)

  if ok then
    local renamed, rename_err = os.rename(tmp_path, path)
    if renamed then
      lua_util.debugm(N, "stored %d bytes to %s", #data, path)
      callback(nil)
    else
      os.remove(tmp_path)
      callback(rename_err or "rename failed")
    end
  else
    callback(err or "write failed")
  end
end

function file_backend:delete(cache_key, platform_id, callback)
  local path = self:_get_path(cache_key, platform_id)
  local ok, err = os.remove(path)

  if ok then
    lua_util.debugm(N, "deleted %s", path)
    callback(nil)
  else
    callback(err or "delete failed")
  end
end

function file_backend:exists_sync(cache_key, platform_id)
  local path = self:_get_path(cache_key, platform_id)
  local exists = rspamd_util.stat(path) ~= nil
  lua_util.debugm(N, "file sync exists check: %s %s", path, exists and "found" or "not found")
  return exists, nil
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
  local path = self:_get_path(cache_key, platform_id)
  lua_util.debugm(N, "file sync load from: %s", path)
  local data, err = rspamd_util.read_file(path)
  if data then
    lua_util.debugm(N, "file sync loaded %d bytes from %s", #data, path)
  else
    lua_util.debugm(N, "file sync load failed from %s: %s", path, err or "file not found")
  end
  return data, err
end

function file_backend:save_sync(cache_key, platform_id, data)
  local path = self:_get_path(cache_key, platform_id)
  lua_util.debugm(N, "file sync save to: %s, size: %d bytes", path, #data)
  self:_ensure_dir(path)

  local tmp_path = path .. ".tmp." .. rspamd_util.random_hex(8)
  local ok, err = rspamd_util.write_file(tmp_path, data)
  if not ok then
    lua_util.debugm(N, "file sync write failed to %s: %s", tmp_path, err)
    return false, err
  end

  local renamed, rename_err = os.rename(tmp_path, path)
  if not renamed then
    lua_util.debugm(N, "file sync rename failed %s -> %s: %s", tmp_path, path, rename_err)
    os.remove(tmp_path)
    return false, rename_err
  end

  lua_util.debugm(N, "file sync stored %d bytes to %s", #data, path)
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

  lua_util.debugm(N, "redis backend config: prefix=%s, ttl=%s, refresh_ttl=%s, compression=%s",
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

  lua_util.debugm(N, "redis EXISTS check for key: %s", key)

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err, data)
      if err then
        lua_util.debugm(N, "redis EXISTS failed for key %s: %s", key, err)
        callback(err, false, nil)
      else
        lua_util.debugm(N, "redis EXISTS result for key %s: %s", key, data == 1 and "found" or "not found")
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
    lua_util.debugm(N, "redis GETEX (with TTL refresh %d) for key: %s", self.default_ttl, key)
    req = {'GETEX', key, 'EX', tostring(self.default_ttl)}
  else
    lua_util.debugm(N, "redis GET for key: %s", key)
    req = {'GET', key}
  end

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err, data)
      if err then
        lua_util.debugm(N, "redis GET failed for key %s: %s", key, err)
        callback(err, nil)
      elseif not data then
        lua_util.debugm(N, "redis cache miss for key %s", key)
        callback("not found", nil)
      else
        -- Decompress if needed
        if self.use_compression then
          local decompress_err, decompressed = rspamd_util.zstd_decompress(data)
          if not decompress_err and decompressed then
            lua_util.debugm(N, "redis loaded and decompressed %d -> %d bytes from key %s (compression ratio: %.1f%%)",
                #data, #decompressed, key, (1 - #data / #decompressed) * 100)
            callback(nil, decompressed)
          else
            lua_util.debugm(N, "redis decompression failed for key %s: %s", key, decompress_err)
            callback(decompress_err or "decompression failed", nil)
          end
        else
          lua_util.debugm(N, "redis loaded %d bytes (uncompressed) from key %s", #data, key)
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

  lua_util.debugm(N, "redis SETEX for key: %s, original size: %d bytes, TTL: %d, compression: %s",
      key, #data, actual_ttl, self.use_compression and "enabled" or "disabled")

  local store_data = data
  -- Compress if enabled
  if self.use_compression then
    local compressed, compress_err = rspamd_util.zstd_compress(data)
    if compressed then
      lua_util.debugm(N, "redis compressed %d -> %d bytes (%.1f%% size reduction) for key %s",
          #data, #compressed, (1 - #compressed / #data) * 100, key)
      store_data = compressed
    else
      logger.warnx(N, "compression failed: %s, storing uncompressed", compress_err)
    end
  end

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err)
      if err then
        lua_util.debugm(N, "redis SETEX failed for key %s: %s", key, err)
        callback(err)
      else
        lua_util.debugm(N, "redis stored %d bytes to key %s with TTL %d",
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

  lua_util.debugm(N, "redis DEL for key: %s", key)

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err)
      if err then
        lua_util.debugm(N, "redis DEL failed for key %s: %s", key, err)
        callback(err)
      else
        lua_util.debugm(N, "redis deleted key %s", key)
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

  lua_util.debugm(N, "http HEAD check for url: %s", url)

  rspamd_http.request({
    url = url,
    method = 'HEAD',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code, _, headers)
      if err then
        lua_util.debugm(N, "http HEAD failed for %s: %s", url, err)
        callback(err, false, nil)
      elseif code == 200 then
        local size = headers and headers['content-length']
        lua_util.debugm(N, "http HEAD found %s, size: %s", url, size or "unknown")
        callback(nil, true, { size = tonumber(size) })
      else
        lua_util.debugm(N, "http HEAD not found %s (code: %d)", url, code)
        callback(nil, false, nil)
      end
    end
  })
end

function http_backend:load(cache_key, platform_id, callback)
  local url = self:_get_url(cache_key, platform_id)

  lua_util.debugm(N, "http GET for url: %s", url)

  rspamd_http.request({
    url = url,
    method = 'GET',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code, body, headers)
      if err then
        lua_util.debugm(N, "http GET failed for %s: %s", url, err)
        callback(err, nil)
      elseif code == 200 and body then
        -- Check if content is compressed
        local content_encoding = headers and headers['content-encoding']
        if content_encoding == 'zstd' or self.use_compression then
          local decompress_err, decompressed = rspamd_util.zstd_decompress(body)
          if not decompress_err and decompressed then
            lua_util.debugm(N, "http loaded and decompressed %d -> %d bytes from %s",
                #body, #decompressed, url)
            callback(nil, decompressed)
          else
            lua_util.debugm(N, "http loaded %d bytes (no decompression) from %s", #body, url)
            callback(nil, body)
          end
        else
          lua_util.debugm(N, "http loaded %d bytes from %s", #body, url)
          callback(nil, body)
        end
      elseif code == 404 then
        lua_util.debugm(N, "http cache miss (404) for %s", url)
        callback("not found", nil)
      else
        lua_util.debugm(N, "http GET failed for %s: HTTP %d", url, code)
        callback(string.format("HTTP %d", code), nil)
      end
    end
  })
end

function http_backend:store(cache_key, platform_id, data, ttl, callback)
  local url = self:_get_url(cache_key, platform_id)
  local headers = self:_get_headers()

  lua_util.debugm(N, "http PUT for url: %s, original size: %d bytes, compression: %s",
      url, #data, self.use_compression and "enabled" or "disabled")

  local store_data = data
  if self.use_compression then
    local compressed = rspamd_util.zstd_compress(data)
    if compressed then
      lua_util.debugm(N, "http compressed %d -> %d bytes (%.1f%% size reduction) for %s",
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
        lua_util.debugm(N, "http PUT failed for %s: %s", url, err)
        callback(err)
      elseif code >= 200 and code < 300 then
        lua_util.debugm(N, "http stored %d bytes to %s", #store_data, url)
        callback(nil)
      else
        lua_util.debugm(N, "http PUT failed for %s: HTTP %d", url, code)
        callback(string.format("HTTP %d", code))
      end
    end
  })
end

function http_backend:delete(cache_key, platform_id, callback)
  local url = self:_get_url(cache_key, platform_id)

  lua_util.debugm(N, "http DELETE for url: %s", url)

  rspamd_http.request({
    url = url,
    method = 'DELETE',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code)
      if err then
        lua_util.debugm(N, "http DELETE failed for %s: %s", url, err)
        callback(err)
      elseif code >= 200 and code < 300 or code == 404 then
        lua_util.debugm(N, "http deleted %s", url)
        callback(nil)
      else
        lua_util.debugm(N, "http DELETE failed for %s: HTTP %d", url, code)
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

  lua_util.debugm(N, "creating hyperscan cache backend: %s", backend_type)

  -- Always pass full config - backends will extract what they need
  -- (config contains ev_base, rspamd_config at top level, plus optional
  -- redis/http sub-sections for backend-specific settings)
  if backend_type == 'file' then
    local be = file_backend.new(config)
    lua_util.debugm(N, "file backend created, cache_dir: %s", be.cache_dir or "not set")
    return be
  elseif backend_type == 'redis' then
    local be = redis_backend.new(config)
    if be.redis_params then
      lua_util.debugm(N, "redis backend created, prefix: %s, compression: %s",
          be.prefix, be.use_compression and "enabled" or "disabled")
    else
      logger.errx(N, "redis backend created but no redis params - operations will fail!")
    end
    return be
  elseif backend_type == 'http' then
    local be = http_backend.new(config)
    lua_util.debugm(N, "http backend created, base_url: %s", be.base_url or "not set")
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
