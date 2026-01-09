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
local rspamd_http = require "rspamd_http"

local exports = {}
local N = "lua_hs_cache"

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
    callback(nil, true, { size = stat.size, mtime = stat.mtime })
  else
    callback(nil, false, nil)
  end
end

function file_backend:load(cache_key, platform_id, callback)
  local path = self:_get_path(cache_key, platform_id)

  local data, err = rspamd_util.read_file(path)
  if data then
    logger.debugx(N, "loaded %d bytes from %s", #data, path)
    callback(nil, data)
  else
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
      logger.debugx(N, "stored %d bytes to %s", #data, path)
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
    logger.debugx(N, "deleted %s", path)
    callback(nil)
  else
    callback(err or "delete failed")
  end
end

function file_backend:exists_sync(cache_key, platform_id)
  local path = self:_get_path(cache_key, platform_id)
  return rspamd_util.stat(path) ~= nil, nil
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
  return rspamd_util.read_file(path)
end

function file_backend:save_sync(cache_key, platform_id, data)
  local path = self:_get_path(cache_key, platform_id)
  self:_ensure_dir(path)

  local tmp_path = path .. ".tmp." .. rspamd_util.random_hex(8)
  local ok, err = rspamd_util.write_file(tmp_path, data)
  if not ok then
    return false, err
  end

  local renamed, rename_err = os.rename(tmp_path, path)
  if not renamed then
    os.remove(tmp_path)
    return false, rename_err
  end

  return true, nil
end

-- Redis backend
local redis_backend = {}
redis_backend.__index = redis_backend

function redis_backend.new(config)
  local self = setmetatable({}, redis_backend)
  self.redis_params = lua_redis.parse_redis_server('hyperscan', config)
  if not self.redis_params then
    self.redis_params = lua_redis.parse_redis_server(nil, config)
  end

  if config.ev_base and self.redis_params then
    self.redis_params.ev_base = config.ev_base
  end

  if config.rspamd_config then
    self.config = config.rspamd_config
  else
    self.config = config
  end

  self.prefix = config.prefix or 'rspamd_hs'
  self.default_ttl = config.ttl or (86400 * 30) -- 30 days default
  self.refresh_ttl = config.refresh_ttl ~= false -- Refresh TTL on read by default
  self.use_compression = config.compression ~= false
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

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err, data)
      if err then
        callback(err, false, nil)
      else
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
    req = {'GETEX', key, 'EX', tostring(self.default_ttl)}
  else
    req = {'GET', key}
  end

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err, data)
      if err then
        callback(err, nil)
      elseif not data then
        callback("not found", nil)
	      else
	        -- Decompress if needed
	        if self.use_compression then
	          local decompress_err, decompressed = rspamd_util.zstd_decompress(data)
	          if not decompress_err and decompressed then
	            logger.debugx(N, "loaded and decompressed %d -> %d bytes from redis key %s",
	                #data, #decompressed, key)
	            callback(nil, decompressed)
	          else
	            callback(decompress_err or "decompression failed", nil)
	          end
	        else
	          logger.debugx(N, "loaded %d bytes from redis key %s", #data, key)
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

  local store_data = data
  -- Compress if enabled
  if self.use_compression then
    local compressed, compress_err = rspamd_util.zstd_compress(data)
    if compressed then
      logger.debugx(N, "compressed %d -> %d bytes (%.1f%% reduction)",
          #data, #compressed, (1 - #compressed / #data) * 100)
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
        callback(err)
      else
        logger.debugx(N, "stored %d bytes to redis key %s with TTL %d",
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

  local attrs = {
    ev_base = self.redis_params.ev_base,
    config = self.config,
    callback = function(err)
      if err then
        callback(err)
      else
        logger.debugx(N, "deleted redis key %s", key)
        callback(nil)
      end
    end
  }

  local req = {'DEL', key}
  lua_redis.request(self.redis_params, attrs, req)
end

-- Synchronous methods for C backend interface
function redis_backend:exists_sync(cache_key, platform_id)
  local key = self:_get_key(cache_key, platform_id)

  if not self.redis_params then
    return false, "redis not configured"
  end

  local ret, conn = lua_redis.redis_connect_sync(self.redis_params, false, key,
      self.config or rspamd_config, self.redis_params.ev_base)
  if not ret then
    return false, "cannot connect to redis"
  end

  conn:add_cmd('EXISTS', { key })
  local ok, result = conn:exec()
  if not ok then
    return false, "redis EXISTS failed"
  end

  return result == 1, nil
end

function redis_backend:load_sync(cache_key, platform_id)
  local key = self:_get_key(cache_key, platform_id)

  if not self.redis_params then
    return nil, "redis not configured"
  end

  local ret, conn = lua_redis.redis_connect_sync(self.redis_params, false, key,
      self.config or rspamd_config, self.redis_params.ev_base)
  if not ret then
    return nil, "cannot connect to redis"
  end

  -- Use GETEX to refresh TTL on read if enabled
  if self.refresh_ttl then
    conn:add_cmd('GETEX', { key, 'EX', tostring(self.default_ttl) })
  else
    conn:add_cmd('GET', { key })
  end

  local ok, data = conn:exec()
  if not ok then
    return nil, "redis GET failed"
  end

  if not data then
    return nil, nil -- Cache miss, not an error
  end

  -- Decompress if needed
  if self.use_compression then
    local decompress_err, decompressed = rspamd_util.zstd_decompress(data)
    if not decompress_err and decompressed then
      logger.debugx(N, "loaded and decompressed %d -> %d bytes from redis key %s",
          #data, #decompressed, key)
      return decompressed, nil
    end

    return nil, decompress_err or "decompression failed"
  else
    logger.debugx(N, "loaded %d bytes from redis key %s", #data, key)
    return data, nil
  end
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

function redis_backend:save_sync(cache_key, platform_id, data)
  local key = self:_get_key(cache_key, platform_id)

  if not self.redis_params then
    return false, "redis not configured"
  end

  local ret, conn = lua_redis.redis_connect_sync(self.redis_params, true, key,
      self.config or rspamd_config, self.redis_params.ev_base)
  if not ret then
    return false, "cannot connect to redis"
  end

  local store_data = data
  -- Compress if enabled
  if self.use_compression then
    local compressed, compress_err = rspamd_util.zstd_compress(data)
    if compressed then
      logger.debugx(N, "compressed %d -> %d bytes (%.1f%% reduction)",
          #data, #compressed, (1 - #compressed / #data) * 100)
      store_data = compressed
    else
      logger.warnx(N, "compression failed: %s, storing uncompressed", compress_err)
    end
  end

  conn:add_cmd('SETEX', { key, tostring(self.default_ttl), store_data })
  local ok, result = conn:exec()
  if not ok then
    return false, "redis SETEX failed: " .. tostring(result)
  end

  logger.debugx(N, "stored %d bytes to redis key %s with TTL %d",
      #store_data, key, self.default_ttl)
  return true, nil
end

-- HTTP backend
local http_backend = {}
http_backend.__index = http_backend

function http_backend.new(config)
  local self = setmetatable({}, http_backend)
  self.base_url = config.base_url or config.url
  self.timeout = config.timeout or 30
  self.auth_header = config.auth_header
  self.auth_value = config.auth_value
  self.use_compression = config.compression ~= false
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

  rspamd_http.request({
    url = url,
    method = 'HEAD',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code, _, headers)
      if err then
        callback(err, false, nil)
      elseif code == 200 then
        local size = headers and headers['content-length']
        callback(nil, true, { size = tonumber(size) })
      else
        callback(nil, false, nil)
      end
    end
  })
end

function http_backend:load(cache_key, platform_id, callback)
  local url = self:_get_url(cache_key, platform_id)

  rspamd_http.request({
    url = url,
    method = 'GET',
    headers = self:_get_headers(),
    timeout = self.timeout,
	    callback = function(err, code, body, headers)
      if err then
        callback(err, nil)
      elseif code == 200 and body then
        -- Check if content is compressed
        local content_encoding = headers and headers['content-encoding']
        if content_encoding == 'zstd' or self.use_compression then
          local decompress_err, decompressed = rspamd_util.zstd_decompress(body)
          if not decompress_err and decompressed then
	            callback(nil, decompressed)
          else
	            callback(nil, body)
          end
        else
	          callback(nil, body)
        end
      elseif code == 404 then
        callback("not found", nil)
      else
        callback(string.format("HTTP %d", code), nil)
      end
    end
  })
end

function http_backend:store(cache_key, platform_id, data, ttl, callback)
  local url = self:_get_url(cache_key, platform_id)
  local headers = self:_get_headers()

  local store_data = data
  if self.use_compression then
    local compressed = rspamd_util.zstd_compress(data)
    if compressed then
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
        callback(err)
      elseif code >= 200 and code < 300 then
        callback(nil)
      else
        callback(string.format("HTTP %d", code))
      end
    end
  })
end

function http_backend:delete(cache_key, platform_id, callback)
  local url = self:_get_url(cache_key, platform_id)

  rspamd_http.request({
    url = url,
    method = 'DELETE',
    headers = self:_get_headers(),
    timeout = self.timeout,
    callback = function(err, code)
      if err then
        callback(err)
      elseif code >= 200 and code < 300 or code == 404 then
        callback(nil)
      else
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

  if backend_type == 'file' then
    return file_backend.new(config)
  elseif backend_type == 'redis' then
    local redis_config = config.redis or config
    return redis_backend.new(redis_config)
  elseif backend_type == 'http' then
    local http_config = config.http or config
    return http_backend.new(http_config)
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
