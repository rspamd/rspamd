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
External neural model loading and merging.

This module provides functionality to load pretrained neural models
from external sources (HTTP/HTTPS) via the Maps infrastructure
and merge them with locally trained weights.

Model format (msgpack):
{
  magic = "RNM1",           -- Rspamd Neural Model v1
  version = 1,              -- format version
  model_version = 123,      -- model training version (incremented on retrain)
  providers_digest = "...", -- digest of providers config (must match local)
  ann_data = "...",         -- serialized KANN (zstd compressed)
  pca_data = "...",         -- optional PCA (zstd compressed)
  norm_stats = {...},       -- normalization stats
  roc_thresholds = {...},   -- ROC thresholds
  created_at = timestamp,
}

Usage in neural config:
  external_model = {
    url = "https://your-provider.com/models/<digest>";
    sign_key = "your_key";  -- optional signature verification
    merge_alpha = 0.6;      -- 60% external, 40% local
  };
]]--

local lua_redis = require "lua_redis"
local rspamd_kann = require "rspamd_kann"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_text = require "rspamd_text"
local ucl = require "ucl"

-- Model format constants
local MODEL_MAGIC = "RNM1"
local MODEL_FORMAT_VERSION = 1

local exports = {}

-- Cache of loaded external models: url -> { model, map, callbacks }
local external_model_cache = {}

--- Parse external model from msgpack data
-- @param data raw msgpack data (rspamd_text, possibly zstd compressed)
-- @return table with model data or nil, error message
function exports.parse_model(data)
  if not data then
    return nil, "no data"
  end

  -- Convert rspamd_text to string if needed
  local data_str
  if type(data) == 'userdata' or (type(data) == 'table' and data.cookie) then
    data_str = tostring(data)
  else
    data_str = data
  end

  -- Try zstd decompression first
  local decompressed
  local err, decompressed_data = rspamd_util.zstd_decompress(data_str)
  if not err and decompressed_data then
    decompressed = tostring(decompressed_data)
  else
    -- Assume uncompressed
    decompressed = data_str
  end

  -- Parse msgpack
  local parser = ucl.parser()
  local ok, parse_err = parser:parse_text(decompressed, 'msgpack')
  if not ok then
    return nil, "failed to parse msgpack: " .. (parse_err or "unknown error")
  end

  local model = parser:get_object()

  -- Validate model format
  if model.magic ~= MODEL_MAGIC then
    return nil, string.format("invalid magic: expected %s, got %s",
      MODEL_MAGIC, model.magic or "nil")
  end

  if model.version ~= MODEL_FORMAT_VERSION then
    return nil, string.format("unsupported model version: %s (expected %s)",
      model.version or "nil", MODEL_FORMAT_VERSION)
  end

  return model
end

--- Load KANN from model data
-- @param model parsed model table
-- @return kann_t object or nil, error
function exports.load_ann(model)
  if not model.ann_data then
    return nil, "no ann_data in model"
  end

  -- Decompress ann_data
  local ann_data_str = model.ann_data
  if type(ann_data_str) == 'userdata' or (type(ann_data_str) == 'table' and ann_data_str.cookie) then
    ann_data_str = tostring(ann_data_str)
  end

  local err, ann_data = rspamd_util.zstd_decompress(ann_data_str)
  if err then
    return nil, "failed to decompress ann_data: " .. err
  end

  local ann = rspamd_kann.load(ann_data)
  if not ann then
    return nil, "failed to load KANN from model"
  end

  return ann
end

--- Load PCA from model data
-- @param model parsed model table
-- @return tensor or nil
function exports.load_pca(model)
  if not model.pca_data then
    return nil
  end

  local pca_data_str = model.pca_data
  if type(pca_data_str) == 'userdata' or (type(pca_data_str) == 'table' and pca_data_str.cookie) then
    pca_data_str = tostring(pca_data_str)
  end

  local err, pca_data = rspamd_util.zstd_decompress(pca_data_str)
  if err then
    rspamd_logger.warnx(rspamd_config, "failed to decompress pca_data: %s", err)
    return nil
  end

  local rspamd_tensor = require "rspamd_tensor"
  return rspamd_tensor.load(pca_data)
end

--- Check if model is compatible with local config
-- @param model parsed model table
-- @param providers_digest local providers digest
-- @return boolean, reason
function exports.is_compatible(model, providers_digest)
  if not model.providers_digest then
    return false, "model has no providers_digest"
  end

  if model.providers_digest ~= providers_digest then
    return false, string.format("providers digest mismatch: model=%s, local=%s",
      model.providers_digest:sub(1, 8), providers_digest:sub(1, 8))
  end

  return true, "compatible"
end

--- Merge weights from external ANN into local ANN using interpolation
-- w_new = alpha * w_external + (1-alpha) * w_local
-- @param external_ann kann_t from external model
-- @param local_ann kann_t from local training
-- @param alpha weight for external (0.0 - 1.0)
-- @return merged kann_t or nil, error
function exports.merge_weights(external_ann, local_ann, alpha)
  if not external_ann or not local_ann then
    return nil, "missing ann"
  end

  alpha = alpha or 0.5

  -- Check compatibility first
  local ok = external_ann:is_compatible(local_ann)
  if not ok then
    return nil, "incompatible ANN architectures"
  end

  -- Use the external ANN as base and merge local weights into it
  local merged, err = external_ann:merge_weights(local_ann, 1.0 - alpha)

  if not merged then
    return nil, "merge failed: " .. (err or "unknown")
  end

  return external_ann
end

--- Build URL for external model based on providers digest
-- @param base_url base URL
-- @param providers_digest digest of providers config
-- @return full URL
function exports.build_model_url(base_url, providers_digest)
  -- Remove trailing slash from base_url
  base_url = base_url:gsub('/+$', '')
  return string.format("%s/%s", base_url, providers_digest)
end

--- Register external model as a map
-- This uses the Maps infrastructure for HTTP loading with signature verification
-- @param cfg rspamd_config
-- @param rule neural rule configuration
-- @param providers_digest digest of providers config
-- @param on_load_callback function(model_data, err) called when model is loaded/reloaded
-- @return boolean success
function exports.register_model_map(cfg, rule, providers_digest, on_load_callback)
  local ext_cfg = rule.external_model
  if not ext_cfg or not ext_cfg.url then
    return false
  end

  local url = ext_cfg.url
  local cache_key = url

  -- Check if already registered
  if external_model_cache[cache_key] then
    return true
  end

  -- Map callback: called when map data is loaded
  local function map_callback(data, map)
    if not data then
      rspamd_logger.errx(cfg, 'external neural model map returned no data for %s', url)
      if on_load_callback then
        on_load_callback(nil, "no data from map")
      end
      return
    end

    -- Parse model
    local model, parse_err = exports.parse_model(data)
    if not model then
      rspamd_logger.errx(cfg, 'failed to parse external neural model from %s: %s', url, parse_err)
      if on_load_callback then
        on_load_callback(nil, parse_err)
      end
      return
    end

    -- Check compatibility
    local compatible, reason = exports.is_compatible(model, providers_digest)
    if not compatible then
      rspamd_logger.errx(cfg, 'external neural model incompatible: %s', reason)
      if on_load_callback then
        on_load_callback(nil, reason)
      end
      return
    end

    rspamd_logger.infox(cfg, 'loaded external neural model from %s (version=%s)',
      url, model.model_version or 0)

    -- Update cache
    external_model_cache[cache_key] = {
      model = model,
      last_version = model.model_version,
      last_load = os.time(),
    }

    -- Call user callback
    if on_load_callback then
      on_load_callback(model, nil)
    end
  end

  -- Create callback map
  local map = cfg:add_map({
    url = url,
    type = 'callback',
    description = string.format('External neural model for rule %s', rule.prefix or 'default'),
    callback = map_callback,
    opaque_data = true,  -- Get data as rspamd_text
  })

  if not map then
    rspamd_logger.errx(cfg, 'failed to register external neural model map for %s', url)
    return false
  end

  -- Set sign key if configured
  if ext_cfg.sign_key then
    map:set_sign_key(ext_cfg.sign_key)
  end

  external_model_cache[cache_key] = {
    map = map,
    callbacks = { on_load_callback },
  }

  return true
end

--- Get cached model data for URL
-- @param url model URL
-- @return cached model data or nil
function exports.get_cached_model(url)
  local cached = external_model_cache[url]
  if cached and cached.model then
    return cached.model
  end
  return nil
end

--- Create external model configuration for a neural rule
-- @param rule neural rule configuration
-- @param providers_digest digest of providers config
-- @return table with external model config or nil
function exports.create_external_config(rule, providers_digest)
  local ext = rule.external_model
  if not ext then
    return nil
  end

  local url = ext.url
  if not url then
    -- Build URL from digest if base_url is provided
    if ext.base_url then
      url = exports.build_model_url(ext.base_url, providers_digest)
    else
      rspamd_logger.errx(rspamd_config, 'external_model requires url or base_url')
      return nil
    end
  end

  return {
    url = url,
    sign_key = ext.sign_key,
    merge_strategy = ext.merge_strategy or "interpolate",
    merge_alpha = ext.merge_alpha or 0.5,
    check_interval = ext.check_interval or 86400, -- 24h
    local_fine_tune = ext.local_fine_tune ~= false,
    min_local_samples = ext.min_local_samples or 50,
    providers_digest = providers_digest,
    loaded = false,
    last_version = nil,
    last_check = nil,
  }
end

--- Store external model metadata in Redis for later merge
-- @param redis redis params
-- @param ev_base event base
-- @param ann_key Redis key for the ANN
-- @param model_data parsed model data
-- @param callback function(err)
function exports.store_base_model(redis, ev_base, ann_key, model_data, callback)
  -- Store base model version and compressed ann_data for re-merge
  local base_key = ann_key .. "_base"

  local function store_cb(err)
    if err then
      rspamd_logger.errx(rspamd_config, "failed to store base model: %s", err)
    end
    if callback then
      callback(err)
    end
  end

  -- Ensure ann_data is rspamd_text for opaque storage
  local ann_data = model_data.ann_data
  if type(ann_data) == 'string' then
    -- Already compressed, convert to text
    ann_data = rspamd_text.fromstring(ann_data)
  end

  -- Store base version and ann_data
  lua_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis,
    nil,
    true, -- is write
    store_cb,
    'HMSET',
    {
      base_key,
      'version', tostring(model_data.model_version or 0),
      'ann_data', ann_data,
      'providers_digest', model_data.providers_digest or '',
      'created_at', tostring(model_data.created_at or os.time()),
    },
    { opaque_data = true }
  )
end

--- Load base model from Redis for re-merge
-- @param redis redis params
-- @param ev_base event base
-- @param ann_key Redis key for the ANN
-- @param callback function(err, model_data)
function exports.load_base_model(redis, ev_base, ann_key, callback)
  local base_key = ann_key .. "_base"

  local function load_cb(err, data)
    if err then
      callback(err, nil)
      return
    end

    if type(data) ~= 'table' then
      callback("no base model found", nil)
      return
    end

    local model_data = {
      model_version = tonumber(data[1]) or 0,
      ann_data = data[2], -- rspamd_text
      providers_digest = data[3],
      created_at = tonumber(data[4]) or 0,
    }

    callback(nil, model_data)
  end

  lua_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis,
    nil,
    false, -- is write
    load_cb,
    'HMGET',
    { base_key, 'version', 'ann_data', 'providers_digest', 'created_at' },
    { opaque_data = true }
  )
end

--- Serialize model to msgpack format
-- @param ann kann_t object
-- @param pca optional PCA tensor
-- @param providers_digest providers config digest
-- @param opts optional { norm_stats, roc_thresholds }
-- @return rspamd_text with compressed msgpack data
function exports.serialize_model(ann, pca, providers_digest, opts)
  opts = opts or {}

  -- Save ANN to memory
  local ann_text = ann:save()
  local ann_compressed = rspamd_util.zstd_compress(ann_text)

  local model = {
    magic = MODEL_MAGIC,
    version = MODEL_FORMAT_VERSION,
    model_version = opts.model_version or 1,
    providers_digest = providers_digest,
    ann_data = ann_compressed,
    created_at = os.time(),
  }

  if pca then
    local pca_text = pca:save()
    model.pca_data = rspamd_util.zstd_compress(pca_text)
  end

  if opts.norm_stats then
    model.norm_stats = opts.norm_stats
  end

  if opts.roc_thresholds then
    model.roc_thresholds = opts.roc_thresholds
  end

  return ucl.to_format(model, 'msgpack')
end

exports.MODEL_MAGIC = MODEL_MAGIC
exports.MODEL_FORMAT_VERSION = MODEL_FORMAT_VERSION

return exports
