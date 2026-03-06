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
Export neural network model from Redis to RNM1 format for distribution.

This tool extracts a trained neural model from Redis and saves it as
a portable msgpack file that can be loaded by other rspamd instances.

Usage:
  rspamadm neural_export -o model.rnm

Options:
  -c, --config     Path to rspamd config (to get Redis connection)
  -r, --rule       Rule name to export (default: 'default')
  -s, --settings   Settings ID to export (default: 'default')
  -o, --output     Output file path (required)
  -v, --version    Specific model version to export (default: latest)
  --list           List available models instead of exporting
  --digest         Also print providers digest for URL construction
]]--

local rspamd_logger = require "rspamd_logger"
local lua_redis = require "lua_redis"
local argparse = require "argparse"
local ucl = require "ucl"
local rspamd_util = require "rspamd_util"
local rspamd_kann = require "rspamd_kann"
local rspamd_tensor = require "rspamd_tensor"

local parser = argparse()
    :name "rspamadm neural_export"
    :description "Export neural network model from Redis to RNM1 format"
    :help_description_margin(32)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:option "-r --rule"
      :description "Rule name to export"
      :argname("<rule>")
      :default("default")
parser:option "-s --settings"
      :description "Settings ID to export"
      :argname("<id>")
      :default("default")
parser:option "-o --output"
      :description "Output file path"
      :argname("<file>")
parser:option "-v --version"
      :description "Specific model version to export"
      :argname("<version>")
      :convert(tonumber)
parser:flag "--list"
      :description "List available models instead of exporting"
parser:flag "--digest"
      :description "Print providers digest for URL construction"

-- Model format constants (must match lua_neural_external)
local MODEL_MAGIC = "RNM1"
local MODEL_FORMAT_VERSION = 1

--- Load config and initialize Redis connection
local function init_redis(opts)
  local _r, err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    return nil
  end

  _r, err = rspamd_config:parse_rcl({ 'logging', 'worker' })
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
    return nil
  end

  local redis_params = lua_redis.parse_redis_server('neural')
  if not redis_params then
    rspamd_logger.errx('cannot get Redis configuration for neural module')
    return nil
  end

  return redis_params
end

--- Get neural rule configuration
local function get_neural_rule(opts)
  local neural_opts = rspamd_config:get_all_opt('neural')
  if not neural_opts then
    rspamd_logger.errx('no neural configuration found')
    return nil
  end

  local rules = neural_opts['rules'] or {}
  local rule_name = opts['rule']

  -- Handle legacy config (neural_opts itself is the rule)
  if not rules['default'] and neural_opts.train then
    rules['default'] = neural_opts
  end

  local rule = rules[rule_name]
  if not rule then
    rspamd_logger.errx('rule "%s" not found in neural config', rule_name)
    return nil
  end

  return rule
end

--- Build Redis prefix for a rule/settings combination
local function build_redis_prefix(rule, settings_name)
  local neural_common = require "plugins/neural"
  return neural_common.redis_ann_prefix({
    prefix = rule.prefix or 'default'
  }, settings_name)
end

--- List available models from Redis
local function list_models(redis_params, prefix, callback)
  local function members_cb(err, data)
    if err then
      callback(err, nil)
    else
      callback(nil, data)
    end
  end

  -- Get all profiles from sorted set (most recent first)
  lua_redis.redis_make_request_taskless(nil,
    rspamd_config,
    redis_params,
    nil,
    false,
    members_cb,
    'ZREVRANGE',
    { prefix, '0', '-1', 'WITHSCORES' }
  )
end

--- Load ANN data from Redis
local function load_ann_from_redis(redis_params, ann_key, callback)
  local function data_cb(err, data)
    if err then
      callback(err, nil)
      return
    end

    if type(data) ~= 'table' then
      callback("no data found at key: " .. ann_key, nil)
      return
    end

    -- data[1] = ann, data[2] = roc_thresholds, data[3] = pca,
    -- data[4] = providers_meta, data[5] = norm_stats
    local result = {
      ann_data = data[1],
      roc_thresholds = data[2],
      pca_data = data[3],
      providers_meta = data[4],
      norm_stats = data[5],
    }

    -- Decompress ann_data
    if result.ann_data then
      local dec_err, dec_data = rspamd_util.zstd_decompress(result.ann_data)
      if not dec_err and dec_data then
        result.ann = rspamd_kann.load(dec_data)
      end
    end

    -- Decompress and load PCA
    if result.pca_data then
      local dec_err, dec_data = rspamd_util.zstd_decompress(result.pca_data)
      if not dec_err and dec_data then
        result.pca = rspamd_tensor.load(dec_data)
      end
    end

    -- Parse JSON fields
    if result.roc_thresholds then
      local roc_parser = ucl.parser()
      local ok = roc_parser:parse_text(result.roc_thresholds)
      if ok then
        result.roc_thresholds = roc_parser:get_object()
      end
    end

    if result.norm_stats then
      local norm_parser = ucl.parser()
      local ok = norm_parser:parse_text(result.norm_stats)
      if ok then
        result.norm_stats = norm_parser:get_object()
      end
    end

    callback(nil, result)
  end

  lua_redis.redis_make_request_taskless(nil,
    rspamd_config,
    redis_params,
    nil,
    false,
    data_cb,
    'HMGET',
    { ann_key, 'ann', 'roc_thresholds', 'pca', 'providers_meta', 'norm_stats' },
    { opaque_data = true }
  )
end

--- Load profile from Redis sorted set
local function load_profile(profile_str)
  local profile_parser = ucl.parser()
  local ok = profile_parser:parse_string(profile_str)
  if not ok then
    return nil
  end
  return profile_parser:get_object()
end

--- Serialize model to RNM1 format
local function serialize_model(ann, pca, providers_digest, opts)
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

local function handler(args)
  local opts = parser:parse(args)

  -- Initialize
  local redis_params = init_redis(opts)
  if not redis_params then
    os.exit(1)
  end

  local rule = get_neural_rule(opts)
  if not rule then
    os.exit(1)
  end

  -- Get providers digest
  local neural_common = require "plugins/neural"
  local providers_digest = neural_common.providers_config_digest(rule.providers, rule)

  -- Print digest if requested
  if opts['digest'] then
    print(string.format("Providers digest: %s", providers_digest))
    if not opts['list'] and not opts['output'] then
      return
    end
  end

  local settings_name = opts['settings']
  local prefix = build_redis_prefix(rule, settings_name)

  -- List mode: show available models
  if opts['list'] then
    print(string.format("\nAvailable models for rule '%s', settings '%s':", opts['rule'], settings_name))
    print(string.format("Redis prefix: %s", prefix))
    print("")

    local co = coroutine.create(function()
      list_models(redis_params, prefix, function(err, data)
        if err then
          rspamd_logger.errx('failed to list models: %s', err)
          return
        end

        if not data or #data == 0 then
          print("No models found")
          return
        end

        -- Parse profiles (data is alternating: profile, score, profile, score, ...)
        for i = 1, #data, 2 do
          local profile_str = data[i]
          local score = tonumber(data[i + 1]) or 0
          local profile = load_profile(profile_str)

          if profile then
            local ts = os.date("%Y-%m-%d %H:%M:%S", score)
            print(string.format("  Version: %s, Key: %s, Updated: %s",
              profile.version or 0,
            profile.redis_key or "?",
            ts))
          end
        end
      end)
    end)
    coroutine.resume(co)
    return
  end

  -- Export mode: need output file
  if not opts['output'] then
    rspamd_logger.errx('output file is required for export (use -o <file>)')
    os.exit(1)
  end

  local output_file = opts['output']
  local target_version = opts['version']

  -- Find and load the model
  local co = coroutine.create(function()
    list_models(redis_params, prefix, function(err, data)
      if err then
        rspamd_logger.errx('failed to list models: %s', err)
        return
      end

      if not data or #data == 0 then
        rspamd_logger.errx('no models found in Redis')
        return
      end

      -- Find the target version (or use latest)
      local selected_profile
      local selected_score = 0

      for i = 1, #data, 2 do
        local profile_str = data[i]
        local score = tonumber(data[i + 1]) or 0
        local profile = load_profile(profile_str)

        if profile then
          if target_version then
            -- Looking for specific version
            if profile.version == target_version then
              selected_profile = profile
              selected_score = score
              break
            end
          else
            -- Use latest (highest score in sorted set = most recent)
            if not selected_profile or score > selected_score then
              selected_profile = profile
              selected_score = score
            end
          end
        end
      end

      if not selected_profile then
        if target_version then
          rspamd_logger.errx('model version %s not found', target_version)
        else
          rspamd_logger.errx('no suitable model found')
        end
        return
      end

      local ann_key = selected_profile.redis_key
      rspamd_logger.messagex('Loading model from key: %s (version %s)',
        ann_key, selected_profile.version or 0)

      -- Load ANN data
      load_ann_from_redis(redis_params, ann_key, function(load_err, model_data)
        if load_err then
          rspamd_logger.errx('failed to load model data: %s', load_err)
          return
        end

        if not model_data.ann then
          rspamd_logger.errx('failed to load ANN from Redis')
          return
        end

        -- Serialize to RNM1 format
        local rnm_data = serialize_model(model_data.ann, model_data.pca, providers_digest, {
          model_version = selected_profile.version or 1,
          norm_stats = model_data.norm_stats,
          roc_thresholds = model_data.roc_thresholds,
        })

        -- Write to file
        local out = assert(io.open(output_file, "wb"))
        out:write(rnm_data)
        out:close()

        rspamd_logger.messagex('Exported model to: %s', output_file)
        rspamd_logger.messagex('  Model version: %s', selected_profile.version or 0)
        rspamd_logger.messagex('  Providers digest: %s', providers_digest:sub(1, 16) .. '...')
        rspamd_logger.messagex('  File size: %s bytes', #rnm_data)
      end)
    end)
  end)
  coroutine.resume(co)
end

return {
  name = "neural_export",
  aliases = { "neural_export" },
  handler = handler,
  description = parser._description
}
