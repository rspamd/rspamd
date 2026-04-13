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

  if not rule.prefix then
    rule.prefix = rule_name
  end

  if not rule.name then
    rule.name = rule_name
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

local function redis_connect(redis_params)
  local redis_opts = {}
  for k, v in pairs(redis_params) do
    redis_opts[k] = v
  end
  redis_opts.opaque_data = true

  local ok, conn = lua_redis.redis_connect_sync(redis_opts, false)

  if not ok then
    return nil, conn
  end

  return conn
end

local function maybe_convert_text(data)
  if type(data) == 'userdata' or (type(data) == 'table' and data.cookie) then
    return tostring(data)
  end

  return data
end

--- List available models from Redis
local function list_models(conn, prefix)
  local ok, err = conn:add_cmd('ZREVRANGE', { prefix, '0', '-1', 'WITHSCORES' })

  if not ok then
    return nil, err
  end

  local ret, data = conn:exec()

  if not ret then
    return nil, data
  end

  return data
end

local function profile_has_ann(conn, ann_key)
  local ok, err = conn:add_cmd('HEXISTS', { ann_key, 'ann' })

  if not ok then
    return false, err
  end

  local ret, data = conn:exec()

  if not ret then
    return false, data
  end

  return tonumber(data) == 1, nil
end

--- Load model data from Redis
local function load_model_from_redis(conn, ann_key)
  local ok, err = conn:add_cmd('HMGET', {
    ann_key, 'ann', 'roc_thresholds', 'pca', 'providers_meta', 'norm_stats'
  })

  if not ok then
    return nil, err
  end

  local ret, data = conn:exec()

  if not ret then
    return nil, data
  end

  if type(data) ~= 'table' then
    return nil, 'no data found at key: ' .. ann_key
  end

  -- data[1] = ann, data[2] = roc_thresholds, data[3] = pca,
  -- data[4] = providers_meta, data[5] = norm_stats
  local result = {
    ann_data = maybe_convert_text(data[1]),
    roc_thresholds = maybe_convert_text(data[2]),
    pca_data = maybe_convert_text(data[3]),
    providers_meta = maybe_convert_text(data[4]),
    norm_stats = maybe_convert_text(data[5]),
  }

  if result.roc_thresholds then
    local roc_parser = ucl.parser()
    local parse_ok = roc_parser:parse_text(result.roc_thresholds)
    if parse_ok then
      result.roc_thresholds = roc_parser:get_object()
    end
  end

  if result.norm_stats then
    local norm_parser = ucl.parser()
    local parse_ok = norm_parser:parse_text(result.norm_stats)
    if parse_ok then
      result.norm_stats = norm_parser:get_object()
    end
  end

  return result
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
local function serialize_model(model_data, providers_digest, opts)
  opts = opts or {}

  local model = {
    magic = MODEL_MAGIC,
    version = MODEL_FORMAT_VERSION,
    model_version = opts.model_version or 1,
    providers_digest = providers_digest,
    ann_data = model_data.ann_data,
    created_at = os.time(),
  }

  if model_data.pca_data then
    model.pca_data = model_data.pca_data
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
  local conn, conn_err = redis_connect(redis_params)

  if not conn then
    rspamd_logger.errx('cannot connect to redis server: %s', conn_err or 'unknown error')
    os.exit(1)
  end

  -- List mode: show available models
  if opts['list'] then
    print(string.format("\nAvailable models for rule '%s', settings '%s':", opts['rule'], settings_name))
    print(string.format("Redis prefix: %s", prefix))
    print("")

    local data, err = list_models(conn, prefix)
    if err then
      rspamd_logger.errx('failed to list models: %s', err)
      os.exit(1)
    end

    if not data or #data == 0 then
      print("No models found")
      return
    end

    for i = 1, #data, 2 do
      local profile_str = data[i]
      local score = tonumber(data[i + 1]) or 0
      local profile = load_profile(profile_str)

      if profile then
        local has_ann = false
        if profile.redis_key then
          has_ann = profile_has_ann(conn, profile.redis_key)
        end
        local ts = os.date("%Y-%m-%d %H:%M:%S", score)
        print(string.format("  Version: %s, Key: %s, Updated: %s%s",
          profile.version or 0,
          profile.redis_key or "?",
          ts,
          has_ann and '' or ' [stale]'))
      end
    end

    return
  end

  -- Export mode: need output file
  if not opts['output'] then
    rspamd_logger.errx('output file is required for export (use -o <file>)')
    os.exit(1)
  end

  local output_file = opts['output']
  local target_version = opts['version']
  local data, err = list_models(conn, prefix)
  if err then
    rspamd_logger.errx('failed to list models: %s', err)
    os.exit(1)
  end

  if not data or #data == 0 then
    rspamd_logger.errx('no models found in Redis')
    os.exit(1)
  end

  local selected_profile
  local selected_score = 0

  for i = 1, #data, 2 do
    local profile_str = data[i]
    local score = tonumber(data[i + 1]) or 0
    local profile = load_profile(profile_str)

    if profile then
      local has_ann = profile.redis_key and profile_has_ann(conn, profile.redis_key)

      if not has_ann then
        rspamd_logger.warnx('skip stale model profile: version=%s key=%s',
          profile.version or 0, profile.redis_key or '?')
      elseif target_version then
        if profile.version == target_version then
          selected_profile = profile
          selected_score = score
          break
        end
      elseif not selected_profile or score > selected_score then
        selected_profile = profile
        selected_score = score
      end
    end
  end

  if not selected_profile then
    if target_version then
      rspamd_logger.errx('model version %s not found', target_version)
    else
      rspamd_logger.errx('no suitable model found')
    end
    os.exit(1)
  end

  local ann_key = selected_profile.redis_key
  rspamd_logger.messagex('Loading model from key: %s (version %s)',
    ann_key, selected_profile.version or 0)

  local model_data, load_err = load_model_from_redis(conn, ann_key)
  if load_err then
    rspamd_logger.errx('failed to load model data: %s', load_err)
    os.exit(1)
  end

  if not model_data.ann_data then
    rspamd_logger.errx('failed to load ANN data from Redis')
    os.exit(1)
  end

  local rnm_data = serialize_model(model_data, providers_digest, {
    model_version = selected_profile.version or 1,
    norm_stats = model_data.norm_stats,
    roc_thresholds = model_data.roc_thresholds,
  })

  local out, open_err = io.open(output_file, 'wb')
  if not out then
    rspamd_logger.errx('cannot open output file %s: %s', output_file, open_err)
    os.exit(1)
  end

  local write_ok, write_err = out:write(rnm_data)
  out:close()

  if not write_ok then
    rspamd_logger.errx('cannot write output file %s: %s', output_file, write_err)
    os.exit(1)
  end

  rspamd_logger.messagex('Exported model to: %s', output_file)
  rspamd_logger.messagex('  Model version: %s', selected_profile.version or 0)
  rspamd_logger.messagex('  Providers digest: %s', providers_digest:sub(1, 16) .. '...')
  rspamd_logger.messagex('  File size: %s bytes', #rnm_data)
end

return {
  name = "neural_export",
  aliases = { "neural_export" },
  handler = handler,
  description = parser._description
}
