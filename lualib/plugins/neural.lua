--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local fun = require "fun"
local lua_redis = require "lua_redis"
local lua_settings = require "lua_settings"
local lua_util = require "lua_util"
local meta_functions = require "lua_meta"
local rspamd_kann = require "rspamd_kann"
local rspamd_logger = require "rspamd_logger"
local rspamd_tensor = require "rspamd_tensor"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"

local N = 'neural'

-- Used in prefix to avoid wrong ANN to be loaded
local plugin_ver = '3'

-- Module vars
local default_options = {
  train = {
    max_trains = 1000,
    max_epoch = 1000,
    max_usages = 10,
    max_iterations = 25, -- Torch style
    mse = 0.001,
    autotrain = true,
    train_prob = 1.0,
    learn_threads = 1,
    learn_mode = 'balanced', -- Possible values: balanced, proportional
    learning_rate = 0.01,
    classes_bias = 0.0,      -- balanced mode: what difference is allowed between classes (1:1 proportion means 0 bias)
    spam_skip_prob = 0.0,    -- proportional mode: spam skip probability (0-1)
    ham_skip_prob = 0.0,     -- proportional mode: ham skip probability
    store_pool_only = false, -- store tokens in cache only (disables autotrain);
    store_set_only = false,  -- store ham and spam sets in Redis, but do not train ANN (autotrain must be enabled);
    -- neural_vec_mpack stores vector of training data in messagepack neural_profile_digest stores profile digest
  },
  watch_interval = 60.0,
  lock_expire = 600,
  learning_spawned = false,
  ann_expire = 60 * 60 * 24 * 2,    -- 2 days
  hidden_layer_mult = 1.5,          -- number of neurons in the hidden layer (symbol-based mode)
  -- Multi-layer architecture settings (for LLM embeddings mode)
  layers = nil,                     -- layer size multipliers (auto-computed based on input dim if nil)
  dropout = nil,                    -- dropout rate (0.2 default for embeddings, nil=disabled for symbols)
  use_layernorm = nil,              -- enable layer normalization (true default for embeddings)
  activation = nil,                 -- activation function: 'relu' or 'gelu' (default: gelu for embeddings, relu for symbols)
  roc_enabled = false,              -- Use ROC to find the best possible thresholds for ham and spam. If spam_score_threshold or ham_score_threshold is defined, it takes precedence over ROC thresholds.
  roc_misclassification_cost = 0.5, -- Cost of misclassifying a spam message (must be 0..1).
  spam_score_threshold = nil,       -- neural score threshold for spam (must be 0..1 or nil to disable)
  ham_score_threshold = nil,        -- neural score threshold for ham (must be 0..1 or nil to disable)
  flat_threshold_curve = false,     -- use binary classification 0/1 when threshold is reached
  symbol_spam = 'NEURAL_SPAM',
  symbol_ham = 'NEURAL_HAM',
  max_inputs = nil,              -- when PCA is used
  blacklisted_symbols = {},      -- list of symbols skipped in neural processing
  -- Phase 0 additions (scaffolding for feature providers)
  providers = nil,               -- list of provider configs; if nil, fallback to symbols-only provider
  fusion = {
    normalization = 'none',      -- none|unit|zscore (zscore requires stats)
    per_provider_pca = false,    -- if true, apply PCA per provider before fusion (not active yet)
  },
  disable_symbols_input = false, -- when true, do not use symbols provider unless explicitly listed
}

-- Rule structure:
-- * static config fields (see `default_options`)
-- * prefix - name or defined prefix
-- * settings - table of settings indexed by settings id, -1 is used when no settings defined

-- Rule settings element defines elements for specific settings id:
-- * symbols - static symbols profile (defined by config or extracted from symcache)
-- * name - name of settings id
-- * digest - digest of all symbols
-- * ann - dynamic ANN configuration loaded from Redis
-- * train - train data for ANN (e.g. the currently trained ANN)

-- Settings ANN table is loaded from Redis and represents dynamic profile for ANN
-- Some elements are directly stored in Redis, ANN is, in turn loaded dynamically
-- * version - version of ANN loaded from redis
-- * redis_key - name of ANN key in Redis
-- * symbols - symbols in THIS PARTICULAR ANN (might be different from set.symbols)
-- * distance - distance between set.symbols and set.ann.symbols
-- * ann - kann object

local settings = {
  rules = {},
  prefix = 'rn',    -- Neural network default prefix
  max_profiles = 3, -- Maximum number of NN profiles stored
}

-- Get module & Redis configuration
local module_config = rspamd_config:get_all_opt(N)
settings = lua_util.override_defaults(settings, module_config)
local redis_params = lua_redis.parse_redis_server('neural')

local redis_lua_script_vectors_len = "neural_train_size.lua"
local redis_lua_script_maybe_invalidate = "neural_maybe_invalidate.lua"
local redis_lua_script_maybe_lock = "neural_maybe_lock.lua"
local redis_lua_script_save_unlock = "neural_save_unlock.lua"

local redis_script_id = {}

-- Provider registry (Phase 0 scaffolding)
local registered_providers = {}

--- Registers a feature provider implementation
-- @param name string
-- @param provider table with function collect(task, ctx) -> vector(table of numbers), meta(table)
local function register_provider(name, provider)
  registered_providers[name] = provider
end

local function get_provider(name)
  return registered_providers[name]
end

-- Forward declaration
local result_to_vector

-- Built-in symbols provider (compatibility path)
register_provider('symbols', {
  collect = function(task, ctx)
    local vec = result_to_vector(task, ctx.profile)
    return vec, { name = 'symbols', type = 'symbols', dim = #vec, weight = ctx.weight or 1.0 }
  end,
  collect_async = function(task, ctx, cont)
    local vec = result_to_vector(task, ctx.profile)
    cont(vec, { name = 'symbols', type = 'symbols', dim = #vec, weight = ctx.weight or 1.0 })
  end,
})

-- Metatokens-only provider for contexts where symbols are not available
register_provider('metatokens', {
  collect = function(task, ctx)
    local mt = meta_functions.rspamd_gen_metatokens(task)
    -- Convert to table of numbers
    local vec = {}
    for i = 1, #mt do
      vec[i] = tonumber(mt[i]) or 0.0
    end
    return vec, { name = 'metatokens', type = 'metatokens', dim = #vec, weight = ctx.weight or 1.0 }
  end,
  collect_async = function(task, ctx, cont)
    local mt = meta_functions.rspamd_gen_metatokens(task)
    -- Convert to table of numbers
    local vec = {}
    for i = 1, #mt do
      vec[i] = tonumber(mt[i]) or 0.0
    end
    cont(vec, { name = 'metatokens', type = 'metatokens', dim = #vec, weight = ctx.weight or 1.0 })
  end,
})

local function load_scripts()
  local err
  redis_script_id.vectors_len, err = lua_redis.load_redis_script_from_file(redis_lua_script_vectors_len,
    redis_params)
  if err then
    rspamd_logger.errx(rspamd_config, err)
  end
  redis_script_id.maybe_invalidate, err = lua_redis.load_redis_script_from_file(redis_lua_script_maybe_invalidate,
    redis_params)
  if err then
    rspamd_logger.errx(rspamd_config, err)
  end
  redis_script_id.maybe_lock, err = lua_redis.load_redis_script_from_file(redis_lua_script_maybe_lock,
    redis_params)
  if err then
    rspamd_logger.errx(rspamd_config, err)
  end
  redis_script_id.save_unlock, err = lua_redis.load_redis_script_from_file(redis_lua_script_save_unlock,
    redis_params)
  if err then
    rspamd_logger.errx(rspamd_config, err)
  end
end

-- Creates a simple single-layer ANN for symbol-based inputs (backward compatible)
local function create_symbol_ann(n, rule)
  local nhidden = math.floor(n * (rule.hidden_layer_mult or 1.0) + 1.0)
  local t = rspamd_kann.layer.input(n)
  t = rspamd_kann.transform.relu(t)
  t = rspamd_kann.layer.dense(t, nhidden)
  t = rspamd_kann.layer.cost(t, 1, rspamd_kann.cost.ceb_neg)
  return rspamd_kann.new.kann(t)
end

-- Creates a multi-layer funnel ANN optimized for high-dimensional embeddings
-- Architecture: Input → [Dense → LayerNorm → Activation → Dropout]* → Cost
local function create_embedding_ann(n, rule)
  local t = rspamd_kann.layer.input(n)

  -- Get architecture settings with smart defaults based on input dimension
  local layers = rule.layers
  if not layers then
    -- Auto-compute layer sizes based on input dimension
    if n > 512 then
      layers = { 0.5, 0.25, 0.125 } -- 3 layers for large embeddings (e.g., 1024-dim)
    elseif n > 256 then
      layers = { 0.5, 0.25 }        -- 2 layers for medium embeddings
    else
      layers = { 0.5 }              -- 1 layer for small embeddings
    end
  end

  local dropout_rate = rule.dropout
  if dropout_rate == nil then
    dropout_rate = 0.2 -- Default dropout for regularization
  end

  local use_layernorm = rule.use_layernorm
  if use_layernorm == nil then
    use_layernorm = true -- Default: enable layer normalization
  end

  -- Select activation function: GELU for embeddings (better for high-dim), ReLU as fallback
  local activation = rule.activation
  if not activation then
    -- Default to GELU for embeddings if available
    activation = rspamd_kann.transform.gelu and 'gelu' or 'relu'
  end
  local activate_fn = (activation == 'gelu' and rspamd_kann.transform.gelu) or rspamd_kann.transform.relu

  lua_util.debugm(N, rspamd_config, 'embedding ANN: %s layers, dropout=%s, layernorm=%s, activation=%s',
    #layers, dropout_rate, use_layernorm, activation)

  -- Build funnel architecture with graduated dimension reduction
  for i, layer_mult in ipairs(layers) do
    local layer_size = math.max(math.floor(n * layer_mult), 32)

    -- Dense layer
    t = rspamd_kann.layer.dense(t, layer_size)

    -- Layer normalization for training stability
    if use_layernorm then
      t = rspamd_kann.layer.layernorm(t)
    end

    -- Activation function (GELU or ReLU)
    t = activate_fn(t)

    -- Dropout for regularization (less on final hidden layer)
    if dropout_rate > 0 then
      local rate = (i == #layers) and (dropout_rate * 0.5) or dropout_rate
      t = rspamd_kann.layer.dropout(t, rate)
    end
  end

  t = rspamd_kann.layer.cost(t, 1, rspamd_kann.cost.ceb_neg)
  return rspamd_kann.new.kann(t)
end

-- Conv1d ANN: uses the enhanced embedding architecture.
-- The actual convolution (multi-scale max-over-time pooling) is done in the
-- fasttext_embed provider, which produces compact feature vectors (n_scales * channels).
-- The ANN itself is a simple dense network on these pre-convolved features.
local function create_conv1d_ann(n, rule)
  lua_util.debugm(N, rspamd_config,
    'creating conv1d ANN: %s pre-convolved inputs', n)
  return create_embedding_ann(n, rule)
end

-- Detects if rule uses LLM embeddings provider
local function uses_llm_embeddings(rule)
  if not rule.providers then
    return false
  end
  for _, p in ipairs(rule.providers) do
    if p.type == 'llm' then
      return true
    end
  end
  return false
end

-- Main ANN factory function - auto-selects architecture based on rule configuration
local function create_ann(n, nlayers, rule)
  -- Check for conv1d architecture first
  if rule.conv1d then
    lua_util.debugm(N, rspamd_config, 'creating conv1d ANN with %s inputs', n)
    return create_conv1d_ann(n, rule)
  end

  -- Check if we should use the enhanced embedding architecture
  -- Conditions: has LLM provider, or explicit multi-layer config, or large input dimension
  local use_embedding_arch = uses_llm_embeddings(rule)
    or rule.layers ~= nil
    or rule.use_layernorm ~= nil
    or rule.dropout ~= nil

  if use_embedding_arch then
    lua_util.debugm(N, rspamd_config, 'creating multi-layer embedding ANN with %s inputs', n)
    return create_embedding_ann(n, rule)
  else
    lua_util.debugm(N, rspamd_config, 'creating simple symbol ANN with %s inputs', n)
    return create_symbol_ann(n, rule)
  end
end

-- Fills ANN data for a specific settings element
local function fill_set_ann(set, ann_key)
  if not set.ann then
    set.ann = {
      symbols = set.symbols,
      distance = 0,
      digest = set.digest,
      redis_key = ann_key,
      version = 0,
    }
  end
end

-- This function takes all inputs, applies PCA transformation and returns the final
-- PCA matrix as rspamd_tensor
local function learn_pca(inputs, max_inputs)
  local scatter_matrix = rspamd_tensor.scatter_matrix(rspamd_tensor.fromtable(inputs))
  local eigenvals = scatter_matrix:eigen()
  -- scatter matrix is not filled with eigenvectors
  lua_util.debugm(N, 'eigenvalues: %s', eigenvals)
  local w = rspamd_tensor.new(2, max_inputs, #scatter_matrix[1])
  for i = 1, max_inputs do
    w[i] = scatter_matrix[#scatter_matrix - i + 1]
  end

  lua_util.debugm(N, 'pca matrix: %s', w)

  return w
end

-- Build providers metadata for storage alongside ANN
local function build_providers_meta(metas)
  if not metas or #metas == 0 then return nil end
  local out = {}
  for i, m in ipairs(metas) do
    out[i] = {
      name = m.name,
      type = m.type,
      dim = m.dim,
      weight = m.weight,
      model = m.model,
      provider = m.provider,
    }
  end
  return out
end

-- Normalization helpers
local function l2_normalize_vector(vec)
  local sumsq = 0.0
  for i = 1, #vec do
    local v = vec[i]
    sumsq = sumsq + v * v
  end
  if sumsq > 0 then
    local inv = 1.0 / math.sqrt(sumsq)
    for i = 1, #vec do
      vec[i] = vec[i] * inv
    end
  end
  return vec
end

local function compute_zscore_stats(inputs)
  local n = #inputs
  if n == 0 then return nil end
  local d = #inputs[1]
  local mean = {}
  local m2 = {}
  for j = 1, d do
    mean[j] = 0.0
    m2[j] = 0.0
  end
  for i = 1, n do
    local x = inputs[i]
    for j = 1, d do
      local delta = x[j] - mean[j]
      mean[j] = mean[j] + delta / i
      m2[j] = m2[j] + delta * (x[j] - mean[j])
    end
  end
  local std = {}
  for j = 1, d do
    std[j] = math.sqrt((n > 1 and (m2[j] / (n - 1))) or 0.0)
    if std[j] == 0 or std[j] ~= std[j] then
      std[j] = 1.0 -- avoid division by zero and NaN
    end
  end
  return { mode = 'zscore', mean = mean, std = std }
end

local function apply_normalization(vec, norm_stats_or_mode)
  if not norm_stats_or_mode then return vec end
  if type(norm_stats_or_mode) == 'string' then
    if norm_stats_or_mode == 'unit' then
      return l2_normalize_vector(vec)
    else
      return vec
    end
  else
    if norm_stats_or_mode.mode == 'unit' then
      return l2_normalize_vector(vec)
    elseif norm_stats_or_mode.mode == 'zscore' and norm_stats_or_mode.mean and norm_stats_or_mode.std then
      local mean = norm_stats_or_mode.mean
      local std = norm_stats_or_mode.std
      for i = 1, math.min(#vec, #mean) do
        vec[i] = (vec[i] - (mean[i] or 0.0)) / (std[i] or 1.0)
      end
      return vec
    else
      return vec
    end
  end
end

-- This function computes optimal threshold using ROC for the given set of inputs.
-- Returns a threshold that minimizes:
--        alpha * (false_positive_rate)  +  beta * (false_negative_rate)
--        Where alpha is cost of false positive result
--              beta is cost of false negative result
local function get_roc_thresholds(ann, inputs, outputs, alpha, beta)
  -- Sorts list x and list y based on the values in list x.
  local sort_relative = function(x, y)
    local r = {}

    assert(#x == #y)
    local n = #x

    local a = {}
    local b = {}
    for i = 1, n do
      r[i] = i
    end

    local cmp = function(p, q)
      return p < q
    end

    table.sort(r, function(p, q)
      return cmp(x[p], x[q])
    end)

    for i = 1, n do
      a[i] = x[r[i]]
      b[i] = y[r[i]]
    end

    return a, b
  end

  local function get_scores(nn, input_vectors)
    local scores = {}
    for i = 1, #inputs do
      local score = nn:apply1(input_vectors[i], nn.pca)[1]
      scores[#scores + 1] = score
    end

    return scores
  end

  local fpr = {}
  local fnr = {}
  local scores = get_scores(ann, inputs)

  scores, outputs = sort_relative(scores, outputs)

  local n_samples = #outputs
  local n_spam = 0
  local n_ham = 0
  local ham_count_ahead = {}
  local spam_count_ahead = {}
  local ham_count_behind = {}
  local spam_count_behind = {}

  ham_count_ahead[n_samples + 1] = 0
  spam_count_ahead[n_samples + 1] = 0

  for i = n_samples, 1, -1 do
    -- Labels are -1.0 for ham and 1.0 for spam (ceb_neg cost function)
    if outputs[i][1] < 0 then
      n_ham = n_ham + 1
      ham_count_ahead[i] = 1
      spam_count_ahead[i] = 0
    else
      n_spam = n_spam + 1
      ham_count_ahead[i] = 0
      spam_count_ahead[i] = 1
    end

    ham_count_ahead[i] = ham_count_ahead[i] + ham_count_ahead[i + 1]
    spam_count_ahead[i] = spam_count_ahead[i] + spam_count_ahead[i + 1]
  end

  for i = 1, n_samples do
    -- Labels are -1.0 for ham and 1.0 for spam (ceb_neg cost function)
    if outputs[i][1] < 0 then
      ham_count_behind[i] = 1
      spam_count_behind[i] = 0
    else
      ham_count_behind[i] = 0
      spam_count_behind[i] = 1
    end

    if i ~= 1 then
      ham_count_behind[i] = ham_count_behind[i] + ham_count_behind[i - 1]
      spam_count_behind[i] = spam_count_behind[i] + spam_count_behind[i - 1]
    end
  end

  for i = 1, n_samples do
    fpr[i] = 0
    fnr[i] = 0

    if (ham_count_ahead[i + 1] + ham_count_behind[i]) ~= 0 then
      fpr[i] = ham_count_ahead[i + 1] / (ham_count_ahead[i + 1] + ham_count_behind[i])
    end

    if (spam_count_behind[i] + spam_count_ahead[i + 1]) ~= 0 then
      fnr[i] = spam_count_behind[i] / (spam_count_behind[i] + spam_count_ahead[i + 1])
    end
  end

  local p = n_spam / (n_spam + n_ham)

  local cost = {}
  local min_cost_idx = 0
  local min_cost = math.huge
  for i = 1, n_samples do
    cost[i] = ((1 - p) * alpha * fpr[i]) + (p * beta * fnr[i])
    if min_cost >= cost[i] then
      min_cost = cost[i]
      min_cost_idx = i
    end
  end

  return scores[min_cost_idx]
end

-- This function is intended to extend lock for ANN during training
-- It registers periodic that increases locked key each 30 seconds unless
-- `set.learning_spawned` is set to `true`
local function register_lock_extender(rule, set, ev_base, ann_key)
  rspamd_config:add_periodic(ev_base, 30.0,
    function()
      local function redis_lock_extend_cb(err, _)
        if err then
          rspamd_logger.errx(rspamd_config, 'cannot lock ANN %s from redis: %s',
            ann_key, err)
        else
          rspamd_logger.infox(rspamd_config, 'extend lock for ANN %s for 30 seconds',
            ann_key)
        end
      end

      if set.learning_spawned then
        lua_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          rule.redis,
          nil,
          true,                 -- is write
          redis_lock_extend_cb, --callback
          'HINCRBY',            -- command
          { ann_key, 'lock', '30' }
        )
      else
        lua_util.debugm(N, rspamd_config, "stop lock extension as learning_spawned is false")
        return false -- do not plan any more updates
      end

      return true
    end
  )
end

local function can_push_train_vector(rule, task, learn_type, nspam, nham)
  local train_opts = rule.train
  local coin = math.random()

  if train_opts.train_prob and coin < 1.0 - train_opts.train_prob then
    rspamd_logger.infox(task, 'probabilistically skip sample: %s', coin)
    return false
  end

  if train_opts.learn_mode == 'balanced' then
    -- Keep balanced training set based on number of spam and ham samples
    if learn_type == 'spam' then
      if nspam <= train_opts.max_trains then
        if nspam > nham then
          -- Apply sampling
          local skip_rate = 1.0 - nham / (nspam + 1)
          if coin < skip_rate - train_opts.classes_bias then
            rspamd_logger.infox(task,
              'skip %s sample to keep spam/ham balance; probability %s; %s spam and %s ham vectors stored',
              learn_type,
              skip_rate - train_opts.classes_bias,
              nspam, nham)
            return false
          end
        end
        return true
      else
        -- Enough learns
        rspamd_logger.infox(task, 'skip %s sample to keep spam/ham balance; too many spam samples: %s',
          learn_type,
          nspam)
      end
    else
      if nham <= train_opts.max_trains then
        if nham > nspam then
          -- Apply sampling
          local skip_rate = 1.0 - nspam / (nham + 1)
          if coin < skip_rate - train_opts.classes_bias then
            rspamd_logger.infox(task,
              'skip %s sample to keep spam/ham balance; probability %s; %s spam and %s ham vectors stored',
              learn_type,
              skip_rate - train_opts.classes_bias,
              nspam, nham)
            return false
          end
        end
        return true
      else
        rspamd_logger.infox(task, 'skip %s sample to keep spam/ham balance; too many ham samples: %s', learn_type,
          nham)
      end
    end
  else
    -- Probabilistic learn mode, we just skip learn if we already have enough samples or
    -- if our coin drop is less than desired probability
    if learn_type == 'spam' then
      if nspam <= train_opts.max_trains then
        if train_opts.spam_skip_prob then
          if coin <= train_opts.spam_skip_prob then
            rspamd_logger.infox(task, 'skip %s sample probabilistically; probability %s (%s skip chance)', learn_type,
              coin, train_opts.spam_skip_prob)
            return false
          end

          return true
        end
      else
        rspamd_logger.infox(task, 'skip %s sample; too many spam samples: %s (%s limit)', learn_type,
          nspam, train_opts.max_trains)
      end
    else
      if nham <= train_opts.max_trains then
        if train_opts.ham_skip_prob then
          if coin <= train_opts.ham_skip_prob then
            rspamd_logger.infox(task, 'skip %s sample probabilistically; probability %s (%s skip chance)', learn_type,
              coin, train_opts.ham_skip_prob)
            return false
          end

          return true
        end
      else
        rspamd_logger.infox(task, 'skip %s sample; too many ham samples: %s (%s limit)', learn_type,
          nham, train_opts.max_trains)
      end
    end
  end

  return false
end

-- Closure generator for unlock function
local function gen_unlock_cb(rule, set, ann_key)
  return function(err)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot unlock ANN %s:%s at %s from redis: %s',
        rule.prefix, set.name, ann_key, err)
    else
      lua_util.debugm(N, rspamd_config, 'unlocked ANN %s:%s at %s',
        rule.prefix, set.name, ann_key)
    end
  end
end

-- Used to generate new ANN key for specific profile
local function new_ann_key(rule, set, version)
  local ann_key = string.format('%s_%s_%s_%s_%d', settings.prefix,
    rule.prefix, set.name, set.digest:sub(1, 8), version)

  return ann_key
end

local function redis_ann_prefix(rule, settings_name)
  -- We also need to count metatokens:
  -- Note: meta_functions.version represents the metatoken format version
  local n = meta_functions.version
  return string.format('%s%d_%s_%d_%s',
    settings.prefix, plugin_ver, rule.prefix, n, settings_name)
end

-- Returns a stable key for pending training vectors (version-independent)
-- Used for batch/manual training to avoid version mismatch issues
local function pending_train_key(rule, set)
  return string.format('%s_%s_%s_pending',
    settings.prefix, rule.prefix, set.name)
end

-- Compute a stable digest for providers configuration
local function providers_config_digest(providers_cfg, rule)
  if not providers_cfg then return nil end
  -- Normalize minimal subset of fields to keep digest stable across equivalent configs
  local norm = { providers = {} }

  local fusion = rule and rule.fusion or nil
  if rule then
    local effective_fusion = {
      normalization = (fusion and fusion.normalization) or 'none',
      include_meta = fusion and fusion.include_meta,
      meta_weight = fusion and fusion.meta_weight,
      per_provider_pca = fusion and fusion.per_provider_pca,
    }
    if effective_fusion.include_meta == nil then
      effective_fusion.include_meta = true
    end
    if effective_fusion.meta_weight == nil then
      effective_fusion.meta_weight = 1.0
    end
    if effective_fusion.per_provider_pca == nil then
      effective_fusion.per_provider_pca = false
    end
    norm.fusion = effective_fusion
  end

  if rule and rule.max_inputs then
    norm.max_inputs = rule.max_inputs
  end

  local gpt_settings = rspamd_config:get_all_opt('gpt') or {}

  for i, p in ipairs(providers_cfg) do
    local ptype = p.type or p.name or 'unknown'
    local entry = {
      type = ptype,
      weight = p.weight or 1.0,
      dim = p.dim,
    }

    if ptype == 'llm' then
      local llm_type = p.llm_type or p.api or p.backend or gpt_settings.type
      local model = p.model or gpt_settings.model
      local max_tokens = p.max_tokens
      if not max_tokens and gpt_settings.model_parameters and model then
        local model_cfg = gpt_settings.model_parameters[model] or {}
        max_tokens = model_cfg.max_completion_tokens or model_cfg.max_tokens
      end
      if not max_tokens then
        max_tokens = gpt_settings.max_tokens
      end

      entry.llm_type = llm_type
      entry.model = model
      entry.max_tokens = max_tokens
    end

    -- Conv1d feature extraction settings affect output dimensions
    if p.output_mode == 'conv1d' then
      entry.output_mode = 'conv1d'
      entry.max_words = p.max_words or 32
      entry.kernel_sizes = p.kernel_sizes or { 1, 3, 5 }
      entry.conv_pooling = p.conv_pooling or 'max'
    end

    norm.providers[i] = entry
  end
  return lua_util.unordered_table_digest(norm)
end

-- If no providers configured, fallback to symbols provider unless disabled
-- phase: 'infer' | 'train'
-- Removed synchronous collect_features; use collect_features_async instead

-- Async version: runs providers in parallel and calls cb(fused, meta) when done
local function collect_features_async(task, rule, profile_or_set, phase, cb)
  local providers_cfg = rule.providers
  if not providers_cfg or #providers_cfg == 0 then
    if rule.disable_symbols_input then
      cb(nil, { providers = {}, total_dim = 0, digest = providers_config_digest(providers_cfg, rule) })
      return
    end
    local prov = get_provider('symbols')
    if prov and prov.collect_async then
      prov.collect_async(task, { profile = profile_or_set, weight = 1.0, phase = phase }, function(vec, meta)
        local metas = {}
        if vec then
          metas[1] = meta
        end
        local fused = {}
        if vec then
          local w = (meta and meta.weight) or 1.0
          local norm_mode = (rule.fusion and rule.fusion.normalization) or 'none'
          if norm_mode ~= 'none' then
            vec = apply_normalization(vec, norm_mode)
          end
          for _, x in ipairs(vec) do
            fused[#fused + 1] = x * w
          end
        end
        cb(#fused > 0 and fused or nil, {
          providers = build_providers_meta(metas) or metas,
          total_dim = #fused,
          digest = providers_config_digest(providers_cfg, rule),
        })
      end)
      return
    end
    -- Fallback: direct symbols compute
    local vec = result_to_vector(task, profile_or_set)
    local meta = { name = 'symbols', type = 'symbols', dim = #vec, weight = 1.0 }
    local fused = {}
    local w = 1.0
    local norm_mode = (rule.fusion and rule.fusion.normalization) or 'none'
    if norm_mode ~= 'none' then
      vec = apply_normalization(vec, norm_mode)
    end
    for _, x in ipairs(vec) do
      fused[#fused + 1] = x * w
    end
    cb(fused,
      {
        providers = build_providers_meta({ meta }) or { meta },
        total_dim = #fused,
        digest = providers_config_digest(
          providers_cfg, rule)
      })
    return
  end

  local vectors = {}
  local metas = {}
  local remaining = 0

  local function maybe_finish()
    remaining = remaining - 1
    if remaining == 0 then
      -- Fuse
      local fused = {}
      for i, v in ipairs(vectors) do
        if v then
          local w = (metas[i] and metas[i].weight) or 1.0
          local norm_mode = (rule.fusion and rule.fusion.normalization) or 'none'
          if norm_mode ~= 'none' then
            v = apply_normalization(v, norm_mode)
          end
          for _, x in ipairs(v) do
            fused[#fused + 1] = x * w
          end
        end
      end
      local meta = {
        providers = build_providers_meta(metas) or metas,
        total_dim = #fused,
        digest = providers_config_digest(providers_cfg, rule),
      }
      if #fused == 0 then
        cb(nil, meta)
      else
        cb(fused, meta)
      end
    end
  end

  local function start_provider(i, pcfg)
    local prov = get_provider(pcfg.type or pcfg.name)
    if not prov or not prov.collect_async then
      maybe_finish()
      return
    end
    prov.collect_async(task, {
      profile = profile_or_set,
      set = profile_or_set,
      rule = rule,
      config = pcfg,
      weight = pcfg.weight or 1.0,
      phase = phase,
    }, function(vec, meta)
      if vec then
        metas[i] = meta or { name = pcfg.name or pcfg.type, type = pcfg.type, dim = #vec, weight = pcfg.weight or 1.0 }
        vectors[i] = vec
      end
      maybe_finish()
    end)
  end

  -- Include symbols provider (which includes both symbols AND metatokens) as an extra provider
  -- The name 'include_meta' is historical but it actually includes the full symbols provider
  -- For backward compatibility, include symbols by default unless explicitly disabled
  local include_meta = false
  if not providers_cfg or #providers_cfg == 0 then
    -- No providers, always use symbols (which includes metatokens)
    include_meta = true
  elseif rule.fusion then
    -- Explicit fusion config takes precedence
    include_meta = rule.fusion.include_meta
    if include_meta == nil then
      -- Default to true for backward compatibility when fusion is configured but include_meta not specified
      include_meta = true
    end
  else
    -- Providers configured but no fusion settings - default to including symbols+metatokens
    include_meta = true
  end

  local meta_weight = (rule.fusion and rule.fusion.meta_weight) or 1.0

  remaining = #providers_cfg + (include_meta and 1 or 0)

  -- Start all configured providers
  for i, pcfg in ipairs(providers_cfg) do
    start_provider(i, pcfg)
  end

  if include_meta then
    -- Always use metatokens provider for consistency
    -- This ensures same dimensions whether called from controller or full scan
    local prov = get_provider('metatokens')

    if prov and prov.collect_async then
      local meta_index = #providers_cfg + 1 -- Metatokens always come after providers
      prov.collect_async(task, { profile = profile_or_set, set = profile_or_set, weight = meta_weight, phase = phase },
        function(vec, meta)
          if vec then
            metas[meta_index] = meta
            vectors[meta_index] = vec
          end
          maybe_finish()
        end)
    else
      maybe_finish()
    end
  end
end

-- This function receives training vectors, checks them, spawn learning and saves ANN in Redis
local function spawn_train(params)
  -- Prevent concurrent training (flag may be set by do_train_ann or needs to be set here for direct calls)
  if params.set.learning_spawned then
    lua_util.debugm(N, rspamd_config, 'spawn_train: training already in progress for %s:%s, skipping',
      params.rule.prefix, params.set.name)
    return
  end
  params.set.learning_spawned = true

  -- Check training data sanity
  -- Now we need to join inputs and create the appropriate test vectors
  local n

  -- When using providers, derive dimension from actual vectors
  if params.rule.providers and #params.rule.providers > 0 and
      (#params.spam_vec > 0 or #params.ham_vec > 0) then
    -- Use dimension from stored vectors
    if #params.spam_vec > 0 then
      n = #params.spam_vec[1]
    else
      n = #params.ham_vec[1]
    end
    lua_util.debugm(N, rspamd_config, 'spawn_train: using vector dimension %s from stored vectors', n)
  else
    -- Traditional symbol-based dimension
    n = #params.set.symbols + meta_functions.rspamd_count_metatokens()
    lua_util.debugm(N, rspamd_config, 'spawn_train: using symbol dimension %s symbols + %s metatokens = %s',
      #params.set.symbols, meta_functions.rspamd_count_metatokens(), n)
  end

  -- Now we can train ann - wrap in pcall to catch KANN errors
  local create_ok, train_ann = pcall(create_ann, params.rule.max_inputs or n, 3, params.rule)
  if not create_ok then
    rspamd_logger.errx(rspamd_config, 'failed to create ANN for %s:%s: %s',
      params.rule.prefix, params.set.name, train_ann)
    params.set.learning_spawned = false
    return
  end

  if #params.ham_vec + #params.spam_vec < params.rule.train.max_trains / 2 then
    -- Insufficient training data, reset flag and return
    rspamd_logger.errx(rspamd_config, 'insufficient training data for ANN %s:%s: spam=%s ham=%s (need at least %s total)',
      params.rule.prefix, params.set.name,
      #params.spam_vec, #params.ham_vec, params.rule.train.max_trains / 2)
    params.set.learning_spawned = false
    return
  else
    local inputs, outputs = {}, {}

    -- Used to show parsed vectors in a convenient format (for debugging only)
    local function debug_vec(t)
      local ret = {}
      for i, v in ipairs(t) do
        if v ~= 0 then
          ret[#ret + 1] = string.format('%d=%.2f', i, v)
        end
      end

      return ret
    end

    -- Make training set by joining vectors
    -- KANN automatically shuffles those samples
    -- 1.0 is used for spam and -1.0 is used for ham
    -- It implies that output layer can express that (e.g. tanh output)
    for _, e in ipairs(params.spam_vec) do
      inputs[#inputs + 1] = e
      outputs[#outputs + 1] = { 1.0 }
      --rspamd_logger.debugm(N, rspamd_config, 'spam vector: %s', debug_vec(e))
    end
    for _, e in ipairs(params.ham_vec) do
      inputs[#inputs + 1] = e
      outputs[#outputs + 1] = { -1.0 }
      --rspamd_logger.debugm(N, rspamd_config, 'ham vector: %s', debug_vec(e))
    end

    -- Called in child process
    local function train()
      local log_thresh = params.rule.train.max_iterations / 10
      local seen_nan = false

      local function train_cb(iter, train_cost, value_cost)
        if (iter * (params.rule.train.max_iterations / log_thresh)) % (params.rule.train.max_iterations) == 0 then
          if train_cost ~= train_cost and not seen_nan then
            -- We have nan :( try to log lot's of stuff to dig into a problem
            seen_nan = true
            rspamd_logger.errx(rspamd_config, 'ANN %s:%s: train error: observed nan in error cost!; value cost = %s',
              params.rule.prefix, params.set.name,
              value_cost)
            for i, e in ipairs(inputs) do
              lua_util.debugm(N, rspamd_config, 'train vector %s -> %s',
                debug_vec(e), outputs[i][1])
            end
          end

          rspamd_logger.infox(rspamd_config,
            "ANN %s:%s: learned from %s redis key in %s iterations, error: %s, value cost: %s",
            params.rule.prefix, params.set.name,
            params.ann_key,
            iter,
            train_cost,
            value_cost)
        end
      end

      lua_util.debugm(N, rspamd_config, "subprocess to learn ANN %s:%s has been started",
        params.rule.prefix, params.set.name)

      local pca
      if params.rule.max_inputs then
        -- Train PCA in the main process, presumably it is not that long
        lua_util.debugm(N, rspamd_config, "start PCA train for ANN %s:%s",
          params.rule.prefix, params.set.name)
        pca = learn_pca(inputs, params.rule.max_inputs)
      end

      -- Compute normalization stats if requested
      local norm_stats
      if params.rule.fusion and params.rule.fusion.normalization == 'zscore' then
        norm_stats = compute_zscore_stats(inputs)
      elseif params.rule.fusion and params.rule.fusion.normalization == 'unit' then
        norm_stats = { mode = 'unit' }
      end

      if norm_stats then
        for i = 1, #inputs do
          inputs[i] = apply_normalization(inputs[i], norm_stats)
        end
      end

      lua_util.debugm(N, rspamd_config, "start neural train for ANN %s:%s",
        params.rule.prefix, params.set.name)
      local ret, err = pcall(train_ann.train1, train_ann,
        inputs, outputs, {
          lr = params.rule.train.learning_rate,
          max_epoch = params.rule.train.max_iterations,
          cb = train_cb,
          pca = pca
        })

      if not ret then
        rspamd_logger.errx(rspamd_config, "cannot train ann %s:%s: %s",
          params.rule.prefix, params.set.name, err)

        return nil
      else
        lua_util.debugm(N, rspamd_config, "finished neural train for ANN %s:%s",
          params.rule.prefix, params.set.name)
      end

      local roc_thresholds = {}
      if params.rule.roc_enabled then
        local spam_threshold = get_roc_thresholds(train_ann,
          inputs,
          outputs,
          1 - params.rule.roc_misclassification_cost,
          params.rule.roc_misclassification_cost)
        local ham_threshold = get_roc_thresholds(train_ann,
          inputs,
          outputs,
          params.rule.roc_misclassification_cost,
          1 - params.rule.roc_misclassification_cost)
        roc_thresholds = { spam_threshold, ham_threshold }

        rspamd_logger.messagex(rspamd_config, "ROC thresholds: (spam_threshold: %s, ham_threshold: %s)",
          roc_thresholds[1], roc_thresholds[2])
      end

      if not seen_nan then
        -- Convert to strings as ucl cannot rspamd_text properly
        local pca_data
        if pca then
          pca_data = tostring(pca:save())
        end
        local out = {
          ann_data = tostring(train_ann:save()),
          pca_data = pca_data,
          roc_thresholds = roc_thresholds,
          norm_stats = norm_stats,
        }

        local final_data = ucl.to_format(out, 'msgpack')
        lua_util.debugm(N, rspamd_config, "subprocess for ANN %s:%s returned %s bytes",
          params.rule.prefix, params.set.name, #final_data)
        return final_data
      else
        return nil
      end
    end

    local function redis_save_cb(err)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot save ANN %s:%s to redis key %s: %s',
          params.rule.prefix, params.set.name, params.ann_key, err)
        lua_redis.redis_make_request_taskless(params.ev_base,
          rspamd_config,
          params.rule.redis,
          nil,
          false,                                                  -- is write
          gen_unlock_cb(params.rule, params.set, params.ann_key), --callback
          'HDEL',                                                 -- command
          { params.ann_key, 'lock' }
        )
      else
        rspamd_logger.infox(rspamd_config, 'saved ANN %s:%s to redis: %s',
          params.rule.prefix, params.set.name, params.set.ann.redis_key)

        -- Clean up pending training keys if they were used
        if params.pending_key then
          local function cleanup_cb(cleanup_err)
            if cleanup_err then
              lua_util.debugm(N, rspamd_config, 'failed to cleanup pending keys: %s', cleanup_err)
            else
              lua_util.debugm(N, rspamd_config, 'cleaned up pending training keys for %s',
                params.pending_key)
            end
          end
          -- Delete both spam and ham pending sets
          lua_redis.redis_make_request_taskless(params.ev_base,
            rspamd_config,
            params.rule.redis,
            nil,
            true,       -- is write
            cleanup_cb,
            'DEL',
            { params.pending_key .. '_spam_set', params.pending_key .. '_ham_set' }
          )
        end
      end
    end

    local function ann_trained(err, data)
      params.set.learning_spawned = false
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot train ANN %s:%s : %s',
          params.rule.prefix, params.set.name, err)
        lua_redis.redis_make_request_taskless(params.ev_base,
          rspamd_config,
          params.rule.redis,
          nil,
          true,                                                   -- is write
          gen_unlock_cb(params.rule, params.set, params.ann_key), --callback
          'HDEL',                                                 -- command
          { params.ann_key, 'lock' }
        )
      else
        local parser = ucl.parser()
        local ok, parse_err = parser:parse_text(data, 'msgpack')
        if not ok then
          rspamd_logger.errx(rspamd_config, 'cannot parse training result for ANN %s:%s: %s (data size: %s)',
            params.rule.prefix, params.set.name, parse_err, #data)
          lua_redis.redis_make_request_taskless(params.ev_base,
            rspamd_config,
            params.rule.redis,
            nil,
            true,
            gen_unlock_cb(params.rule, params.set, params.ann_key),
            'HDEL',
            { params.ann_key, 'lock' }
          )
          return
        end
        local parsed = parser:get_object()
        local ann_data = rspamd_util.zstd_compress(parsed.ann_data)
        local pca_data = parsed.pca_data
        local roc_thresholds = parsed.roc_thresholds
        local norm_stats = parsed.norm_stats

        fill_set_ann(params.set, params.ann_key)
        if pca_data then
          params.set.ann.pca = rspamd_tensor.load(pca_data)
          pca_data = rspamd_util.zstd_compress(pca_data)
        end

        if roc_thresholds then
          params.set.ann.roc_thresholds = roc_thresholds
        end


        -- Deserialise ANN from the child process
        local loaded_ann = rspamd_kann.load(parsed.ann_data)
        local version = (params.set.ann.version or 0) + 1
        params.set.ann.version = version
        params.set.ann.ann = loaded_ann
        params.set.ann.symbols = params.set.symbols
        params.set.ann.redis_key = new_ann_key(params.rule, params.set, version)

        local profile = {
          symbols = params.set.symbols,
          digest = params.set.digest,
          redis_key = params.set.ann.redis_key,
          version = version,
          providers_digest = providers_config_digest(params.rule.providers, params.rule),
        }

        local profile_serialized = ucl.to_format(profile, 'json-compact', true)
        local roc_thresholds_serialized = ucl.to_format(roc_thresholds, 'json-compact', true)
        local providers_meta_serialized
        if params.rule.providers then
          providers_meta_serialized = ucl.to_format(
            build_providers_meta(params.set.ann.providers or params.rule.providers), 'json-compact', true)
        end

        rspamd_logger.infox(rspamd_config,
          'trained ANN %s:%s, %s bytes (%s compressed); %s rows in pca (%sb compressed); redis key: %s (old key %s)',
          params.rule.prefix, params.set.name,
          #data, #ann_data,
          #(params.set.ann.pca or {}), #(pca_data or {}),
          params.set.ann.redis_key, params.ann_key)

        -- Ensure all arguments are non-nil for Lua 5.4 compatibility
        -- (nil values in tables cause length/iteration issues)
        lua_redis.exec_redis_script(redis_script_id.save_unlock,
          { ev_base = params.ev_base, is_write = true },
          redis_save_cb,
          { profile.redis_key,
            redis_ann_prefix(params.rule, params.set.name),
            params.ann_key, -- old key to unlock...
          },
          { ann_data,
            profile_serialized,
            tostring(params.rule.ann_expire),
            tostring(os.time()),
            roc_thresholds_serialized or '',
            pca_data or '',
            providers_meta_serialized or '',
            ucl.to_format(norm_stats, 'json-compact', true) or '',
          })
      end
      -- Force GC to clean up training temporaries (parsed data, compressed buffers, etc.)
      -- to prevent LuaJIT GC atomic phase stalls on a bloated heap
      collectgarbage('collect')
    end

    if params.rule.max_inputs then
      fill_set_ann(params.set, params.ann_key)
    end

    params.worker:spawn_process {
      func = train,
      on_complete = ann_trained,
      proctitle = string.format("ANN train for %s/%s", params.rule.prefix, params.set.name),
    }
    -- Register lock extension (learning_spawned already set at start of spawn_train)
    register_lock_extender(params.rule, params.set, params.ev_base, params.ann_key)
    return
  end
end

-- This function is used to adjust profiles and allowed setting ids for each rule
-- It must be called when all settings are already registered (e.g. at post-init for config)
local function process_rules_settings()
  local function process_settings_elt(rule, selt)
    local profile = rule.profile[selt.name]
    if profile then
      -- Use static user defined profile
      -- Ensure that we have an array...
      lua_util.debugm(N, rspamd_config, "use static profile for %s (%s): %s",
        rule.prefix, selt.name, profile)
      if not profile[1] then
        profile = lua_util.keys(profile)
      end
      selt.symbols = profile
    else
      lua_util.debugm(N, rspamd_config, "use dynamic cfg based profile for %s (%s)",
        rule.prefix, selt.name)
    end

    local function filter_symbols_predicate(sname)
      if settings.blacklisted_symbols and settings.blacklisted_symbols[sname] then
        return false
      end
      local fl = rspamd_config:get_symbol_flags(sname)
      if fl then
        fl = lua_util.list_to_hash(fl)

        return not (fl.nostat or fl.idempotent or fl.skip or fl.composite)
      end

      return true
    end

    -- Generic stuff
    if not profile then
      -- Do filtering merely if we are using a dynamic profile
      selt.symbols = fun.totable(fun.filter(filter_symbols_predicate, selt.symbols))
    end

    table.sort(selt.symbols)

    selt.digest = lua_util.table_digest(selt.symbols)
    selt.prefix = redis_ann_prefix(rule, selt.name)

    rspamd_logger.messagex(rspamd_config,
      'use NN prefix for rule %s; settings id "%s"; symbols digest: "%s"',
      selt.prefix, selt.name, selt.digest)

    lua_redis.register_prefix(selt.prefix, N,
      string.format('NN prefix for rule "%s"; settings id "%s"',
        selt.prefix, selt.name), {
        persistent = true,
        type = 'zlist',
      })
    -- Versions
    lua_redis.register_prefix(selt.prefix .. '_\\d+', N,
      string.format('NN storage for rule "%s"; settings id "%s"',
        selt.prefix, selt.name), {
        persistent = true,
        type = 'hash',
      })
    lua_redis.register_prefix(selt.prefix .. '_\\d+_spam_set', N,
      string.format('NN learning set (spam) for rule "%s"; settings id "%s"',
        selt.prefix, selt.name), {
        persistent = true,
        type = 'set',
      })
    lua_redis.register_prefix(selt.prefix .. '_\\d+_ham_set', N,
      string.format('NN learning set (ham) for rule "%s"; settings id "%s"',
        rule.prefix, selt.name), {
        persistent = true,
        type = 'set',
      })
  end

  for k, rule in pairs(settings.rules) do
    if not rule.allowed_settings then
      rule.allowed_settings = {}
    elseif rule.allowed_settings == 'all' then
      -- Extract all settings ids
      rule.allowed_settings = lua_util.keys(lua_settings.all_settings())
    end

    -- Convert to a map <setting_id> -> true
    rule.allowed_settings = lua_util.list_to_hash(rule.allowed_settings)

    -- Check if we can work without settings
    if k == 'default' or type(rule.default) ~= 'boolean' then
      rule.default = true
    end

    rule.settings = {}

    if rule.default then
      local default_settings = {
        symbols = lua_settings.default_symbols(),
        name = 'default'
      }

      process_settings_elt(rule, default_settings)
      rule.settings[-1] = default_settings -- Magic constant, but OK as settings are positive int32
    end

    -- Now, for each allowed settings, we store sorted symbols + digest
    -- We set table rule.settings[id] -> { name = name, symbols = symbols, digest = digest }
    for s, _ in pairs(rule.allowed_settings) do
      -- Here, we have a name, set of symbols and
      local settings_id = s
      if type(settings_id) ~= 'number' then
        settings_id = lua_settings.numeric_settings_id(s)
      end
      local selt = lua_settings.settings_by_id(settings_id)

      local nelt = {
        symbols = selt.symbols, -- Already sorted
        name = selt.name
      }

      process_settings_elt(rule, nelt)
      for id, ex in pairs(rule.settings) do
        if type(ex) == 'table' then
          if nelt and lua_util.distance_sorted(ex.symbols, nelt.symbols) == 0 then
            -- Equal symbols, add reference
            lua_util.debugm(N, rspamd_config,
              'added reference from settings id %s to %s; same symbols',
              nelt.name, ex.name)
            rule.settings[settings_id] = id
            nelt = nil
          end
        end
      end

      if nelt then
        rule.settings[settings_id] = nelt
        lua_util.debugm(N, rspamd_config, 'added new settings id %s(%s) to %s',
          nelt.name, settings_id, rule.prefix)
      end
    end
  end
end

-- Extract settings element for a specific settings id
local function get_rule_settings(task, rule)
  local sid = task:get_settings_id() or -1
  local set = rule.settings[sid]

  if not set then
    return nil
  end

  while type(set) == 'number' do
    -- Reference to another settings!
    set = rule.settings[set]
  end

  return set
end

result_to_vector = function(task, profile)
  if not profile.zeros then
    -- Fill zeros vector
    local zeros = {}
    for i = 1, meta_functions.rspamd_count_metatokens() do
      zeros[i] = 0.0
    end
    for _, _ in ipairs(profile.symbols) do
      zeros[#zeros + 1] = 0.0
    end
    profile.zeros = zeros
  end

  local vec = lua_util.shallowcopy(profile.zeros)
  local mt = meta_functions.rspamd_gen_metatokens(task)

  for i, v in ipairs(mt) do
    vec[i] = v
  end

  task:process_ann_tokens(profile.symbols, vec, #mt, 0.1)

  return vec
end

return {
  can_push_train_vector = can_push_train_vector,
  collect_features_async = collect_features_async,
  create_ann = create_ann,
  default_options = default_options,
  build_providers_meta = build_providers_meta,
  apply_normalization = apply_normalization,
  gen_unlock_cb = gen_unlock_cb,
  get_provider = get_provider,
  get_rule_settings = get_rule_settings,
  load_scripts = load_scripts,
  module_config = module_config,
  new_ann_key = new_ann_key,
  pending_train_key = pending_train_key,
  providers_config_digest = providers_config_digest,
  register_provider = register_provider,
  plugin_ver = plugin_ver,
  process_rules_settings = process_rules_settings,
  redis_ann_prefix = redis_ann_prefix,
  redis_params = redis_params,
  redis_script_id = redis_script_id,
  result_to_vector = result_to_vector,
  settings = settings,
  spawn_train = spawn_train,
}
