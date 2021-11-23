--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
local plugin_ver = '2'

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
    classes_bias = 0.0, -- balanced mode: what difference is allowed between classes (1:1 proportion means 0 bias)
    spam_skip_prob = 0.0, -- proportional mode: spam skip probability (0-1)
    ham_skip_prob = 0.0, -- proportional mode: ham skip probability
    store_pool_only = false, -- store tokens in cache only (disables autotrain);
    -- neural_vec_mpack stores vector of training data in messagepack neural_profile_digest stores profile digest
  },
  watch_interval = 60.0,
  lock_expire = 600,
  learning_spawned = false,
  ann_expire = 60 * 60 * 24 * 2, -- 2 days
  hidden_layer_mult = 1.5, -- number of neurons in the hidden layer
  roc_enabled = false, -- Use ROC to find the best possible thresholds for ham and spam. If spam_score_threshold or ham_score_threshold is defined, it takes precedence over ROC thresholds.
  roc_misclassification_cost = 0.5, -- Cost of misclassifying a spam message (must be 0..1).
  spam_score_threshold = nil, -- neural score threshold for spam (must be 0..1 or nil to disable)
  ham_score_threshold = nil, -- neural score threshold for ham (must be 0..1 or nil to disable)
  flat_threshold_curve = false, -- use binary classification 0/1 when threshold is reached
  symbol_spam = 'NEURAL_SPAM',
  symbol_ham = 'NEURAL_HAM',
  max_inputs = nil, -- when PCA is used
  blacklisted_symbols = {}, -- list of symbols skipped in neural processing
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
  prefix = 'rn', -- Neural network default prefix
  max_profiles = 3, -- Maximum number of NN profiles stored
}

-- Get module & Redis configuration
local module_config = rspamd_config:get_all_opt(N)
settings = lua_util.override_defaults(settings, module_config)
local redis_params = lua_redis.parse_redis_server('neural')

-- Lua script that checks if we can store a new training vector
-- Uses the following keys:
-- key1 - ann key
-- returns nspam,nham (or nil if locked)
local redis_lua_script_vectors_len = [[
  local prefix = KEYS[1]
  local locked = redis.call('HGET', prefix, 'lock')
  if locked then
    local host = redis.call('HGET', prefix, 'hostname') or 'unknown'
    return string.format('%s:%s', host, locked)
  end
  local nspam = 0
  local nham = 0

  local ret = redis.call('LLEN', prefix .. '_spam')
  if ret then nspam = tonumber(ret) end
  ret = redis.call('LLEN', prefix .. '_ham')
  if ret then nham = tonumber(ret) end

  return {nspam,nham}
]]

-- Lua script to invalidate ANNs by rank
-- Uses the following keys
-- key1 - prefix for keys
-- key2 - number of elements to leave
local redis_lua_script_maybe_invalidate = [[
  local card = redis.call('ZCARD', KEYS[1])
  local lim = tonumber(KEYS[2])
  if card > lim then
    local to_delete = redis.call('ZRANGE', KEYS[1], 0, card - lim - 1)
    for _,k in ipairs(to_delete) do
      local tb = cjson.decode(k)
      redis.call('DEL', tb.redis_key)
      -- Also train vectors
      redis.call('DEL', tb.redis_key .. '_spam')
      redis.call('DEL', tb.redis_key .. '_ham')
    end
    redis.call('ZREMRANGEBYRANK', KEYS[1], 0, card - lim - 1)
    return to_delete
  else
    return {}
  end
]]

-- Lua script to invalidate ANN from redis
-- Uses the following keys
-- key1 - prefix for keys
-- key2 - current time
-- key3 - key expire
-- key4 - hostname
local redis_lua_script_maybe_lock = [[
  local locked = redis.call('HGET', KEYS[1], 'lock')
  local now = tonumber(KEYS[2])
  if locked then
    locked = tonumber(locked)
    local expire = tonumber(KEYS[3])
    if now > locked and (now - locked) < expire then
      return {tostring(locked), redis.call('HGET', KEYS[1], 'hostname') or 'unknown'}
    end
  end
  redis.call('HSET', KEYS[1], 'lock', tostring(now))
  redis.call('HSET', KEYS[1], 'hostname', KEYS[4])
  return 1
]]

-- Lua script to save and unlock ANN in redis
-- Uses the following keys
-- key1 - prefix for ANN
-- key2 - prefix for profile
-- key3 - compressed ANN
-- key4 - profile as JSON
-- key5 - expire in seconds
-- key6 - current time
-- key7 - old key
-- key8 - ROC Thresholds
-- key9 - optional PCA
local redis_lua_script_save_unlock = [[
  local now = tonumber(KEYS[6])
  redis.call('ZADD', KEYS[2], now, KEYS[4])
  redis.call('HSET', KEYS[1], 'ann', KEYS[3])
  redis.call('DEL', KEYS[1] .. '_spam')
  redis.call('DEL', KEYS[1] .. '_ham')
  redis.call('HDEL', KEYS[1], 'lock')
  redis.call('HDEL', KEYS[7], 'lock')
  redis.call('EXPIRE', KEYS[1], tonumber(KEYS[5]))
  redis.call('HSET', KEYS[1], 'roc_thresholds', KEYS[8])
  if KEYS[9] then
    redis.call('HSET', KEYS[1], 'pca', KEYS[9])
  end
  return 1
]]

local redis_script_id = {}

local function load_scripts()
  redis_script_id.vectors_len = lua_redis.add_redis_script(redis_lua_script_vectors_len,
    redis_params)
  redis_script_id.maybe_invalidate = lua_redis.add_redis_script(redis_lua_script_maybe_invalidate,
    redis_params)
  redis_script_id.maybe_lock = lua_redis.add_redis_script(redis_lua_script_maybe_lock,
    redis_params)
  redis_script_id.save_unlock = lua_redis.add_redis_script(redis_lua_script_save_unlock,
    redis_params)
end

local function create_ann(n, nlayers, rule)
    -- We ignore number of layers so far when using kann
  local nhidden = math.floor(n * (rule.hidden_layer_mult or 1.0) + 1.0)
  local t = rspamd_kann.layer.input(n)
  t = rspamd_kann.transform.relu(t)
  t = rspamd_kann.layer.dense(t, nhidden);
  t = rspamd_kann.layer.cost(t, 1, rspamd_kann.cost.ceb_neg)
  return rspamd_kann.new.kann(t)
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
  for i=1,max_inputs do
    w[i] = scatter_matrix[#scatter_matrix - i + 1]
  end

  lua_util.debugm(N, 'pca matrix: %s', w)

  return w
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
    for i=1,n do
      r[i] = i
    end

    local cmp = function(p, q) return p < q end

    table.sort(r, function(p, q) return cmp(x[p], x[q]) end)

    for i=1,n do 
      a[i] = x[r[i]]
      b[i] = y[r[i]]
    end

    return a, b
  end

  local function get_scores(nn, input_vectors)
    local scores = {}
    for i=1,#inputs do
      local score = nn:apply1(input_vectors[i], nn.pca)[1]
      scores[#scores+1] = score
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

	for i=n_samples,1,-1 do

		if outputs[i][1] == 0 then
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

	for i=1,n_samples do
    if outputs[i][1] == 0 then
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

	for i=1,n_samples do
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
	for i=1,n_samples do
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
        local function redis_lock_extend_cb(_err, _)
          if _err then
            rspamd_logger.errx(rspamd_config, 'cannot lock ANN %s from redis: %s',
                ann_key, _err)
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
              true, -- is write
              redis_lock_extend_cb, --callback
              'HINCRBY', -- command
              {ann_key, 'lock', '30'}
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
      else -- Enough learns
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
            rspamd_logger.infox(task, 'skip %s sample probabilisticaly; probability %s (%s skip chance)', learn_type,
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
            rspamd_logger.infox(task, 'skip %s sample probabilisticaly; probability %s (%s skip chance)', learn_type,
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
  return function (err)
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
  local ann_key = string.format('%s_%s_%s_%s_%s', settings.prefix,
      rule.prefix, set.name, set.digest:sub(1, 8), tostring(version))

  return ann_key
end

local function redis_ann_prefix(rule, settings_name)
  -- We also need to count metatokens:
  local n = meta_functions.version
  return string.format('%s%d_%s_%d_%s',
    settings.prefix, plugin_ver, rule.prefix, n, settings_name)
end

-- This function receives training vectors, checks them, spawn learning and saves ANN in Redis
local function spawn_train(params)
  -- Check training data sanity
  -- Now we need to join inputs and create the appropriate test vectors
  local n = #params.set.symbols +
      meta_functions.rspamd_count_metatokens()

  -- Now we can train ann
  local train_ann = create_ann(params.rule.max_inputs or n, 3, params.rule)

  if #params.ham_vec + #params.spam_vec < params.rule.train.max_trains / 2 then
    -- Invalidate ANN as it is definitely invalid
    -- TODO: add invalidation
    assert(false)
  else
    local inputs, outputs = {}, {}

    -- Used to show sparsed vectors in a convenient format (for debugging only)
    local function debug_vec(t)
      local ret = {}
      for i,v in ipairs(t) do
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
    for _,e in ipairs(params.spam_vec) do
      inputs[#inputs + 1] = e
      outputs[#outputs + 1] = {1.0}
      --rspamd_logger.debugm(N, rspamd_config, 'spam vector: %s', debug_vec(e))
    end
    for _,e in ipairs(params.ham_vec) do
      inputs[#inputs + 1] = e
      outputs[#outputs + 1] = {-1.0}
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
            for i,e in ipairs(inputs) do
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

      lua_util.debugm(N, rspamd_config, "start neural train for ANN %s:%s",
          params.rule.prefix, params.set.name)
      local ret,err = pcall(train_ann.train1, train_ann,
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
        roc_thresholds = {spam_threshold, ham_threshold}

        rspamd_logger.messagex("ROC thresholds: (spam_threshold: %s, ham_threshold: %s)",
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
        }

        local final_data = ucl.to_format(out, 'msgpack')
        lua_util.debugm(N, rspamd_config, "subprocess for ANN %s:%s returned %s bytes",
            params.rule.prefix, params.set.name, #final_data)
        return final_data
      else
        return nil
      end
    end

    params.set.learning_spawned = true

    local function redis_save_cb(err)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot save ANN %s:%s to redis key %s: %s',
            params.rule.prefix, params.set.name, params.ann_key, err)
        lua_redis.redis_make_request_taskless(params.ev_base,
            rspamd_config,
            params.rule.redis,
            nil,
            false, -- is write
            gen_unlock_cb(params.rule, params.set, params.ann_key), --callback
            'HDEL', -- command
            {params.ann_key, 'lock'}
        )
      else
        rspamd_logger.infox(rspamd_config, 'saved ANN %s:%s to redis: %s',
            params.rule.prefix, params.set.name, params.set.ann.redis_key)
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
            true, -- is write
            gen_unlock_cb(params.rule, params.set, params.ann_key), --callback
            'HDEL', -- command
            {params.ann_key, 'lock'}
        )
      else
        local parser = ucl.parser()
        local ok, parse_err = parser:parse_text(data, 'msgpack')
        assert(ok, parse_err)
        local parsed = parser:get_object()
        local ann_data = rspamd_util.zstd_compress(parsed.ann_data)
        local pca_data = parsed.pca_data
        local roc_thresholds = parsed.roc_thresholds

        fill_set_ann(params.set, params.ann_key)
        if pca_data then
          params.set.ann.pca = rspamd_tensor.load(pca_data)
          pca_data = rspamd_util.zstd_compress(pca_data)
        end

        if roc_thresholds then
          params.set.ann.roc_thresholds = roc_thresholds
        end


        -- Deserialise ANN from the child process
        ann_trained = rspamd_kann.load(parsed.ann_data)
        local version = (params.set.ann.version or 0) + 1
        params.set.ann.version = version
        params.set.ann.ann = ann_trained
        params.set.ann.symbols = params.set.symbols
        params.set.ann.redis_key = new_ann_key(params.rule, params.set, version)

        local profile = {
          symbols = params.set.symbols,
          digest = params.set.digest,
          redis_key = params.set.ann.redis_key,
          version = version
        }

        local profile_serialized = ucl.to_format(profile, 'json-compact', true)
        local roc_thresholds_serialized = ucl.to_format(roc_thresholds, 'json-compact', true)

        rspamd_logger.infox(rspamd_config,
            'trained ANN %s:%s, %s bytes (%s compressed); %s rows in pca (%sb compressed); redis key: %s (old key %s)',
            params.rule.prefix, params.set.name,
            #data, #ann_data,
            #(params.set.ann.pca or {}), #(pca_data or {}),
            params.set.ann.redis_key, params.ann_key)

        lua_redis.exec_redis_script(redis_script_id.save_unlock,
            {ev_base = params.ev_base, is_write = true},
            redis_save_cb,
            {profile.redis_key,
             redis_ann_prefix(params.rule, params.set.name),
             ann_data,
             profile_serialized,
             tostring(params.rule.ann_expire),
             tostring(os.time()),
             params.ann_key, -- old key to unlock...
             roc_thresholds_serialized,
             pca_data,
            })
      end
    end

    if params.rule.max_inputs then
      fill_set_ann(params.set, params.ann_key)
    end

    params.worker:spawn_process{
      func = train,
      on_complete = ann_trained,
      proctitle = string.format("ANN train for %s/%s", params.rule.prefix, params.set.name),
    }
    -- Spawn learn and register lock extension
    params.set.learning_spawned = true
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
      if not profile[1] then profile = lua_util.keys(profile) end
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

      return false
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
    lua_redis.register_prefix(selt.prefix .. '_\\d+_spam', N,
        string.format('NN learning set (spam) for rule "%s"; settings id "%s"',
            selt.prefix, selt.name), {
          persistent = true,
          type = 'list',
        })
    lua_redis.register_prefix(selt.prefix .. '_\\d+_ham', N,
        string.format('NN learning set (spam) for rule "%s"; settings id "%s"',
            rule.prefix, selt.name), {
          persistent = true,
          type = 'list',
        })
  end

  for k,rule in pairs(settings.rules) do
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
    for s,_ in pairs(rule.allowed_settings) do
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
      for id,ex in pairs(rule.settings) do
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

  if not set then return nil end

  while type(set) == 'number' do
    -- Reference to another settings!
    set = rule.settings[set]
  end

  return set
end

local function result_to_vector(task, profile)
  if not profile.zeros then
    -- Fill zeros vector
    local zeros = {}
    for i=1,meta_functions.count_metatokens() do
      zeros[i] = 0.0
    end
    for _,_ in ipairs(profile.symbols) do
      zeros[#zeros + 1] = 0.0
    end
    profile.zeros = zeros
  end

  local vec = lua_util.shallowcopy(profile.zeros)
  local mt = meta_functions.rspamd_gen_metatokens(task)

  for i,v in ipairs(mt) do
    vec[i] = v
  end

  task:process_ann_tokens(profile.symbols, vec, #mt, 0.1)

  return vec
end

return {
  can_push_train_vector = can_push_train_vector,
  create_ann = create_ann,
  default_options = default_options,
  gen_unlock_cb = gen_unlock_cb,
  get_rule_settings = get_rule_settings,
  load_scripts = load_scripts,
  module_config = module_config,
  new_ann_key = new_ann_key,
  plugin_ver = plugin_ver,
  process_rules_settings = process_rules_settings,
  redis_ann_prefix = redis_ann_prefix,
  redis_params = redis_params,
  redis_script_id = redis_script_id,
  result_to_vector = result_to_vector,
  settings = settings,
  spawn_train = spawn_train,
}
