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
local lua_util = require "lua_util"
local lua_verdict = require "lua_verdict"
local neural_common = require "plugins/neural"
local neural_learn = require "lua_neural_learn"
local rspamd_kann = require "rspamd_kann"
local rspamd_logger = require "rspamd_logger"
local rspamd_tensor = require "rspamd_tensor"
local rspamd_text = require "rspamd_text"
local rspamd_util = require "rspamd_util"
local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"
-- Load providers
pcall(require, "plugins/neural/providers/llm")
pcall(require, "plugins/neural/providers/symbols")
pcall(require, "plugins/neural/providers/text_hash")
pcall(require, "plugins/neural/providers/fasttext_embed")

local N = "neural"

local settings = neural_common.settings

local redis_profile_schema = T.table({
  digest = T.string():doc({ summary = "Symbols digest" }),
  symbols = T.array(T.string()):doc({ summary = "List of symbols" }),
  version = T.number():doc({ summary = "Profile version" }),
  redis_key = T.string():doc({ summary = "Redis key for ANN" }),
  distance = T.number():optional():doc({ summary = "Distance metric" }),
  providers_digest = T.string():optional():doc({ summary = "Providers digest" }),
}):doc({ summary = "Neural network profile schema" })

PluginSchema.register("plugins.neural.profile", redis_profile_schema)

if confighelp then
  return
end

local has_blas = rspamd_tensor.has_blas()
local text_cookie = rspamd_text.cookie

-- Creates and stores ANN profile in Redis
local function new_ann_profile(task, rule, set, version)
  local ann_key = neural_common.new_ann_key(rule, set, version, settings)

  local profile = {
    symbols = set.symbols,
    redis_key = ann_key,
    version = version,
    digest = set.digest,
    distance = 0, -- Since we are using our own profile
    providers_digest = neural_common.providers_config_digest(rule.providers, rule),
  }

  local ucl = require "ucl"
  local profile_serialized = ucl.to_format(profile, 'json-compact', true)

  local function add_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'cannot store ANN profile for %s:%s at %s : %s',
        rule.prefix, set.name, profile.redis_key, err)
    else
      rspamd_logger.infox(task, 'created new ANN profile for %s:%s, data stored at prefix %s',
        rule.prefix, set.name, profile.redis_key)
    end
  end

  lua_redis.redis_make_request(task,
    rule.redis,
    nil,
    true,   -- is write
    add_cb, --callback
    'ZADD', -- command
    { set.prefix, tostring(rspamd_util.get_time()), profile_serialized }
  )

  return profile
end


-- ANN filter function, used to insert scores based on the existing symbols
local function ann_scores_filter(task)
  for _, rule in pairs(settings.rules) do
    local sid = task:get_settings_id() or -1
    local ann
    local profile

    local set = neural_common.get_rule_settings(task, rule)
    if set then
      if set.ann then
        ann = set.ann.ann
        profile = set.ann
      else
        lua_util.debugm(N, task, 'no ann loaded for %s:%s',
          rule.prefix, set.name)
      end
    else
      lua_util.debugm(N, task, 'no ann defined in %s for settings id %s',
        rule.prefix, sid)
    end

    if ann then
      local function after_features(vec, meta)
        -- For providers-based ANNs, require matching digest
        -- For symbols-based ANNs (no providers), skip this check
        local has_providers = rule.providers and #rule.providers > 0
        if has_providers then
          local stored_digest = profile.providers_digest
          local current_digest = meta and meta.digest
          if not stored_digest then
            -- Old ANN was trained without providers - needs retraining with current config
            lua_util.debugm(N, task,
              'ANN %s:%s was trained without providers, skipping (retrain with current config)',
              rule.prefix, set.name)
            vec = nil
          elseif stored_digest ~= current_digest then
            rspamd_logger.warnx(task,
              'providers config changed for %s:%s (stored=%s, current=%s), ANN needs retraining',
              rule.prefix, set.name, stored_digest, current_digest or 'none')
            vec = nil
          end
        end

        local score
        if not vec then
          return
        end
        if set.ann.norm_stats then
          vec = neural_common.apply_normalization(vec, set.ann.norm_stats)
        end
        local out = ann:apply1(vec, set.ann.pca)
        score = out[1]

        local symscore = string.format('%.3f', score)
        task:cache_set(rule.prefix .. '_neural_score', score)
        lua_util.debugm(N, task, '%s:%s:%s ann score: %s',
          rule.prefix, set.name, set.ann.version, symscore)

        if score > 0 then
          local result = score

          -- If spam_score_threshold is defined, override all other thresholds.
          local spam_threshold = 0
          if rule.spam_score_threshold then
            spam_threshold = rule.spam_score_threshold
          elseif rule.roc_enabled and set.ann.roc_thresholds then
            spam_threshold = set.ann.roc_thresholds[1]
          end

          if result >= spam_threshold then
            if rule.flat_threshold_curve then
              task:insert_result(rule.symbol_spam, 1.0, symscore)
            else
              task:insert_result(rule.symbol_spam, result, symscore)
            end
          else
            lua_util.debugm(N, task, '%s:%s:%s ann score: %s < %s (spam threshold)',
              rule.prefix, set.name, set.ann.version, symscore,
              spam_threshold)
          end
        else
          local result = -(score)

          -- If ham_score_threshold is defined, override all other thresholds.
          local ham_threshold = 0
          if rule.ham_score_threshold then
            ham_threshold = rule.ham_score_threshold
          elseif rule.roc_enabled and set.ann.roc_thresholds then
            ham_threshold = set.ann.roc_thresholds[2]
          end

          if result >= ham_threshold then
            if rule.flat_threshold_curve then
              task:insert_result(rule.symbol_ham, 1.0, symscore)
            else
              task:insert_result(rule.symbol_ham, result, symscore)
            end
          else
            lua_util.debugm(N, task, '%s:%s:%s ann score: %s < %s (ham threshold)',
              rule.prefix, set.name, set.ann.version, result,
              ham_threshold)
          end
        end
      end

      if rule.providers and #rule.providers > 0 then
        neural_common.collect_features_async(task, rule, profile, 'infer', after_features)
      else
        local vec = neural_common.result_to_vector(task, profile)
        after_features(vec)
      end
    end
  end
end

local function get_ann_train_header(task)
  local hdr = task:get_request_header('ANN-Train')
  if type(hdr) == 'table' then
    hdr = hdr[1]
  end
  if hdr then
    return tostring(hdr):lower()
  end
  return nil
end

local function ann_push_task_result(rule, task, verdict, score, set)
  local train_opts = rule.train
  local learn_spam, learn_ham
  local skip_reason = 'unknown'
  local manual_train = false

  -- First, honor explicit manual training header if present
  do
    local hv = get_ann_train_header(task)
    if hv then
      lua_util.debugm(N, task, 'found ANN-Train header, enable manual train mode: %s', hv)
      if hv == 'spam' then
        learn_spam = true
        manual_train = true
      elseif hv == 'ham' then
        learn_ham = true
        manual_train = true
      else
        skip_reason = 'no explicit header'
      end
    end
  end

  -- Check for autolearn class set by mempool (integration with external learning decisions)
  if not manual_train then
    local autolearn_class = neural_learn.get_autolearn_class(task)
    if autolearn_class then
      lua_util.debugm(N, task, 'found neural autolearn class in mempool: %s', autolearn_class)
      if autolearn_class == 'spam' then
        learn_spam = true
        manual_train = true
      elseif autolearn_class == 'ham' then
        learn_ham = true
        manual_train = true
      end
    end
  end

  -- Check which providers are configured
  local has_llm_provider = false
  local has_symbols_provider = false
  if rule.providers and #rule.providers > 0 then
    for _, p in ipairs(rule.providers) do
      if p.type == 'llm' then
        has_llm_provider = true
      elseif p.type == 'symbols' then
        has_symbols_provider = true
      end
    end
  else
    -- No providers configured = implicit symbols-only mode
    has_symbols_provider = true
  end

  if has_llm_provider and not manual_train then
    -- Use expression-based autolearn conditions for LLM providers
    if rule.autolearn and rule.autolearn.enabled then
      local learn_type, reason = neural_learn.get_learn_type(task, rule)
      if learn_type == 'spam' then
        learn_spam = true
        lua_util.debugm(N, task, 'autolearn spam via expression: %s', reason)
      elseif learn_type == 'ham' then
        learn_ham = true
        lua_util.debugm(N, task, 'autolearn ham via expression: %s', reason)
      else
        skip_reason = reason or 'autolearn condition not met'
        lua_util.debugm(N, task, 'autolearn skip: %s', skip_reason)
      end
    else
      -- LLM provider without autolearn config - require manual training
      learn_spam = false
      learn_ham = false
      skip_reason = 'llm provider requires autolearn config or manual training'
      lua_util.debugm(N, task, 'suppress autotrain: llm provider present, no autolearn config')
    end
  elseif not manual_train and (not train_opts.store_pool_only and train_opts.autotrain) then
    -- Traditional score/verdict based learning for non-LLM providers
    if train_opts.spam_score then
      learn_spam = score >= train_opts.spam_score

      if not learn_spam then
        skip_reason = string.format('score < spam_score: %f < %f',
          score, train_opts.spam_score)
      end
    else
      learn_spam = verdict == 'spam' or verdict == 'junk'

      if not learn_spam then
        skip_reason = string.format('verdict: %s',
          verdict)
      end
    end

    if train_opts.ham_score then
      learn_ham = score <= train_opts.ham_score
      if not learn_ham then
        skip_reason = string.format('score > ham_score: %f > %f',
          score, train_opts.ham_score)
      end
    else
      learn_ham = verdict == 'ham'

      if not learn_ham then
        skip_reason = string.format('verdict: %s',
          verdict)
      end
    end
  elseif not manual_train then
    if train_opts.store_pool_only then
      local ucl = require "ucl"
      learn_ham = false
      learn_spam = false

      -- Explicitly store tokens in cache (use async collector if providers configured)
      local function after_collect(vec)
        if not vec then
          vec = neural_common.result_to_vector(task, set)
        end
        task:cache_set(rule.prefix .. '_neural_vec_mpack', ucl.to_format(vec, 'msgpack'))
        task:cache_set(rule.prefix .. '_neural_profile_digest', set.digest)
      end
      if rule.providers and #rule.providers > 0 then
        neural_common.collect_features_async(task, rule, set, 'train', after_collect)
      else
        after_collect(nil)
      end
      skip_reason = 'store_pool_only has been set'
    end
  end

  if learn_spam or learn_ham then
    local learn_type
    if learn_spam then
      learn_type = 'spam'
    else
      learn_type = 'ham'
    end

    local function vectors_len_cb(err, data)
      if not err and type(data) == 'table' then
        local nspam, nham = data[1], data[2]

        if manual_train or neural_common.can_push_train_vector(rule, task, learn_type, nspam, nham) then
          local function store_train_vec(vec)
            if not vec then
              lua_util.debugm(N, task, "no vector collected for training")
              return
            end

            local str = rspamd_util.zstd_compress(table.concat(vec, ';'))
            -- For manual training:
            -- - LLM-only mode: use pending key (embedding dims may vary between versions)
            -- - Symbols-only or hybrid (LLM+symbols): use versioned key (dimension is stable)
            local target_key
            if manual_train and has_llm_provider and not has_symbols_provider then
              target_key = neural_common.pending_train_key(rule, set) .. '_' .. learn_type .. '_set'
            else
              target_key = set.ann.redis_key .. '_' .. learn_type .. '_set'
            end

            local function learn_vec_cb(redis_err)
              if redis_err then
                rspamd_logger.errx(task, 'cannot store train vector for %s:%s: %s',
                  rule.prefix, set.name, redis_err)
              else
                lua_util.debugm(N, task,
                  "add train data for ANN rule " ..
                  "%s:%s, save %s vector of %s elts in %s key; %s bytes compressed",
                  rule.prefix, set.name, learn_type, #vec, target_key, #str)
              end
            end

            lua_redis.redis_make_request(task,
              rule.redis,
              nil,
              true,               -- is write
              learn_vec_cb,       --callback
              'SADD',             -- command
              { target_key, str } -- arguments
            )
          end

          if rule.providers and #rule.providers > 0 then
            -- Use async feature collection with providers, same as inference
            neural_common.collect_features_async(task, rule, set, 'train', store_train_vec)
          else
            -- Traditional symbol-based vector
            local vec = neural_common.result_to_vector(task, set)
            store_train_vec(vec)
          end
        else
          lua_util.debugm(N, task,
            "do not add %s train data for ANN rule " ..
            "%s:%s",
            learn_type, rule.prefix, set.name)
        end
      else
        if err then
          rspamd_logger.errx(task, 'cannot check if we can train %s:%s : %s',
            rule.prefix, set.name, err)
        elseif type(data) == 'string' then
          -- nil return value
          rspamd_logger.infox(task, "cannot learn %s ANN %s:%s; redis_key: %s: locked for learning: %s",
            learn_type, rule.prefix, set.name, set.ann.redis_key, data)
        else
          rspamd_logger.errx(task, 'cannot check if we can train %s:%s : type of Redis key %s is %s, expected table' ..
            'please remove this key from Redis manually if you perform upgrade from the previous version',
            rule.prefix, set.name, set.ann.redis_key, type(data))
        end
      end
    end

    -- Check if we can learn
    -- For manual training, bypass can_store_vectors check (it may not be set yet)
    if set.can_store_vectors or manual_train then
      if not set.ann then
        -- Need to create or load a profile corresponding to the current configuration
        set.ann = new_ann_profile(task, rule, set, 0)
        lua_util.debugm(N, task,
          'requested new profile for %s, set.ann is missing (manual_train=%s)',
          set.name, manual_train)
      end

      lua_redis.exec_redis_script(neural_common.redis_script_id.vectors_len,
        { task = task, is_write = false },
        vectors_len_cb,
        {
          set.ann.redis_key,
        })
    else
      lua_util.debugm(N, task,
        'do not push data: train condition not satisfied; reason: not checked existing ANNs')
    end
  else
    lua_util.debugm(N, task,
      'do not push data to key %s: train condition not satisfied; reason: %s',
      (set.ann or {}).redis_key,
      skip_reason)
  end
end

--- Offline training logic

-- Utility to extract and split saved training vectors to a table of tables
local function process_training_vectors(data)
  return fun.totable(fun.map(function(tok)
    local _, str = rspamd_util.zstd_decompress(tok)
    return fun.totable(fun.map(tonumber, lua_util.str_split(tostring(str), ';')))
  end, data))
end

-- This function does the following:
-- * Tries to lock ANN
-- * Loads spam and ham vectors (from versioned key AND pending key)
-- * Spawn learning process
local function do_train_ann(worker, ev_base, rule, set, ann_key)
  -- Check early to prevent concurrent training
  if set.learning_spawned then
    lua_util.debugm(N, rspamd_config, 'do_train_ann: training already in progress for %s:%s, skipping',
      rule.prefix, set.name)
    return
  end

  local spam_elts = {}
  local ham_elts = {}
  local pending_key = neural_common.pending_train_key(rule, set)
  lua_util.debugm(N, rspamd_config, 'do_train_ann: start for %s:%s key=%s pending=%s',
    rule.prefix, set.name, ann_key, pending_key)

  local function redis_ham_cb(err, data)
    if err or type(data) ~= 'table' then
      rspamd_logger.errx(rspamd_config, 'cannot get ham tokens for ANN %s from redis: %s',
        ann_key, err)
      -- Unlock on error
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        true,                                            -- is write
        neural_common.gen_unlock_cb(rule, set, ann_key), --callback
        'HDEL',                                          -- command
        { ann_key, 'lock' }
      )
    else
      -- Decompress and convert to numbers each training vector
      ham_elts = process_training_vectors(data)
      neural_common.spawn_train({
        worker = worker,
        ev_base = ev_base,
        rule = rule,
        set = set,
        ann_key = ann_key,
        ham_vec = ham_elts,
        spam_vec = spam_elts,
        pending_key = pending_key
      })
    end
  end

  -- Spam vectors received
  local function redis_spam_cb(err, data)
    if err or type(data) ~= 'table' then
      rspamd_logger.errx(rspamd_config, 'cannot get spam tokens for ANN %s from redis: %s',
        ann_key, err)
      -- Unlock ANN on error
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        true,                                            -- is write
        neural_common.gen_unlock_cb(rule, set, ann_key), --callback
        'HDEL',                                          -- command
        { ann_key, 'lock' }
      )
    else
      -- Decompress and convert to numbers each training vector
      spam_elts = process_training_vectors(data)
      -- Now get ham vectors from both versioned and pending keys
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        false,        -- is write
        redis_ham_cb, --callback
        'SUNION',     -- command (union of sets)
        { ann_key .. '_ham_set', pending_key .. '_ham_set' }
      )
    end
  end

  local function redis_lock_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot call lock script for ANN %s from redis: %s',
        ann_key, err)
    elseif type(data) == 'number' and data == 1 then
      -- ANN is locked, so we can extract SPAM and HAM vectors and spawn learning
      -- Fetch from both versioned key and pending key using SUNION
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        false,         -- is write
        redis_spam_cb, --callback
        'SUNION',      -- command (union of sets)
        { ann_key .. '_spam_set', pending_key .. '_spam_set' }
      )

      rspamd_logger.infox(rspamd_config, 'lock ANN %s:%s (key name %s, pending %s) for learning',
        rule.prefix, set.name, ann_key, pending_key)
    else
      local lock_tm = tonumber(data[1])
      rspamd_logger.infox(rspamd_config, 'do not learn ANN %s:%s (key name %s), ' ..
        'locked by another host %s at %s', rule.prefix, set.name, ann_key,
        data[2], os.date('%c', lock_tm))
    end
  end

  -- Check if we are already learning this network
  if set.learning_spawned then
    rspamd_logger.infox(rspamd_config, 'do not learn ANN %s, already learning another ANN',
      ann_key)
    return
  end

  -- Call Redis script that tries to acquire a lock
  -- This script returns either a boolean or a pair {'lock_time', 'hostname'} when
  -- ANN is locked by another host (or a process, meh)
  lua_redis.exec_redis_script(neural_common.redis_script_id.maybe_lock,
    { ev_base = ev_base, is_write = true },
    redis_lock_cb,
    {
      ann_key,
      tostring(os.time()),
      tostring(math.floor(math.max(10.0, rule.watch_interval * 2))),
      rspamd_util.get_hostname()
    })
end

-- This function loads new ann from Redis
-- This is based on `profile` attribute.
-- ANN is loaded from `profile.redis_key`
-- Rank of `profile` key is also increased, unfortunately, it means that we need to
-- serialize profile one more time and set its rank to the current time
-- set.ann fields are set according to Redis data received
local function load_new_ann(rule, ev_base, set, profile, min_diff)
  local ann_key = profile.redis_key

  local function data_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot get ANN data from key: %s; %s',
        ann_key, err)
    else
      if type(data) == 'table' then
        if type(data[1]) == 'userdata' and data[1].cookie == text_cookie then
          local _err, ann_data = rspamd_util.zstd_decompress(data[1])
          local ann

          if _err or not ann_data then
            rspamd_logger.errx(rspamd_config, 'cannot decompress ANN for %s from Redis key %s: %s',
              rule.prefix .. ':' .. set.name, ann_key, _err)
            return
          else
            ann = rspamd_kann.load(ann_data)

            if ann then
              set.ann = {
                digest = profile.digest,
                version = profile.version,
                symbols = profile.symbols,
                distance = min_diff,
                redis_key = profile.redis_key,
                providers_digest = profile.providers_digest,
              }

              local ucl = require "ucl"
              local profile_serialized = ucl.to_format(profile, 'json-compact', true)
              set.ann.ann = ann -- To avoid serialization

              local function rank_cb(_, _)
                -- TODO: maybe add some logging
              end
              -- Also update rank for the loaded ANN to avoid removal
              lua_redis.redis_make_request_taskless(ev_base,
                rspamd_config,
                rule.redis,
                nil,
                true,    -- is write
                rank_cb, --callback
                'ZADD',  -- command
                { set.prefix, tostring(rspamd_util.get_time()), profile_serialized }
              )
              rspamd_logger.infox(rspamd_config,
                'loaded ANN for %s:%s from %s; %s bytes compressed; version=%s',
                rule.prefix, set.name, ann_key, #data[1], profile.version)
            else
              rspamd_logger.errx(rspamd_config,
                'cannot unpack/deserialise ANN for %s:%s from Redis key %s',
                rule.prefix, set.name, ann_key)
            end
          end
        else
          lua_util.debugm(N, rspamd_config, 'missing ANN for %s:%s in Redis key %s',
            rule.prefix, set.name, ann_key)
        end

        if set.ann and set.ann.ann and type(data[2]) == 'userdata' and data[2].cookie == text_cookie then
          if rule.roc_enabled then
            local ucl = require "ucl"
            local parser = ucl.parser()
            local ok, parse_err = parser:parse_text(data[2])
            assert(ok, parse_err)
            local roc_thresholds = parser:get_object()
            set.ann.roc_thresholds = roc_thresholds
            rspamd_logger.infox(rspamd_config,
              'loaded ROC thresholds for %s:%s; version=%s',
              rule.prefix, set.name, profile.version)
            rspamd_logger.debugx(rspamd_config, "ROC thresholds: %s", roc_thresholds)
          end
        end

        if set.ann and set.ann.ann and type(data[3]) == 'userdata' and data[3].cookie == text_cookie then
          -- PCA table
          local _err, pca_data = rspamd_util.zstd_decompress(data[3])
          if pca_data then
            if rule.max_inputs then
              -- We can use PCA
              set.ann.pca = rspamd_tensor.load(pca_data)
              rspamd_logger.infox(rspamd_config,
                'loaded PCA for ANN for %s:%s from %s; %s bytes compressed; version=%s',
                rule.prefix, set.name, ann_key, #data[3], profile.version)
            else
              -- no need in pca, why is it there?
              rspamd_logger.warnx(rspamd_config,
                'extra PCA for ANN for %s:%s from Redis key %s: no max inputs defined',
                rule.prefix, set.name, ann_key)
            end
          else
            -- pca can be missing merely if we have no max_inputs
            if rule.max_inputs then
              rspamd_logger.errx(rspamd_config, 'cannot unpack/deserialise ANN for %s:%s from Redis key %s: no PCA: %s',
                rule.prefix, set.name, ann_key, _err)
              set.ann.ann = nil
            else
              -- It is okay
              set.ann.pca = nil
            end
          end
        end

        -- Providers meta (optional)
        if set.ann and set.ann.ann and type(data[4]) == 'userdata' and data[4].cookie == text_cookie then
          local ucl = require "ucl"
          local parser = ucl.parser()
          local ok = parser:parse_text(data[4])
          if ok then
            set.ann.providers_meta = parser:get_object()
          end
        end
        -- Normalization stats (optional)
        if set.ann and set.ann.ann and type(data[5]) == 'userdata' and data[5].cookie == text_cookie then
          local ucl = require "ucl"
          local parser = ucl.parser()
          local ok = parser:parse_text(data[5])
          if ok then
            set.ann.norm_stats = parser:get_object()
          end
        end
      else
        lua_util.debugm(N, rspamd_config, 'no ANN key for %s:%s in Redis key %s',
          rule.prefix, set.name, ann_key)
      end
    end
  end
  lua_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    rule.redis,
    nil,
    false,                                                                       -- is write
    data_cb,                                                                     --callback
    'HMGET',                                                                     -- command
    { ann_key, 'ann', 'roc_thresholds', 'pca', 'providers_meta', 'norm_stats' }, -- arguments
    { opaque_data = true }
  )
end

-- Used to check an element in Redis serialized as JSON
-- for some specific rule + some specific setting
-- This function tries to load more fresh or more specific ANNs in lieu of
-- the existing ones.
-- Use this function to load ANNs as `callback` parameter for `check_anns` function
local function process_existing_ann(_, ev_base, rule, set, profiles)
  local my_symbols = set.symbols
  local min_diff = math.huge
  local sel_elt
  lua_util.debugm(N, rspamd_config, 'process_existing_ann: have %s profiles for %s:%s',
    type(profiles) == 'table' and #profiles or -1, rule.prefix, set.name)

  for _, elt in fun.iter(profiles) do
    if elt and elt.symbols then
      local dist = lua_util.distance_sorted(elt.symbols, my_symbols)
      -- Check distance
      if dist < #my_symbols * .3 then
        -- Prefer profiles with smaller distance, or higher version when distance is equal
        if dist < min_diff or (dist == min_diff and sel_elt and elt.version > sel_elt.version) then
          min_diff = dist
          sel_elt = elt
        end
      end
    end
  end

  if sel_elt then
    -- We can load element from ANN
    if set.ann then
      -- We have an existing ANN, probably the same...
      if set.ann.digest == sel_elt.digest then
        -- Same ANN, check version
        if set.ann.version < sel_elt.version then
          -- Load new ann
          rspamd_logger.infox(rspamd_config, 'ann %s is changed, ' ..
            'our version = %s, remote version = %s',
            rule.prefix .. ':' .. set.name,
            set.ann.version,
            sel_elt.version)
          load_new_ann(rule, ev_base, set, sel_elt, min_diff)
        else
          lua_util.debugm(N, rspamd_config, 'ann %s is not changed, ' ..
            'our version = %s, remote version = %s',
            rule.prefix .. ':' .. set.name,
            set.ann.version,
            sel_elt.version)
        end
      else
        -- We have some different ANN, so we need to compare distance
        if set.ann.distance > min_diff then
          -- Load more specific ANN
          rspamd_logger.infox(rspamd_config, 'more specific ann is available for %s, ' ..
            'our distance = %s, remote distance = %s',
            rule.prefix .. ':' .. set.name,
            set.ann.distance,
            min_diff)
          load_new_ann(rule, ev_base, set, sel_elt, min_diff)
        else
          lua_util.debugm(N, rspamd_config, 'ann %s is not changed or less specific, ' ..
            'our distance = %s, remote distance = %s',
            rule.prefix .. ':' .. set.name,
            set.ann.distance,
            min_diff)
        end
      end
    else
      -- We have no ANN, load new one
      load_new_ann(rule, ev_base, set, sel_elt, min_diff)
    end
  end
  if sel_elt then
    lua_util.debugm(N, rspamd_config, 'process_existing_ann: selected profile version=%s key=%s', sel_elt.version,
      sel_elt.redis_key)
  else
    lua_util.debugm(N, rspamd_config, 'process_existing_ann: no suitable profile found')
  end
end


-- This function checks all profiles and selects if we can train our
-- ANN. By our we mean that it has exactly the same symbols in profile.
-- Use this function to train ANN as `callback` parameter for `check_anns` function
local function maybe_train_existing_ann(worker, ev_base, rule, set, profiles)
  local my_symbols = set.symbols
  local sel_elt
  local lens = {
    spam = 0,
    ham = 0,
  }
  lua_util.debugm(N, rspamd_config, 'maybe_train_existing_ann: %s profiles for %s:%s',
    type(profiles) == 'table' and #profiles or -1, rule.prefix, set.name)

  for _, elt in fun.iter(profiles) do
    if elt and elt.symbols then
      local dist = lua_util.distance_sorted(elt.symbols, my_symbols)
      -- Check distance
      if dist == 0 then
        sel_elt = elt
        break
      end
    end
  end

  if sel_elt then
    -- We have our ANN and that's train vectors, check if we can learn
    local ann_key = sel_elt.redis_key

    -- Check if we need to train ann
    if rule.train.store_set_only then
      lua_util.debugm(N, rspamd_config, "skiped check if ANN %s needs to be trained due to store_set_only", ann_key)
      return
    end

    local pending_key = neural_common.pending_train_key(rule, set)

    lua_util.debugm(N, rspamd_config, "check if ANN %s (pending %s) needs to be trained",
      ann_key, pending_key)

    local function initiate_train()
      rspamd_logger.infox(rspamd_config,
        'need to learn ANN %s (pending %s) after %s required learn vectors',
        ann_key, pending_key, lens)
      lua_util.debugm(N, rspamd_config, 'maybe_train_existing_ann: initiating train for key=%s spam=%s ham=%s', ann_key,
        lens.spam or -1, lens.ham or -1)
      do_train_ann(worker, ev_base, rule, set, ann_key)
    end

    -- Final check after all vectors are counted
    local function maybe_initiate_train()
      local max_len = math.max(lua_util.unpack(lua_util.values(lens)))
      local min_len = math.min(lua_util.unpack(lua_util.values(lens)))

      lua_util.debugm(N, rspamd_config,
        'final vector count for ANN %s: spam=%s ham=%s (min=%s max=%s required=%s)',
        ann_key, lens.spam, lens.ham, min_len, max_len, rule.train.max_trains)

      if rule.train.learn_mode == 'balanced' then
        local len_bias_check_pred = function(_, l)
          return l >= rule.train.max_trains * (1.0 - rule.train.classes_bias)
        end
        if max_len >= rule.train.max_trains and fun.all(len_bias_check_pred, lens) then
          initiate_train()
        else
          lua_util.debugm(N, rspamd_config,
            'cannot learn ANN %s: balanced mode requires more vectors (has %s)',
            ann_key, lens)
        end
      else
        -- Probabilistic mode
        if min_len > 0 and max_len >= rule.train.max_trains then
          initiate_train()
        else
          lua_util.debugm(N, rspamd_config,
            'cannot learn ANN %s: need min_len > 0 and max_len >= %s (has %s)',
            ann_key, rule.train.max_trains, lens)
        end
      end
    end

    -- Callback that adds count from pending key and continues
    local function add_pending_cb(cont_cb, what)
      return function(err, data)
        if not err and (type(data) == 'number' or type(data) == 'string') then
          local pending_count = tonumber(data) or 0
          lens[what] = (lens[what] or 0) + pending_count
          lua_util.debugm(N, rspamd_config, 'added %s pending %s vectors, total now %s',
            pending_count, what, lens[what])
        end
        cont_cb()
      end
    end

    -- Simple callback that just adds versioned count and continues
    local function add_versioned_cb(cont_cb, what)
      return function(err, data)
        if not err and (type(data) == 'number' or type(data) == 'string') then
          local count = tonumber(data) or 0
          lens[what] = (lens[what] or 0) + count
          lua_util.debugm(N, rspamd_config, 'added %s versioned %s vectors, total now %s',
            count, what, lens[what])
        end
        cont_cb()
      end
    end

    -- Check pending ham, then make final decision
    local function check_pending_ham()
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        false,
        add_pending_cb(maybe_initiate_train, 'ham'),
        'SCARD',
        { pending_key .. '_ham_set' }
      )
    end

    -- Check versioned ham, then check pending ham
    local function check_ham_len()
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        false,
        add_versioned_cb(check_pending_ham, 'ham'),
        'SCARD',
        { ann_key .. '_ham_set' }
      )
    end

    -- Check pending spam, then check ham
    local function check_pending_spam()
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        false,
        add_pending_cb(check_ham_len, 'spam'),
        'SCARD',
        { pending_key .. '_spam_set' }
      )
    end

    -- Check versioned spam, then pending spam
    local function check_spam_len()
      lua_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        rule.redis,
        nil,
        false,
        add_versioned_cb(check_pending_spam, 'spam'),
        'SCARD',
        { ann_key .. '_spam_set' }
      )
    end

    -- Start the chain
    check_spam_len()
  end
end

-- Used to deserialise ANN element from a list
local function load_ann_profile(element)
  local ucl = require "ucl"

  local parser = ucl.parser()
  local res, ucl_err = parser:parse_string(element)
  if not res then
    rspamd_logger.warnx(rspamd_config, 'cannot parse ANN from redis: %s',
      ucl_err)
    return nil
  else
    local profile = parser:get_object()
    local checked, schema_err = redis_profile_schema:transform(profile)
    if not checked then
      rspamd_logger.errx(rspamd_config, "cannot parse profile schema: %s", schema_err)

      return nil
    end
    return checked
  end
end

-- Function to check or load ANNs from Redis
local function check_anns(worker, cfg, ev_base, rule, process_callback, what)
  for _, set in pairs(rule.settings) do
    local function members_cb(err, data)
      if err then
        rspamd_logger.errx(cfg, 'cannot get ANNs list from redis: %s',
          err)
        set.can_store_vectors = true
      elseif type(data) == 'table' then
        lua_util.debugm(N, cfg, '%s: process element %s:%s (profiles=%s)',
          what, rule.prefix, set.name, #data)
        -- Use fun.totable to convert iterator to table for Lua 5.4 compatibility
        process_callback(worker, ev_base, rule, set, fun.totable(fun.map(load_ann_profile, data)))
        set.can_store_vectors = true
      else
        lua_util.debugm(N, cfg, '%s: no profiles for %s:%s', what, rule.prefix, set.name)
        set.can_store_vectors = true
      end
    end

    if type(set) == 'table' then
      -- Extract all profiles for some specific settings id
      -- Get the last `max_profiles` recently used
      -- Select the most appropriate to our profile but it should not differ by more
      -- than 30% of symbols
      lua_redis.redis_make_request_taskless(ev_base,
        cfg,
        rule.redis,
        nil,
        false,                                               -- is write
        members_cb,                                          --callback
        'ZREVRANGE',                                         -- command
        { set.prefix, '0', tostring(settings.max_profiles) } -- arguments
      )
    end
  end -- Cycle over all settings

  return rule.watch_interval
end

-- Function to clean up old ANNs
local function cleanup_anns(rule, cfg, ev_base)
  for _, set in pairs(rule.settings) do
    local function invalidate_cb(err, data)
      if err then
        rspamd_logger.errx(cfg, 'cannot exec invalidate script in redis: %s',
          err)
      elseif type(data) == 'table' then
        for _, expired in ipairs(data) do
          local profile = load_ann_profile(expired)
          rspamd_logger.infox(cfg, 'invalidated ANN for %s; redis key: %s; version=%s',
            rule.prefix .. ':' .. set.name,
            profile.redis_key,
            profile.version)
        end
      end
    end

    if type(set) == 'table' then
      lua_redis.exec_redis_script(neural_common.redis_script_id.maybe_invalidate,
        { ev_base = ev_base, is_write = true },
        invalidate_cb,
        { set.prefix, tostring(settings.max_profiles) })
    end
  end
end

local function ann_push_vector(task)
  if task:has_flag('skip') then
    lua_util.debugm(N, task, 'do not push data for skipped task')
    return
  end
  -- Allow manual training via ANN-Train header regardless of allow_local
  local manual_train_header = get_ann_train_header(task)
  if not settings.allow_local and not manual_train_header and lua_util.is_rspamc_or_controller(task) then
    lua_util.debugm(N, task, 'do not push data for manual scan')
    return
  end

  local verdict, score = lua_verdict.get_specific_verdict(N, task)

  if verdict == 'passthrough' then
    lua_util.debugm(N, task, 'ignore task as its verdict is %s(%s)',
      verdict, score)

    return
  end

  if score ~= score then
    lua_util.debugm(N, task, 'ignore task as its score is nan (%s verdict)',
      verdict)

    return
  end

  for _, rule in pairs(settings.rules) do
    local set = neural_common.get_rule_settings(task, rule)

    if set then
      ann_push_task_result(rule, task, verdict, score, set)
    else
      lua_util.debugm(N, task, 'settings not found in rule %s', rule.prefix)
    end
  end
end


-- Initialization part
if not (neural_common.module_config and type(neural_common.module_config) == 'table')
    or not neural_common.redis_params then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  lua_util.disable_module(N, "redis")
  return
end

local rules = neural_common.module_config['rules']

if not rules then
  -- Use legacy configuration
  rules = {}
  rules['default'] = neural_common.module_config
end

local id = rspamd_config:register_symbol({
  name = 'NEURAL_CHECK',
  type = 'postfilter,callback',
  flags = 'nostat',
  priority = lua_util.symbols_priorities.medium,
  callback = ann_scores_filter
})

neural_common.settings.rules = {} -- Reset unless validated further in the cycle

if settings.blacklisted_symbols and settings.blacklisted_symbols[1] then
  -- Transform to hash for simplicity
  settings.blacklisted_symbols = lua_util.list_to_hash(settings.blacklisted_symbols)
end

-- Check all rules
for k, r in pairs(rules) do
  local rule_elt = lua_util.override_defaults(neural_common.default_options, r)
  rule_elt['redis'] = neural_common.redis_params
  rule_elt['anns'] = {} -- Store ANNs here

  if not rule_elt.prefix then
    rule_elt.prefix = k
  end
  if not rule_elt.name then
    rule_elt.name = k
  end
  if rule_elt.train.max_train and not rule_elt.train.max_trains then
    rule_elt.train.max_trains = rule_elt.train.max_train
  end

  if not rule_elt.profile then
    rule_elt.profile = {}
  end

  if rule_elt.max_inputs and not has_blas then
    rspamd_logger.errx(rspamd_config, 'cannot set max inputs to %s as BLAS is not compiled in',
      rule_elt.name, rule_elt.max_inputs)
    rule_elt.max_inputs = nil
  end

  -- Phase 4: basic provider config validation + init
  if rule_elt.providers and #rule_elt.providers > 0 then
    for i, pcfg in ipairs(rule_elt.providers) do
      if not (pcfg.type or pcfg.name) then
        rspamd_logger.errx(rspamd_config, 'provider at index %s in rule %s has no type/name; will be ignored', i, k)
      end
      if (pcfg.type == 'llm' or pcfg.name == 'llm') and not (pcfg.model or (rspamd_config:get_all_opt('gpt') or {}).model) then
        rspamd_logger.errx(rspamd_config,
          'llm provider in rule %s requires model; please set providers[i].model or gpt.model', k)
      end
      -- Call provider init at config time (for map registration etc.)
      local prov = neural_common.get_provider(pcfg.type or pcfg.name)
      if prov and prov.init then
        prov.init(pcfg)
      end
    end
  end

  rspamd_logger.infox(rspamd_config, "register ann rule %s", k)
  settings.rules[k] = rule_elt
  rspamd_config:set_metric_symbol({
    name = rule_elt.symbol_spam,
    score = 0.0,
    description = 'Neural network SPAM',
    group = 'neural'
  })
  rspamd_config:register_symbol({
    name = rule_elt.symbol_spam,
    type = 'virtual',
    flags = 'nostat',
    parent = id
  })

  rspamd_config:set_metric_symbol({
    name = rule_elt.symbol_ham,
    score = -0.0,
    description = 'Neural network HAM',
    group = 'neural'
  })
  rspamd_config:register_symbol({
    name = rule_elt.symbol_ham,
    type = 'virtual',
    flags = 'nostat',
    parent = id
  })
end

rspamd_config:register_symbol({
  name = 'NEURAL_LEARN',
  type = 'idempotent,callback',
  flags = 'nostat,explicit_disable,ignore_passthrough',
  callback = ann_push_vector
})

-- We also need to deal with settings
rspamd_config:add_post_init(neural_common.process_rules_settings)

-- Add training scripts
for _, rule in pairs(settings.rules) do
  neural_common.load_scripts(rule.redis)
  -- This function will check ANNs in Redis when a worker is loaded
  rspamd_config:add_on_load(function(cfg, ev_base, worker)
    if worker:is_scanner() then
      rspamd_config:add_periodic(ev_base, 0.0,
        function(_, _)
          return check_anns(worker, cfg, ev_base, rule, process_existing_ann,
            'try_load_ann')
        end)
    end

    if worker:is_primary_controller() then
      -- We also want to train neural nets when they have enough data
      rspamd_config:add_periodic(ev_base, 0.0,
        function(_, _)
          -- Clean old ANNs
          cleanup_anns(rule, cfg, ev_base)
          return check_anns(worker, cfg, ev_base, rule, maybe_train_existing_ann,
            'try_train_ann')
        end)
    end
  end)
end

-- Register plugin API in rspamd_plugins for user hooks
if rspamd_plugins then
  rspamd_plugins['neural'] = rspamd_plugins['neural'] or {}
  -- Expose autolearn hooks for user customization
  rspamd_plugins['neural'].autolearn = {
    -- Register a custom guard that can block learning
    -- cb: function(task, learn_type, ctx) -> bool, reason
    register_guard = neural_learn.register_guard,
    -- Remove a registered guard
    unregister_guard = neural_learn.unregister_guard,
    -- Configure global autolearn defaults
    configure = neural_learn.configure,
    -- Check if task qualifies for autolearn
    -- Returns: can_learn (bool), reason (string)
    can_autolearn = neural_learn.can_autolearn,
    -- Get learn type for task based on conditions
    -- Returns: 'spam', 'ham', or nil
    get_learn_type = neural_learn.get_learn_type,
    -- Set autolearn class in mempool (triggers learning in idempotent callback)
    set_autolearn_class = neural_learn.set_autolearn_class,
    -- Get autolearn class from mempool
    get_autolearn_class = neural_learn.get_autolearn_class,
  }
end
