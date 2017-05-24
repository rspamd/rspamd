--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This plugin is a concept of FANN scores adjustment
-- NOT FOR PRODUCTION USE so far

if confighelp then
  return
end

local rspamd_logger = require "rspamd_logger"
local rspamd_fann = require "rspamd_fann"
local rspamd_util = require "rspamd_util"
local fann_symbol_spam = 'FANNR_SPAM'
local fann_symbol_ham = 'FANNR_HAM'
local rspamd_redis = require "lua_redis"
local fun = require "fun"

local module_log_id = 0x200
-- Module vars
-- ANNs indexed by settings id
local fanns = {
  ['0'] = {
    version = 0,
  }
}


-- Lua script to train a row
-- Uses the following keys:
-- key1 - prefix for fann
-- key2 - fann suffix (settings id)
-- key3 - spam or ham
-- key4 - maximum trains
-- returns 1 or 0: 1 - allow learn, 0 - not allow learn
local redis_lua_script_can_train = [[
  local prefix = KEYS[1] .. KEYS[2]
  local locked = redis.call('GET', prefix .. '_locked')
  if locked then return 0 end
  local nspam = 0
  local nham = 0
  local lim = tonumber(KEYS[4])
  lim = lim + lim * 0.1

  local exists = redis.call('SISMEMBER', KEYS[1], KEYS[2])
  if not exists or exists == 0 then
    redis.call('SADD', KEYS[1], KEYS[2])
  end

  local ret = redis.call('LLEN', prefix .. '_spam')
  if ret then nspam = tonumber(ret) end
  ret = redis.call('LLEN', prefix .. '_ham')
  if ret then nham = tonumber(ret) end

  if KEYS[3] == 'spam' then
    if nham <= lim and nham + 1 >= nspam then return tostring(nspam + 1) end
  else
    if nspam <= lim and nspam + 1 >= nham then return tostring(nham + 1) end
  end

  return tostring(0)
]]
local redis_can_train_sha = nil

-- Lua script to load ANN from redis
-- Uses the following keys
-- key1 - prefix for keys
-- key2 - local version
-- returns nil or bulk string if new ANN can be loaded
local redis_lua_script_maybe_load = [[
  local ver = 0
  local ret = redis.call('GET', KEYS[1] .. '_version')
  if ret then ver = tonumber(ret) end
  if ver > tonumber(KEYS[2]) then
    return {redis.call('GET', KEYS[1] .. '_data'), ret}
  end

  return false
]]
local redis_maybe_load_sha = nil

-- Lua script to invalidate ANN from redis
-- Uses the following keys
-- key1 - prefix for keys
local redis_lua_script_maybe_invalidate = [[
  local locked = redis.call('GET', KEYS[1] .. '_locked')
  if locked then return false end
  redis.call('SET', KEYS[1] .. '_locked', '1')
  redis.call('SET', KEYS[1] .. '_version', '0')
  redis.call('DEL', KEYS[1] .. '_spam')
  redis.call('DEL', KEYS[1] .. '_ham')
  redis.call('DEL', KEYS[1] .. '_data')
  redis.call('DEL', KEYS[1] .. '_locked')
  redis.call('DEL', KEYS[1] .. '_hostname')
  return 1
]]
local redis_maybe_invalidate_sha = nil

-- Lua script to invalidate ANN from redis
-- Uses the following keys
-- key1 - prefix for keys
local redis_lua_script_locked_invalidate = [[
  redis.call('SET', KEYS[1] .. '_version', '0')
  redis.call('DEL', KEYS[1] .. '_spam')
  redis.call('DEL', KEYS[1] .. '_ham')
  redis.call('DEL', KEYS[1] .. '_data')
  redis.call('DEL', KEYS[1] .. '_locked')
  redis.call('DEL', KEYS[1] .. '_hostname')
  return 1
]]
local redis_locked_invalidate_sha = nil

-- Lua script to invalidate ANN from redis
-- Uses the following keys
-- key1 - prefix for keys
-- key2 - current time
-- key3 - key expire
-- key4 - hostname
local redis_lua_script_maybe_lock = [[
  local locked = redis.call('GET', KEYS[1] .. '_locked')
  if locked then
    if tonumber(KEYS[2]) < tonumber(locked) then
      return false
    end
  end
  redis.call('SET', KEYS[1] .. '_locked', tostring(tonumber(KEYS[2]) + tonumber(KEYS[3])))
  redis.call('SET', KEYS[1] .. '_hostname', KEYS[4])
  return 1
]]
local redis_maybe_lock_sha = nil

-- Lua script to save and unlock ANN in redis
-- Uses the following keys
-- key1 - prefix for keys
-- key2 - compressed ANN
-- key3 - expire in seconds
local redis_lua_script_save_unlock = [[
  redis.call('INCRBY', KEYS[1] .. '_version', '1')
  redis.call('DEL', KEYS[1] .. '_spam')
  redis.call('DEL', KEYS[1] .. '_ham')
  redis.call('SET', KEYS[1] .. '_data', KEYS[2])
  redis.call('DEL', KEYS[1] .. '_locked')
  redis.call('DEL', KEYS[1] .. '_hostname')
  redis.call('EXPIRE', KEYS[1] .. '_data', KEYS[3])
  redis.call('EXPIRE', KEYS[1] .. '_version', KEYS[3])
  return 1
]]
local redis_save_unlock_sha = nil

local redis_params
redis_params = rspamd_parse_redis_server('fann_redis')

local fann_prefix = 'RFANN'
local max_trains = 1000
local max_epoch = 1000
local max_usages = 10
local use_settings = false
local watch_interval = 60.0
local mse = 0.0001
local nlayers = 4
local lock_expire = 600
local learning_spawned = false
local ann_expire = 60 * 60 * 24 * 2 -- 2 days

local function load_scripts(cfg, ev_base, on_load_cb)
  local function can_train_sha_cb(err, data)
    if err or not data or type(data) ~= 'string' then
      rspamd_logger.errx(cfg, 'cannot save redis train script: %s', err)
    else
      redis_can_train_sha = tostring(data)
    end
  end
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    can_train_sha_cb, --callback
    'SCRIPT', -- command
    {'LOAD', redis_lua_script_can_train} -- arguments
  )

  local function maybe_load_sha_cb(err, data)
    if err or not data or type(data) ~= 'string' then
      rspamd_logger.errx(cfg, 'cannot save redis load script: %s', err)
    else
      redis_maybe_load_sha = tostring(data)

      if on_load_cb then
        rspamd_config:add_periodic(ev_base, 0.0,
          function(_cfg, _ev_base)
            return on_load_cb(_cfg, _ev_base)
          end)
      end
    end
  end
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    maybe_load_sha_cb, --callback
    'SCRIPT', -- command
    {'LOAD', redis_lua_script_maybe_load} -- arguments
  )

  local function maybe_invalidate_sha_cb(err, data)
    if err or not data or type(data) ~= 'string' then
      rspamd_logger.errx(cfg, 'cannot save redis invalidate script: %s', err)
    else
      redis_maybe_invalidate_sha = tostring(data)
    end
  end
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    maybe_invalidate_sha_cb, --callback
    'SCRIPT', -- command
    {'LOAD', redis_lua_script_maybe_invalidate} -- arguments
  )

  local function locked_invalidate_sha_cb(err, data)
    if err or not data or type(data) ~= 'string' then
      rspamd_logger.errx(cfg, 'cannot save redis locked invalidate script: %s', err)
    else
      redis_locked_invalidate_sha = tostring(data)
    end
  end
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    locked_invalidate_sha_cb, --callback
    'SCRIPT', -- command
    {'LOAD', redis_lua_script_locked_invalidate} -- arguments
  )

  local function maybe_lock_sha_cb(err, data)
    if err or not data or type(data) ~= 'string' then
      rspamd_logger.errx(cfg, 'cannot save redis lock script: %s', err)
    else
      redis_maybe_lock_sha = tostring(data)
    end
  end
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    maybe_lock_sha_cb, --callback
    'SCRIPT', -- command
    {'LOAD', redis_lua_script_maybe_lock} -- arguments
  )

  local function save_unlock_sha_cb(err, data)
    if err or not data or type(data) ~= 'string' then
      rspamd_logger.errx(cfg, 'cannot save redis save script: %s', err)
    else
      redis_save_unlock_sha = tostring(data)
    end
  end
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    save_unlock_sha_cb, --callback
    'SCRIPT', -- command
    {'LOAD', redis_lua_script_save_unlock} -- arguments
  )
end

local function symbols_to_fann_vector(syms, scores)
  local learn_data = {}
  local matched_symbols = {}
  local n = rspamd_config:get_symbols_count()

  fun.each(function(s, score)
     matched_symbols[s + 1] = rspamd_util.tanh(score)
  end, fun.zip(syms, scores))

  for i=1,n do
    if matched_symbols[i] then
      learn_data[i] = matched_symbols[i]
    else
      learn_data[i] = 0
    end
  end

  return learn_data
end

local function gen_fann_prefix(id)
  if id then
    return fann_prefix .. rspamd_config:get_symbols_cksum():hex() .. id,id
  else
    return fann_prefix .. rspamd_config:get_symbols_cksum():hex(), nil
  end
end

local function is_fann_valid(prefix, ann)
  if ann then
    local n = rspamd_config:get_symbols_count() + rspamd_count_metatokens()

    if n ~= ann:get_inputs() then
      rspamd_logger.infox(rspamd_config, 'ANN %s has incorrect number of inputs: %s, %s symbols' ..
      ' is found in the cache', prefix, ann:get_inputs(), n)
      return false
    end
    local layers = ann:get_layers()

    if not layers or #layers ~= nlayers then
      rspamd_logger.infox(rspamd_config, 'ANN %s has incorrect number of layers: %s',
        prefix, #layers)
      return false
    end

    return true
  end
end

local function fann_scores_filter(task)
  local id = '0'
  if use_settings then
   local sid = task:get_settings_id()
   if sid then
    id = tostring(sid)
   end
  end

  if fanns[id].fann then
    local symbols,scores = task:get_symbols_numeric()
    local fann_data = symbols_to_fann_vector(symbols, scores)
    local mt = rspamd_gen_metatokens(task)

    for _,tok in ipairs(mt) do
      table.insert(fann_data, tok)
    end

    local out = fanns[id].fann:test(fann_data)
    local symscore = string.format('%.3f', out[1])
    rspamd_logger.infox(task, 'fann score: %s', symscore)

    if out[1] > 0 then
      local result = rspamd_util.normalize_prob(out[1] / 2.0, 0)
      task:insert_result(fann_symbol_spam, result, symscore, id)
    else
      local result = rspamd_util.normalize_prob((-out[1]) / 2.0, 0)
      task:insert_result(fann_symbol_ham, result, symscore, id)
    end
  end
end

local function create_train_fann(n, id)
  id = tostring(id)
  local prefix = gen_fann_prefix(id)
  if not fanns[id] then
    fanns[id] = {}
  end

  if fanns[id].fann then
    if n ~= fanns[id].fann:get_inputs() or
      (fanns[id].fann_train and n ~= fanns[id].fann_train:get_inputs()) then
      rspamd_logger.infox(rspamd_config, 'recreate ANN %s as it has a wrong number of inputs, version %s', prefix,
        fanns[id].version)
      fanns[id].fann_train = rspamd_fann.create(nlayers, n, n / 2, n / 4, 1)
      fanns[id].fann = nil
    elseif fanns[id].version % max_usages == 0 then
      -- Forget last fann
      rspamd_logger.infox(rspamd_config, 'recreate ANN %s, version %s', prefix,
        fanns[id].version)
      fanns[id].fann_train = rspamd_fann.create(nlayers, n, n / 2, n / 4, 1)
    else
      fanns[id].fann_train = fanns[id].fann
    end
  else
    fanns[id].fann_train = rspamd_fann.create(nlayers, n, n / 2, n / 4, 1)
    fanns[id].version = 0
  end
end

local function load_or_invalidate_fann(data, id, ev_base)
  local ver = data[2]
  local prefix = gen_fann_prefix(id)

  if not ver or not tonumber(ver) then
    rspamd_logger.errx(rspamd_config, 'cannot get version for ANN: %s', prefix)
    return
  end

  local err,ann_data = rspamd_util.zstd_decompress(data[1])
  local ann

  if err or not ann_data then
    rspamd_logger.errx(rspamd_config, 'cannot decompress ANN %s: %s', prefix, err)
    return
  else
    ann = rspamd_fann.load_data(ann_data)
  end

  if is_fann_valid(prefix, ann) then
    fanns[id].fann = ann
    rspamd_logger.infox(rspamd_config, 'loaded ANN %s version %s from redis',
      prefix, ver)
    fanns[id].version = tonumber(ver)
  else
    local function redis_invalidate_cb(_err, _data)
      if _err then
        rspamd_logger.errx(rspamd_config, 'cannot invalidate ANN %s from redis: %s', prefix, _err)
        if string.match(_err, 'NOSCRIPT') then
          load_scripts(rspamd_config, ev_base, nil)
        end
      elseif type(_data) == 'string' then
        rspamd_logger.infox(rspamd_config, 'invalidated ANN %s from redis: %s', prefix, _err)
        fanns[id].version = 0
      end
    end
    -- Invalidate ANN
    rspamd_logger.infox(rspamd_config, 'invalidate ANN %s', prefix)
    rspamd_redis.redis_make_request_taskless(ev_base,
      rspamd_config,
      redis_params,
      nil,
      true, -- is write
      redis_invalidate_cb, --callback
      'EVALSHA', -- command
      {redis_maybe_invalidate_sha, 1, prefix}
    )
  end
end

local function fann_train_callback(score, required_score, results, _, id, opts, extra, ev_base)
  local fname,suffix = gen_fann_prefix(id)

  local learn_spam, learn_ham

  if opts['spam_score'] then
    learn_spam = score >= opts['spam_score']
  else
    learn_spam = score >= required_score
  end
  if opts['ham_score'] then
    learn_ham = score <= opts['ham_score']
  else
    learn_ham = score < 0
  end

  if learn_spam or learn_ham then
    local k
    if learn_spam then k = 'spam' else k = 'ham' end

    local function learn_vec_cb(err)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot store train vector for %s: %s', fname, err)
      end
    end

    local function can_train_cb(err, data)
      if not err and tonumber(data) > 0 then
        local learn_data = symbols_to_fann_vector(
          fun.map(function(r) return r[1] end, results),
          fun.map(function(r) return r[2] end, results)
        )
        -- Add filtered meta tokens
        fun.each(function(e) table.insert(learn_data, e) end, extra)
        local str = rspamd_util.zstd_compress(table.concat(learn_data, ';'))

        rspamd_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          redis_params,
          nil,
          true, -- is write
          learn_vec_cb, --callback
          'LPUSH', -- command
          {fname .. '_' .. k, str} -- arguments
        )
      else
        if err then
          rspamd_logger.errx(rspamd_config, 'cannot check if we can train %s: %s', fname, err)
          if string.match(err, 'NOSCRIPT') then
            load_scripts(rspamd_config, ev_base, nil)
          end
        end
      end
    end

    rspamd_redis.redis_make_request_taskless(ev_base,
      rspamd_config,
      redis_params,
      nil,
      true, -- is write
      can_train_cb, --callback
      'EVALSHA', -- command
      {redis_can_train_sha, '4', gen_fann_prefix(nil), suffix, k, tostring(max_trains)} -- arguments
    )
  end
end

local function train_fann(_, ev_base, elt)
  local spam_elts = {}
  local ham_elts = {}
  elt = tostring(elt)
  local prefix = gen_fann_prefix(elt)

  local function redis_unlock_cb(err)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot unlock ANN %s from redis: %s',
        prefix, err)
    end
  end

  local function redis_save_cb(err)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot save ANN %s to redis: %s',
        prefix, err)
      rspamd_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params,
        nil,
        false, -- is write
        redis_unlock_cb, --callback
        'DEL', -- command
        {prefix .. '_locked'}
      )
      if string.match(err, 'NOSCRIPT') then
        load_scripts(rspamd_config, ev_base, nil)
      end
    end
  end

  local function ann_trained(errcode, errmsg, train_mse)
    learning_spawned = false
    if errcode ~= 0 then
      rspamd_logger.errx(rspamd_config, 'cannot train ANN %s: %s',
        prefix, errmsg)
      rspamd_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params,
        nil,
        true, -- is write
        redis_unlock_cb, --callback
        'DEL', -- command
        {prefix .. '_locked'}
      )
    else
      rspamd_logger.infox(rspamd_config, 'trained ANN %s: MSE: %s',
        prefix, train_mse)
      local ann_data = rspamd_util.zstd_compress(fanns[elt].fann_train:data())
      fanns[elt].version = fanns[elt].version + 1
      fanns[elt].fann = fanns[elt].fann_train
      fanns[elt].fann_train = nil
      rspamd_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params,
        nil,
        true, -- is write
        redis_save_cb, --callback
        'EVALSHA', -- command
        {redis_save_unlock_sha, '2', prefix, ann_data, tostring(ann_expire)}
      )
    end
  end

  local function redis_ham_cb(err, data)
    if err or type(data) ~= 'table' then
      rspamd_logger.errx(rspamd_config, 'cannot get ham tokens for ANN %s from redis: %s',
        prefix, err)
      rspamd_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params,
        nil,
        true, -- is write
        redis_unlock_cb, --callback
        'DEL', -- command
        {prefix .. '_locked'}
      )
    else
      -- Decompress and convert to numbers each training vector
      ham_elts = fun.totable(fun.map(function(tok)
        local _,str = rspamd_util.zstd_decompress(tok)
        return fun.totable(fun.map(tonumber, rspamd_str_split(tostring(str), ';')))
      end, data))

      -- Now we need to join inputs and create the appropriate test vectors
      local inputs = {}
      local outputs = {}

      local n = rspamd_config:get_symbols_count() + rspamd_count_metatokens()
      local filt = function(elts)
        return #elts == n
      end

      fun.each(function(spam_sample, ham_sample)
        table.insert(inputs, spam_sample)
        table.insert(outputs, {1.0})
        table.insert(inputs, ham_sample)
        table.insert(outputs, {-1.0})
      end, fun.zip(fun.filter(filt, spam_elts), fun.filter(filt, ham_elts)))

      -- Now we can train fann
      if not fanns[elt] or not fanns[elt].fann_train
        or n ~= fanns[elt].fann_train:get_inputs() then
        -- Create fann if it does not exist
        create_train_fann(n, elt)
      end

      if #inputs < max_trains / 2 then
        -- Invalidate ANN as it is definitely invalid
        local function redis_invalidate_cb(_err, _data)
          if _err then
            rspamd_logger.errx(rspamd_config, 'cannot invalidate ANN %s from redis: %s', prefix, _err)
          elseif type(_data) == 'string' then
            rspamd_logger.infox(rspamd_config, 'invalidated ANN %s from redis: %s', prefix, _err)
            fanns[elt].version = 0
          end
        end
        -- Invalidate ANN
        rspamd_logger.infox(rspamd_config, 'invalidate ANN %s: training data is invalid', prefix)
        rspamd_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          redis_params,
          nil,
          true, -- is write
          redis_invalidate_cb, --callback
          'EVALSHA', -- command
          {redis_locked_invalidate_sha, 1, prefix}
        )
      else
        learning_spawned = true
        rspamd_logger.infox(rspamd_config, 'start learning ANN %s', prefix)
        fanns[elt].fann_train:train_threaded(inputs, outputs, ann_trained, ev_base,
          {max_epochs = max_epoch, desired_mse = mse})
      end
    end
  end

  local function redis_spam_cb(err, data)
    if err or type(data) ~= 'table' then
      rspamd_logger.errx(rspamd_config, 'cannot get spam tokens for ANN %s from redis: %s',
        prefix, err)
      rspamd_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params,
        nil,
        true, -- is write
        redis_unlock_cb, --callback
        'DEL', -- command
        {prefix .. '_locked'}
      )
    else
      -- Decompress and convert to numbers each training vector
      spam_elts = fun.totable(fun.map(function(tok)
        local _,str = rspamd_util.zstd_decompress(tok)
        return fun.totable(fun.map(tonumber, rspamd_str_split(tostring(str), ';')))
      end, data))
      rspamd_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params,
        nil,
        false, -- is write
        redis_ham_cb, --callback
        'LRANGE', -- command
        {prefix .. '_ham', '0', '-1'}
      )
    end
  end

  local function redis_lock_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot lock ANN %s from redis: %s',
        prefix, err)
      if string.match(err, 'NOSCRIPT') then
        load_scripts(rspamd_config, ev_base, nil)
      end
    elseif type(data) == 'number' then
      -- Can train ANN
      rspamd_redis.redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params,
        nil,
        false, -- is write
        redis_spam_cb, --callback
        'LRANGE', -- command
        {prefix .. '_spam', '0', '-1'}
      )

      rspamd_config:add_periodic(ev_base, 30.0,
        function(_, _)
          local function redis_lock_extend_cb(_err, _)
            if _err then
              rspamd_logger.errx(rspamd_config, 'cannot lock ANN %s from redis: %s',
                prefix, _err)
            else
              rspamd_logger.infox(rspamd_config, 'extend lock for ANN %s for 30 seconds',
                prefix)
            end
          end
          if learning_spawned then
            rspamd_redis.redis_make_request_taskless(ev_base,
              rspamd_config,
              redis_params,
              nil,
              true, -- is write
              redis_lock_extend_cb, --callback
              'INCRBY', -- command
              {prefix .. '_locked', '30'}
            )
          else
            return false -- do not plan any more updates
          end

          return true
        end
      )
      rspamd_logger.infox(rspamd_config, 'lock ANN %s for learning', prefix)
    else
      rspamd_logger.infox(rspamd_config, 'do not learn ANN %s, locked by another process', prefix)
    end
  end
  if learning_spawned then
    rspamd_logger.infox(rspamd_config, 'do not learn ANN %s, already learning another ANN', prefix)
    return
  end
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    redis_lock_cb, --callback
    'EVALSHA', -- command
    {redis_maybe_lock_sha, '4', prefix, tostring(os.time()),
      tostring(lock_expire), rspamd_util.get_hostname()}
  )
end

local function maybe_train_fanns(cfg, ev_base)
  local function members_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot get FANNS list from redis: %s', err)
    elseif type(data) == 'table' then
      fun.each(function(elt)
        elt = tostring(elt)
        local prefix = gen_fann_prefix(elt)
        local redis_len_cb = function(_err, _data)
          if _err then
            rspamd_logger.errx(rspamd_config, 'cannot get FANN trains %s from redis: %s', prefix, _err)
          elseif _data and type(_data) == 'number' or type(_data) == 'string' then
            if tonumber(_data) and tonumber(_data) >= max_trains then
              rspamd_logger.infox(rspamd_config, 'need to learn ANN %s after %s learn vectors (%s required)',
                prefix, tonumber(_data), max_trains)
              train_fann(cfg, ev_base, elt)
            end
          end
        end

        rspamd_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          redis_params,
          nil,
          false, -- is write
          redis_len_cb, --callback
          'LLEN', -- command
          {prefix .. '_spam'}
        )
      end,
      data)
    end
  end

  if not redis_maybe_load_sha then
    -- Plan new event early
    return 1.0
  end
  -- First we need to get all fanns stored in our Redis
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    false, -- is write
    members_cb, --callback
    'SMEMBERS', -- command
    {gen_fann_prefix(nil)} -- arguments
  )

  return watch_interval
end

local function check_fanns(_, ev_base)
  local function members_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot get FANNS list from redis: %s', err)
    elseif type(data) == 'table' then
      fun.each(function(elt)
        elt = tostring(elt)
        local redis_update_cb = function(_err, _data)
          if _err then
            rspamd_logger.errx(rspamd_config, 'cannot get FANN version %s from redis: %s', elt, _err)
            if string.match(_err, 'NOSCRIPT') then
              load_scripts(rspamd_config, ev_base, nil)
            end
          elseif _data and type(_data) == 'table' then
            load_or_invalidate_fann(_data, elt, ev_base)
          end
        end

        local local_ver = 0
        if fanns[elt] then
          if fanns[elt].version then
            local_ver = fanns[elt].version
          end
        end
        rspamd_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          redis_params,
          nil,
          false, -- is write
          redis_update_cb, --callback
          'EVALSHA', -- command
          {redis_maybe_load_sha, 2, gen_fann_prefix(elt), tostring(local_ver)}
        )
      end,
      data)
    end
  end

  if not redis_maybe_load_sha then
    -- Plan new event early
    return 1.0
  end
  -- First we need to get all fanns stored in our Redis
  rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    false, -- is write
    members_cb, --callback
    'SMEMBERS', -- command
    {gen_fann_prefix(nil)} -- arguments
  )

  return watch_interval
end

-- Initialization part

local opts = rspamd_config:get_all_opt("fann_redis")
if not (opts and type(opts) == 'table') or not redis_params then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  return
end

if not rspamd_fann.is_enabled() then
  rspamd_logger.errx(rspamd_config, 'fann is not compiled in rspamd, this ' ..
    'module is eventually disabled')
  return
else
  use_settings = opts['use_settings']
  if opts['spam_symbol'] then
    fann_symbol_spam = opts['spam_symbol']
  end
  if opts['ham_symbol'] then
    fann_symbol_ham = opts['ham_symbol']
  end
  if opts['prefix'] then
    fann_prefix = opts['prefix']
  end
  if opts['lock_expire'] then
    lock_expire = tonumber(opts['lock_expire'])
  end
  rspamd_config:set_metric_symbol({
    name = fann_symbol_spam,
    score = 3.0,
    description = 'Neural network SPAM',
    group = 'fann'
  })
  local id = rspamd_config:register_symbol({
    name = fann_symbol_spam,
    type = 'postfilter',
    priority = 5,
    callback = fann_scores_filter
  })
  rspamd_config:set_metric_symbol({
    name = fann_symbol_ham,
    score = -2.0,
    description = 'Neural network HAM',
    group = 'fann'
  })
  rspamd_config:register_symbol({
    name = fann_symbol_ham,
    type = 'virtual',
    parent = id
  })
  if opts['train'] then
    rspamd_config:add_on_load(function(cfg)
      if opts['train']['max_train'] then
        max_trains = opts['train']['max_train']
      end
      if opts['train']['max_epoch'] then
        max_epoch = opts['train']['max_epoch']
      end
      if opts['train']['max_usages'] then
        max_usages = opts['train']['max_usages']
      end
      if opts['train']['mse'] then
        mse = opts['train']['mse']
      end
      local ret = cfg:register_worker_script("log_helper",
        function(score, req_score, results, cf, _id, extra, ev_base)
          -- fun.map (snd x) (fun.filter (fst x == module_id) extra)
          local extra_fann = fun.map(function(e) return e[2] end,
            fun.filter(function(e) return e[1] == module_log_id end, extra))
          if use_settings then
            fann_train_callback(score, req_score, results, cf,
              tostring(_id), opts['train'], extra_fann, ev_base)
          else
            fann_train_callback(score, req_score, results, cf, '0',
              opts['train'], extra_fann, ev_base)
          end
        end)

      if not ret then
        rspamd_logger.errx(cfg, 'cannot find worker "log_helper"')
      end
    end)
    -- This is needed to pass extra tokens from worker to log_helper
    rspamd_plugins["fann_redis"] = {
      log_callback = function(task)
        return fun.totable(fun.map(
          function(tok) return {module_log_id, tok} end,
          rspamd_gen_metatokens(task)))
      end
    }
  end
  -- Add training scripts
  rspamd_config:add_on_load(function(cfg, ev_base, worker)
    load_scripts(cfg, ev_base, check_fanns)

    if worker:get_name() == 'normal' then
      -- We also want to train neural nets when they have enough data
      rspamd_config:add_periodic(ev_base, 0.0,
        function(_cfg, _ev_base)
          return maybe_train_fanns(_cfg, _ev_base)
        end)
    end
  end)
end
