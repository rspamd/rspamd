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

local rspamd_logger = require "rspamd_logger"
local rspamd_fann = require "rspamd_fann"
local rspamd_util = require "rspamd_util"
local fann_symbol_spam = 'FANN_SPAM'
local fann_symbol_ham = 'FANN_HAM'
require "fun" ()
local ucl = require "ucl"

local module_log_id = 0x100
-- Module vars
-- ANNs indexed by settings id
local data = {
  ['0'] = {
    fann_mtime = 0,
    ntrains = 0,
    epoch = 0,
  }
}


-- Lua script to train a row
-- Uses the following keys:
-- key1 - prefix for keys
-- key2 - max count of learns
-- key3 - spam or ham
-- returns 1 or 0: 1 - allow learn, 0 - not allow learn
local redis_lua_script_can_train = [[
  local locked = redis.call('GET', KEYS[1] .. '_locked')
  if locked then return 0 end
  local nspam = 0
  local nham = 0

  local ret = redis.call('LLEN', KEYS[1] .. '_spam')
  if ret then nspam = tonumber(ret) end
  ret = redis.call('LLEN', KEYS[1] .. '_ham')
  if ret then nham = tonumber(ret) end

  if KEYS[3] == 'spam' then
    if nham + 1 >= nspam then return tostring(nspam + 1) end
  else
    if nspam + 1 >= nham then return tostring(nham + 1) end
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
  local locked = redis.call('GET', KEYS[1] .. '_locked')
  if locked then return false end

  local ver = 0
  local ret = redis.call('GET', KEYS[1] .. '_version')
  if ret then ver = tonumber(ret) end
  if ver > KEYS[2] then return redis.call('GET', KEYS[1] .. '_ann') end

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
  return 1
]]
local redis_maybe_invalidate_sha = nil

local redis_params
redis_params = rspamd_parse_redis_server('fann_scores')

local fann_prefix = 'RFANN'
local max_trains = 1000
local max_epoch = 100
local use_settings = false
local watch_interval = 60.0

local function redis_make_request(ev_base, cfg, key, is_write, callback, command, args)
  if not ev_base or not redis_params or not callback or not command then
    return false,nil,nil
  end

  local addr
  local rspamd_redis = require "rspamd_redis"

  if key then
    if is_write then
      addr = redis_params['write_servers']:get_upstream_by_hash(key)
    else
      addr = redis_params['read_servers']:get_upstream_by_hash(key)
    end
  else
    if is_write then
      addr = redis_params['write_servers']:get_upstream_master_slave(key)
    else
      addr = redis_params['read_servers']:get_upstream_round_robin(key)
    end
  end

  if not addr then
    logger.errx(task, 'cannot select server to make redis request')
  end

  local options = {
    ev_base = ev_base,
    config = cfg,
    callback = callback,
    host = addr:get_addr(),
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }

  if redis_params['password'] then
    options['password'] = redis_params['password']
  end

  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end

  local ret,conn = rspamd_redis.make_request(options)
  if not ret then
    rspamd_logger.errx('cannot execute redis request')
  end
  return ret,conn,addr
end

-- Metafunctions
local function fann_size_function(task)
  local sizes = {
    100,
    200,
    500,
    1000,
    2000,
    4000,
    10000,
    20000,
    30000,
    100000,
    200000,
    400000,
    800000,
    1000000,
    2000000,
    8000000,
  }

  local size = task:get_size()
  for i = 1,#sizes do
    if sizes[i] >= size then
      return {i / #sizes}
    end
  end

  return {0}
end

local function fann_images_function(task)
  local images = task:get_images()
  local ntotal = 0
  local njpg = 0
  local npng = 0
  local nlarge = 0
  local nsmall = 0

  if images then
    for _,img in ipairs(images) do
      if img:get_type() == 'png' then
        npng = npng + 1
      elseif img:get_type() == 'jpeg' then
        njpg = njpg + 1
      end

      local w = img:get_width()
      local h = img:get_height()

      if w > 0 and h > 0 then
        if w + h > 256 then
          nlarge = nlarge + 1
        else
          nsmall = nsmall + 1
        end
      end

      ntotal = ntotal + 1
    end
  end
  if ntotal > 0 then
    njpg = njpg / ntotal
    npng = npng / ntotal
    nlarge = nlarge / ntotal
    nsmall = nsmall / ntotal
  end
  return {ntotal,njpg,npng,nlarge,nsmall}
end

local function fann_nparts_function(task)
  local nattachments = 0
  local ntextparts = 0
  local totalparts = 1

  local tp = task:get_text_parts()
  if tp then
    ntextparts = #tp
  end

  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      if p:get_filename() then
        nattachments = nattachments + 1
      end
      totalparts = totalparts + 1
    end
  end

  return {ntextparts/totalparts, nattachments/totalparts}
end

local function fann_encoding_function(task)
  local nutf = 0
  local nother = 0

  local tp = task:get_text_parts()
  if tp then
    for _,p in ipairs(tp) do
      if p:is_utf() then
        nutf = nutf + 1
      else
        nother = nother + 1
      end
    end
  end

  return {nutf, nother}
end

local function fann_recipients_function(task)
  local nmime = 0
  local nsmtp = 0

  if task:has_recipients('mime') then
    nmime = #(task:get_recipients('mime'))
  end
  if task:has_recipients('smtp') then
    nsmtp = #(task:get_recipients('smtp'))
  end

  if nmime > 0 then nmime = 1.0 / nmime end
  if nsmtp > 0 then nsmtp = 1.0 / nsmtp end

  return {nmime,nsmtp}
end

local function fann_received_function(task)
  local ret = 0
  local rh = task:get_received_headers()

  if rh and #rh > 0 then
    ret = 1 / #rh
  end

  return {ret}
end

local function fann_urls_function(task)
  if task:has_urls() then
    return {1.0 / #(task:get_urls())}
  end

  return {0}
end

local function fann_attachments_function(task)
end

local metafunctions = {
  {
    cb = fann_size_function,
    ninputs = 1,
  },
  {
    cb = fann_images_function,
    ninputs = 5,
    -- 1 - number of images,
    -- 2 - number of png images,
    -- 3 - number of jpeg images
    -- 4 - number of large images (> 128 x 128)
    -- 5 - number of small images (< 128 x 128)
  },
  {
    cb = fann_nparts_function,
    ninputs = 2,
    -- 1 - number of text parts
    -- 2 - number of attachments
  },
  {
    cb = fann_encoding_function,
    ninputs = 2,
    -- 1 - number of utf parts
    -- 2 - number of non-utf parts
  },
  {
    cb = fann_recipients_function,
    ninputs = 2,
    -- 1 - number of mime rcpt
    -- 2 - number of smtp rcpt
  },
  {
    cb = fann_received_function,
    ninputs = 1,
  },
  {
    cb = fann_urls_function,
    ninputs = 1,
  },
}

local function gen_metatokens(task)
  local metatokens = {}
  for _,mt in ipairs(metafunctions) do
    local ct = mt.cb(task)

    for _,tok in ipairs(ct) do
      table.insert(metatokens, tok)
    end
  end

  return metatokens
end

local function count_metatokens()
  local total = 0
  for _,mt in ipairs(metafunctions) do
    total = total + mt.ninputs
  end

  return total
end

local function symbols_to_fann_vector(syms, scores)
  local learn_data = {}
  local matched_symbols = {}
  local n = rspamd_config:get_symbols_count()

  each(function(s, score)
     matched_symbols[s + 1] = rspamd_util.tanh(score)
  end, zip(syms, scores))

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
  if use_settings then
    return fann_prefix .. id
  else
    return fann_prefix
  end
end

local function is_fann_valid(ann)
  if ann then
    local n = rspamd_config:get_symbols_count() + count_metatokens()

    if n ~= ann:get_inputs() then
      rspamd_logger.infox(rspamd_config, 'fann has incorrect number of inputs: %s, %s symbols' ..
      ' is found in the cache', ann:get_inputs(), n)
      return false
    end
    local layers = ann:get_layers()

    if not layers or #layers ~= 5 then
      rspamd_logger.infox(rspamd_config, 'fann has incorrect number of layers: %s',
        #layers)
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

  if data[id].fann then
    local symbols,scores = task:get_symbols_numeric()
    local fann_data = symbols_to_fann_vector(symbols, scores)
    local mt = gen_metatokens(task)

    for _,tok in ipairs(mt) do
      table.insert(fann_data, tok)
    end

    local out = data[id].fann:test(fann_data)
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
  data[id].fann_train = rspamd_fann.create(5, n, n, n / 2, n / 4, 1)
  data[id].ntrains = 0
  data[id].epoch = 0
end

local function load_or_invalidate_fann(data, id, ev_base)
  local err,ann_data = rspamd_util.zstd_decompress(data)
  local ann

  if err or not ann_data then
    rspamd_logger.errx('cannot decompress ann: %s', err)
  else
    ann = rspamd_fann.load_data(ann_data)
  end

  if is_fann_valid(ann) then
    data[id].fann = ann
  else
    local function redis_invalidate_cb(err, data)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot invalidate ANN %s from redis: %s', id, err)
      elseif type(data) == 'string' then
        rspamd_logger.info(rspamd_config, 'invalidated ANN %s from redis: %s', id, err)
      end
    end
    -- Invalidate ANN
    rspamd_logger.infox('invalidate ANN %s')
    redis_make_request(ev_base,
      rspamd_config,
      nil,
      true, -- is write
      redis_invalidate_cb, --callback
      'EVALSHA', -- command
      {redis_maybe_invalidate_sha, 1, fann_prefix .. id}
    )
  end
end

local function fann_train_callback(score, required_score, results, cf, id, opts, extra, ev_base)
  local fname = gen_fann_prefix(id)

  local learn_spam, learn_ham = false, false

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

    local function learn_vec_cb(err, data)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot store train vector: %s', err)
      end
    end

    local function can_train_cb(err, data)
      if not err and tonumber(data) > 0 then
        local learn_data = symbols_to_fann_vector(
          map(function(r) return r[1] end, results),
          map(function(r) return r[2] end, results)
        )
        -- Add filtered meta tokens
        each(function(e) table.insert(learn_data, e) end, extra)
        local str = rspamd_util.zstd_compress(table.concat(learn_data, ';'))

        redis_make_request(ev_base,
          rspamd_config,
          nil,
          true, -- is write
          learn_vec_cb, --callback
          'LPUSH', -- command
          {fname .. '_' .. k, str} -- arguments
        )
      else
        if err then
          rspamd_logger.errx(rspamd_config, 'cannot check if we can train: %s', err)
        end
      end
    end

    redis_make_request(ev_base,
      rspamd_config,
      nil,
      false, -- is write
      can_train_cb, --callback
      'EVALSHA', -- command
      {redis_can_train_sha, '3', fname, tostring(max_trains), k} -- arguments
    )
  end
end

local function train_fann(cfg, ev_base, elt)

end

local function maybe_train_fanns(cfg, ev_base)
  local function members_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot get FANNS list from redis: %s', err)
    elseif type(data) == 'table' then
      each(function(i, elt)
        local redis_len_cb = function(err, data)
          if err then
            rspamd_logger.errx(rspamd_config, 'cannot get FANN trains %s from redis: %s', elt, err)
          elseif data and type(data) == 'number' or type(data) == 'string' then
            if tonumber(data) and tonumber(data) > max_trains then
              train_fann(cfg, ev_base, elt)
            end
          end
        end

        local local_ver = 0
        local numelt = tonumber(elt)
        if data[numelt] then
          if data[numelt].version then
            local_ver = data[numelt].version
          end
        end
        redis_make_request(ev_base,
          rspamd_config,
          nil,
          false, -- is write
          redis_len_cb, --callback
          'LLEN', -- command
          {fann_prefix .. elt .. '_spam'}
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
  redis_make_request(ev_base,
    rspamd_config,
    nil,
    false, -- is write
    members_cb, --callback
    'SMEMBERS', -- command
    {fann_prefix} -- arguments
  )

  return watch_interval
end

local function check_fanns(cfg, ev_base)
  local function members_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot get FANNS list from redis: %s', err)
    elseif type(data) == 'table' then
      each(function(i, elt)
        local redis_update_cb = function(err, data)
          if err then
            rspamd_logger.errx(rspamd_config, 'cannot get FANN version %s from redis: %s', elt, err)
          elseif data and type(data) == 'string' then
            load_or_invalidate_fann(data, elt, ev_base)
          end
        end

        local local_ver = 0
        local numelt = tonumber(elt)
        if data[numelt] then
          if data[numelt].version then
            local_ver = data[numelt].version
          end
        end
        redis_make_request(ev_base,
          rspamd_config,
          nil,
          false, -- is write
          redis_update_cb, --callback
          'EVALSHA', -- command
          {redis_maybe_load_sha, 2, fann_prefix .. elt, tostring(local_ver)}
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
  redis_make_request(ev_base,
    rspamd_config,
    nil,
    false, -- is write
    members_cb, --callback
    'SMEMBERS', -- command
    {fann_prefix} -- arguments
  )

  return watch_interval
end

-- Initialization part

local opts = rspamd_config:get_all_opt("fann_scores")
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  return
end

if not rspamd_fann.is_enabled() then
  rspamd_logger.errx(rspamd_config, 'fann is not compiled in rspamd, this ' ..
    'module is eventually disabled')
  return
else
  use_settings = opts['use_settings']
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
      local ret = cfg:register_worker_script("log_helper",
        function(score, req_score, results, cf, id, extra, ev_base)
          -- map (snd x) (filter (fst x == module_id) extra)
          local extra_fann = map(function(e) return e[2] end,
            filter(function(e) return e[1] == module_log_id end, extra))
          if use_settings then
            fann_train_callback(score, req_score, results, cf,
              tostring(id), opts['train'], extra_fann, ev_base)
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
    rspamd_plugins["fann_score"] = {
      log_callback = function(task)
        return totable(map(
          function(tok) return {module_log_id, tok} end,
          gen_metatokens(task)))
      end
    }
  end
  -- Add training scripts
  rspamd_config:add_on_load(function(cfg, ev_base, worker)
    local function can_train_sha_cb(err, data)
      if err or not data or type(data) ~= 'string' then
        rspamd_logger.errx(cfg, 'cannot save redis train script: %s', err)
      else
        redis_can_train_sha = tostring(data)
      end
    end
    redis_make_request(ev_base,
      rspamd_config,
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

        rspamd_config:add_periodic(ev_base, 0.0,
          function(cfg, ev_base)
            return check_fanns(cfg, ev_base)
          end)
      end
    end
    redis_make_request(ev_base,
      rspamd_config,
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
    redis_make_request(ev_base,
      rspamd_config,
      nil,
      true, -- is write
      maybe_invalidate_sha_cb, --callback
      'SCRIPT', -- command
      {'LOAD', redis_lua_script_maybe_invalidate} -- arguments
    )

    if worker:get_name() == 'normal' then
      -- We also want to train neural nets when they have enough data
      rspamd_config:add_periodic(ev_base, 0.0,
        function(cfg, ev_base)
          return maybe_train_fanns(cfg, ev_base)
        end)
    end
  end)
end
