--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local fann_file
local max_trains = 1000
local max_epoch = 100
local use_settings = false


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

local function gen_fann_file(id)
  if use_settings then
    return fann_file .. id
  else
    return fann_file
  end
end

local function load_fann(id)
  local fname = gen_fann_file(id)
  local err,st = rspamd_util.stat(fname)

  if err then
    return false
  end

  local fd = rspamd_util.lock_file(fname)
  data[id].fann = rspamd_fann.load(fname)
  rspamd_util.unlock_file(fd) -- closes fd

  if data[id].fann then
    local n = rspamd_config:get_symbols_count() + count_metatokens()

    if n ~= data[id].fann:get_inputs() then
      rspamd_logger.infox(rspamd_config, 'fann has incorrect number of inputs: %s, %s symbols' ..
      ' is found in the cache; removing', data[id].fann:get_inputs(), n)
      data[id].fann = nil

      local ret,err = rspamd_util.unlink(fname)
      if not ret then
        rspamd_logger.errx(rspamd_config, 'cannot remove invalid fann from %s: %s',
          fname, err)
      end
    else
      rspamd_logger.infox(rspamd_config, 'loaded fann from %s', fname)
      return true
    end
  else
    rspamd_logger.infox(rspamd_config, 'fann is invalid: "%s"; removing', fname)
    local ret,err = rspamd_util.unlink(fname)
    if not ret then
      rspamd_logger.errx(rspamd_config, 'cannot remove invalid fann from %s: %s',
        fname, err)
    end
  end

  return false
end

local function check_fann(id)
  if data[id].fann then
    local n = rspamd_config:get_symbols_count() + count_metatokens()

    if n ~= data[id].fann:get_inputs() then
      rspamd_logger.infox(rspamd_config, 'fann has incorrect number of inputs: %s, %s symbols' ..
      ' is found in the cache', data[id].fann:get_inputs(), n)
      data[id].fann = nil
    end
  end

  local fname = gen_fann_file(id)
  local err,st = rspamd_util.stat(fname)

  if not err then
    local mtime = st['mtime']

    if mtime > data[id].fann_mtime then
      rspamd_logger.infox(rspamd_config, 'have more fresh version of fann ' ..
        'file: %s -> %s, need to reload %s', data[id].fann_mtime, mtime, fname)
      data[id].fann_mtime = mtime
      data[id].fann = nil
    end
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

  check_fann(id)

  if data[id].fann then
    local symbols,scores = task:get_symbols_numeric()
    local fann_data = symbols_to_fann_vector(symbols, scores)
    local mt = gen_metatokens(task)

    for _,tok in ipairs(mt) do
      table.insert(fann_data, tok)
    end

    local out = data[id].fann:test(fann_data)
    local result = rspamd_util.tanh(2 * (out[1] - 0.5))
    local symscore = string.format('%.3f', out[1])
    rspamd_logger.infox(task, 'fann score: %s', symscore)

    if result > 0 then
      task:insert_result(fann_symbol_spam, result, symscore, id)
    else
      task:insert_result(fann_symbol_ham, -(result), symscore, id)
    end
  else
    if load_fann(id) then
      fann_scores_filter(task)
    end
  end
end

local function create_train_fann(n, id)
  data[id].fann_train = rspamd_fann.create(3, n, n / 2, 1)
  data[id].ntrains = 0
  data[id].epoch = 0
end

local function fann_train_callback(score, required_score, results, cf, id, opts, extra)
  local n = cf:get_symbols_count() + count_metatokens()
  local fname = gen_fann_file(id)

  if not data[id].fann_train then
    create_train_fann(n, id)
  end

  if data[id].fann_train:get_inputs() ~= n then
    rspamd_logger.infox(cf, 'fann has incorrect number of inputs: %s, %s symbols' ..
      ' is found in the cache', data[id].fann_train:get_inputs(), n)
    create_train_fann(n, id)
  end

  if data[id].ntrains > max_trains then
    -- Store fann on disk
    local res = false

    local err,st = rspamd_util.stat(fname)
    if err then
      local fd,err = rspamd_util.create_file(fname)
      if not fd then
        rspamd_logger.errx(cf, 'cannot save fann in %s: %s', fname, err)
      else
        rspamd_util.lock_file(fname, fd)
        res = data[id].fann_train:save(fname)
        rspamd_util.unlock_file(fd) -- Closes fd as well
      end
    else
      local fd = rspamd_util.lock_file(fname)
      res = data[id].fann_train:save(fname)
      rspamd_util.unlock_file(fd) -- Closes fd as well
    end

    if not res then
      rspamd_logger.errx(cf, 'cannot save fann in %s', fname)
    else
      data[id].exist = true
      data[id].ntrains = 0
      data[id].epoch = data[id].epoch + 1
    end
  else
    if not data[id].checked then
      data[id].checked = true
      local err,st = rspamd_util.stat(fname)
      if err then
        data[id].exist = false
      end
    end
    if not data[id].exist then
      rspamd_logger.infox(cf, 'not enough trains for fann %s, %s left', fname,
        max_trains - data[id].ntrains)
    end
  end

  if data[id].epoch > max_epoch then
    -- Re-create fann
    rspamd_logger.infox(cf, 'create new fann in %s after %s epoches', fname,
      max_epoch)
    create_train_fann(n, id)
  end

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
    local learn_data = symbols_to_fann_vector(
      map(function(r) return r[1] end, results),
      map(function(r) return r[2] end, results)
    )
    -- Add filtered meta tokens
    each(function(e) table.insert(learn_data, e) end, extra)

    if learn_spam then
      data[id].fann_train:train(learn_data, {1.0})
    else
      data[id].fann_train:train(learn_data, {0.0})
    end

    data[id].ntrains = data[id].ntrains + 1
  end
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
  if not opts['fann_file'] then
    rspamd_logger.warnx(rspamd_config, 'fann_scores module requires ' ..
      '`fann_file` to be specified')
  else
    fann_file = opts['fann_file']
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
        cfg:register_worker_script("log_helper",
          function(score, req_score, results, cf, id, extra)
            -- map (snd x) (filter (fst x == module_id) extra)
            local extra_fann = map(function(e) return e[2] end,
              filter(function(e) return e[1] == module_log_id end, extra))
            if use_settings then
              fann_train_callback(score, req_score, results, cf,
                tostring(id), opts['train'], extra_fann)
            else
              fann_train_callback(score, req_score, results, cf, '0',
                opts['train'], extra_fann)
            end
        end)
      end)
      rspamd_plugins["fann_score"] = {
        log_callback = function(task)
          return totable(map(
            function(tok) return {module_log_id, tok} end,
            gen_metatokens(task)))
        end
      }
    end
  end
end

local redis_params
local classifier_config = {
  key = 'neural_net',
  neurons = 200,
  layers = 3,
}

local current_classify_ann = {
  loaded = false,
  version = 0,
  spam_learned = 0,
  ham_learned = 0
}

redis_params = rspamd_parse_redis_server('fann_scores')

local function maybe_load_fann(task, continue_cb, call_if_fail)
  local function load_fann()
    local function redis_fann_load_cb(task, err, data)
      if not err and type(data) == 'table' and type(data[2]) == 'string' then
        local version = tonumber(data[1])
        local ann_data = data[2]
        local ann = rspamd_fann.load_data(ann_data)

        if ann then
          current_classify_ann.loaded = true
          current_classify_ann.version = version
          current_classify_ann.ann = ann
          current_classify_ann.spam_learned = tonumber(data[3])
          current_classify_ann.ham_learned = tonumber(data[4])
          rspamd_logger.infox(task, "loaded fann classifier version %s", version)
          continue_cb(task, true)
        elseif call_if_fail then
          continue_cb(task, false)
        end
      elseif call_if_fail then
        continue_cb(task, false)
      end
    end

    local key = classifier_config.key
    local ret,_,_ = rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_fann_load_cb, --callback
      'HMGET', -- command
      {key, 'version', 'data', 'spam', 'ham'} -- arguments
    )
  end

  local function check_fann()
    local function redis_fann_check_cb(task, err, data)
      if not err and type(data) == 'string' then
        local version = tonumber(data)

        if version == current_classify_ann.version then
          continue_cb(task, true)
        else
          load_fann()
        end
      end
    end

    local key = classifier_config.key
    local ret,_,_ = rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_fann_check_cb, --callback
      'HGET', -- command
      {key, 'version'} -- arguments
    )
  end

  if not current_classify_ann.loaded then
    load_fann()
  else
    check_fann()
  end
end

local function tokens_to_vector(tokens)
  local vec = map(function(tok) return tok[1] end, tokens)
  local ret = {}
  local neurons = classifier_config.neurons
  for i = 1,neurons do
    ret[i] = 0
  end
  each(function(e)
    local n = (e % neurons) + 1
    ret[n] = ret[n] + 1
  end, vec)
  for i = 1,neurons do
    if ret[i] ~= 0 then
      ret[i] = 1.0 / ret[i]
    end
  end

  return ret
end

local function add_metatokens(task, vec)
    local mt = gen_metatokens(task)
    for _,tok in ipairs(mt) do
      table.insert(vec, tok)
    end
end

local function create_fann()
  local layers = {}
  local mt_size = count_metatokens()
  local neurons = classifier_config.neurons + mt_size

  for i = 1,classifier_config.layers - 1 do
    layers[i] = math.floor(neurons / i)
  end

  table.insert(layers, 1)

  local ann = rspamd_fann.create(classifier_config.layers, layers)
  current_classify_ann.loaded = true
  current_classify_ann.version = 0
  current_classify_ann.ann = ann
  current_classify_ann.spam_learned = 0
  current_classify_ann.ham_learned = 0
end

local function save_fann(task, is_spam)
  local function redis_fann_save_cb(task, err, data)
    if err then
      rspamd_logger.errx(task, "cannot save neural net to redis: %s", err)
    end
  end

  local data = current_classify_ann.ann:data()
  local key = classifier_config.key
  current_classify_ann.version = current_classify_ann.version + 1

  if is_spam then
    current_classify_ann.spam_learned = current_classify_ann.spam_learned + 1
  else
    current_classify_ann.ham_learned = current_classify_ann.ham_learned + 1
  end
  local ret,_,_ = rspamd_redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    true, -- is write
    redis_fann_save_cb, --callback
    'HMSET', -- command
    {
      key,
      'version', tostring(current_classify_ann.version),
      'data', tostring(data),
      'spam', tostring(current_classify_ann.spam_learned),
      'ham', tostring(current_classify_ann.ham_learned),
    } -- arguments
  )
end

if redis_params then
  rspamd_classifiers['neural'] = {
    classify = function(task, classifier, tokens)
      local function classify_cb(task)
        local min_learns = classifier:get_param('min_learns')

        if min_learns then
          min_learns = tonumber(min_learns)
        end

        if min_learns and min_learns > 0 then
          if current_classify_ann.ham_learned < min_learns or
            current_classify_ann.spam_learned < min_learns then

             rspamd_logger.infox(task, 'fann classifier has not enough learns: (%s spam, %s ham), %s required',
              current_classify_ann.spam_learned, current_classify_ann.ham_learned,
              min_learns)
            return
          end
        end

        -- Perform classification
        local vec = tokens_to_vector(tokens)
        add_metatokens(task, vec)
        local out = current_classify_ann.ann:test(vec)
        local result = rspamd_util.tanh(2 * (out[1] - 0.5))
        local symscore = string.format('%.3f', out[1])
        rspamd_logger.infox(task, 'fann classifier score: %s', symscore)

        if result > 0 then
          each(function(st)
              task:insert_result(st:get_symbol(), result, symscore)
            end,
            filter(function(st)
              return st:is_spam()
            end, classifier:get_statfiles())
          )
        else
          each(function(st)
              task:insert_result(st:get_symbol(), -result, symscore)
            end,
            filter(function(st)
              return not st:is_spam()
            end, classifier:get_statfiles())
          )
        end
      end
      maybe_load_fann(task, classify_cb, false)
    end,

    learn = function(task, classifier, tokens, is_spam, is_unlearn)
      local function learn_cb(task, is_loaded)
        if not is_loaded then
          create_fann()
        end
        local vec = tokens_to_vector(tokens)
        add_metatokens(task, vec)
        rspamd_logger.infox(task, "vector: %s", vec)
        if is_spam then
          current_classify_ann.ann:train(vec, {1.0})
        else
          current_classify_ann.ann:train(vec, {0.0})
        end
        save_fann(task, is_spam)
      end
      maybe_load_fann(task, learn_cb, true)
    end,
  }
end
