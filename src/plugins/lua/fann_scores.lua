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

  return {ntotal,njpg,npng,nlarge,nsmall}
end

local function fann_nparts_function(task)
  local nattachments = 0
  local ntextparts = 0

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
    end
  end

  return {ntextparts, nattachments}
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

  return {nmime,nsmtp}
end

local function fann_received_function(task)
  return {#(task:get_received_headers())}
end

local function fann_urls_function(task)
  if task:has_urls() then
    return {#(task:get_urls())}
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
     matched_symbols[s + 1] = score
  end, zip(syms, scores))

  for i=1,n do
    if matched_symbols[i] then
      learn_data[i] = math.abs(matched_symbols[i])
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
      data[id].ntrains = 0
      data[id].epoch = data[id].epoch + 1
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
else
  if not opts['fann_file'] then
    rspamd_logger.errx(rspamd_config, 'fann_scores module requires ' ..
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
