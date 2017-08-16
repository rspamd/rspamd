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
local fann_symbol_spam = 'FANN_SPAM'
local fann_symbol_ham = 'FANN_HAM'
local fun = require "fun"

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

local function symbols_to_fann_vector(syms, scores)
  local learn_data = {}
  local matched_symbols = {}
  local n = rspamd_config:get_symbols_count()

  fun.each(function(s, score)
    if score ~= score then score = 0.0 end -- nan sanity
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

local function gen_fann_file(id)
  if use_settings then
    return fann_file .. id
  else
    return fann_file
  end
end

local function load_fann(id)
  local fname = gen_fann_file(id)
  local err = rspamd_util.stat(fname)

  if err then
    return false
  end

  local fd = rspamd_util.lock_file(fname)
  data[id].fann = rspamd_fann.load(fname)
  rspamd_util.unlock_file(fd) -- closes fd

  if data[id].fann then
    local n = rspamd_config:get_symbols_count() + rspamd_count_metatokens()

    if n ~= data[id].fann:get_inputs() then
      rspamd_logger.infox(rspamd_config, 'fann has incorrect number of inputs: %s, %s symbols' ..
      ' is found in the cache; removing', data[id].fann:get_inputs(), n)
      data[id].fann = nil

      local ret,_err = rspamd_util.unlink(fname)
      if not ret then
        rspamd_logger.errx(rspamd_config, 'cannot remove invalid fann from %s: %s',
          fname, _err)
      end
    else
      local layers = data[id].fann:get_layers()

      if not layers or #layers ~= 5 then
        rspamd_logger.infox(rspamd_config, 'fann has incorrect number of layers: %s, removing',
          #layers)
        data[id].fann = nil
        local ret,_err = rspamd_util.unlink(fname)
        if not ret then
          rspamd_logger.errx(rspamd_config, 'cannot remove invalid fann from %s: %s',
            fname, _err)
        end
      else
        rspamd_logger.infox(rspamd_config, 'loaded fann from %s', fname)
        return true
      end
    end
  else
    rspamd_logger.infox(rspamd_config, 'fann is invalid: "%s"; removing', fname)
    local ret,_err = rspamd_util.unlink(fname)
    if not ret then
      rspamd_logger.errx(rspamd_config, 'cannot remove invalid fann from %s: %s',
        fname, _err)
    end
  end

  return false
end

local function check_fann(id)
  if data[id].fann then
    local n = rspamd_config:get_symbols_count() + rspamd_count_metatokens()

    if n ~= data[id].fann:get_inputs() then
      rspamd_logger.infox(rspamd_config, 'fann has incorrect number of inputs: %s, %s symbols' ..
      ' is found in the cache', data[id].fann:get_inputs(), n)
      data[id].fann = nil
    end
    local layers = data[id].fann:get_layers()

    if not layers or #layers ~= 5 then
      rspamd_logger.infox(rspamd_config, 'fann has incorrect number of layers: %s',
        #layers)
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
    local mt = rspamd_gen_metatokens(task)

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
  else
    if load_fann(id) then
      fann_scores_filter(task)
    end
  end
end

local function create_train_fann(n, id)
  data[id].fann_train = rspamd_fann.create(5, n, n, n / 2, n / 4, 1)
  data[id].ntrains = 0
  data[id].epoch = 0
end

local function fann_train_callback(score, required_score, results, cf, id, opts, extra)
  local n = cf:get_symbols_count() + rspamd_count_metatokens()
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

    local err = rspamd_util.stat(fname)
    local fd
    if err then
      fd,err = rspamd_util.create_file(fname)
      if not fd then
        rspamd_logger.errx(cf, 'cannot save fann in %s: %s', fname, err)
      else
        rspamd_util.lock_file(fname, fd)
        res = data[id].fann_train:save(fname)
        rspamd_util.unlock_file(fd) -- Closes fd as well
      end
    else
      fd = rspamd_util.lock_file(fname)
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
      local err = rspamd_util.stat(fname)
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
    local learn_data = symbols_to_fann_vector(
      fun.map(function(r) return r[1] end, results),
      fun.map(function(r) return r[2] end, results)
    )
    -- Add filtered meta tokens
    fun.each(function(e) table.insert(learn_data, e) end, extra)

    if learn_spam then
      data[id].fann_train:train(learn_data, {1.0})
    else
      data[id].fann_train:train(learn_data, {-1.0})
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
        local ret = cfg:register_worker_script("log_helper",
          function(score, req_score, results, cf, _id, extra)
            -- map (snd x) (filter (fst x == module_id) extra)
            local extra_fann = fun.map(function(e) return e[2] end,
              fun.filter(function(e) return e[1] == module_log_id end, extra))
            if use_settings then
              fann_train_callback(score, req_score, results, cf,
                tostring(_id), opts['train'], extra_fann)
            else
              fann_train_callback(score, req_score, results, cf, '0',
                opts['train'], extra_fann)
            end
        end)

        if not ret then
          rspamd_logger.errx(cfg, 'cannot find worker "log_helper"')
        end
      end)
      rspamd_plugins["fann_score"] = {
        log_callback = function(task)
          return fun.totable(fun.map(
            function(tok) return {module_log_id, tok} end,
            rspamd_gen_metatokens(task)))
        end
      }
    end
  end
end
