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

if confighelp then
  return
end

-- This plugin is a concept of FANN scores adjustment
-- NOT FOR PRODUCTION USE so far
local rspamd_logger = require "rspamd_logger"
local rspamd_fann = require "rspamd_fann"
local rspamd_util = require "rspamd_util"
local fun = require "fun"

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

redis_params = rspamd_parse_redis_server('fann_classifier')

local function maybe_load_fann(task, continue_cb, call_if_fail)
  local function load_fann()
    local function redis_fann_load_cb(err, data)
      -- XXX: upstreams
      if not err and type(data) == 'table' and type(data[2]) == 'string' then
        local version = tonumber(data[1])
        local _err,ann_data = rspamd_util.zstd_decompress(data[2])
        local ann

        if _err or not ann_data then
          rspamd_logger.errx(task, 'cannot decompress ann: %s', _err)
        else
          ann = rspamd_fann.load_data(ann_data)
        end

        if ann then
          current_classify_ann.loaded = true
          current_classify_ann.version = version
          current_classify_ann.ann = ann
          if type(data[3]) == 'string' then
            current_classify_ann.spam_learned = tonumber(data[3])
          else
            current_classify_ann.spam_learned = 0
          end
          if type(data[4]) == 'string' then
            current_classify_ann.ham_learned = tonumber(data[4])
          else
            current_classify_ann.ham_learned = 0
          end
          rspamd_logger.infox(task, "loaded fann classifier version %s (%s spam, %s ham), %s MSE",
            version, current_classify_ann.spam_learned,
            current_classify_ann.ham_learned,
            ann:get_mse())
          continue_cb(task, true)
        elseif call_if_fail then
          continue_cb(task, false)
        end
      elseif call_if_fail then
        continue_cb(task, false)
      end
    end

    local key = classifier_config.key
    local ret = rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_fann_load_cb, --callback
      'HMGET', -- command
      {key, 'version', 'data', 'spam', 'ham'} -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, 'got error connecting to redis')
    end
  end

  local function check_fann()
    local _, ret, upstream
    local function redis_fann_check_cb(err, data)
      if err then
        rspamd_logger.errx(task, 'redis error on host %s: %s', upstream:get_addr(), err)
      end
      if not err and type(data) == 'string' then
        local version = tonumber(data)

        if version <= current_classify_ann.version then
          continue_cb(task, true)
        else
          load_fann()
        end
      end
    end

    local key = classifier_config.key
    ret,_,upstream = rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_fann_check_cb, --callback
      'HGET', -- command
      {key, 'version'} -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, 'got error connecting to redis')
    end
  end

  if not current_classify_ann.loaded then
    load_fann()
  else
    check_fann()
  end
end

local function tokens_to_vector(tokens)
  local vec = fun.totable(fun.map(function(tok) return tok[1] end, tokens))
  local ret = {}
  local neurons = classifier_config.neurons
  for i = 1,neurons do
    ret[i] = 0
  end
  fun.each(function(e)
    local n = (e % neurons) + 1
    ret[n] = ret[n] + 1
  end, vec)
  local norm = 0
  for i = 1,neurons do
    if ret[i] > norm then
      norm = ret[i]
    end
  end
  for i = 1,neurons do
    if ret[i] ~= 0 and norm > 0 then
      ret[i] = ret[i] / norm
    end
  end

  return ret
end

local function add_metatokens(task, vec)
    local mt = rspamd_gen_metatokens(task)
    for _,tok in ipairs(mt) do
      table.insert(vec, tok)
    end
end

local function create_fann()
  local layers = {}
  local mt_size = rspamd_count_metatokens()
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
  local function redis_fann_save_cb(err)
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
  local ret,conn = rspamd_redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    true, -- is write
    redis_fann_save_cb, --callback
    'HMSET', -- command
    {
      key,
      'data', rspamd_util.zstd_compress(data),
    }) -- arguments

  if ret then
    conn:add_cmd('HINCRBY', {key, 'version', 1})
    if is_spam then
      conn:add_cmd('HINCRBY', {key, 'spam', 1})
    else
      conn:add_cmd('HINCRBY', {key, 'ham', 1})
    end
  else
    rspamd_logger.errx(task, 'got error connecting to redis')
  end
end

if redis_params then
  rspamd_classifiers['neural'] = {
    classify = function(task, classifier, tokens)
      local function classify_cb()
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
        local result = rspamd_util.tanh(2 * (out[1]))
        local symscore = string.format('%.3f', out[1])
        rspamd_logger.infox(task, 'fann classifier score: %s', symscore)

        if result > 0 then
          fun.each(function(st)
              task:insert_result(st:get_symbol(), result, symscore)
            end,
            fun.filter(function(st)
              return st:is_spam()
            end, classifier:get_statfiles())
          )
        else
          fun.each(function(st)
              task:insert_result(st:get_symbol(), -result, symscore)
            end,
            fun.filter(function(st)
              return not st:is_spam()
            end, classifier:get_statfiles())
          )
        end
      end
      maybe_load_fann(task, classify_cb, false)
    end,

    learn = function(task, _, tokens, is_spam)
      local function learn_cb(_, is_loaded)
        if not is_loaded then
          create_fann()
        end
        local vec = tokens_to_vector(tokens)
        add_metatokens(task, vec)

        if is_spam then
          current_classify_ann.ann:train(vec, {1.0})
          rspamd_logger.infox(task, "learned ANN spam, MSE: %s",
            current_classify_ann.ann:get_mse())
        else
          current_classify_ann.ann:train(vec, {-1.0})
          rspamd_logger.infox(task, "learned ANN ham, MSE: %s",
            current_classify_ann.ann:get_mse())
        end

        save_fann(task, is_spam)
      end
      maybe_load_fann(task, learn_cb, true)
    end,
  }
end
