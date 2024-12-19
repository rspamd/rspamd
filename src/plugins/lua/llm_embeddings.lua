--[[
Copyright (c) 2024, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local N = "llm_embeddings"

if confighelp then
  rspamd_config:add_example(nil, N,
      "Performs statistical analysis of messages using LLM for embeddings and NN for classification",
      [[
llm_embeddings {
  # Supported types: openai, ollama
  type = "ollama";
  # Your key to access the API
  api_key = "xxx";
  # Model name
  model = "nomic-embed-text";
  # Check the documentation for the model for this value
  dimensions = 8192;
  # Maximum tokens to generate
  max_tokens = 1000;
  # URL for the API
  url = "http://localhost:11434/api/embeddings";
  # Redis parameters to save the resulting classifier
  servers = "localhost:6379";
  # Prefix for keys
  prefix = "llm";
  # How many learns are required to start classifying
  min_learns = 100;
  # Check messages with passthrough result
  allow_passthrough = false;
  # Check messages that are apparent ham (no action and negative score)
  allow_ham = false;
}
  ]])
  return
end

local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local lua_mime = require "lua_mime"
local ucl = require "ucl"
local rspamd_kann = require "rspamd_kann"
local rspamd_tensor = require "rspamd_tensor"
local lua_redis = require "lua_redis"

local settings = {
  type = 'ollama',
  api_key = nil,
  model = 'gpt-4o-mini',
  max_tokens = 5000,
  timeout = 10,
  prompt = nil,
  condition = nil,
  autolearn = false,
  url = 'http://localhost:11434/api/embeddings',
  allow_passthrough = false,
  allow_ham = false,
  dimensions = 8192,
  hidden_layer_mult = 0.5, -- Compress in hidden layer
}

local has_blas = rspamd_tensor.has_blas()
local kann_model
local model_learns = 0
local redis_params

local function extract_data(task)
  -- Check result
  -- 1) Skip passthrough
  local result = task:get_metric_result()
  if result then
    if result.passthrough and not settings.allow_passthrough then
      return false, 'passthrough'
    end
  end

  -- Check if we have text at all
  local sel_part = lua_mime.get_displayed_text_part(task)

  if not sel_part then
    return false, 'no text part found'
  end

  -- Check limits and size sanity
  local nwords = sel_part:get_words_count()

  if nwords < 5 then
    return false, 'less than 5 words'
  end

  if nwords > settings.max_tokens then
    -- We need to truncate words (sometimes get_words_count returns a different number comparing to `get_words`)
    local words = sel_part:get_words('norm')
    nwords = #words
    if nwords > settings.max_tokens then
      return true, table.concat(words, ' ', 1, settings.max_tokens)
    end
  end
  return true, sel_part:get_content_oneline()
end

local function gen_embeddings_ollama(task, continuation_cb)
  local condition, content = extract_data(task)
  if not condition then
    return
  end

  local function embeddings_cb(err, code, data)
    if err then
      rspamd_logger.errx(task, 'cannot get embeddings: %s', err)
      return
    end

    if data then
      lua_util.debugm(N, task, 'got reply from embeddings model: %s', data)
      local parser = ucl.parser()
      local res, err = parser:parse_string(data)
      if not res then
        rspamd_logger.errx(task, 'cannot parse reply: %s', err)
        return
      end
      local reply = parser:get_object()

      if reply and type(reply) == 'table' and type(reply.embedding) == 'table' then
        lua_util.debugm(N, task, 'got embeddings: %s', #reply.embedding)
        continuation_cb(task, reply.embedding)
      else
        rspamd_logger.errx(task, 'cannot parse embeddings: %s', data)
      end
    end
  end

  local post_data = {
    model = settings.model,
    prompt = content,
  }

  rspamd_http.request({
    url = settings.url,
    task = task,
    callback = embeddings_cb,
    body = ucl.to_json(post_data),
    timeout = settings.timeout,
    headers = {
      ['Authorization'] = settings.api_key,
      ['Content-Type'] = 'application/json',
    },
  })
end

local function kann_model_create()
  local t = rspamd_kann.layer.input(settings.dimensions)
  t = rspamd_kann.transform.relu(t)
  t = rspamd_kann.layer.dense(t, settings.dimensions * settings.hidden_layer_mult);
  t = rspamd_kann.layer.cost(t, 1, rspamd_kann.cost.ceb_neg)
  kann_model = rspamd_kann.new.kann(t)
end

local function redis_prefix()
  return settings.prefix .. '_' .. settings.model
end

local function kann_model_save(ev_base)
  if not redis_params then
    return
  end

  local function save_cb(err, _)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot save model: %s', err)
    end
  end

  local packed_model = kann_model:save()
  local key = redis_prefix() .. '_model'
  lua_redis.redis_make_request_taskless(ev_base, rspamd_config,
      redis_params, key, true,
      save_cb, 'SET', { key, packed_model })
end

local function kann_model_maybe_load(ev_base)
  if not redis_params then
    return
  end

  local function load_cb(err, data)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot load model: %s', err)
    else
      if data then
        kann_model = rspamd_kann.load(data)
      end
    end
  end

  local key = redis_prefix() .. '_model'
  lua_redis.redis_make_request_taskless(ev_base, rspamd_config,
      redis_params, key, false,
      load_cb, 'GET', { key })
end

local function save_embeddings_vector(task, is_spam)
  local function save_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'cannot save embeddings: %s', err)
    end
  end

  local function save_vector(emb)
    local key = redis_prefix() .. (is_spam and '_spam' or '_ham')
    local packed_vector = ucl.to_format(emb, 'msgpack')
    lua_redis.redis_make_request(task,
        redis_params, key, true,
        save_cb, 'LPUSH', { key, packed_vector })
  end

  gen_embeddings_ollama(task, save_vector)
end

local function nn_learn(task, is_spam)
  if not kann_model then
    kann_model_create()
  end

  save_embeddings_vector(task, is_spam)
end

local function nn_learn_spam(task)
  lua_util.debugm(N, task, 'learn spam')
  nn_learn(task, true)
end

local function nn_learn_ham(task)
  lua_util.debugm(N, task, 'learn ham')
  nn_learn(task, false)
end

local function nn_classify(task)
  -- TODO: Implement
end

local module_config = rspamd_config:get_all_opt(N)
settings = lua_util.override_defaults(settings, module_config)
redis_params = lua_redis.parse_redis_server(N)

if not redis_params then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  lua_util.disable_module(N, "redis")
  return
end

local id = rspamd_config:register_symbol {
  name = "LLM_CLASSIFY_CHECK",
  type = 'callback',
  callback = nn_classify,
}
rspamd_config:register_symbol {
  name = "LLM_EMBEDDINGS_SPAM",
  type = 'virtual',
  parent = id,
}
rspamd_config:register_symbol {
  name = "LLM_EMBEDDINGS_HAM",
  type = 'virtual',
  parent = id,
}

-- Allow this symbol to be enabled merely explicitly when we need to learn
rspamd_config:register_symbol {
  name = "LLM_LEARN_SPAM",
  type = 'callback',
  callback = nn_learn_spam,
  flags = 'explicit_enable',
}
-- Allow this symbol to be enabled merely explicitly when we need to learn
rspamd_config:register_symbol {
  name = "LLM_LEARN_HAM",
  type = 'callback',
  callback = nn_learn_ham,
  flags = 'explicit_enable',
}