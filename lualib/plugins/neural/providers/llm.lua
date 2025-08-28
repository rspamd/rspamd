--[[
LLM provider for neural feature fusion
Collects text from the most relevant part and requests embeddings from an LLM API.
Supports minimal OpenAI- and Ollama-compatible embedding endpoints.
]] --

local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local neural_common = require "plugins/neural"
local lua_cache = require "lua_cache"
local llm_common = require "llm_common"

local N = "neural.llm"

local function select_text(task)
  local input_tbl = llm_common.build_llm_input(task)
  return input_tbl
end

local function compose_llm_settings(pcfg)
  local gpt_settings = rspamd_config:get_all_opt('gpt') or {}
  local llm_type = pcfg.type or gpt_settings.type or 'openai'
  local model = pcfg.model or gpt_settings.model
  local timeout = pcfg.timeout or gpt_settings.timeout or 2.0
  local url = pcfg.url
  local api_key = pcfg.api_key or gpt_settings.api_key

  if not url then
    if llm_type == 'openai' then
      url = 'https://api.openai.com/v1/embeddings'
    elseif llm_type == 'ollama' then
      url = 'http://127.0.0.1:11434/api/embeddings'
    end
  end

  return {
    type = llm_type,
    model = model,
    timeout = timeout,
    url = url,
    api_key = api_key,
    cache_ttl = pcfg.cache_ttl or 86400,
    cache_prefix = pcfg.cache_prefix or 'neural_llm',
    cache_hash_len = pcfg.cache_hash_len or 16,
    cache_use_hashing = pcfg.cache_use_hashing ~= false,
  }
end

local function extract_embedding(llm_type, parsed)
  if llm_type == 'openai' then
    -- { data = [ { embedding = [...] } ] }
    if parsed and parsed.data and parsed.data[1] and parsed.data[1].embedding then
      return parsed.data[1].embedding
    end
  elseif llm_type == 'ollama' then
    -- { embedding = [...] }
    if parsed and parsed.embedding then
      return parsed.embedding
    end
  end
  return nil
end

neural_common.register_provider('llm', {
  collect = function(task, ctx)
    local pcfg = ctx.config or {}
    local llm = compose_llm_settings(pcfg)

    if not llm.model then
      rspamd_logger.debugm(N, task, 'llm provider missing model; skip')
      return nil
    end

    local input_tbl = select_text(task)
    if not input_tbl then
      rspamd_logger.debugm(N, task, 'llm provider has no content to embed; skip')
      return nil
    end

    -- Build request input string (text then optional subject), keeping rspamd_text intact
    local input_string = input_tbl.text or ''
    if input_tbl.subject and input_tbl.subject ~= '' then
      input_string = input_string .. "\nSubject: " .. input_tbl.subject
    end

    local body
    if llm.type == 'openai' then
      body = { model = llm.model, input = input_string }
    elseif llm.type == 'ollama' then
      body = { model = llm.model, prompt = input_string }
    else
      rspamd_logger.debugm(N, task, 'unsupported llm type: %s', llm.type)
      return nil
    end

    -- Redis cache: hash the final input string only (IUF is trivial here)
    local cache_ctx = lua_cache.create_cache_context(neural_common.redis_params, {
      cache_prefix = llm.cache_prefix,
      cache_ttl = llm.cache_ttl,
      cache_format = 'messagepack',
      cache_hash_len = llm.cache_hash_len,
      cache_use_hashing = llm.cache_use_hashing,
    }, N)

    local hasher = require 'rspamd_cryptobox_hash'
    local key = string.format('%s:%s:%s', llm.type, llm.model or 'model', hasher.create(input_string):hex())

    local function do_request_and_cache()
      local headers = { ['Content-Type'] = 'application/json' }
      if llm.type == 'openai' and llm.api_key then
        headers['Authorization'] = 'Bearer ' .. llm.api_key
      end

      local http_params = {
        url = llm.url,
        mime_type = 'application/json',
        timeout = llm.timeout,
        log_obj = task,
        headers = headers,
        body = ucl.to_format(body, 'json-compact', true),
        task = task,
        method = 'POST',
        use_gzip = true,
      }

      local function http_cb(err, code, resp, _)
        if err then
          rspamd_logger.debugm(N, task, 'llm http error: %s', err)
          return
        end
        if code ~= 200 or not resp then
          rspamd_logger.debugm(N, task, 'llm bad http code: %s', code)
          return
        end

        local parser = ucl.parser()
        local ok, perr = parser:parse_string(resp)
        if not ok then
          rspamd_logger.debugm(N, task, 'llm cannot parse reply: %s', perr)
          return
        end
        local parsed = parser:get_object()
        local emb = extract_embedding(llm.type, parsed)
        if type(emb) == 'table' then
          cache_ctx:set_cached(key, emb)
          neural_common.append_provider_vector(ctx, { provider = 'llm', vector = emb })
        end
      end

      rspamd_http.request(http_params, http_cb)
    end

    local cached = cache_ctx:get_cached(key)
    if type(cached) == 'table' then
      neural_common.append_provider_vector(ctx, { provider = 'llm', vector = cached })
      return
    end

    do_request_and_cache()
  end,
})
