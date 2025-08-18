--[[
LLM provider for neural feature fusion
Collects text from the most relevant part and requests embeddings from an LLM API.
Supports minimal OpenAI- and Ollama-compatible embedding endpoints.
]] --

local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local lua_mime = require "lua_mime"
local neural_common = require "plugins/neural"
local lua_cache = require "lua_cache"

local N = "neural.llm"

local function select_text(task, cfg)
  local part = lua_mime.get_displayed_text_part(task)
  if part then
    local tp = part:get_text()
    if tp then
      -- Prefer UTF text content
      local content = tp:get_content('raw_utf') or tp:get_content('raw')
      if content and #content > 0 then
        return content
      end
    end
    -- Fallback to raw content
    local rc = part:get_raw_content()
    if type(rc) == 'userdata' then
      rc = tostring(rc)
    end
    return rc
  end

  -- Fallback to subject if no text part
  return task:get_subject() or ''
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

    local content = select_text(task, pcfg)
    if not content or #content == 0 then
      rspamd_logger.debugm(N, task, 'llm provider has no content to embed; skip')
      return nil
    end

    local body
    if llm.type == 'openai' then
      body = { model = llm.model, input = content }
    elseif llm.type == 'ollama' then
      body = { model = llm.model, prompt = content }
    else
      rspamd_logger.debugm(N, task, 'unsupported llm type: %s', llm.type)
      return nil
    end

    -- Redis cache: use content hash + model + provider as key
    local cache_ctx = lua_cache.create_cache_context(neural_common.redis_params, {
      cache_prefix = llm.cache_prefix,
      cache_ttl = llm.cache_ttl,
      cache_format = 'messagepack',
      cache_hash_len = llm.cache_hash_len,
      cache_use_hashing = llm.cache_use_hashing,
    }, N)

    -- Use a stable key based on content digest
    local hasher = require 'rspamd_cryptobox_hash'
    local key = string.format('%s:%s:%s', llm.type, llm.model or 'model', hasher.create(content):hex())

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

      local err, data = rspamd_http.request(http_params)
      if err then
        rspamd_logger.debugm(N, task, 'llm request failed: %s', err)
        return nil
      end

      local parser = ucl.parser()
      local ok, perr = parser:parse_string(data.content)
      if not ok then
        rspamd_logger.debugm(N, task, 'cannot parse llm response: %s', perr)
        return nil
      end

      local parsed = parser:get_object()
      local embedding = extract_embedding(llm.type, parsed)
      if not embedding or #embedding == 0 then
        rspamd_logger.debugm(N, task, 'no embedding in llm response')
        return nil
      end

      for i = 1, #embedding do
        embedding[i] = tonumber(embedding[i]) or 0.0
      end

      lua_cache.cache_set(task, key, { e = embedding }, cache_ctx)
      return embedding
    end

    -- Try cache first
    local cached_result
    local done = false
    lua_cache.cache_get(task, key, cache_ctx, llm.timeout or 2.0,
      function(_)
        -- Uncached: perform request synchronously and store
        cached_result = do_request_and_cache()
        done = true
      end,
      function(_, err, data)
        if data and data.e then
          cached_result = data.e
        end
        done = true
      end
    )

    if not done then
      -- Fallback: ensure we still do the request now (cache API is async-ready, but we need sync path)
      cached_result = do_request_and_cache()
    end

    local embedding = cached_result
    if not embedding then
      return nil
    end

    local meta = {
      name = pcfg.name or 'llm',
      type = 'llm',
      dim = #embedding,
      weight = pcfg.weight or 1.0,
      model = llm.model,
      provider = llm.type,
    }

    return embedding, meta
  end,
  collect_async = function(task, ctx, cont)
    local pcfg = ctx.config or {}
    local llm = compose_llm_settings(pcfg)
    if not llm.model then
      return cont(nil)
    end
    local content = select_text(task, pcfg)
    if not content or #content == 0 then
      return cont(nil)
    end
    local body
    if llm.type == 'openai' then
      body = { model = llm.model, input = content }
    elseif llm.type == 'ollama' then
      body = { model = llm.model, prompt = content }
    else
      return cont(nil)
    end
    local cache_ctx = lua_cache.create_cache_context(neural_common.redis_params, {
      cache_prefix = llm.cache_prefix,
      cache_ttl = llm.cache_ttl,
      cache_format = 'messagepack',
      cache_hash_len = llm.cache_hash_len,
      cache_use_hashing = llm.cache_use_hashing,
    }, N)
    local hasher = require 'rspamd_cryptobox_hash'
    local key = string.format('%s:%s:%s', llm.type, llm.model or 'model', hasher.create(content):hex())

    local function finish_with_embedding(embedding)
      if not embedding then return cont(nil) end
      for i = 1, #embedding do
        embedding[i] = tonumber(embedding[i]) or 0.0
      end
      cont(embedding, {
        name = pcfg.name or 'llm',
        type = 'llm',
        dim = #embedding,
        weight = pcfg.weight or 1.0,
        model = llm.model,
        provider = llm.type,
      })
    end

    local function request_and_cache()
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
        callback = function(err, _, data)
          if err then return cont(nil) end
          local parser = ucl.parser()
          local ok = parser:parse_text(data)
          if not ok then return cont(nil) end
          local parsed = parser:get_object()
          local embedding = extract_embedding(llm.type, parsed)
          if embedding and cache_ctx then
            lua_cache.cache_set(task, key, { e = embedding }, cache_ctx)
          end
          finish_with_embedding(embedding)
        end,
      }
      rspamd_http.request(http_params)
    end

    if cache_ctx then
      lua_cache.cache_get(task, key, cache_ctx, llm.timeout or 2.0,
        function(_)
          request_and_cache()
        end,
        function(_, err, data)
          if data and data.e then
            finish_with_embedding(data.e)
          else
            request_and_cache()
          end
        end
      )
    else
      request_and_cache()
    end
  end
})
