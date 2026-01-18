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

local function select_text(task, opts)
  return llm_common.build_llm_input(task, opts)
end

local function compose_llm_settings(pcfg)
  local gpt_settings = rspamd_config:get_all_opt('gpt') or {}
  -- Provider identity is pcfg.type=='llm'; backend type is specified via one of these keys
  local llm_type = pcfg.llm_type or pcfg.api or pcfg.backend or gpt_settings.type or 'openai'
  local model = pcfg.model or gpt_settings.model
  local model_params = gpt_settings.model_parameters or {}
  local model_cfg = model and model_params[model] or {}
  local max_tokens = pcfg.max_tokens
  if not max_tokens then
    max_tokens = model_cfg.max_completion_tokens or model_cfg.max_tokens or gpt_settings.max_tokens
  end
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
    max_tokens = max_tokens,
    timeout = timeout,
    url = url,
    api_key = api_key,
    cache_ttl = pcfg.cache_ttl or 86400,
    cache_prefix = pcfg.cache_prefix or 'neural_llm',
    cache_hash_len = pcfg.cache_hash_len or 32,
    cache_use_hashing = (pcfg.cache_use_hashing ~= false),
    -- Optional staged timeouts (inherit from global gpt if present)
    connect_timeout = pcfg.connect_timeout or gpt_settings.connect_timeout,
    ssl_timeout = pcfg.ssl_timeout or gpt_settings.ssl_timeout,
    write_timeout = pcfg.write_timeout or gpt_settings.write_timeout,
    read_timeout = pcfg.read_timeout or gpt_settings.read_timeout,
    reply_trim_mode = pcfg.reply_trim_mode or gpt_settings.reply_trim_mode,
  }
end

local function normalize_cache_key_input(input_string)
  if type(input_string) == 'userdata' then
    return input_string:str()
  end
  return tostring(input_string)
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
  collect_async = function(task, ctx, cont)
    local pcfg = ctx.config or {}
    local llm = compose_llm_settings(pcfg)

    if not llm.model then
      rspamd_logger.debugm(N, task, 'llm provider missing model; skip')
      cont(nil)
      return
    end

    -- Do not run embeddings on infer if ANN is not loaded for this set/profile
    if ctx.phase == 'infer' then
      local set_or_profile = ctx.profile or ctx.set
      if not set_or_profile or not set_or_profile.ann then
        rspamd_logger.debugm(N, task, 'skip llm on infer: ANN not loaded for current settings')
        cont(nil)
        return
      end
    end

    local input_tbl = select_text(task, { reply_trim_mode = llm.reply_trim_mode })
    if not input_tbl then
      rspamd_logger.debugm(N, task, 'llm provider has no content to embed; skip')
      cont(nil)
      return
    end

    -- Build request input string (text then optional subject), keeping rspamd_text intact
    local input_string = input_tbl.text or ''
    if input_tbl.subject and input_tbl.subject ~= '' then
      input_string = input_string .. "\nSubject: " .. input_tbl.subject
    end

    local input_key = normalize_cache_key_input(input_string)
    rspamd_logger.debugm(N, task, 'llm embedding request: model=%s url=%s len=%s', tostring(llm.model), tostring(llm.url),
      tostring(#input_key))

    local body
    if llm.type == 'openai' then
      body = { model = llm.model, input = input_string }
    elseif llm.type == 'ollama' then
      body = { model = llm.model, prompt = input_string }
    else
      rspamd_logger.debugm(N, task, 'unsupported llm type: %s', llm.type)
      cont(nil)
      return
    end

    -- Redis cache: hash the final input string only
    local cache_ctx = lua_cache.create_cache_context(neural_common.redis_params, {
      cache_prefix = llm.cache_prefix,
      cache_ttl = llm.cache_ttl,
      cache_format = 'messagepack',
      cache_hash_len = llm.cache_hash_len,
      cache_use_hashing = llm.cache_use_hashing,
    }, N)

    -- Use raw key and allow cache module to hash/shorten it per context
    local key = string.format('%s:%s:%s', llm.type, llm.model or 'model', input_key)

    local function finish_with_vec(vec)
      if type(vec) == 'table' and #vec > 0 then
        local meta = {
          name = pcfg.name or 'llm',
          type = 'llm',
          dim = #vec,
          weight = ctx.weight or 1.0,
          model = llm.model,
          provider = llm.type,
        }
        rspamd_logger.debugm(N, task, 'llm embedding result: dim=%s', #vec)
        cont(vec, meta)
      else
        rspamd_logger.debugm(N, task, 'llm embedding result: empty')
        cont(nil)
      end
    end

    local function http_cb(err, code, resp, _)
      if err then
        rspamd_logger.debugm(N, task, 'llm http error: %s', err)
        cont(nil)
        return
      end
      if code ~= 200 or not resp then
        rspamd_logger.debugm(N, task, 'llm bad http code: %s', code)
        cont(nil)
        return
      end

      local parser = ucl.parser()
      local ok, perr = parser:parse_string(resp)
      if not ok then
        rspamd_logger.debugm(N, task, 'llm cannot parse reply: %s', perr)
        cont(nil)
        return
      end
      local parsed = parser:get_object()
      local emb = extract_embedding(llm.type, parsed)
      if type(emb) == 'table' then
        lua_cache.cache_set(task, key, emb, cache_ctx)
        finish_with_vec(emb)
      else
        rspamd_logger.debugm(N, task, 'llm embedding parse: no embedding field')
        cont(nil)
      end
    end

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
        keepalive = true,
        callback = http_cb,
        -- staged timeouts
        connect_timeout = llm.connect_timeout,
        ssl_timeout = llm.ssl_timeout,
        write_timeout = llm.write_timeout,
        read_timeout = llm.read_timeout,
      }

      rspamd_http.request(http_params)
    end

    -- Use async cache API
    lua_cache.cache_get(task, key, cache_ctx, llm.timeout or 2.0,
      function()
        -- Uncached path
        do_request_and_cache()
      end,
      function(_, err, data)
        if data and type(data) == 'table' then
          finish_with_vec(data)
        else
          do_request_and_cache()
        end
      end)
  end,
})
