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

local N = "gpt"
local REDIS_PREFIX = "rsllm"
local E = {}

if confighelp then
  rspamd_config:add_example(nil, 'gpt',
      "Performs postfiltering using GPT model",
      [[
gpt {
  # Supported types: openai, ollama
  type = "openai";
  # Your key to access the API
  api_key = "xxx";
  # Model name
  model = "gpt-4o-mini";
  # Maximum tokens to generate
  max_tokens = 1000;
  # Temperature for sampling
  temperature = 0.0;
  # Timeout for requests
  timeout = 10s;
  # Prompt for the model (use default if not set)
  prompt = "xxx";
  # Custom condition (lua function)
  condition = "xxx";
  # Autolearn if gpt classified
  autolearn = true;
  # Reply conversion (lua code)
  reply_conversion = "xxx";
  # URL for the API
  url = "https://api.openai.com/v1/chat/completions";
  # Check messages with passthrough result
  allow_passthrough = false;
  # Check messages that are apparent ham (no action and negative score)
  allow_ham = false;
  # Add header with reason (null to disable)
  reason_header = "X-GPT-Reason";
  # Use JSON format for response
  json = false;
}
  ]])
  return
end

local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local lua_mime = require "lua_mime"
local lua_redis = require "lua_redis"
local ucl = require "ucl"
local fun = require "fun"
local lua_cache = require "lua_cache"

-- Exclude checks if one of those is found
local default_symbols_to_except = {
  BAYES_SPAM = 0.9, -- We already know that it is a spam, so we can safely skip it, but no same logic for HAM!
  WHITELIST_SPF = -1,
  WHITELIST_DKIM = -1,
  WHITELIST_DMARC = -1,
  FUZZY_DENIED = -1,
  REPLY = -1,
  BOUNCE = -1,
}

local default_extra_symbols = {
  GPT_MARKETING = {
    score = 0.0,
    description = 'GPT model detected marketing content',
    category = 'marketing',
  },
  GPT_PHISHING = {
    score = 3.0,
    description = 'GPT model detected phishing content',
    category = 'phishing',
  },
  GPT_SCAM = {
    score = 3.0,
    description = 'GPT model detected scam content',
    category = 'scam',
  },
  GPT_MALWARE = {
    score = 3.0,
    description = 'GPT model detected malware content',
    category = 'malware',
  },
}

-- Should be filled from extra symbols
local categories_map = {}

local settings = {
  type = 'openai',
  api_key = nil,
  model = 'gpt-4o-mini',
  max_tokens = 1000,
  temperature = 0.0,
  timeout = 10,
  prompt = nil,
  condition = nil,
  autolearn = false,
  reason_header = nil,
  url = 'https://api.openai.com/v1/chat/completions',
  symbols_to_except = nil,
  symbols_to_trigger = nil, -- Exclude/include logic
  allow_passthrough = false,
  allow_ham = false,
  json = false,
  extra_symbols = nil,
  cache_prefix = REDIS_PREFIX,
}
local redis_params
local cache_context

local function default_condition(task)
  -- Check result
  -- 1) Skip passthrough
  -- 2) Skip already decided as spam
  -- 3) Skip already decided as ham
  local result = task:get_metric_result()
  if result then
    if result.passthrough and not settings.allow_passthrough then
      return false, 'passthrough'
    end
    local score = result.score
    local action = result.action

    if action == 'reject' and result.npositive > 1 then
      return false, 'already decided as spam'
    end

    if (action == 'no action' and score < 0) and not settings.allow_ham then
      return false, 'negative score, already decided as ham'
    end
  end

  if settings.symbols_to_except then
    for s, required_weight in pairs(settings.symbols_to_except) do
      if task:has_symbol(s) then
        if required_weight > 0 then
          -- Also check score
          local sym = task:get_symbol(s) or E
          -- Must exist as we checked it before with `has_symbol`
          if sym.weight then
            if math.abs(sym.weight) >= required_weight then
              return false, 'skip as "' .. s .. '" is found (weight: ' .. sym.weight .. ')'
            end
          end
          lua_util.debugm(N, task, 'symbol %s has weight %s, but required %s', s,
              sym.weight, required_weight)
        else
          return false, 'skip as "' .. s .. '" is found'
        end
      end
    end
  end
  if settings.symbols_to_trigger then
    for s, required_weight in pairs(settings.symbols_to_trigger) do
      if task:has_symbol(s) then
        if required_weight > 0 then
          -- Also check score
          local sym = task:get_symbol(s) or E
          -- Must exist as we checked it before with `has_symbol`
          if sym.weight then
            if math.abs(sym.weight) < required_weight then
              return false, 'skip as "' .. s .. '" is found with low weight (weight: ' .. sym.weight .. ')'
            end
          end
          lua_util.debugm(N, task, 'symbol %s has weight %s, but required %s', s,
              sym.weight, required_weight)
        end
      else
        return false, 'skip as "' .. s .. '" is not found'
      end
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
      return true, table.concat(words, ' ', 1, settings.max_tokens), sel_part
    end
  end
  return true, sel_part:get_content_oneline(), sel_part
end

local function maybe_extract_json(str)
  -- Find the first opening brace
  local startPos, endPos = str:find('json%s*{')
  if not startPos then
    startPos, endPos = str:find('{')
  end
  if not startPos then
    return nil
  end

  startPos = endPos - 1
  local openBraces = 0
  endPos = startPos
  local len = #str

  -- Iterate through the string to find matching braces
  for i = startPos, len do
    local char = str:sub(i, i)
    if char == "{" then
      openBraces = openBraces + 1
    elseif char == "}" then
      openBraces = openBraces - 1
      -- When we find the matching closing brace
      if openBraces == 0 then
        endPos = i
        break
      end
    end
  end

  -- If we found a complete JSON-like structure
  if openBraces == 0 then
    return str:sub(startPos, endPos)
  end

  return nil
end

local function default_openai_json_conversion(task, input)
  local parser = ucl.parser()
  local res, err = parser:parse_string(input)
  if not res then
    rspamd_logger.errx(task, 'cannot parse reply: %s', err)
    return
  end
  local reply = parser:get_object()
  if not reply then
    rspamd_logger.errx(task, 'cannot get object from reply')
    return
  end

  if type(reply.choices) ~= 'table' or type(reply.choices[1]) ~= 'table' then
    rspamd_logger.errx(task, 'no choices in reply')
    return
  end

  local first_message = reply.choices[1].message.content

  if not first_message then
    rspamd_logger.errx(task, 'no content in the first message')
    return
  end

  -- Apply heuristic to extract JSON
  first_message = maybe_extract_json(first_message) or first_message

  parser = ucl.parser()
  res, err = parser:parse_string(first_message)
  if not res then
    rspamd_logger.errx(task, 'cannot parse JSON gpt reply: %s', err)
    return
  end

  reply = parser:get_object()

  if type(reply) == 'table' and reply.probability then
    lua_util.debugm(N, task, 'extracted probability: %s', reply.probability)
    local spam_score = tonumber(reply.probability)

    if not spam_score then
      -- Maybe we need GPT to convert GPT reply here?
      if reply.probability == "high" then
        spam_score = 0.9
      elseif reply.probability == "low" then
        spam_score = 0.1
      else
        rspamd_logger.infox("cannot convert to spam probability: %s", reply.probability)
      end
    end

    if type(reply.usage) == 'table' then
      rspamd_logger.infox(task, 'usage: %s tokens', reply.usage.total_tokens)
    end

    return spam_score, reply.reason, {}
  end

  rspamd_logger.errx(task, 'cannot convert spam score: %s', first_message)
  return
end

-- Remove what we don't need
local function clean_reply_line(line)
  if not line then
    return ''
  end
  return lua_util.str_trim(line):gsub("^%d%.%s+", "")
end

-- Assume that we have 3 lines: probability, reason, additional symbols
local function default_openai_plain_conversion(task, input)
  local parser = ucl.parser()
  local res, err = parser:parse_string(input)
  if not res then
    rspamd_logger.errx(task, 'cannot parse reply: %s', err)
    return
  end
  local reply = parser:get_object()
  if not reply then
    rspamd_logger.errx(task, 'cannot get object from reply')
    return
  end

  if type(reply.choices) ~= 'table' or type(reply.choices[1]) ~= 'table' then
    rspamd_logger.errx(task, 'no choices in reply')
    return
  end

  local first_message = reply.choices[1].message.content

  if not first_message then
    rspamd_logger.errx(task, 'no content in the first message')
    return
  end
  local lines = lua_util.str_split(first_message, '\n')
  local first_line = clean_reply_line(lines[1])
  local spam_score = tonumber(first_line)
  local reason = clean_reply_line(lines[2])
  local categories = lua_util.str_split(clean_reply_line(lines[3]), ',')

  if spam_score then
    return spam_score, reason, categories
  end

  rspamd_logger.errx(task, 'cannot parse plain gpt reply: %s (all: %s)', lines[1])
  return
end

local function default_ollama_plain_conversion(task, input)
  local parser = ucl.parser()
  local res, err = parser:parse_string(input)
  if not res then
    rspamd_logger.errx(task, 'cannot parse reply: %s', err)
    return
  end
  local reply = parser:get_object()
  if not reply then
    rspamd_logger.errx(task, 'cannot get object from reply')
    return
  end

  if type(reply.message) ~= 'table' then
    rspamd_logger.errx(task, 'bad message in reply')
    return
  end

  local first_message = reply.message.content

  if not first_message then
    rspamd_logger.errx(task, 'no content in the first message')
    return
  end
  local lines = lua_util.str_split(first_message, '\n')
  local first_line = clean_reply_line(lines[1])
  local spam_score = tonumber(first_line)
  local reason = clean_reply_line(lines[2])
  local categories = lua_util.str_split(clean_reply_line(lines[3]), ',')

  if spam_score then
    return spam_score, reason, categories
  end

  rspamd_logger.errx(task, 'cannot parse plain gpt reply: %s', lines[1])
  return
end

local function default_ollama_json_conversion(task, input)
  local parser = ucl.parser()
  local res, err = parser:parse_string(input)
  if not res then
    rspamd_logger.errx(task, 'cannot parse reply: %s', err)
    return
  end
  local reply = parser:get_object()
  if not reply then
    rspamd_logger.errx(task, 'cannot get object from reply')
    return
  end

  if type(reply.message) ~= 'table' then
    rspamd_logger.errx(task, 'bad message in reply')
    return
  end

  local first_message = reply.message.content

  if not first_message then
    rspamd_logger.errx(task, 'no content in the first message')
    return
  end

  -- Apply heuristic to extract JSON
  first_message = maybe_extract_json(first_message) or first_message

  parser = ucl.parser()
  res, err = parser:parse_string(first_message)
  if not res then
    rspamd_logger.errx(task, 'cannot parse JSON gpt reply: %s', err)
    return
  end

  reply = parser:get_object()

  if type(reply) == 'table' and reply.probability then
    lua_util.debugm(N, task, 'extracted probability: %s', reply.probability)
    local spam_score = tonumber(reply.probability)

    if not spam_score then
      -- Maybe we need GPT to convert GPT reply here?
      if reply.probability == "high" then
        spam_score = 0.9
      elseif reply.probability == "low" then
        spam_score = 0.1
      else
        rspamd_logger.infox("cannot convert to spam probability: %s", reply.probability)
      end
    end

    if type(reply.usage) == 'table' then
      rspamd_logger.infox(task, 'usage: %s tokens', reply.usage.total_tokens)
    end

    return spam_score, reply.reason
  end

  rspamd_logger.errx(task, 'cannot convert spam score: %s', first_message)
  return
end

-- Make cache specific to all settings to avoid conflicts
local env_digest = nil

local function redis_cache_key(sel_part)
  if not env_digest then
    local hasher = require "rspamd_cryptobox_hash"
    local digest = hasher.create()
    digest:update(settings.prompt)
    digest:update(settings.model)
    digest:update(settings.url)
    env_digest = digest:hex():sub(1, 4)
  end
  return string.format('%s_%s', env_digest,
      sel_part:get_mimepart():get_digest():sub(1, 24))
end

local function process_categories(task, categories)
  for _, category in ipairs(categories) do
    local sym = categories_map[category:lower()]
    if sym then
      task:insert_result(sym.name, 1.0)
    end
  end
end

local function insert_results(task, result, sel_part)
  if not result.probability then
    rspamd_logger.errx(task, 'no probability in result')
    return
  end

  if result.probability > 0.5 then
    task:insert_result('GPT_SPAM', (result.probability - 0.5) * 2, tostring(result.probability))
    if settings.autolearn then
      task:set_flag("learn_spam")
    end

    if result.categories then
      process_categories(task, result.categories)
    end
  else
    task:insert_result('GPT_HAM', (0.5 - result.probability) * 2, tostring(result.probability))
    if settings.autolearn then
      task:set_flag("learn_ham")
    end
    if result.categories then
      process_categories(task, result.categories)
    end
  end
  if result.reason and settings.reason_header then
      lua_mime.modify_headers(task,
          { add = { [settings.reason_header] = { value = tostring(result.reason), order = 1 } } })
    end

  if cache_context then
    lua_cache.cache_set(task, redis_cache_key(sel_part), result, cache_context)
  end
end

local function check_consensus_and_insert_results(task, results, sel_part)
  for _, result in ipairs(results) do
    if not result.checked then
      return
    end
  end

  local nspam, nham = 0, 0
  local max_spam_prob, max_ham_prob = 0, 0
  local reasons = {}

  for _, result in ipairs(results) do
    if result.success then
      if result.probability > 0.5 then
        nspam = nspam + 1
        max_spam_prob = math.max(max_spam_prob, result.probability)
        lua_util.debugm(N, task, "model: %s; spam: %s; reason: '%s'",
            result.model, result.probability, result.reason)
      else
        nham = nham + 1
        max_ham_prob = math.min(max_ham_prob, result.probability)
        lua_util.debugm(N, task, "model: %s; ham: %s; reason: '%s'",
            result.model, result.probability, result.reason)
      end

      if result.reason then
        table.insert(reasons, result)
      end
    end
  end

  lua_util.shuffle(reasons)
  local reason = reasons[1] or nil

  if nspam > nham and max_spam_prob > 0.75 then
    insert_results(task, {
      probability = max_spam_prob,
      reason = reason.reason,
      categories = reason.categories,
    },
        sel_part)
  elseif nham > nspam and max_ham_prob < 0.25 then
    insert_results(task, {
      probability = max_ham_prob,
      reason = reason.reason,
      categories = reason.categories,
    },
        sel_part)
  else
    -- No consensus
    lua_util.debugm(N, task, "no consensus")
  end

end

local function get_meta_llm_content(task)
  local url_content = "Url domains: no urls found"
  if task:has_urls() then
    local urls = lua_util.extract_specific_urls { task = task, limit = 5, esld_limit = 1 }
    url_content = "Url domains: " .. table.concat(fun.totable(fun.map(function(u)
      return u:get_tld() or ''
    end, urls or {})), ', ')
  end

  local from_or_empty = ((task:get_from('mime') or E)[1] or E)
  local from_content = string.format('From: %s <%s>', from_or_empty.name, from_or_empty.addr)
  lua_util.debugm(N, task, "gpt urls: %s", url_content)
  lua_util.debugm(N, task, "gpt from: %s", from_content)

  return url_content, from_content
end

local function check_llm_uncached(task, content, sel_part)
  return settings.specific_check(task, content, sel_part)
end

local function check_llm_cached(task, content, sel_part)
  local cache_key = redis_cache_key(sel_part)

  lua_cache.cache_get(task, cache_key, cache_context, settings.timeout * 1.5, function()
    check_llm_uncached(task, content, sel_part)
  end, function(_, err, data)
    if err then
      rspamd_logger.errx(task, 'cannot get cache: %s', err)
      check_llm_uncached(task, content, sel_part)
    end

    if data then
      rspamd_logger.infox(task, 'found cached response %s', cache_key)
      insert_results(task, data, sel_part)
    else
      check_llm_uncached(task, content, sel_part)
    end
  end)
end

local function openai_check(task, content, sel_part)
  lua_util.debugm(N, task, "sending content to gpt: %s", content)

  local upstream

  local results = {}

  local function gen_reply_closure(model, idx)
    return function(err, code, body)
      results[idx].checked = true
      if err then
        rspamd_logger.errx(task, '%s: request failed: %s', model, err)
        upstream:fail()
        check_consensus_and_insert_results(task, results, sel_part)
        return
      end

      upstream:ok()
      lua_util.debugm(N, task, "%s: got reply: %s", model, body)
      if code ~= 200 then
        rspamd_logger.errx(task, 'bad reply: %s', body)
        return
      end

      local reply, reason, categories = settings.reply_conversion(task, body)

      results[idx].model = model

      if reply then
        results[idx].success = true
        results[idx].probability = reply
        results[idx].reason = reason

        if categories then
          results[idx].categories = categories
        end
      end

      check_consensus_and_insert_results(task, results, sel_part)
    end
  end

  local from_content, url_content = get_meta_llm_content(task)

  local body = {
    model = settings.model,
    max_tokens = settings.max_tokens,
    temperature = settings.temperature,
    messages = {
      {
        role = 'system',
        content = settings.prompt
      },
      {
        role = 'user',
        content = 'Subject: ' .. task:get_subject() or '',
      },
      {
        role = 'user',
        content = from_content,
      },
      {
        role = 'user',
        content = url_content,
      },
      {
        role = 'user',
        content = content
      }
    }
  }

  -- Conditionally add response_format
  if settings.include_response_format then
    body.response_format = { type = "json_object" }
  end

  if type(settings.model) == 'string' then
    settings.model = { settings.model }
  end

  upstream = settings.upstreams:get_upstream_round_robin()
  for idx, model in ipairs(settings.model) do
    results[idx] = {
      success = false,
      checked = false
    }
    body.model = model
    local http_params = {
      url = settings.url,
      mime_type = 'application/json',
      timeout = settings.timeout,
      log_obj = task,
      callback = gen_reply_closure(model, idx),
      headers = {
        ['Authorization'] = 'Bearer ' .. settings.api_key,
      },
      keepalive = true,
      body = ucl.to_format(body, 'json-compact', true),
      task = task,
      upstream = upstream,
      use_gzip = true,
    }

    if not rspamd_http.request(http_params) then
      results[idx].checked = true
    end

  end
end

local function ollama_check(task, content, sel_part)
  lua_util.debugm(N, task, "sending content to gpt: %s", content)

  local upstream
  local results = {}

  local function gen_reply_closure(model, idx)
    return function(err, code, body)
      results[idx].checked = true
      if err then
        rspamd_logger.errx(task, '%s: request failed: %s', model, err)
        upstream:fail()
        check_consensus_and_insert_results(task, results, sel_part)
        return
      end

      upstream:ok()
      lua_util.debugm(N, task, "%s: got reply: %s", model, body)
      if code ~= 200 then
        rspamd_logger.errx(task, 'bad reply: %s', body)
        return
      end

      local reply, reason = settings.reply_conversion(task, body)

      results[idx].model = model

      if reply then
        results[idx].success = true
        results[idx].probability = reply
        results[idx].reason = reason
      end

      check_consensus_and_insert_results(task, results, sel_part)
    end
  end

  local from_content, url_content = get_meta_llm_content(task)

  if type(settings.model) == 'string' then
    settings.model = { settings.model }
  end

  local body = {
    stream = false,
    model = settings.model,
    max_tokens = settings.max_tokens,
    temperature = settings.temperature,
    messages = {
      {
        role = 'system',
        content = settings.prompt
      },
      {
        role = 'user',
        content = 'Subject: ' .. task:get_subject() or '',
      },
      {
        role = 'user',
        content = from_content,
      },
      {
        role = 'user',
        content = url_content,
      },
      {
        role = 'user',
        content = content
      }
    }
  }

  for i, model in ipairs(settings.model) do
    -- Conditionally add response_format
    if settings.include_response_format then
      body.response_format = { type = "json_object" }
    end

    results[i] = {
      success = false,
      checked = false
    }
    body.model = model

    upstream = settings.upstreams:get_upstream_round_robin()
    local http_params = {
      url = settings.url,
      mime_type = 'application/json',
      timeout = settings.timeout,
      log_obj = task,
      callback = gen_reply_closure(model, i),
      keepalive = true,
      body = ucl.to_format(body, 'json-compact', true),
      task = task,
      upstream = upstream,
      use_gzip = true,
    }

    rspamd_http.request(http_params)
  end
end

local function gpt_check(task)
  local ret, content, sel_part = settings.condition(task)

  if not ret then
    rspamd_logger.info(task, "skip checking gpt as the condition is not met: %s", content)
    return
  end

  if not content then
    lua_util.debugm(N, task, "no content to send to gpt classification")
    return
  end

  if sel_part then
    -- Check digest
    check_llm_cached(task, content, sel_part)
  else
    check_llm_uncached(task, content)
  end
end

local types_map = {
  openai = {
    check = openai_check,
    condition = default_condition,
    conversion = function(is_json)
      return is_json and default_openai_json_conversion or default_openai_plain_conversion
    end,
    require_passkey = true,
  },
  ollama = {
    check = ollama_check,
    condition = default_condition,
    conversion = function(is_json)
      return is_json and default_ollama_json_conversion or default_ollama_plain_conversion
    end,
    require_passkey = false,
  },
}

local opts = rspamd_config:get_all_opt(N)
if opts then
  redis_params = lua_redis.parse_redis_server(N, opts)
  settings = lua_util.override_defaults(settings, opts)

  if redis_params then
    cache_context = lua_cache.create_cache_context(redis_params, settings, N)
  end

  if not settings.symbols_to_except then
    settings.symbols_to_except = default_symbols_to_except
  end

  if not settings.extra_symbols then
    settings.extra_symbols = default_extra_symbols
  end

  local llm_type = types_map[settings.type]
  if not llm_type then
    rspamd_logger.warnx(rspamd_config, 'unsupported gpt type: %s', settings.type)
    lua_util.disable_module(N, "config")
    return
  end
  settings.specific_check = llm_type.check

  if settings.condition then
    settings.condition = load(settings.condition)()
  else
    settings.condition = llm_type.condition
  end

  if settings.reply_conversion then
    settings.reply_conversion = load(settings.reply_conversion)()
  else
    settings.reply_conversion = llm_type.conversion(settings.json)
  end

  if not settings.api_key and llm_type.require_passkey then
    rspamd_logger.warnx(rspamd_config, 'no api_key is specified for LLM type %s, disabling module', settings.type)
    lua_util.disable_module(N, "config")

    return
  end

  settings.upstreams = lua_util.http_upstreams_by_url(rspamd_config:get_mempool(), settings.url)

  local id = rspamd_config:register_symbol({
    name = 'GPT_CHECK',
    type = 'postfilter',
    callback = gpt_check,
    priority = lua_util.symbols_priorities.medium,
    augmentations = { string.format("timeout=%f", settings.timeout or 0.0) },
  })

  rspamd_config:register_symbol({
    name = 'GPT_SPAM',
    type = 'virtual',
    parent = id,
    score = 3.0,
  })
  rspamd_config:register_symbol({
    name = 'GPT_HAM',
    type = 'virtual',
    parent = id,
    score = -2.0,
  })

  if settings.extra_symbols then
    for sym, data in pairs(settings.extra_symbols) do
      rspamd_config:register_symbol({
        name = sym,
        type = 'virtual',
        parent = id,
        score = data.score,
        description = data.description,
      })
      data.name = sym
      categories_map[data.category] = data
    end
  end

  if not settings.prompt then
    if settings.extra_symbols then
      settings.prompt = "Analyze this email strictly as a spam detector given the email message, subject, " ..
          "FROM and url domains. Evaluate spam probability (0-1). " ..
          "Output ONLY 3 lines:\n" ..
          "1. Numeric score (0.00-1.00)\n" ..
          "2. One-sentence reason citing whether it is spam, the strongest red flag, or why it is ham\n" ..
          "3. Primary concern category if found from the list: " .. table.concat(lua_util.keys(categories_map), ', ')
    else
      settings.prompt = "Analyze this email strictly as a spam detector given the email message, subject, " ..
          "FROM and url domains. Evaluate spam probability (0-1). " ..
          "Output ONLY 2 lines:\n" ..
          "1. Numeric score (0.00-1.00)\n" ..
          "2. One-sentence reason citing whether it is spam, the strongest red flag, or why it is ham\n"
    end
  end
end
