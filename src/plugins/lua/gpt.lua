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
  model = "gpt-5-mini"; # or parallel model requests [ "gpt-5-mini", "gpt-4o-mini" ];
  # Per-model parameters
  model_parameters = {
    "gpt-5-mini" = {
      max_completion_tokens = 1000,
    },
    "gpt-5-nano" = {
      max_completion_tokens = 1000,
    },
    "gpt-4o-mini" = {
      max_tokens = 1000,
      temperature = 0.0,
    }
  };
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
  # Optional: pass request timeout to the server (in seconds)
  # WARNING: Not all API implementations support this parameter (e.g., standard OpenAI API doesn't)
  # Only enable if your API endpoint/proxy specifically supports max_completion_time parameter
  # If not set, this parameter will not be sent to the server
  # Note: the actual value sent to server is multiplied by 0.95 to account for
  # connection setup, SSL handshake, and data transfer overhead
  # request_timeout = 8;

  # Optional user/domain context in Redis
  context = {
    enabled = true; # fetch and inject user/domain conversation context
    # scope level for identity: user | domain | esld
    level = "user";
    # redis key structure: <key_prefix>:<identity>:<key_suffix>
    key_prefix = "user";
    key_suffix = "mail_context";
    # sliding window and TTLs
    max_messages = 40; # keep up to N compact message summaries
    min_messages = 5; # warm-up: inject context only after N messages collected
    message_ttl = 14d; # forget messages older than this when recomputing
    ttl = 30d; # Redis key TTL
    top_senders = 5; # track top senders
    summary_max_chars = 512; # compress body to this size for storage
    flagged_phrases = ["reset your password", "click here to verify"]; # optional list
    last_labels_count = 10; # keep last N labels
    as_system = true; # place context snippet as additional system message
  };

  # Optional web search context (extract domains from URLs and search for context)
  search_context = {
    enabled = false; # fetch web search context for domains in email
    search_url = "https://leta.mullvad.net/search/__data.json"; # Search API endpoint
    search_engine = "brave"; # Search engine (brave, google, etc.)
    max_domains = 3; # Maximum domains to search
    max_results_per_query = 3; # Maximum results per domain
    timeout = 5; # HTTP timeout in seconds
    cache_ttl = 3600; # Cache TTL in seconds (1 hour)
    cache_key_prefix = "gpt_search"; # Redis cache key prefix
    as_system = true; # Inject as system message (false = user message)
    # Optional gating expressions to enable/disable search context dynamically
    # enable_expression = { ... }; # Enable for specific conditions
    # disable_expression = { ... }; # Disable for specific conditions
  };
  }
  ]])
  return
end

local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local lua_mime = require "lua_mime"
local llm_common = require "llm_common"
local lua_redis = require "lua_redis"
local ucl = require "ucl"
-- local fun = require "fun" -- no longer needed after llm_common usage
local lua_cache = require "lua_cache"
local llm_context = require "llm_context"
local llm_search_context = require "llm_search_context"
local lua_maps_expressions = require "lua_maps_expressions"
local lua_maps = require "lua_maps"
local lua_selectors = require "lua_selectors"

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
  GPT_UNCERTAIN = {
    score = 0.0,
    description = 'GPT model was uncertain about classification',
    category = 'uncertain',
  },
}

-- Should be filled from extra symbols
local categories_map = {}

local settings = {
  type = 'openai',
  api_key = nil,
  model = 'gpt-5-mini', -- or parallel model requests: [ 'gpt-5-mini', 'gpt-4o-mini' ],
  model_parameters = {
    ["gpt-5-mini"] = {
      max_completion_tokens = 1000,
    },
    ["gpt-5-nano"] = {
      max_completion_tokens = 1000,
    },
    ["gpt-4o-mini"] = {
      max_tokens = 1000,
      temperature = 0.0,
    }
  },
  timeout = 10,
  -- Optional staged timeouts
  connect_timeout = nil,
  ssl_timeout = nil,
  write_timeout = nil,
  read_timeout = nil,
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
  request_timeout = nil, -- Optional: pass request timeout to server (in seconds)
  -- user/domain context options (nested table forwarded to llm_context)
  context = {
    enabled = false,
    level = 'user', -- 'user' | 'domain' | 'esld'
    key_prefix = 'user',
    key_suffix = 'mail_context',
    max_messages = 40,
    min_messages = 5,      -- warm-up threshold: minimum messages before injecting context into prompt
    message_ttl = 1209600, -- 14d
    ttl = 2592000,         -- 30d
    top_senders = 5,
    summary_max_chars = 512,
    flagged_phrases = { 'reset your password', 'click here to verify' },
    last_labels_count = 10,
    as_system = true, -- inject context snippet as system message; false => user message
    -- Optional gating using selectors and maps to enable/disable context dynamically
    -- One can use either a simple enable_map or a full maps expression
    -- Example enable_map:
    -- enable_map = { selector = "esld_principal_recipient_domain", map = "/etc/rspamd/context-enabled-domains.map", type = "set" }
    enable_map = nil,
    -- Example enable_expression:
    -- enable_expression = {
    --   rules = {
    --     dom = { selector = "esld_principal_recipient_domain", map = "/etc/rspamd/context-enabled-domains.map" },
    --     user = { selector = "user", map = "/etc/rspamd/context-enabled-users.map" },
    --   },
    --   expression = "dom | user"
    -- }
    enable_expression = nil,
    -- Optional negative gating
    disable_expression = nil,
  },
  -- Web search context options (for extracting and searching domains from URLs)
  search_context = {
    enabled = false,
    search_url = 'https://leta.mullvad.net/search/__data.json', -- Search API endpoint
    search_engine = 'brave',                            -- Search engine (brave, google, etc.)
    max_domains = 3,                                    -- Maximum domains to search
    max_results_per_query = 3,                          -- Maximum results per domain
    timeout = 5,                                        -- HTTP timeout in seconds
    cache_ttl = 3600,                                   -- Cache TTL (1 hour)
    cache_key_prefix = 'gpt_search',                    -- Redis cache key prefix
    as_system = true,                                   -- Inject as system message (false = user message)
    -- Optional gating using selectors and maps to enable/disable search context dynamically
    enable_expression = nil,
    disable_expression = nil,
  },
}
local redis_params
local cache_context
local compiled_context_gating = {
  enable_expr = nil,
  disable_expr = nil,
  enable_map = nil, -- { selector_fn, map }
}
local compiled_search_context_gating = {
  enable_expr = nil,
  disable_expr = nil,
}

local function is_context_enabled_for_task(task)
  local ctx = settings.context
  if not ctx then return false end

  local enabled = ctx.enabled or false

  -- Positive gating via expression
  if compiled_context_gating.enable_expr then
    local res = compiled_context_gating.enable_expr:process(task)
    if res then
      enabled = true
    end
  end

  -- Positive gating via simple map
  if compiled_context_gating.enable_map then
    local vals = compiled_context_gating.enable_map.selector_fn(task)
    local matched = false
    if type(vals) == 'table' then
      for _, v in ipairs(vals) do
        if compiled_context_gating.enable_map.map:get_key(v) then
          matched = true
          break
        end
      end
    elseif vals then
      matched = compiled_context_gating.enable_map.map:get_key(vals) and true or false
    end
    if matched then
      enabled = true
    end
  end

  -- Negative gating
  if enabled and compiled_context_gating.disable_expr then
    local res = compiled_context_gating.disable_expr:process(task)
    if res then
      enabled = false
    end
  end

  return enabled
end

local function is_search_context_enabled_for_task(task)
  local ctx = settings.search_context
  if not ctx then return false end

  local enabled = ctx.enabled or false

  -- Positive gating via expression
  if compiled_search_context_gating.enable_expr then
    local res = compiled_search_context_gating.enable_expr:process(task)
    if res then
      enabled = true
    end
  end

  -- Negative gating
  if enabled and compiled_search_context_gating.disable_expr then
    local res = compiled_search_context_gating.disable_expr:process(task)
    if res then
      enabled = false
    end
  end

  return enabled
end

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

  -- Unified LLM input building (subject/from/urls/body one-line)
  local model_cfg = settings.model_parameters[settings.model] or {}
  local max_tokens = model_cfg.max_completion_tokens or model_cfg.max_tokens or 1000
  local input_tbl, sel_part = llm_common.build_llm_input(task, { max_tokens = max_tokens })
  if not sel_part then
    return false, 'no text part found'
  end
  if not input_tbl then
    local nwords = sel_part:get_words_count() or 0
    if nwords < 5 then
      return false, 'less than 5 words'
    end
    return false, 'no content to send'
  end
  return true, input_tbl, sel_part
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

-- Helper function to remove <think>...</think> and trim leading newlines
local function clean_gpt_response(text)
  -- Remove <think>...</think> including multiline
  text = text:gsub("<think>.-</think>", "")
  -- Trim leading whitespace and newlines
  text = text:gsub("^%s*\n*", "")
  return text
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
        lua_util.debugm(N, task, "cannot convert to spam probability: %s", reply.probability)
      end
    end

    if type(reply.usage) == 'table' then
      lua_util.debugm(N, task, 'usage: %s tokens', reply.usage.total_tokens)
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

-- Assume that we have 3 lines: probability, reason, additional categories
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
  local finish_reason = reply.choices[1].finish_reason or 'unknown'

  if not first_message or first_message == "" then
    if finish_reason == 'length' then
      -- Token limit exceeded - provide helpful error message
      local usage = reply.usage or {}
      local completion_tokens = usage.completion_tokens or 0
      local reasoning_tokens = usage.completion_tokens_details and usage.completion_tokens_details.reasoning_tokens or 0
      rspamd_logger.errx(task, 'LLM response truncated: token limit exceeded. ' ..
        'Used %s completion tokens (including %s reasoning tokens). ' ..
        'Increase max_completion_tokens in model_parameters config for this model.',
        completion_tokens, reasoning_tokens)
    else
      rspamd_logger.errx(task, 'no content in the first message (finish_reason: %s, usage: %s)',
        finish_reason, reply.usage and ucl.to_format(reply.usage, 'json-compact') or 'none')
    end
    return
  end

  -- Clean message
  first_message = clean_gpt_response(first_message)

  local lines = lua_util.str_split(first_message, '\n')
  local first_line = clean_reply_line(lines[1])
  local spam_score = tonumber(first_line)
  local reason = clean_reply_line(lines[2])
  local categories = lua_util.str_split(clean_reply_line(lines[3]), ',')

  if type(reply.usage) == 'table' then
    lua_util.debugm(N, task, 'usage: %s tokens', reply.usage.total_tokens)
  end

  if spam_score then
    return spam_score, reason, categories
  end

  rspamd_logger.errx(task, 'cannot parse plain gpt reply: %s (all: %s)', lines[1], first_message)
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

  -- Clean message
  first_message = clean_gpt_response(first_message)

  local lines = lua_util.str_split(first_message, '\n')
  local first_line = clean_reply_line(lines[1])
  local spam_score = tonumber(first_line)
  local reason = clean_reply_line(lines[2])
  local categories = lua_util.str_split(clean_reply_line(lines[3]), ',')

  if spam_score then
    return spam_score, reason, categories
  end

  rspamd_logger.errx(task, 'cannot parse plain gpt reply: %s (all: %s)', lines[1], first_message)
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
        lua_util.debugm(N, task, "cannot convert to spam probability: %s", reply.probability)
      end
    end

    if type(reply.usage) == 'table' then
      lua_util.debugm(N, task, 'usage: %s tokens', reply.usage.total_tokens)
    end

    return spam_score, reply.reason, {}
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
  elseif result.probability < 0.5 then
    task:insert_result('GPT_HAM', (0.5 - result.probability) * 2, tostring(result.probability))
    if settings.autolearn then
      task:set_flag("learn_ham")
    end
    if result.categories then
      process_categories(task, result.categories)
    end
  else
    -- probability == 0.5, uncertain result, don't set GPT_SPAM/GPT_HAM
    if result.categories then
      process_categories(task, result.categories)
    end
  end
  if result.reason and settings.reason_header then
    if type(settings.reason_header) == 'string' and #result.reason > 0 then
      local ok, v = pcall(lua_util.fold_header_with_encoding, task, settings.reason_header,
        result.reason, { encode = false, structured = false })
      if ok and v then
        lua_mime.modify_headers(task,
          { add = { [settings.reason_header] = { value = v, order = 1 } } })
      else
        rspamd_logger.warnx(task, 'cannot fold header %s: %s; using raw value', settings.reason_header,
          v)
        -- Fallback: use raw value without encoding
        lua_mime.modify_headers(task,
          { add = { [settings.reason_header] = { value = result.reason, order = 1 } } })
      end
    end
  end

  if cache_context then
    lua_cache.cache_set(task, redis_cache_key(sel_part), result, cache_context)
  end

  -- Update long-term user/domain context after classification
  if redis_params and settings.context then
    llm_context.update_after_classification(task, redis_params, settings.context, result, sel_part, N)
  end
end

local function check_consensus_and_insert_results(task, results, sel_part)
  for _, result in ipairs(results) do
    if not result.checked then
      return
    end
  end

  local nspam, nham = 0, 0
  local max_spam_prob, max_ham_prob = 0, 1.0
  local reasons = {}

  for _, result in ipairs(results) do
    if result.success and result.probability then
      if result.probability > 0.5 then
        nspam = nspam + 1
        max_spam_prob = math.max(max_spam_prob, result.probability)
        lua_util.debugm(N, task, "model: %s; spam: %s; reason: '%s'",
          result.model or 'unknown', result.probability, result.reason or 'no reason')
      else
        nham = nham + 1
        max_ham_prob = math.min(max_ham_prob, result.probability)
        lua_util.debugm(N, task, "model: %s; ham: %s; reason: '%s'",
          result.model or 'unknown', result.probability, result.reason or 'no reason')
      end

      if result.reason then
        table.insert(reasons, result)
      end
    end
  end

  lua_util.shuffle(reasons)
  local reason_obj = reasons[1]
  local reason_text = reason_obj and reason_obj.reason or nil
  local reason_categories = reason_obj and reason_obj.categories or nil

  if nspam > nham and max_spam_prob > 0.75 then
    insert_results(task, {
        probability = max_spam_prob,
        reason = reason_text,
        categories = reason_categories,
      },
      sel_part)
  elseif nham > nspam and max_ham_prob < 0.25 then
    insert_results(task, {
        probability = max_ham_prob,
        reason = reason_text,
        categories = reason_categories,
      },
      sel_part)
  else
    -- No consensus - still cache and set uncertain symbol to avoid re-querying LLM
    lua_util.debugm(N, task, "no consensus: nspam=%s, nham=%s, max_spam_prob=%s, max_ham_prob=%s",
      nspam, nham, max_spam_prob, max_ham_prob)
    -- Use 0.5 (neutral) probability with uncertain marker
    local uncertain_reason = reason_text or string.format(
      "Uncertain classification: spam votes=%d (max %.2f), ham votes=%d (min %.2f)",
      nspam, max_spam_prob, nham, max_ham_prob)
    insert_results(task, {
        probability = 0.5,
        reason = uncertain_reason,
        categories = { 'uncertain' },
      },
      sel_part)
    task:insert_result('GPT_UNCERTAIN', 1.0)
  end
end

-- get_meta_llm_content moved to llm_common

local function check_llm_uncached(task, content, sel_part, context_snippet)
  return settings.specific_check(task, content, sel_part, context_snippet)
end

local function check_llm_cached(task, content, sel_part, context_snippet)
  local cache_key = redis_cache_key(sel_part)

  lua_cache.cache_get(task, cache_key, cache_context, settings.timeout * 1.5, function()
    check_llm_uncached(task, content, sel_part, context_snippet)
  end, function(_, err, data)
    if err then
      rspamd_logger.errx(task, 'cannot get cache: %s', err)
      check_llm_uncached(task, content, sel_part)
    end

    if data then
      lua_util.debugm(N, task, 'found cached response %s', cache_key)
      insert_results(task, data, sel_part)
    else
      check_llm_uncached(task, content, sel_part, context_snippet)
    end
  end)
end

local function openai_check(task, content, sel_part, context_snippet)
  lua_util.debugm(N, task, "sending content to gpt: %s", content)
  if context_snippet then
    lua_util.debugm(N, task, "with context snippet (%s chars): %s", #context_snippet, context_snippet)
  else
    lua_util.debugm(N, task, "no context snippet")
  end

  local upstream
  local results = {}

  local function gen_reply_closure(model, i)
    return function(err, code, body)
      results[i].checked = true
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

      results[i].model = model

      if reply then
        results[i].success = true
        results[i].probability = reply
        results[i].reason = reason

        if categories then
          results[i].categories = categories
        end
      end

      check_consensus_and_insert_results(task, results, sel_part)
    end
  end

  -- Build messages with optional user/domain context
  local user_messages
  if type(content) == 'table' then
    local subject_line = 'Subject: ' .. (content.subject or '')
    user_messages = {
      { role = 'user', content = subject_line },
      { role = 'user', content = content.from or '' },
      { role = 'user', content = content.url_domains or '' },
      { role = 'user', content = content.text or '' },
    }
  else
    user_messages = {
      { role = 'user', content = content }
    }
  end

  local sys_messages = {
    { role = 'system', content = settings.prompt }
  }
  if context_snippet and settings.context and settings.context.as_system ~= false then
    table.insert(sys_messages, { role = 'system', content = context_snippet })
  elseif context_snippet and settings.context and settings.context.as_system == false then
    table.insert(user_messages, 1, { role = 'user', content = context_snippet })
  end

  local body_base = {
    stream = false,
    messages = {}
  }
  for _, m in ipairs(sys_messages) do table.insert(body_base.messages, m) end
  for _, m in ipairs(user_messages) do table.insert(body_base.messages, m) end

  local models_list = type(settings.model) == 'string' and { settings.model } or settings.model

  for idx, model in ipairs(models_list) do
    results[idx] = {
      success = false,
      checked = false
    }
    -- Fresh body for each model
    local body = lua_util.deepcopy(body_base)

    -- Merge model-specific parameters into body
    local params = settings.model_parameters[model]
    if params then
      for k, v in pairs(params) do
        body[k] = v
      end
    end

    -- Conditionally add response_format
    if settings.include_response_format then
      body.response_format = { type = "json_object" }
    end

    -- Optionally add request timeout for server-side timeout control
    -- Only pass if explicitly configured (not all API implementations support this)
    -- Multiply by 0.95 to account for connection setup, SSL handshake, and data transfer time
    if settings.request_timeout then
      body.max_completion_time = settings.request_timeout * 0.95
    end

    body.model = model

    upstream = settings.upstreams:get_upstream_round_robin()
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
      -- staged timeouts
      connect_timeout = settings.connect_timeout,
      ssl_timeout = settings.ssl_timeout,
      write_timeout = settings.write_timeout,
      read_timeout = settings.read_timeout,
    }

    if not rspamd_http.request(http_params) then
      results[idx].checked = true
    end
  end
end

local function ollama_check(task, content, sel_part, context_snippet)
  lua_util.debugm(N, task, "sending content to gpt: %s", content)
  if context_snippet then
    lua_util.debugm(N, task, "with context snippet (%s chars): %s", #context_snippet, context_snippet)
  else
    lua_util.debugm(N, task, "no context snippet")
  end

  local upstream
  local results = {}

  local function gen_reply_closure(model, i)
    return function(err, code, body)
      results[i].checked = true
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

      results[i].model = model

      if reply then
        results[i].success = true
        results[i].probability = reply
        results[i].reason = reason
        if categories then
          results[i].categories = categories
        end
      end

      check_consensus_and_insert_results(task, results, sel_part)
    end
  end

  local user_messages
  if type(content) == 'table' then
    local subject_line = 'Subject: ' .. (content.subject or '')
    user_messages = {
      { role = 'user', content = subject_line },
      { role = 'user', content = content.from or '' },
      { role = 'user', content = content.url_domains or '' },
      { role = 'user', content = content.text or '' },
    }
  else
    user_messages = {
      { role = 'user', content = content }
    }
  end

  local models_list = type(settings.model) == 'string' and { settings.model } or settings.model

  local sys_messages = {
    { role = 'system', content = settings.prompt }
  }
  if context_snippet and settings.context and settings.context.as_system ~= false then
    table.insert(sys_messages, { role = 'system', content = context_snippet })
  elseif context_snippet and settings.context and settings.context.as_system == false then
    table.insert(user_messages, 1, { role = 'user', content = context_snippet })
  end

  local body_base = {
    stream = false,
    messages = {}
  }
  for _, m in ipairs(sys_messages) do table.insert(body_base.messages, m) end
  for _, m in ipairs(user_messages) do table.insert(body_base.messages, m) end

  for idx, model in ipairs(models_list) do
    results[idx] = {
      success = false,
      checked = false
    }
    -- Fresh body for each model
    local body = lua_util.deepcopy(body_base)

    -- Merge model-specific parameters into body
    local params = settings.model_parameters[model]
    if params then
      for k, v in pairs(params) do
        body[k] = v
      end
    end

    -- Conditionally add response_format
    if settings.include_response_format then
      body.response_format = { type = "json_object" }
    end

    -- Optionally add request timeout for server-side timeout control
    -- Only pass if explicitly configured (not all API implementations support this)
    -- Multiply by 0.95 to account for connection setup, SSL handshake, and data transfer time
    if settings.request_timeout then
      body.max_completion_time = settings.request_timeout * 0.95
    end

    body.model = model

    upstream = settings.upstreams:get_upstream_round_robin()
    local http_params = {
      url = settings.url,
      mime_type = 'application/json',
      timeout = settings.timeout,
      log_obj = task,
      callback = gen_reply_closure(model, idx),
      keepalive = true,
      body = ucl.to_format(body, 'json-compact', true),
      task = task,
      upstream = upstream,
      use_gzip = true,
      -- staged timeouts
      connect_timeout = settings.connect_timeout,
      ssl_timeout = settings.ssl_timeout,
      write_timeout = settings.write_timeout,
      read_timeout = settings.read_timeout,
    }

    if not rspamd_http.request(http_params) then
      results[idx].checked = true
    end
  end
end

local function gpt_check(task)
  local ret, content, sel_part = settings.condition(task)

  -- Always update context if enabled, even when condition is not met
  local context_enabled = redis_params and settings.context and is_context_enabled_for_task(task)
  if context_enabled and not ret then
    -- Condition not met (e.g. BAYES_SPAM, passthrough, etc.)
    -- Update context without LLM call; infer result from task metrics
    if not sel_part then
      -- Try to get text part for context update
      sel_part = lua_mime.get_displayed_text_part(task)
    end
    if sel_part then
      local result = task:get_metric_result()
      local inferred_result = nil
      if result then
        if result.action == 'reject' or (result.score and result.score > 10) then
          inferred_result = { probability = 0.9, reason = 'rejected by filters', categories = {} }
        elseif result.action == 'no action' and result.score and result.score < 0 then
          inferred_result = { probability = 0.1, reason = 'ham by filters', categories = {} }
        end
      end
      llm_context.update_after_classification(task, redis_params, settings.context, inferred_result, sel_part, N)
    end
    lua_util.debugm(N, task, "skip checking gpt as the condition is not met: %s; context updated", content)
    return
  end

  if not ret then
    lua_util.debugm(N, task, "skip checking gpt as the condition is not met: %s", content)
    return
  end

  if not content then
    lua_util.debugm(N, task, "no content to send to gpt classification")
    return
  end

  local function proceed(combined_context)
    if sel_part then
      -- Check digest
      check_llm_cached(task, content, sel_part, combined_context)
    else
      check_llm_uncached(task, content, nil, combined_context)
    end
  end

  -- Check if we need to fetch search context
  local search_context_enabled = is_search_context_enabled_for_task(task)

  if context_enabled or search_context_enabled then
    local pending_fetches = 0
    local user_context_snippet = nil
    local search_context_snippet = nil

    local function maybe_proceed()
      if pending_fetches == 0 then
        -- Combine contexts
        local combined_context = nil
        if user_context_snippet and search_context_snippet then
          combined_context = user_context_snippet .. "\n\n" .. search_context_snippet
        elseif user_context_snippet then
          combined_context = user_context_snippet
        elseif search_context_snippet then
          combined_context = search_context_snippet
        end
        proceed(combined_context)
      end
    end

    if context_enabled then
      pending_fetches = pending_fetches + 1
      llm_context.fetch(task, redis_params, settings.context, function(_, _, snippet)
        user_context_snippet = snippet
        pending_fetches = pending_fetches - 1
        maybe_proceed()
      end, N)
    end

    if search_context_enabled then
      pending_fetches = pending_fetches + 1
      llm_search_context.fetch_and_format(task, redis_params, settings.search_context, function(_, _, snippet)
        search_context_snippet = snippet
        pending_fetches = pending_fetches - 1
        maybe_proceed()
      end, N)
    end

    -- If no fetches were initiated, proceed immediately
    if pending_fetches == 0 then
      proceed(nil)
    end
  else
    proceed(nil)
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
    group = 'GPT',
  })
  rspamd_config:register_symbol({
    name = 'GPT_HAM',
    type = 'virtual',
    parent = id,
    score = -2.0,
    group = 'GPT',
  })

  if settings.extra_symbols then
    for sym, data in pairs(settings.extra_symbols) do
      rspamd_config:register_symbol({
        name = sym,
        type = 'virtual',
        parent = id,
        score = data.score or 0,
        group = data.group or 'GPT',
        description = data.description,
      })
      data.name = sym
      categories_map[data.category] = data
    end
  end

  if not settings.prompt then
    if settings.extra_symbols then
      settings.prompt = "Analyze this email as a spam detector. Evaluate spam probability (0-1).\n\n" ..
          "LEGITIMATE patterns to recognize:\n" ..
          "- Verification emails with time-limited codes are NORMAL and legitimate\n" ..
          "- Transactional emails (receipts, confirmations, password resets) from services\n" ..
          "- 'Verify email' or 'confirmation code' is NOT automatically phishing\n" ..
          "- Emails from frequent/known senders (see context) are more trustworthy\n\n" ..
          "Flag as SPAM/PHISHING only with MULTIPLE red flags:\n" ..
          "- Urgent threats or fear tactics (account closure, legal action)\n" ..
          "- Domain impersonation or suspicious lookalikes\n" ..
          "- Requests for passwords, SSN, credit card numbers\n" ..
          "- Mismatched URLs pointing to different domains than sender\n" ..
          "- Poor grammar/spelling in supposedly professional emails\n\n" ..
          "IMPORTANT: If sender is 'frequent' or 'known', reduce phishing probability " ..
          "unless there are strong contradictory signals.\n\n" ..
          "Output ONLY 3 lines:\n" ..
          "1. Numeric score (0.00-1.00)\n" ..
          "2. One-sentence reason citing the strongest indicator\n" ..
          "3. Primary category if applicable: " ..
          table.concat(lua_util.keys(categories_map), ', ')
    else
      settings.prompt = "Analyze this email as a spam detector. Evaluate spam probability (0-1).\n\n" ..
          "LEGITIMATE patterns to recognize:\n" ..
          "- Verification emails with time-limited codes are NORMAL and legitimate\n" ..
          "- Transactional emails (receipts, confirmations, password resets) from services\n" ..
          "- 'Verify email' or 'confirmation code' is NOT automatically phishing\n" ..
          "- Emails from frequent/known senders (see context) are more trustworthy\n\n" ..
          "Flag as SPAM/PHISHING only with MULTIPLE red flags:\n" ..
          "- Urgent threats or fear tactics (account closure, legal action)\n" ..
          "- Domain impersonation or suspicious lookalikes\n" ..
          "- Requests for passwords, SSN, credit card numbers\n" ..
          "- Mismatched URLs pointing to different domains than sender\n" ..
          "- Poor grammar/spelling in supposedly professional emails\n\n" ..
          "IMPORTANT: If sender is 'frequent' or 'known', reduce phishing probability " ..
          "unless there are strong contradictory signals.\n\n" ..
          "Output ONLY 2 lines:\n" ..
          "1. Numeric score (0.00-1.00)\n" ..
          "2. One-sentence reason citing the strongest indicator"
    end
  end

  -- Compile optional context gating
  if settings.context then
    local ctx = settings.context
    if ctx.enable_expression then
      local expr = lua_maps_expressions.create(rspamd_config, ctx.enable_expression, N .. "/context-enable")
      if expr then
        compiled_context_gating.enable_expr = expr
      else
        rspamd_logger.warnx(rspamd_config, 'failed to compile context enable_expression')
      end
    end
    if ctx.disable_expression then
      local expr = lua_maps_expressions.create(rspamd_config, ctx.disable_expression, N .. "/context-disable")
      if expr then
        compiled_context_gating.disable_expr = expr
      else
        rspamd_logger.warnx(rspamd_config, 'failed to compile context disable_expression')
      end
    end
    if ctx.enable_map and type(ctx.enable_map) == 'table' and ctx.enable_map.selector and ctx.enable_map.map then
      local sel = lua_selectors.create_selector_closure(rspamd_config, ctx.enable_map.selector)
      local map = lua_maps.map_add_from_ucl(ctx.enable_map.map, ctx.enable_map.type or 'set',
        'GPT context enable map')
      if sel and map then
        compiled_context_gating.enable_map = {
          selector_fn = sel,
          map = map,
        }
      else
        rspamd_logger.warnx(rspamd_config, 'failed to compile context enable_map: selector or map invalid')
      end
    end
  end

  -- Compile optional search context gating
  if settings.search_context then
    local sctx = settings.search_context
    if sctx.enable_expression then
      local expr = lua_maps_expressions.create(rspamd_config, sctx.enable_expression, N .. "/search-context-enable")
      if expr then
        compiled_search_context_gating.enable_expr = expr
      else
        rspamd_logger.warnx(rspamd_config, 'failed to compile search_context enable_expression')
      end
    end
    if sctx.disable_expression then
      local expr = lua_maps_expressions.create(rspamd_config, sctx.disable_expression, N .. "/search-context-disable")
      if expr then
        compiled_search_context_gating.disable_expr = expr
      else
        rspamd_logger.warnx(rspamd_config, 'failed to compile search_context disable_expression')
      end
    end
  end
end
