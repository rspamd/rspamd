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
local E = {}

if confighelp then
  rspamd_config:add_example(nil, 'gpt',
      "Performs postfiltering using GPT model",
      [[
gpt {
  # Supported types: openai
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
}
  ]])
  return
end

local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local fun = require "fun"

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
  url = 'https://api.openai.com/v1/chat/completions',
  symbols_to_except = default_symbols_to_except,
}

local function default_condition(task)
  -- Check result
  -- 1) Skip passthrough
  -- 2) Skip already decided as spam
  -- 3) Skip already decided as ham
  local result = task:get_metric_result()
  if result then
    if result.passthrough then
      return false, 'passthrough'
    end
    local score = result.score
    local action = result.action

    if action == 'reject' and result.npositive > 1 then
      return true, 'already decided as spam'
    end

    if action == 'no action' and score < 0 then
      return true, 'negative score, already decided as ham'
    end
  end
  -- We also exclude some symbols
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

  -- Check if we have text at all
  local mp = task:get_parts() or {}
  local sel_part
  for _, mime_part in ipairs(mp) do
    if mime_part:is_text() then
      local part = mime_part:get_text()
      if part:is_html() then
        -- We prefer html content
        sel_part = part
      elseif not sel_part then
        sel_part = part
      end
    end
  end

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

local function default_conversion(task, input)
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

  parser = ucl.parser()
  res, err = parser:parse_string(first_message)
  if not res then
    rspamd_logger.errx(task, 'cannot parse JSON gpt reply: %s', err)
    return
  end

  reply = parser:get_object()

  if type(reply) == 'table' and reply.probability then
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

    return spam_score
  end

  rspamd_logger.errx(task, 'cannot convert spam score: %s', first_message)
  return
end

local function openai_gpt_check(task)
  local ret, content = settings.condition(task)

  if not ret then
    rspamd_logger.info(task, "skip checking gpt as the condition is not met: %s", content)
    return
  end

  if not content then
    lua_util.debugm(N, task, "no content to send to gpt classification")
    return
  end

  lua_util.debugm(N, task, "sending content to gpt: %s", content)

  local upstream

  local function on_reply(err, code, body)

    if err then
      rspamd_logger.errx(task, 'request failed: %s', err)
      upstream:fail()
      return
    end

    upstream:ok()
    lua_util.debugm(N, task, "got reply: %s", body)
    if code ~= 200 then
      rspamd_logger.errx(task, 'bad reply: %s', body)
      return
    end

    local reply = settings.reply_conversion(task, body)
    if not reply then
      return
    end

    if reply > 0.75 then
      task:insert_result('GPT_SPAM', (reply - 0.75) * 4, tostring(reply))
      if settings.autolearn then
        task:set_flag("learn_spam")
      end
    elseif reply < 0.25 then
      task:insert_result('GPT_HAM', (0.25 - reply) * 4, tostring(reply))
      if settings.autolearn then
        task:set_flag("learn_ham")
      end
    else
      lua_util.debugm(N, task, "uncertain result: %s", reply)
    end

  end

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

  local body = {
    model = settings.model,
    max_tokens = settings.max_tokens,
    temperature = settings.temperature,
    response_format = { type = "json_object" },
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

  upstream = settings.upstreams:get_upstream_round_robin()
  local http_params = {
    url = settings.url,
    mime_type = 'application/json',
    timeout = settings.timeout,
    log_obj = task,
    callback = on_reply,
    headers = {
      ['Authorization'] = 'Bearer ' .. settings.api_key,
    },
    keepalive = true,
    body = ucl.to_format(body, 'json-compact', true),
    task = task,
    upstream = upstream,
    use_gzip = true,
  }

  rspamd_http.request(http_params)
end

local function gpt_check(task)
  return settings.specific_check(task)
end

local opts = rspamd_config:get_all_opt('gpt')
if opts then
  settings = lua_util.override_defaults(settings, opts)

  if not settings.api_key then
    rspamd_logger.warnx(rspamd_config, 'no api_key is specified, disabling module')
    lua_util.disable_module(N, "config")

    return
  end
  if settings.condition then
    settings.condition = load(settings.condition)()
  else
    settings.condition = default_condition
  end

  if settings.reply_conversion then
    settings.reply_conversion = load(settings.reply_conversion)()
  else
    settings.reply_conversion = default_conversion
  end

  if not settings.prompt then
    settings.prompt = "You will be provided with the email message, subject, from and url domains, " ..
        "and your task is to evaluate the probability to be spam as number from 0 to 1, " ..
        "output result as JSON with 'probability' field."
  end

  if settings.type == 'openai' then
    settings.specific_check = openai_gpt_check
  else
    rspamd_logger.warnx(rspamd_config, 'unsupported gpt type: %s', settings.type)
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
    score = 5.0,
  })
  rspamd_config:register_symbol({
    name = 'GPT_HAM',
    type = 'virtual',
    parent = id,
    score = -2.0,
  })
end