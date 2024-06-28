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
  model = "gpt-3.5-turbo";
  # Maximum tokens to generate
  max_tokens = 1000;
  # Temperature for sampling
  temperature = 0.7;
  # Top p for sampling
  top_p = 0.9;
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

-- Exclude checks if one of those is found
local default_symbols_to_except = {
  'BAYES_SPAM', -- We already know that it is a spam, so we can safely skip it, but no same logic for HAM!
  'WHITELIST_SPF',
  'WHITELIST_DKIM',
  'WHITELIST_DMARC',
  'FUZZY_DENIED',
}

local settings = {
  type = 'openai',
  api_key = nil,
  model = 'gpt-3.5-turbo',
  max_tokens = 1000,
  temperature = 0.7,
  top_p = 0.9,
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
  for _, s in ipairs(settings.symbols_to_except) do
    if task:has_symbol(s) then
      return false, 'skip as "' .. s .. '" is found'
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
      -- Trim something that does not fit
      for i = nwords, settings.max_tokens, -1 do
        rawset(words, i, nil)
      end
      return true, table.concat(words, ' ')
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

  local spam_score = tonumber(first_message)
  if not spam_score then
    rspamd_logger.errx(task, 'cannot convert spam score: %s', first_message)
    return
  end

  if type(reply.usage) == 'table' then
    rspamd_logger.infox(task, 'usage: %s tokens', reply.usage.total_tokens)
  end

  return spam_score
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
    elseif reply < 0.25 then
      task:insert_result('GPT_HAM', (0.25 - reply) * 4, tostring(reply))
    else
      lua_util.debugm(N, task, "uncertain result: %s", reply)
    end

    -- TODO: add autolearn here
  end

  local body = {
    model = settings.model,
    max_tokens = settings.max_tokens,
    temperature = settings.temperature,
    top_p = settings.top_p,
    messages = {
      {
        role = 'system',
        content = settings.prompt
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
    settings.prompt = "You will be provided with a text of the email, " ..
        "and your task is to classify its probability to be spam, " ..
        "output resulting probability as a single floating point number from 0.0 to 1.0."
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