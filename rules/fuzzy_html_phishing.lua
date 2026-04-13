--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local lua_util = require "lua_util"
local N = 'fuzzy_html_phishing'

-- Collect symbols from fuzzy rules that have html_shingles enabled
local html_fuzzy_symbols = {}

local fuzzy_conf = rspamd_config:get_all_opt('fuzzy_check')
if fuzzy_conf and fuzzy_conf.rule then
  local function process_rule(rule)
    if not rule.html_shingles then
      return
    end

    -- Default symbol for the rule
    if rule.symbol then
      html_fuzzy_symbols[rule.symbol] = true
    end

    -- Per-flag mapped symbols
    if rule.fuzzy_map then
      for _, map in pairs(rule.fuzzy_map) do
        if type(map) == 'table' and map.symbol then
          html_fuzzy_symbols[map.symbol] = true
        end
      end
    end
  end

  for _, rule in pairs(fuzzy_conf.rule) do
    if type(rule) == 'table' then
      if rule.servers or rule.read_servers or rule.write_servers then
        -- Unnamed rule
        process_rule(rule)
      else
        -- Named rules container
        for _, subrule in pairs(rule) do
          if type(subrule) == 'table' then
            process_rule(subrule)
          end
        end
      end
    end
  end
end

if not next(html_fuzzy_symbols) then
  lua_util.debugm(N, rspamd_config, 'no fuzzy rules with html_shingles enabled, skip registration')
  return
end

local function check_fuzzy_mismatch(task)
  local text_parts = task:get_text_parts()
  if not text_parts then
    return
  end

  local has_html = false
  for _, tp in ipairs(text_parts) do
    if tp:is_html() then
      has_html = true
      break
    end
  end

  if not has_html then
    return
  end

  local all_symbols = task:get_symbols_all()
  if not all_symbols then
    return
  end

  for _, sym in ipairs(all_symbols) do
    if not html_fuzzy_symbols[sym.name] or not sym.options then
      goto continue
    end

    local matched = {}

    for _, opt in ipairs(sym.options) do
      local mtype = opt:match('^%d+:%w+:[%d%.]+:(%a+)')
      if mtype then
        matched[mtype] = true
      end
    end

    if matched['txt'] and not matched['html'] then
      task:insert_result('FUZZY_TEXT_WITHOUT_HTML', 1.0, sym.name)
      lua_util.debugm(N, task, 'text matched but html did not for %s', sym.name)
    elseif matched['html'] and not matched['txt'] then
      task:insert_result('FUZZY_HTML_WITHOUT_TEXT', 1.0, sym.name)
      lua_util.debugm(N, task, 'html matched but text did not for %s', sym.name)
    end

    -- Phishing detection: HTML template matches but domains differ
    if matched['html'] and not matched['htmld'] then
      task:insert_result('FUZZY_HTML_PHISHING', 1.0, sym.name)
      lua_util.debugm(N, task, 'html template matched but domains differ for %s (possible phishing)', sym.name)
    end

    ::continue::
  end
end

local cb_id = rspamd_config:register_symbol{
  name = 'FUZZY_MISMATCH_CHECK',
  type = 'callback',
  callback = check_fuzzy_mismatch,
  score = 0.0,
  group = 'fuzzy',
  description = 'Check for text/HTML fuzzy type mismatches',
}

rspamd_config:register_symbol{
  name = 'FUZZY_TEXT_WITHOUT_HTML',
  type = 'virtual',
  score = 4.0,
  parent = cb_id,
  group = 'fuzzy',
  description = 'Text fuzzy matches but HTML structure does not (possible template swap)',
}

rspamd_config:register_symbol{
  name = 'FUZZY_HTML_WITHOUT_TEXT',
  type = 'virtual',
  score = 2.0,
  parent = cb_id,
  group = 'fuzzy',
  description = 'HTML structure fuzzy matches but text content does not',
}

rspamd_config:register_symbol{
  name = 'FUZZY_HTML_PHISHING',
  type = 'virtual',
  score = 6.0,
  parent = cb_id,
  group = 'fuzzy',
  description = 'HTML template matches but link domains differ (possible phishing)',
}

rspamd_config:register_dependency('FUZZY_MISMATCH_CHECK', 'FUZZY_CALLBACK')
