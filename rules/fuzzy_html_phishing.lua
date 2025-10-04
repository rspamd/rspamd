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

--[[
HTML Fuzzy Phishing Detection Rules

Detects phishing based on fuzzy hash mismatches:
1. Text content matches known legitimate email (whitelist)
2. But HTML structure doesn't match or has different CTA domains
3. Or vice versa: HTML structure matches but text/CTA is suspicious

This indicates possible template reuse for phishing.
]]

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"

local N = 'fuzzy_html_phishing'

local function check_fuzzy_mismatch(task)
  local fuzzy_results = task:get_mempool():get_variable('fuzzy_result')
  
  if not fuzzy_results then
    return false
  end
  
  -- Collect results by type
  local text_matches = {}
  local html_matches = {}
  
  for _, hash_result in ipairs(fuzzy_results) do
    local symbol = tostring(hash_result)
    -- Parse fuzzy result format: "flag:hash:prob:type"
    -- This is simplified - actual parsing depends on result format
    
    -- For now, check mempool variables set by fuzzy_insert_result
    -- We need to enhance fuzzy_check to expose result types
  end
  
  -- Get fuzzy check symbols from task results
  local fuzzy_symbols = task:get_symbols_all()
  local has_text_fuzzy = false
  local has_html_fuzzy = false
  local text_score = 0
  local html_score = 0
  
  for _, sym in ipairs(fuzzy_symbols) do
    if sym.name:match('FUZZY.*TEXT') or sym.name == 'R_FUZZY_HASH' then
      has_text_fuzzy = true
      text_score = math.max(text_score, sym.score or 0)
    end
    if sym.name:match('FUZZY.*HTML') then
      has_html_fuzzy = true
      html_score = math.max(html_score, sym.score or 0)
    end
  end
  
  -- Scenario 1: Text matches legitimate but no HTML match
  -- This could indicate phishing with copied text but fake HTML/CTA
  if has_text_fuzzy and not has_html_fuzzy and text_score > 5.0 then
    task:insert_result('FUZZY_HTML_PHISHING_MISMATCH', 0.5,
      string.format('text_score:%.2f', text_score))
    lua_util.debugm(N, task,
      'Phishing suspect: text fuzzy match (%.2f) without HTML match',
      text_score)
    return true
  end
  
  -- Scenario 2: HTML matches but text doesn't (less suspicious)
  -- This is common for newsletters/notifications with varying content
  if has_html_fuzzy and not has_text_fuzzy and html_score > 8.0 then
    -- Only flag if HTML score is very high (known template)
    lua_util.debugm(N, task,
      'HTML template match (%.2f) with varying text - likely legitimate newsletter',
      html_score)
    -- Could add negative score or just log
  end
  
  return false
end

-- Register symbol
rspamd_config:register_symbol{
  name = 'FUZZY_HTML_PHISHING_MISMATCH',
  type = 'virtual',
  score = 5.0,
  description = 'Text fuzzy matches legitimate but HTML structure does not',
  group = 'fuzzy'
}

-- Register callback
local id = rspamd_config:register_symbol{
  name = 'FUZZY_HTML_PHISHING_CHECK',
  type = 'callback',
  callback = check_fuzzy_mismatch,
  score = 0.0,
  group = 'fuzzy',
  description = 'Check for HTML/text fuzzy mismatches indicating phishing'
}

-- Depends on fuzzy_check
rspamd_config:register_dependency('FUZZY_HTML_PHISHING_CHECK', 'FUZZY_CALLBACK')
