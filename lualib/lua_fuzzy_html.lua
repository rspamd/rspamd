--[[
HTML Fuzzy Hashing Helper Module

This module provides helper functions for HTML fuzzy hash matching
and phishing detection based on HTML structure vs. content mismatches.

Use case: Detect phishing where HTML structure matches legitimate emails
but CTA (Call-To-Action) domains are different.
]]

local exports = {}
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"

--[[
Analyze fuzzy results to detect potential phishing based on:
- Text content fuzzy match (high score)
- HTML structure fuzzy match (high score)
- But HTML CTA domains differ from known legitimate

Returns: phishing_score, explanation
]]
exports.check_html_text_mismatch = function(task, fuzzy_results)
  local html_matches = {}
  local text_matches = {}
  
  -- Separate HTML and text fuzzy matches
  for _, res in ipairs(fuzzy_results or {}) do
    if res.type == 'html' then
      table.insert(html_matches, res)
    elseif res.type == 'txt' then
      table.insert(text_matches, res)
    end
  end
  
  -- Phishing scenario: high text match but low/no HTML match
  if #text_matches > 0 and #html_matches == 0 then
    local max_text_score = 0
    for _, res in ipairs(text_matches) do
      if res.score > max_text_score then
        max_text_score = res.score
      end
    end
    
    -- High text match but no HTML match = suspicious
    if max_text_score > 0.7 then
      return max_text_score * 0.5, string.format(
        "Text fuzzy match (%.2f) without HTML match - possible CTA substitution",
        max_text_score)
    end
  end
  
  -- Inverse scenario: HTML match but no text match
  -- (Could be template with varying content - less suspicious)
  if #html_matches > 0 and #text_matches == 0 then
    local max_html_score = 0
    for _, res in ipairs(html_matches) do
      if res.score > max_html_score then
        max_html_score = res.score
      end
    end
    
    -- This is expected for newsletters/notifications
    lua_util.debugm('fuzzy_html', task,
      'HTML match (%.2f) without text match - likely template variation',
      max_html_score)
  end
  
  return 0, nil
end

--[[
Check if message has suspicious HTML fuzzy pattern:
- Known legitimate HTML structure
- But text content is different or manipulated
- Useful for brand protection

Example: Amazon email template with phishing text
]]
exports.check_brand_hijack = function(task, html_fuzzy_result, text_fuzzy_result)
  if not html_fuzzy_result then
    return 0, nil
  end
  
  -- High HTML match = known template
  if html_fuzzy_result.score > 0.8 then
    -- Check if text is suspicious
    if not text_fuzzy_result or text_fuzzy_result.score < 0.3 then
      return html_fuzzy_result.score * 0.6,
        string.format("Known HTML template (%.2f) with unfamiliar text - possible brand hijacking",
          html_fuzzy_result.score)
    end
  end
  
  return 0, nil
end

return exports
