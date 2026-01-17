--[[
Common helpers for building LLM input content from a task
]] --

local lua_util = require "lua_util"
local lua_mime = require "lua_mime"
local fun = require "fun"

local M = {}
local N = 'llm_common'

local function get_meta_llm_content(task)
  local url_content = "Url domains: no urls found"
  if task:has_urls() then
    local urls = lua_util.extract_specific_urls { task = task, limit = 5, esld_limit = 1 }
    url_content = "Url domains: " .. table.concat(fun.totable(fun.map(function(u)
      return u:get_tld() or ''
    end, urls or {})), ', ')
  end

  local from_or_empty = ((task:get_from('mime') or {})[1] or {})
  local from_name = from_or_empty.name or ''
  local from_addr = from_or_empty.addr or ''
  local from_content = string.format('From: %s <%s>', from_name, from_addr)

  return url_content, from_content
end

-- Build structured payload suitable for LLM embeddings and chat
-- Returns: table { subject = <string>, from = <string>, url_domains = <string>, text = <rspamd_text|string> }, part
function M.build_llm_input(task, opts)
  opts = opts or {}
  local subject = task:get_subject() or ''
  local url_content, from_content = get_meta_llm_content(task)

  -- Use extract_text_limited for content
  local max_tokens = tonumber(opts.max_tokens) or 1024
  -- Rough estimation: 1 token approx 4 bytes (english), but let's be generous
  -- However, we can use max_words as a proxy for tokens?
  -- opts.max_tokens is typically tokens.
  -- Rspamd uses bytes for limit.
  -- Let's stick with what we had but using extract_text_limited

  local extraction_opts = {
    max_bytes = max_tokens * 6, -- Rough estimate
    max_words = max_tokens, -- Better estimate if available
    strip_quotes = true, -- Default cleanup for LLM
    smart_trim = true, -- Enable heuristics
  }

  local res = lua_mime.extract_text_limited(task, extraction_opts)

  if not res or res.text == "" then
    lua_util.debugm(N, task, 'no text extracted')
    return nil, nil
  end

  return {
    subject = subject,
    from = from_content,
    url_domains = url_content,
    text = res.text,
  }, nil -- part is not available as before since we extract from task directly
end

-- Backwards-compat alias
M.build_embedding_input = M.build_llm_input

M.get_meta_llm_content = get_meta_llm_content

return M
