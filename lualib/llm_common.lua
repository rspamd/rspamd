--[[
Common helpers for building LLM input content from a task
]] --

local lua_util = require "lua_util"
local lua_mime = require "lua_mime"
local fun = require "fun"

local M = {}

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

-- Build a single text payload suitable for LLM embeddings
function M.build_llm_input(task, opts)
  opts = opts or {}
  local subject = task:get_subject() or ''
  local url_content, from_content = get_meta_llm_content(task)

  local sel_part = lua_mime.get_displayed_text_part(task)
  if not sel_part then
    return nil, nil
  end

  local nwords = sel_part:get_words_count() or 0
  if nwords < 5 then
    return nil, sel_part
  end

  local max_tokens = tonumber(opts.max_tokens) or 1024
  local text_line
  if nwords > max_tokens then
    local words = sel_part:get_words('norm') or {}
    if #words > max_tokens then
      text_line = table.concat(words, ' ', 1, max_tokens)
    else
      text_line = table.concat(words, ' ')
    end
  else
    text_line = sel_part:get_content_oneline() or ''
  end

  local content = table.concat({
    'Subject: ' .. subject,
    from_content,
    url_content,
    text_line,
  }, '\n')

  return content, sel_part
end

-- Backwards-compat alias
M.build_embedding_input = M.build_llm_input

M.get_meta_llm_content = get_meta_llm_content

return M
