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

---@module lua_url_filter
-- Fast URL validation during parsing - called from C
-- URLs passed as rspamd_text for efficient processing

local exports = {}
local rspamd_util = require "rspamd_util"

-- Filter result constants
exports.ACCEPT = 0
exports.SUSPICIOUS = 1
exports.REJECT = 2

-- Custom filters (user can add their own)
local custom_filters = {}

---
-- Register a custom URL filter
-- @param filter_func function(url_text, flags) -> result
function exports.register_filter(filter_func)
  table.insert(custom_filters, filter_func)
end

---
-- Clear all custom filters (mainly for testing)
function exports.clear_filters()
  custom_filters = {}
end

---
-- Main entry point called from C during URL parsing
-- @param url_text rspamd_text - URL string as text object
-- @param flags number - URL parsing flags
-- @return number - ACCEPT/SUSPICIOUS/REJECT
function exports.filter_url_string(url_text, flags)
  -- Sanity check: URL length
  local url_len = url_text:len()
  if url_len > 2048 then
    return exports.REJECT -- Overly long URL
  end

  -- Build control character set: 0x00-0x08, 0x0B-0x1F, 0x7F
  -- (excluding \t=0x09 and \n=0x0A)
  local control_chars = "\000\001\002\003\004\005\006\007\008" .. -- 0x00-0x08
      "\011\012\013\014\015\016\017\018\019\020" .. -- 0x0B-0x14
      "\021\022\023\024\025\026\027\028\029\030\031" .. -- 0x15-0x1F
      "\127" -- 0x7F (DEL)

  -- Check for control characters using memcspn
  local span = url_text:memcspn(control_chars)
  if span < url_len then
    return exports.REJECT -- Control character found
  end

  -- UTF-8 validation (rspamd_util.is_valid_utf8 accepts both text and string)
  if not rspamd_util.is_valid_utf8(url_text) then
    return exports.REJECT -- Invalid UTF-8
  end

  -- Count @ signs and check user field using rspamd_text methods only
  local at_count = 0
  local first_at_pos = nil
  local search_from = 1

  -- Count @ signs using memchr
  while search_from <= url_len do
    local substr = url_text:sub(search_from)
    local found = substr:memchr(string.byte('@'), false)

    if not found or found == -1 then
      break
    end

    at_count = at_count + 1
    -- Adjust found position to be relative to start of url_text
    local absolute_pos = search_from + found - 1
    if at_count == 1 then
      first_at_pos = absolute_pos
    end
    search_from = absolute_pos + 1 -- Move past the @ we just found

    if at_count > 20 then
      return exports.REJECT -- Way too many @ signs
    end
  end

  -- Check user field length (if @ present)
  if first_at_pos then
    -- Find :// to determine start of user field
    local schema_pos = url_text:find("://")
    local user_start = schema_pos and (schema_pos + 3) or 1
    local user_len = first_at_pos - user_start

    if user_len > 512 then
      return exports.REJECT -- Extremely long user field
    elseif user_len > 64 then
      return exports.SUSPICIOUS -- Long user field, mark for inspection
    end

    -- Multiple @ signs is suspicious
    if at_count > 1 then
      return exports.SUSPICIOUS
    end
  end

  -- Run custom filters
  for _, filter in ipairs(custom_filters) do
    local result = filter(url_text, flags)
    if result == exports.REJECT then
      return exports.REJECT -- First filter to reject wins
    end
    -- Note: SUSPICIOUS results don't immediately return; we continue checking
    -- other filters as one might REJECT (upgrade), but we won't downgrade to ACCEPT
  end

  return exports.ACCEPT
end

---
-- Filter URL object (called from Lua plugin context)
-- @param url userdata - URL object
-- @return number - ACCEPT/SUSPICIOUS/REJECT
function exports.filter_url(url)
  if not url then
    return exports.ACCEPT
  end

  -- Get URL as rspamd_text (pass true to get_text)
  local url_text = url:get_text(true)
  if not url_text then
    return exports.ACCEPT
  end

  -- Get flags directly from URL object (no table conversion)
  local flags = url:get_flags_num() or 0

  return exports.filter_url_string(url_text, flags)
end

return exports
