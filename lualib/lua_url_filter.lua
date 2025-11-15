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

  -- Convert to string for pattern matching
  -- This is acceptable since we're called rarely (only on suspicious patterns)
  local url_str = url_text:str()

  -- Check for control characters (0x00-0x1F except tab/newline, and 0x7F)
  -- Using string.find with byte patterns
  for i = 0, 31 do
    if i ~= 9 and i ~= 10 then -- Allow tab (\t) and newline (\n)
      if url_str:find(string.char(i), 1, true) then
        return exports.REJECT -- Control character found
      end
    end
  end
  if url_str:find(string.char(127), 1, true) then -- DEL
    return exports.REJECT
  end

  -- UTF-8 validation using rspamd_util
  if not rspamd_util.is_valid_utf8(url_str) then
    return exports.REJECT -- Invalid UTF-8
  end

  -- Count @ signs for suspicious patterns
  local _, at_count = url_str:gsub("@", "")
  if at_count > 20 then
    return exports.REJECT -- Way too many @ signs
  end

  -- Check user field length (if @ present)
  if at_count > 0 then
    -- Find first @
    local first_at = url_str:find("@", 1, true)
    if first_at then
      -- Check what comes before it (could be schema://user@host)
      -- Look for :// to find start of user field
      local schema_end = url_str:find("://", 1, true)
      local user_start = schema_end and (schema_end + 3) or 1
      local user_len = first_at - user_start

      if user_len > 512 then
        return exports.REJECT -- Extremely long user field
      elseif user_len > 128 then
        return exports.SUSPICIOUS -- Long user field, mark for inspection
      end
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

  -- Get URL as text
  local url_text = url:get_text()
  if not url_text then
    return exports.ACCEPT
  end

  -- Get flags from URL object
  local flags = 0
  local url_table = url:to_table()
  if url_table and url_table.flags then
    flags = url_table.flags
  end

  return exports.filter_url_string(url_text, flags)
end

return exports
