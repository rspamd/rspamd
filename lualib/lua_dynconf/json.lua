--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

--[[[
-- @module lua_dynconf.json
-- Compact JSON encoder shared by the dynconf backends.
--
-- The UCL emitter prints floats with 6 digits only, and the override tables must round-trip exactly.
--]]

local rspamd_util = require "rspamd_util"

local exports = {}

local JSON_ESCAPES = {
  ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t',
  ['\b'] = '\\b', ['\f'] = '\\f',
}

local function json_escape(c)
  return JSON_ESCAPES[c] or string.format('\\u%04x', c:byte())
end

local function encode_value(v, depth)
  local tv = type(v)
  if tv == 'string' then
    if not rspamd_util.is_valid_utf8(v) then
      error('string is not valid UTF-8')
    end
    return '"' .. (v:gsub('[%c"\\]', json_escape)) .. '"'
  elseif tv == 'number' then
    if v ~= v or v == math.huge or v == -math.huge then
      error('number is not finite')
    end
    if v == math.floor(v) and math.abs(v) < 1e15 then
      return string.format('%.0f', v)
    end
    -- ucl prints floats with 6 digits only: the shortest exact form is encoded here
    local str = string.format('%.14g', v)
    if tonumber(str) ~= v then
      str = string.format('%.17g', v)
    end
    return str
  elseif tv == 'boolean' then
    return v and 'true' or 'false'
  elseif tv ~= 'table' then
    error(string.format('values of type %s cannot be encoded', tv))
  end

  if depth > 64 then
    error('value is nested too deeply')
  end

  local n, count = #v, 0
  for _ in pairs(v) do
    count = count + 1
  end
  local parts = {}
  if n > 0 and n == count then
    for i = 1, n do
      parts[i] = encode_value(v[i], depth + 1)
    end
    return '[' .. table.concat(parts, ',') .. ']'
  end

  local keys = {}
  for k in pairs(v) do
    keys[#keys + 1] = tostring(k)
  end
  table.sort(keys)
  for _, k in ipairs(keys) do
    local val = v[k]
    if val == nil then
      val = v[tonumber(k)]
    end
    parts[#parts + 1] = encode_value(k, depth + 1) .. ':' .. encode_value(val, depth + 1)
  end
  return '{' .. table.concat(parts, ',') .. '}'
end

--[[[
-- @function lua_dynconf.json.encode(value)
-- Compact JSON encoder that keeps the full precision of numbers (the UCL emitter does not)
-- @return {string} JSON or `nil, error`
--]]
function exports.encode(value)
  local ok, res = pcall(encode_value, value, 1)
  if not ok then
    return nil, tostring(res)
  end
  return res
end

return exports
