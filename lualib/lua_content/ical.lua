--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local l = require 'lpeg'

local wsp = l.P" "
local crlf = l.P"\r"^-1 * l.P"\n"
local eol = (crlf * #crlf) + (crlf - (crlf^-1 * wsp))
local name = l.C((l.P(1) - (l.P":"))^1) / function(v) return (v:gsub("[\n\r]+%s","")) end
local value = l.C((l.P(1) - eol)^0) / function(v) return (v:gsub("[\n\r]+%s","")) end
local elt = name * ":" * wsp^0 * value * eol

local exports = {}

local function ical_txt_values(input)
  local control={n='\n', r='\r'}
  local escaper = l.Ct((elt / function(_,b) return (b:gsub("\\(.)", control)) end)^1)

  local values = escaper:match(input)

  if not values then
    return nil
  end

  return table.concat(values, "\n")
end

--[[[
-- @function lua_ical.ical_txt_values(input)
-- Returns all values from ical as a plain text. Names are completely ignored.
--]]
exports.ical_txt_values = ical_txt_values

return exports