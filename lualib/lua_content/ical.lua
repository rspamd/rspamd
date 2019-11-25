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
local rspamd_text = require "rspamd_text"

local ical_grammar

local function gen_grammar()
  if not ical_grammar then
    local wsp = l.P" "
    local crlf = l.P"\r"^-1 * l.P"\n"
    local eol = (crlf * #crlf) + (crlf - (crlf^-1 * wsp))
    local name = l.C((l.P(1) - (l.P":"))^1) / function(v) return (v:gsub("[\n\r]+%s","")) end
    local value = l.C((l.P(1) - eol)^0) / function(v) return (v:gsub("[\n\r]+%s","")) end
    ical_grammar = name * ":" * wsp^0 * value * eol
  end

  return ical_grammar
end

local exports = {}

local function process_ical(input, _, task)
  local control={n='\n', r='\r'}
  local rspamd_url = require "rspamd_url"
  local escaper = l.Ct((gen_grammar() / function(_, value)
    value = value:gsub("\\(.)", control)
    local local_urls = rspamd_url.all(task:get_mempool(), value)

    if local_urls and #local_urls > 0 then
      for _,u in ipairs(local_urls) do
        task:inject_url(u)
      end
    end
    return value
  end)^1)

  local values = escaper:match(input)

  if not values then
    return nil
  end

  return rspamd_text.fromtable(values, "\n")
end

--[[[
-- @function lua_ical.process(input)
-- Returns all values from ical as a plain text. Names are completely ignored.
--]]
exports.process = process_ical

return exports