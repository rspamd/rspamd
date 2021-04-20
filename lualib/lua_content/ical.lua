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
local lua_util = require "lua_util"
local N = "lua_content"

local ical_grammar

local function gen_grammar()
  if not ical_grammar then
    local wsp = l.S(" \t\v\f")
    local crlf = (l.P"\r"^-1 * l.P"\n") + l.P"\r"
    local eol = (crlf * #crlf) + (crlf - (crlf^-1 * wsp))
    local name = l.C((l.P(1) - (l.P":"))^1) / function(v) return (v:gsub("[\n\r]+%s","")) end
    local value = l.C((l.P(1) - eol)^0) / function(v) return (v:gsub("[\n\r]+%s","")) end
    ical_grammar = name * ":" * wsp^0 * value * eol^-1
  end

  return ical_grammar
end

local exports = {}

local function extract_text_data(specific)
  local fun = require "fun"

  local tbl = fun.totable(fun.map(function(e) return e[2]:lower() end, specific.elts))
  return table.concat(tbl, '\n')
end


-- Keys that can have visible urls
local url_keys = lua_util.list_to_hash{
  'description',
  'location',
  'summary',
  'organizer',
  'organiser',
  'attendee',
  'url'
}

local function process_ical(input, mpart, task)
  local control={n='\n', r=''}
  local rspamd_url = require "rspamd_url"
  local escaper = l.Ct((gen_grammar() / function(key, value)
    value = value:gsub("\\(.)", control)
    key = key:lower():match('^([^;]+)')

    if key and url_keys[key] then
      local local_urls = rspamd_url.all(task:get_mempool(), value)

      if local_urls and #local_urls > 0 then
        for _,u in ipairs(local_urls) do
          lua_util.debugm(N, task, 'ical: found URL in ical key "%s": %s',
                  key, tostring(u))
          task:inject_url(u, mpart)
        end
      end
    end
    lua_util.debugm(N, task, 'ical: ical key %s = "%s"',
        key, value)
    return {key, value}
  end)^1)

  local elts = escaper:match(input)

  if not elts then
    return nil
  end

  return {
    tag = 'ical',
    extract_text = extract_text_data,
    elts = elts
  }
end

--[[[
-- @function lua_ical.process(input)
-- Returns all values from ical as a plain text. Names are completely ignored.
--]]
exports.process = process_ical

return exports