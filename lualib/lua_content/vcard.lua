--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local vcard_grammar

-- XXX: Currently it is a copy of ical grammar
local function gen_grammar()
  if not vcard_grammar then
    local wsp = l.S(" \t\v\f")
    local crlf = (l.P"\r"^-1 * l.P"\n") + l.P"\r"
    local eol = (crlf * #crlf) + (crlf - (crlf^-1 * wsp))
    local name = l.C((l.P(1) - (l.P":"))^1) / function(v) return (v:gsub("[\n\r]+%s","")) end
    local value = l.C((l.P(1) - eol)^0) / function(v) return (v:gsub("[\n\r]+%s","")) end
    vcard_grammar = name * ":" * wsp^0 * value * eol^-1
  end

  return vcard_grammar
end

local exports = {}

local function process_vcard(input, mpart, task)
  local control={n='\n', r=''}
  local rspamd_url = require "rspamd_url"
  local escaper = l.Ct((gen_grammar() / function(key, value)
    value = value:gsub("\\(.)", control)
    key = key:lower()
    local local_urls = rspamd_url.all(task:get_mempool(), value)

    if local_urls and #local_urls > 0 then
      for _,u in ipairs(local_urls) do
        lua_util.debugm(N, task, 'vcard: found URL in vcard %s',
            tostring(u))
        task:inject_url(u, mpart)
      end
    end
    lua_util.debugm(N, task, 'vcard: vcard key %s = "%s"',
        key, value)
    return {key, value}
  end)^1)

  local elts = escaper:match(input)

  if not elts then
    return nil
  end

  return {
    tag = 'vcard',
    extract_text = function() return nil end, -- NYI
    elts = elts
  }
end

--[[[
-- @function vcard.process(input)
-- Returns all values from vcard as a plain text. Names are completely ignored.
--]]
exports.process = process_vcard

return exports