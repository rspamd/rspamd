--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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
    local crlf = (l.P "\r" ^ -1 * l.P "\n") + l.P "\r"
    local eol = (crlf * #crlf) + (crlf - (crlf ^ -1 * wsp))
    -- A name ends at the colon of its own line, or of the lines that
    -- continue it: a line without a colon is not the start of the name of
    -- the property after it
    local fold = crlf * wsp
    local name = l.C((fold + (l.P(1) - l.S ":\r\n")) ^ 1) / function(v)
      return (v:gsub("[\n\r]+%s", ""))
    end
    local value = l.C((l.P(1) - eol) ^ 0) / function(v)
      return (v:gsub("[\n\r]+%s", ""))
    end
    ical_grammar = name * ":" * wsp ^ 0 * value * eol ^ -1
  end

  return ical_grammar
end

local exports = {}

-- What is read of one file: real ones are a few kilobytes
local max_input_size = 1024 * 1024
local max_elts = 10000

local function extract_text_data(specific)
  local fun = require "fun"

  local tbl = fun.totable(fun.map(function(e)
    return e[2]:lower()
  end, specific.elts))
  return table.concat(tbl, '\n')
end


-- Keys that can have visible urls
local url_keys = lua_util.list_to_hash {
  'description',
  'location',
  'summary',
  'organizer',
  'organiser',
  'attendee',
  'url',
  'attach',
  'conference',
  'comment',
  'contact',
}

local function process_ical(input, mpart, task)
  local control = { n = '\n', r = '' }
  local rspamd_url = require "rspamd_url"
  local nelts = 0
  local truncated = false

  if #input > max_input_size then
    -- A property that is cut in the middle is still a property
    input = input:sub(1, max_input_size)
    truncated = true
  end

  local function process_property(key, value)
    value = value:gsub("\\(.)", control)
    key = key:lower():match('^([^;]+)')

    -- Also the properties of the applications, which hold the links to join
    -- a meeting and the description as html
    if key and (url_keys[key] or key:find('^x%-')) then
      local local_urls = rspamd_url.all(task:get_mempool(), value)

      if local_urls and #local_urls > 0 then
        for _, u in ipairs(local_urls) do
          lua_util.debugm(N, task, 'ical: found URL in ical key "%s": %s',
              key, tostring(u))
          task:inject_url(u, mpart)
        end
      end
    end
    lua_util.debugm(N, task, 'ical: ical key %s = "%s"',
        key, value)
    return { key, value }
  end

  -- Each property becomes a table that lives as long as the task does, so
  -- their number is bounded. They are matched one by one: a single match
  -- over the input would also keep a capture per property on the stack
  local property = gen_grammar() * l.Cp()
  local line_end = (1 - l.P '\n') ^ 0 * l.P '\n' * l.Cp()
  local elts = {}
  local pos = 1
  local skipped = 0

  while true do
    local key, value, next_pos = property:match(input, pos)

    if not next_pos then
      -- Not a property: go on from the next line
      local next_line = line_end:match(input, pos)

      if not next_line or skipped >= max_elts then
        break
      end

      skipped = skipped + 1
      pos = next_line
    else

      if nelts >= max_elts then
        truncated = true
        break
      end

      nelts = nelts + 1
      elts[nelts] = process_property(key, value)
      pos = next_pos
    end
  end

  if nelts == 0 then
    return nil
  end

  return {
    tag = 'ical',
    extract_text = extract_text_data,
    elts = elts,
    truncated = truncated or nil,
  }
end

--[[[
-- @function lua_ical.process(input)
-- Returns all values from ical as a plain text. Names are completely ignored.
--]]
exports.process = process_ical

return exports