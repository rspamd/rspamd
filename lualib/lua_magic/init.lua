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

--[[[
-- @module lua_magic
-- This module contains file types detection logic
--]]

local patterns = require "lua_magic/patterns"
local types = require "lua_magic/types"
local fun = require "fun"
local lua_util = require "lua_util"

local rspamd_text = require "rspamd_text"
local rspamd_trie = require "rspamd_trie"

local N = "lua_magic"
local exports = {}
-- trie object
local compiled_patterns
-- {<str>, <match_object>, <pattern_object>} indexed by pattern number
local processed_patterns = {}

local function process_patterns()
  if not compiled_patterns then
    for _,pattern in ipairs(patterns) do
      for _,match in ipairs(pattern.matches) do
        if match.string then
          processed_patterns[#processed_patterns + 1] = {
            match.string, match, pattern
          }
        end
      end
    end

    compiled_patterns = rspamd_trie.create(fun.totable(
        fun.map(function(t) return t[1] end, processed_patterns)),
        rspamd_trie.flags.re
    )

    lua_util.debugm(N, rspamd_config, 'compiled %s patterns',
        #processed_patterns)
  end
end

local function match_chunk(input, offset, log_obj, res)
  local matches = compiled_patterns:match(input)

  if not log_obj then log_obj = rspamd_config end

  local function add_result(match, pattern)
    if not res[pattern.ext] then
      res[pattern.ext] = 0
    end
    if match.weight then
      res[pattern.ext] = res[pattern.ext] + match.weight
    else
      res[pattern.ext] = res[pattern.ext] + 1
    end

    lua_util.debugm(N, log_obj,'add pattern for %s, weight %s, total weight %s',
        pattern.ext, match.weight, res[pattern.ext])
  end

  for npat,matched_positions in pairs(matches) do
    local pat_data = processed_patterns[npat]
    local pattern = pat_data[3]
    local match = pat_data[2]

    local function match_position(pos, expected)
      local cmp = function(a, b) return a == b end
      if type(expected) == 'table' then
        -- Something like {'>', 0}
        if expected[1] == '>' then
          cmp = function(a, b) return a > b end
        elseif expected[1] == '>=' then
          cmp = function(a, b) return a >= b end
        elseif expected[1] == '<' then
          cmp = function(a, b) return a < b end
        elseif expected[1] == '<=' then
          cmp = function(a, b) return a <= b end
        elseif expected[1] == '!=' then
          cmp = function(a, b) return a ~= b end
        end
        expected = expected[2]
      end

      return cmp(pos, expected)
    end
    -- Single position
    if match.position then
      local position = match.position

      for _,pos in ipairs(matched_positions) do
        if match_position(pos + offset, position) then
          add_result(match, pattern)
        end
      end
    end
    -- Match all positions
    if match.positions then
      for _,position in ipairs(match.positions) do
        for _,pos in ipairs(matched_positions) do
          if match_position(pos, position) then
            add_result(match, pattern)
          end
        end
      end
    end
  end
end
exports.detect = function(input, log_obj)
  process_patterns()
  local res = {}

  if type(input) == 'string' then
    -- Convert to rspamd_text
    input = rspamd_text.fromstring(input)
  end

  if type(input) == 'userdata' and #input > exports.chunk_size * 3 then
    -- Split by chunks
    local chunk1, chunk2, chunk3 =
    input:span(1, exports.chunk_size),
    input:span(exports.chunk_size, exports.chunk_size),
    input:span(#input - exports.chunk_size, exports.chunk_size)
    local offset1, offset2, offset3 = 0, exports.chunk_size, #input - exports.chunk_size

    match_chunk(chunk1, offset1, log_obj, res)
    match_chunk(chunk2, offset2, log_obj, res)
    match_chunk(chunk3, offset3, log_obj, res)
  else
    match_chunk(input, 0, log_obj, res)
  end

  local extensions = lua_util.keys(res)

  if #extensions > 0 then
    table.sort(extensions, function(ex1, ex2)
      return res[ex1] > res[ex2]
    end)

    return extensions[1],types[extensions[1]]
  end

  -- Nothing found
  return nil
end

-- This parameter specifies how many bytes are checked in the input
-- Rspamd checks 2 chunks at start and 1 chunk at the end
exports.chunk_size = 16384

return exports