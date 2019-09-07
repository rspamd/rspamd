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
-- @module lua_magic/heuristics
-- This module contains heuristics for some specific cases
--]]

local rspamd_trie = require "rspamd_trie"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local bit = require "bit"
local fun = require "fun"

local N = "lua_magic"
local msoffice_trie
local msoffice_patterns = {
  doc = [[WordDocument]],
  xls = [[Workbook]],
  ppt = [[PowerPoint Document]]
}

local exports = {}

local function compile_msoffice_trie(log_obj)
  if not msoffice_trie then
    local strs = {}
    for ext,pat in pairs(msoffice_patterns) do
      strs[#strs + 1] = '^' ..
         table.concat(
             fun.totable(
                 fun.map(function(c) return c .. [[\x{00}]] end,
                     fun.iter(pat))))
      msoffice_patterns[ext] = #strs
    end
    msoffice_trie = rspamd_trie.create(strs, rspamd_trie.flags.re)
  end
end

local function detect_ole_format(input, log_obj)
  local inplen = #input
  if inplen < 0x31 + 4 then
    lua_util.debugm(N, log_obj, "short length: %s", inplen)
    return nil
  end

  compile_msoffice_trie(log_obj)
  local bom,sec_size = rspamd_util.unpack('<I2<I2', input:span(29, 4))
  if bom == 0xFFFE then
    bom = '<'
  else
    lua_util.debugm(N, log_obj, "bom file!: %s", bom)
    bom = '>'; sec_size = bit.bswap(sec_size)
  end

  if sec_size < 7 or sec_size > 9 then
    lua_util.debugm(N, log_obj, "bad sec_size: %s", sec_size)
    return nil
  end

  sec_size = 2 ^ sec_size

  -- SecID of first sector of the directory stream
  local directory_offset = (rspamd_util.unpack(bom .. 'I4', input:span(0x31, 4)))
      * sec_size + 512 + 1
  lua_util.debugm(N, log_obj, "directory: %s", directory_offset)

  if inplen < directory_offset then
    lua_util.debugm(N, log_obj, "short length: %s", inplen)
    return nil
  end

  local function process_dir_entry(offset)
    local dtype = input:at(offset + 66)
    lua_util.debugm(N, log_obj, "dtype: %s", dtype)

    if dtype == 5 then
      -- Skip root dentry
      return true,nil
    elseif dtype == 2 then
      local matches = msoffice_trie:match(input:span(offset, 64))
      if matches then
        for n,_ in pairs(matches) do
          for ext,num in pairs(msoffice_patterns) do
            if num == n then
              return true,ext
            end
          end
        end
      end
      return true,nil
    elseif dtype < 5 then
      -- Bad type
      return true,nil
    end

    return false,nil
  end

  repeat
    local res,ext = process_dir_entry(directory_offset)

    if res and ext then
      return ext,60
    end

    if not res then
      break
    end

    directory_offset = directory_offset + 128
  until directory_offset >= inplen
end

exports.ole_format_heuristic = detect_ole_format

return exports