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
  doc = {[[WordDocument]]},
  xls = {[[Workbook]], [[Book]]},
  ppt = {[[PowerPoint Document]], [[Current User]]},
  vsd = {[[VisioDocument]]},
}
local msoffice_trie_clsid
local msoffice_clsids = {
  doc = {[[0609020000000000c000000000000046]]},
  xls = {[[1008020000000000c000000000000046]], [[2008020000000000c000000000000046]]},
  ppt = {[[108d81649b4fcf1186ea00aa00b929e8]]},
  msg = {[[46f0060000000000c000000000000046]], [[0b0d020000000000c000000000000046]]},
  msi = {[[84100c0000000000c000000000000046]]},
}
local msoffice_clsid_indexes = {}
local msoffice_patterns_indexes = {}

local exports = {}

local function compile_msoffice_trie(log_obj)
  if not msoffice_trie then
    -- Directory names
    local strs = {}
    for ext,pats in pairs(msoffice_patterns) do
      for _,pat in ipairs(pats) do
        strs[#strs + 1] = '^' ..
            table.concat(
                fun.totable(
                    fun.map(function(c) return c .. [[\x{00}]] end,
                        fun.iter(pat))))
        msoffice_patterns_indexes[#msoffice_patterns_indexes + 1] = ext

      end
    end
    msoffice_trie = rspamd_trie.create(strs, rspamd_trie.flags.re)
    -- Clsids
    strs = {}
    for ext,pats in pairs(msoffice_clsids) do
      for _,pat in ipairs(pats) do
        local hex_table = {}
        for i=1,#pat,2 do
          local subc = pat:sub(i, i + 1)
          hex_table[#hex_table + 1] = string.format('\\x{%s}', subc)
        end
        strs[#strs + 1] = '^' .. table.concat(hex_table) .. '$'
        msoffice_clsid_indexes[#msoffice_clsid_indexes + 1] = ext

      end
    end
    msoffice_trie_clsid = rspamd_trie.create(strs, rspamd_trie.flags.re)
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

  if sec_size < 7 or sec_size > 31 then
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
    lua_util.debugm(N, log_obj, "dtype: %s, offset: %s", dtype, offset)

    if dtype == 5 then
      -- Extract clsid
      local matches = msoffice_trie_clsid:match(input:span(offset + 80, 16))
      if matches then
        for n,_ in pairs(matches) do
          if msoffice_clsid_indexes[n] then
            lua_util.debugm(N, log_obj, "found valid clsid for %s",
                msoffice_clsid_indexes[n])
            return true,msoffice_clsid_indexes[n]
          end
        end
      end
      return true,nil
    elseif dtype == 2 then
      local matches = msoffice_trie:match(input:span(offset, 64))
      if matches then
        for n,_ in pairs(matches) do
          if msoffice_patterns_indexes[n] then
            return true,msoffice_patterns_indexes[n]
          end
        end
      end
      return true,nil
    elseif dtype >= 0 and dtype < 5 then
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