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
-- @module lua_content/pdf
-- This module contains some heuristics for PDF files
--]]

local rspamd_trie = require "rspamd_trie"
local bit = require "bit"
local pdf_trie
local N = "lua_content"
local lua_util = require "lua_util"
local pdf_patterns = {
  trailer = {
    patterns = {
      [[\ntrailer\r?\n]]
    }
  },
  javascript = {
    patterns = {
      [[\s|>/JS]],
      [[\s|>/JavaScript]],
    }
  },
  suspicious = {
    patterns = {
      [[netsh\s]],
      [[echo\s]],
    }
  }
}

-- index[n] ->
--  t[1] - pattern,
--  t[2] - key in patterns table,
--  t[3] - value in patterns table
--  t[4] - local pattern index
local pdf_indexes = {}
local exports = {}

-- Used to process patterns found in PDF
-- positions for functional processors should be a iter/table from trie matcher in form
---- [{n1, pat_idx1}, ... {nn, pat_idxn}] where
---- pat_idxn is pattern index and n1 ... nn are match positions
local processors = {}

local function compile_tries()
  local default_compile_flags = bit.bor(rspamd_trie.flags.re,
      rspamd_trie.flags.dot_all,
      rspamd_trie.flags.single_match,
      rspamd_trie.flags.no_start)
  local function compile_pats(patterns, indexes, compile_flags)
    local strs = {}
    for what,data in pairs(patterns) do
      for i,pat in ipairs(data.patterns) do
        strs[#strs + 1] = pat
        indexes[#indexes + 1] = {what, data, pat, i}
      end
    end

    return rspamd_trie.create(strs, compile_flags or default_compile_flags)
  end

  if not pdf_trie then
    pdf_trie = compile_pats(pdf_patterns, pdf_indexes)
  end
end

-- Call immediately on require
compile_tries()

local function extract_text_data(specific)
  return nil -- NYI
end

local function process_pdf(input, _, task)
  local matches = pdf_trie:match(input)

  if matches then
    local pdf_output = {
      tag = 'pdf',
      extract_text = extract_text_data,
    }
    local grouped_processors = {}
    for npat,matched_positions in pairs(matches) do
      local index = pdf_indexes[npat]

      local proc_key,loc_npat = index[1], index[4]

      if not grouped_processors[proc_key] then
        grouped_processors[proc_key] = {
          processor_func = processors[proc_key],
          offsets = {},
        }
      end
      local proc = grouped_processors[proc_key]
      -- Fill offsets
      for _,pos in ipairs(matched_positions) do
        proc.offsets[#proc.offsets + 1] = {pos, loc_npat}
      end
    end

    for name,processor in pairs(grouped_processors) do
      -- Sort by offset
      lua_util.debugm(N, task, "pdf: process group %s with %s matches",
          name, #processor.offsets)
      table.sort(processor.offsets, function(e1, e2) return e1[1] < e2[1] end)
      processor.processor_func(input, task, processor.offsets, pdf_output)
    end

    return pdf_output
  end
end

-- Processes the PDF trailer
processors.trailer = function(input, task, positions, output)
  local last_pos = positions[#positions]

  local last_span = input:span(last_pos[1])
  for line in last_span:lines(true) do
    if line:find('/Encrypt ') then
      lua_util.debugm(N, task, "pdf: found encrypted line in trailer: %s",
          line)
      output.encrypted = true
    end
  end
end

processors.javascript = function(_, task, _, output)
  lua_util.debugm(N, task, "pdf: found javascript tag")
  output.javascript = true
end

processors.suspicious = function(_, task, _, output)
  lua_util.debugm(N, task, "pdf: found a suspicious pattern")
  output.suspicious = true
end

exports.process = process_pdf

return exports