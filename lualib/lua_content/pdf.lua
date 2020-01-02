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
local rspamd_regexp = require "rspamd_regexp"
local pdf_patterns = {
  trailer = {
    patterns = {
      [[\ntrailer\r?\n]]
    }
  },
  javascript = {
    patterns = {
      [[\/JS(?:[\s/><])]],
      [[\/JavaScript(?:[\s/><])]],
    }
  },
  openaction = {
    patterns = {
      [[\/OpenAction(?:[\s/><])]],
      [[\/AA(?:[\s/><])]],
    }
  },
  suspicious = {
    patterns = {
      [[netsh\s]],
      [[echo\s]],
      [[\/[A-Za-z]*#\d\d(?:[#A-Za-z<>/\s])]], -- Hex encode obfuscation
    }
  },
  start_object = {
    patterns = {
      [[\n\s*\d+ \d+ obj\r?\n]]
    }
  },
  end_object = {
    patterns = {
      [=[endobj[\r\n]]=]
    }
  },
  start_stream = {
    patterns = {
      [[>\s*stream\r?\n]],
    }
  },
  end_stream = {
    patterns = {
      [=[endstream[\r\n]]=]
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

-- Used to match objects
local object_re = rspamd_regexp.create_cached([=[/(\d+)\s+(\d+)\s+obj\s*/]=])

local function compile_tries()
  local default_compile_flags = bit.bor(rspamd_trie.flags.re,
      rspamd_trie.flags.dot_all,
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

local function postprocess_pdf_objects(task, input, pdf)
  local start_pos, end_pos = 1, 1

  local objects = {}
  local obj_count = 0

  while start_pos <= #pdf.start_objects and end_pos <= #pdf.end_objects do
    local first = pdf.start_objects[start_pos]
    local last = pdf.end_objects[end_pos]

    -- 7 is length of `endobj\n`
    if first + 7 < last then
      local len = last - first - 7

      -- Also get the starting span and try to match it versus obj re to get numbers
      local obj_line_potential = first - 32
      if obj_line_potential < 1 then obj_line_potential = 1 end

      if end_pos > 1 and pdf.end_objects[end_pos - 1] >= obj_line_potential then
        obj_line_potential = pdf.end_objects[end_pos - 1] + 1
      end

      local obj_line_span = input:span(obj_line_potential, first - obj_line_potential + 1)
      local matches = object_re:search(obj_line_span, true, true)

      if matches and matches[1] then
        objects[obj_count + 1] = {
          start = first,
          len = len,
          data = input:span(first, len),
          major = matches[1][2],
          minor = matches[1][3],
        }

      end

      obj_count = obj_count + 1
      start_pos = start_pos + 1
      end_pos = end_pos + 1
    elseif start_pos > end_pos then
      end_pos = end_pos + 1
    end
  end

  -- Now we have objects and we need to attach streams that are in bounds
  if pdf.start_streams and pdf.end_streams then
    start_pos, end_pos = 1, 1

    for _,obj in ipairs(objects) do
      while start_pos <= #pdf.start_streams and end_pos <= #pdf.end_streams do
        local first = pdf.start_streams[start_pos]
        local last = pdf.end_streams[end_pos]
        last = last - 10 -- Exclude endstream\n pattern
        lua_util.debugm(N, task, "start: %s, end: %s; obj: %s-%s",
            first, last, obj.start, obj.start + obj.len)
        if first > obj.start and last < obj.start + obj.len and last > first then
          -- In case if we have fake endstream :(
          while pdf.end_streams[end_pos + 1] and pdf.end_streams[end_pos + 1] < obj.start + obj.len do
            end_pos = end_pos + 1
            last = pdf.end_streams[end_pos]
          end
          local len = last - first
          obj.stream = {
            start = first,
            len = len,
            data = input:span(first, len)
          }
          start_pos = start_pos + 1
          end_pos = end_pos + 1
          break
        elseif first < obj.start then
          start_pos = start_pos + 1
        elseif last > obj.start + obj.len then
          -- Not this object
          break
        else
          start_pos = start_pos + 1
          end_pos = end_pos + 1
        end
      end
      if obj.stream then
        lua_util.debugm(N, task, 'found object %s:%s %s start %s len, %s stream start, %s stream length',
            obj.major, obj.minor, obj.start, obj.len, obj.stream.start, obj.stream.len)
      else
        lua_util.debugm(N, task, 'found object %s:%s %s start %s len, no stream',
            obj.major, obj.minor, obj.start, obj.len)
      end
    end
  end

  pdf.objects = objects
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

    if pdf_output.start_objects and pdf_output.end_objects then
      -- Postprocess objects
      postprocess_pdf_objects(task, input, pdf_output)
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

processors.openaction = function(_, task, _, output)
  lua_util.debugm(N, task, "pdf: found openaction tag")
  output.openaction = true
end

processors.suspicious = function(_, task, _, output)
  lua_util.debugm(N, task, "pdf: found a suspicious pattern")
  output.suspicious = true
end

local function generic_table_inserter(positions, output, output_key)
  if not output[output_key] then
    output[output_key] = {}
  end
  local shift = #output[output_key]
  for i,pos in ipairs(positions) do
    output[output_key][i + shift] = pos[1]
  end
end

processors.start_object = function(_, task, positions, output)
  generic_table_inserter(positions, output, 'start_objects')
end

processors.end_object = function(_, task, positions, output)
  generic_table_inserter(positions, output, 'end_objects')
end

processors.start_stream = function(_, task, positions, output)
  generic_table_inserter(positions, output, 'start_streams')
end

processors.end_stream = function(_, task, positions, output)
  generic_table_inserter(positions, output, 'end_streams')
end

exports.process = process_pdf

return exports