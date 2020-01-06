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
local rspamd_util = require "rspamd_util"
local rspamd_text = require "rspamd_text"
local bit = require "bit"
local N = "lua_content"
local lua_util = require "lua_util"
local rspamd_regexp = require "rspamd_regexp"
local lpeg = require "lpeg"
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
      [=[[\r\n]\s*\d+ \d+ obj[\r\n]]=]
    }
  },
  end_object = {
    patterns = {
      [=[endobj[\r\n]]=]
    }
  },
  start_stream = {
    patterns = {
      [=[>\s*stream[\r\n]]=],
    }
  },
  end_stream = {
    patterns = {
      [=[endstream[\r\n]]=]
    }
  }
}

local pdf_text_patterns = {
  start = {
    patterns = {
      [[\sBT\s]]
    }
  },
  stop = {
    patterns = {
      [[\sET\b]]
    }
  }
}

-- index[n] ->
--  t[1] - pattern,
--  t[2] - key in patterns table,
--  t[3] - value in patterns table
--  t[4] - local pattern index
local pdf_indexes = {}
local pdf_text_indexes = {}

local pdf_trie
local pdf_text_trie

local exports = {}

-- Used to process patterns found in PDF
-- positions for functional processors should be a iter/table from trie matcher in form
---- [{n1, pat_idx1}, ... {nn, pat_idxn}] where
---- pat_idxn is pattern index and n1 ... nn are match positions
local processors = {}
-- PDF objects outer grammar in LPEG style (performing table captures)
local pdf_outer_grammar
local pdf_text_grammar

local max_extraction_size = 512 * 1024 -- TODO: make it configurable

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
  if not pdf_text_trie then
    pdf_text_trie = compile_pats(pdf_text_patterns, pdf_text_indexes)
  end
end

-- Returns a table with generic grammar elements for PDF
local function generic_grammar_elts()
  local P = lpeg.P
  local R = lpeg.R
  local S = lpeg.S
  local V = lpeg.V
  local C = lpeg.C
  local D = R'09' -- Digits

  local grammar_elts = {}

  -- Helper functions
  local function pdf_hexstring_unescape(s)
    local function ue(cc)
      return string.char(tonumber(cc, 16))
    end
    if #s % 2 == 0 then
      -- Sane hex string
      return s:gsub('..', ue)
    end

    -- WTF hex string
    -- Append '0' to it and unescape...
    return s:sub(1, #s - 1):gsub('..' , ue) .. (s:sub(#s) .. '0'):gsub('..' , ue)
  end

  local function pdf_string_unescape(s)
    -- TODO: add unescaping logic
    return s
  end

  local function pdf_id_unescape(s)
    return (s:gsub('#%d%d', function (cc)
      return string.char(tonumber(cc:sub(2), 16))
    end))
  end

  local delim = S'()<>[]{}/%'
  grammar_elts.ws = S'\0 \r\n\t\f'
  local hex = R'af' + R'AF' + D
  -- Comments.
  local eol = P'\r\n' + '\n'
  local line = (1 - S'\r\n\f')^0 * eol^-1
  grammar_elts.comment = P'%' * line

  -- Numbers.
  local sign = S'+-'^-1
  local decimal = D^1
  local float = D^1 * P'.' * D^0 + P'.' * D^1
  grammar_elts.number = C(sign * (float + decimal)) / tonumber

  -- String
  grammar_elts.str = P{ "(" * C(((1 - S"()") + V(1))^0) / pdf_string_unescape * ")" }
  grammar_elts.hexstr = P{"<" * C(hex^0) / pdf_hexstring_unescape * ">"}

  -- Identifier
  grammar_elts.id = P{'/' * C((1-(delim + grammar_elts.ws))^1) / pdf_id_unescape}

  -- Booleans (who care about them?)
  grammar_elts.boolean = C(P("true") + P("false"))

  -- Stupid references
  grammar_elts.ref = lpeg.Ct{lpeg.Cc("%REF%") * C(D^1) * " " * C(D^1) * " " * "R"}

  return grammar_elts
end


-- Generates a grammar to parse outer elements (external objects in PDF notation)
local function gen_outer_grammar()
  local V = lpeg.V
  local gen = generic_grammar_elts()

  return lpeg.P{
    "EXPR";
    EXPR = gen.ws^0 * V("ELT")^0 * gen.ws^0,
    ELT = V("ARRAY") + V("DICT") + V("ATOM"),
    ATOM = gen.ws^0 * (gen.comment + gen.boolean + gen.ref +
        gen.number + V("STRING") + gen.id) * gen.ws^0,
    DICT = "<<" * gen.ws^0  * lpeg.Cf(lpeg.Ct("") * V("KV_PAIR")^0, rawset) * gen.ws^0 * ">>",
    KV_PAIR = lpeg.Cg(gen.id * gen.ws^0 * V("ELT") * gen.ws^0),
    ARRAY = "[" * gen.ws^0 * lpeg.Ct(V("ELT")^0) * gen.ws^0 * "]",
    STRING = lpeg.P{gen.str + gen.hexstr},
  }
end

-- Graphic state in PDF
local function gen_graphics_unary()
  local P = lpeg.P
  local S = lpeg.S

  return P("q") + P("Q") + P("h") +
    P("W") + P("W*") + S("SsFfBb") * P("*")^0 + P("n")

end
local function gen_graphics_binary()
  local P = lpeg.P

  return P("g") + P("G") + P("W") + P("J") +
      P("j") + P("M") + P("ri") + P("gs") + P("i") +
      P("CS") + P("cs")
end
local function gen_graphics_ternary()
  local P = lpeg.P

  return P("RG") + P("rg") + P("d")
end
local function gen_graphics_nary()
  local P = lpeg.P

  return P("SC") + P("sc") + P("SCN") + P("scn") + P("k") + P("K")
end

-- Generates a grammar to parse text blocks (between BT and ET)
local function gen_text_grammar()
  local V = lpeg.V
  local P = lpeg.P
  local C = lpeg.C
  local gen = generic_grammar_elts()

  local empty = ""
  local unary_ops = C("T*") / "\n" +
      C(gen_graphics_unary()) / empty
  local binary_ops = P("Tc") + P("Tw") + P("Tz") + P("TL") + P("Tr") + P("Ts") +
      gen_graphics_binary()
  local ternary_ops = P("TD") + P("Td") + P("Tf") + gen_graphics_ternary()
  local nary_op = P("Tm") + gen_graphics_nary()
  local text_binary_op = P("Tj") + P("TJ") + P("'")
  local text_quote_op = P('"')

  return lpeg.P{
    "EXPR";
    EXPR = gen.ws^0 * lpeg.Ct(V("COMMAND")^0),
    COMMAND = (V("UNARY") + V("BINARY") + V("TERNARY") + V("NARY") + V("TEXT") + gen.comment) * gen.ws^0,
    UNARY = unary_ops,
    BINARY = V("ARG") / empty * gen.ws^1 * binary_ops,
    TERNARY = V("ARG") / empty * gen.ws^1 * V("ARG") / empty * gen.ws^1 * ternary_ops,
    NARY = (gen.number / 0 * gen.ws^1)^1 * (gen.id / empty * gen.ws^0)^-1 * nary_op,
    ARG = V("ARRAY") + V("DICT") + V("ATOM"),
    ATOM = (gen.comment + gen.boolean + gen.ref +
        gen.number + V("STRING") + gen.id),
    DICT = "<<" * gen.ws^0  * lpeg.Cf(lpeg.Ct("") * V("KV_PAIR")^0, rawset) * gen.ws^0 * ">>",
    KV_PAIR = lpeg.Cg(gen.id * gen.ws^0 * V("ARG") * gen.ws^0),
    ARRAY = "[" * gen.ws^0 * lpeg.Ct(V("ARG")^0) * gen.ws^0 * "]",
    STRING = lpeg.P{gen.str + gen.hexstr},
    TEXT = (V("TEXT_ARG") * gen.ws^1 * text_binary_op) +
        (V("ARG") / 0 * gen.ws^1 * V("ARG") / 0 * gen.ws^1 * V("TEXT_ARG") * gen.ws^1 * text_quote_op),
    TEXT_ARG = lpeg.Ct(V("STRING")) + V("TEXT_ARRAY"),
    TEXT_ARRAY = "[" *
        lpeg.Ct(((gen.ws^0 * (gen.ws^0 * (gen.number / 0)^0 * gen.ws^0 * (gen.str + gen.hexstr)))^1)) * gen.ws^0 * "]",
  }
end

-- Call immediately on require
compile_tries()
pdf_outer_grammar = gen_outer_grammar()
pdf_text_grammar = gen_text_grammar()

local function extract_text_data(specific)
  return nil -- NYI
end

-- Generates index for major/minor pair
local function obj_ref(major, minor)
  return major * 10.0 + 1.0 / (minor + 1.0)
end

-- Return indirect object reference (if needed)
local function maybe_dereference_object(elt, pdf)
  if type(elt) == 'table' and elt[1] == '%REF%' then
    local ref = obj_ref(elt[2], elt[3])

    if pdf.ref[ref] then
      -- No recursion!
      return pdf.ref[ref].dict
    end
  end

  return elt
end

-- Enforced dereference
local function dereference_object(elt, pdf)
  if type(elt) == 'table' and elt[1] == '%REF%' then
    local ref = obj_ref(elt[2], elt[3])

    if pdf.ref[ref] then
      -- Not a dict but the object!
      return pdf.ref[ref]
    end
  end

  return nil
end

local function process_dict(task, pdf, obj, dict)
  if type(dict) == 'table' and dict.Type then
    if dict.Type == 'FontDescriptor' then
      obj.type = 'font'
      obj.ignore = true

      lua_util.debugm(N, task, "obj %s:%s is a font descriptor",
         obj.major, obj.minor)

      local stream_ref
      if dict.FontFile then
        stream_ref = dereference_object(dict.FontFile, pdf)
      end
      if dict.FontFile2 then
        stream_ref = dereference_object(dict.FontFile2, pdf)
      end
      if dict.FontFile3 then
        stream_ref = dereference_object(dict.FontFile3, pdf)
      end

      if stream_ref then
        if not stream_ref.dict then
          stream_ref.dict = {}
        end
        stream_ref.dict.type = 'font_data'
        stream_ref.dict.ignore = true

        lua_util.debugm(N, task, "obj %s:%s is a font data stream",
            stream_ref.major, stream_ref.minor)
      end
    end
  end
end

-- Processes PDF objects: extracts streams, object numbers, process outer grammar,
-- augment object types
local function postprocess_pdf_objects(task, input, pdf)
  local start_pos, end_pos = 1, 1

  local objects = {}
  local obj_count = 0
  pdf.ref = {} -- references table

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
          major = tonumber(matches[1][2]),
          minor = tonumber(matches[1][3]),
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
          -- Strip the first \n
          while first < last do
            local chr = input:at(first)
            if chr ~= 13 and chr ~= 10 then break end
            first = first + 1
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
      if obj.major and obj.minor then
        -- Parse grammar
        local obj_dict_span
        if obj.stream then
          obj_dict_span = obj.data:span(1, obj.stream.start - obj.start)
        else
          obj_dict_span = obj.data
        end

        if obj_dict_span:len() < 1024 * 128 then
          local ret,obj_or_err = pcall(pdf_outer_grammar.match, pdf_outer_grammar, obj_dict_span)

          if ret then
            obj.dict = obj_or_err
            lua_util.debugm(N, task, 'object %s:%s is parsed to: %s',
                obj.major, obj.minor, obj_or_err)
          else
            lua_util.debugm(N, task, 'object %s:%s cannot be parsed: %s',
                obj.major, obj.minor, obj_or_err)
          end
        else
          lua_util.debugm(N, task, 'object %s:%s cannot be parsed: too large %s',
              obj.major, obj.minor, obj_dict_span:len())
        end
        pdf.ref[obj_ref(obj.major, obj.minor)] = obj
      end
    end

  end

  for _,obj in ipairs(objects) do
    if obj.dict then
      -- Types processing
      process_dict(task, pdf, obj, obj.dict)
    end
  end

  pdf.objects = objects
end

local function extract_pdf_objects(task, pdf)
  local function maybe_extract_object(obj)
    local dict = obj.dict
    if dict.Filter and dict.Length then
      local len = math.min(obj.stream.len,
          tonumber(maybe_dereference_object(dict.Length, pdf)) or 0)
      local real_stream = obj.stream.data:span(1, len)

      if dict.Filter == 'FlateDecode' and real_stream:len() > 0 then
        local uncompressed = rspamd_util.inflate(real_stream, max_extraction_size)

        if uncompressed then
          lua_util.debugm(N, task, 'extracted object %s:%s: %s (%s -> %s)',
              obj.major, obj.minor, uncompressed, len, uncompressed:len())
          obj.uncompressed = uncompressed
        else
          lua_util.debugm(N, task, 'cannot extract object %s:%s; len = %s; filter = %s',
              obj.major, obj.minor, len, dict.Filter)
        end
      else

        lua_util.debugm(N, task, 'cannot extract object %s:%s; len = %s; filter = %s',
            obj.major, obj.minor, len, dict.Filter)
      end
    end
  end

  for _,obj in ipairs(pdf.objects or {}) do
    if obj.stream and obj.dict and type(obj.dict) == 'table' and not obj.dict.ignore then
      maybe_extract_object(obj)
    end
  end
end

local function offsets_to_blocks(starts, ends, out)
  local start_pos, end_pos = 1, 1

  while start_pos <= #starts and end_pos <= #ends do
    local first = starts[start_pos]
    local last = ends[end_pos]

    if first < last then
      local len = last - first
      out[#out + 1] = {
        start = first,
        len = len,
      }
      start_pos = start_pos + 1
      end_pos = end_pos + 1
    elseif start_pos > end_pos then
      end_pos = end_pos + 1
    else
      -- Not ordered properly!
      break
    end
  end
end

local function search_text(task, pdf)
  for _,obj in ipairs(pdf.objects) do
    if obj.uncompressed then
      local matches = pdf_text_trie:match(obj.uncompressed)
      if matches then
        local text_blocks = {}
        local starts = {}
        local ends = {}

        for npat,matched_positions in pairs(matches) do
          if npat == 1 then
            for _,pos in ipairs(matched_positions) do
              starts[#starts + 1] = pos
            end
          else
            for _,pos in ipairs(matched_positions) do
              ends[#ends + 1] = pos
            end
          end
        end

        offsets_to_blocks(starts, ends, text_blocks)
        for _,bl in ipairs(text_blocks) do
          if bl.len > 2 then
            -- To remove \s+ET\b pattern (it can leave trailing space or not but it doesn't matter)
            bl.len = bl.len - 2
          end

          bl.data = obj.uncompressed:span(bl.start, bl.len)
          --lua_util.debugm(N, task, 'extracted text from object %s:%s: %s',
          --    obj.major, obj.minor, bl.data)

          if bl.len < 10 * 1024 then
            local ret,obj_or_err = pcall(pdf_text_grammar.match, pdf_text_grammar,
              bl.data)

            if ret then
              obj.text = rspamd_text.fromtable(obj_or_err)
              lua_util.debugm(N, task, 'object %s:%s is parsed to: %s',
                  obj.major, obj.minor, obj.text)
            else
              lua_util.debugm(N, task, 'object %s:%s cannot be parsed: %s',
                  obj.major, obj.minor, obj_or_err)
            end

          end
        end
      end
    end
  end
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

    pdf_output.flags = {}

    if pdf_output.start_objects and pdf_output.end_objects then
      -- Postprocess objects
      postprocess_pdf_objects(task, input, pdf_output)
      extract_pdf_objects(task, pdf_output)
      search_text(task, pdf_output)
    else
      pdf_output.flags.no_objects = true
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