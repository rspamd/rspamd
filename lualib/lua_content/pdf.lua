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

--[[[
-- @module lua_content/pdf
-- This module contains some heuristics for PDF files
--]]

local rspamd_trie = require "rspamd_trie"
local rspamd_util = require "rspamd_util"
local rspamd_text = require "rspamd_text"
local rspamd_url = require "rspamd_url"
local rspamd_pdf_text = require "rspamd_pdf_text"
local bit = require "bit"
local N = "lua_content"
local lua_util = require "lua_util"
local rspamd_regexp = require "rspamd_regexp"
local lpeg = require "lpeg"
local pdf_patterns = {
  trailer = {
    patterns = {
      [=[[\r\n]trailer[\s<]]=]
    }
  },
  suspicious = {
    patterns = {
      [[netsh\s]],
      [[echo\s]],
      [=[\/[A-Za-z]*#[0-9A-Fa-f]{2}[#A-Za-z<>/\s]]=], -- Hex encode obfuscation
    }
  },
  start_object = {
    patterns = {
      -- Objects are separated by any white space, not only by a line end, and
      -- whatever starts the object can follow the keyword at once
      -- The CRLF alternative is for the regexp fallback of the matcher, which
      -- never starts a match between the two bytes of a line end
      [=[(?:\r\n|[\s\0>\]])\d+\s+\d+\s+obj\b]=]
    }
  },
  end_object = {
    patterns = {
      [=[endobj\b]=]
    }
  },
  start_stream = {
    patterns = {
      -- Blanks before the line end are skipped by readers
      [=[>\s*stream[ \t\f\0]*[\r\n]]=],
    }
  },
  end_stream = {
    patterns = {
      [=[endstream\b]=]
    }
  }
}

local pdf_cmap_patterns = {
  start = {
    patterns = {
      [[\d\s+beginbfchar\s]],
      [[\d\s+beginbfrange\s]]
    }
  },
  stop = {
    patterns = {
      [[\sendbfrange\b]],
      [[\sendbchar\b]]
    }
  }
}

-- index[n] ->
--  t[1] - pattern,
--  t[2] - key in patterns table,
--  t[3] - value in patterns table
--  t[4] - local pattern index
local pdf_indexes = {}
local pdf_cmap_indexes = {}

local pdf_trie
local pdf_cmap_trie

local exports = {}

local config = {
  -- What inflate has really been returning: the old limit was only tested once
  -- the buffer was full, so it doubled past itself and let ~1Mb through. The
  -- binding enforces the limit exactly now, so the knob states the ceiling that
  -- streams have been decoded under for years
  max_extraction_size = 1024 * 1024,
  -- What a grammar is run over. The work is linear, so this bounds a single
  -- object and not the file: a dictionary padded past it is not looked at
  max_processing_size = 256 * 1024,
  text_extraction = true,
  url_extraction = true,
  enabled = true,
  js_fuzzy = true, -- Generate fuzzy hashes from PDF javascripts
  min_js_fuzzy = 256, -- Minimum size of js to be considered as a fuzzy
  openaction_fuzzy_only = false, -- Generate fuzzy from all scripts
  max_pdf_objects = 10000, -- Maximum number of objects to be considered
  min_obj_content_size = 32, -- Skip objects smaller than this (evasion padding)
  max_total_pdf_objects = 50000, -- Hard ceiling on stored objects, including ObjStm members
  max_pattern_matches = 50000, -- Hard ceiling on marker occurrences collected per processor
  max_extracted_text_size = 2 * 1024 * 1024, -- Cumulative budget for text taken out of content streams
  max_stream_filters = 4, -- Maximum number of filters applied to a single stream
  max_decoded_size = 32 * 1024 * 1024, -- Cumulative budget for the output of stream filters
  max_cmap_size = 4 * 1024 * 1024, -- Cumulative budget for the ToUnicode cmaps that are parsed
  max_pdf_trailer = 10 * 1024 * 1024, -- Maximum trailer size (to avoid abuse)
  max_pdf_trailer_lines = 100, -- Maximum number of lines in pdf trailer
  max_pdf_trailer_line = 16 * 1024, -- Maximum bytes examined in a single trailer line
  pdf_process_timeout = 2.0, -- Timeout in seconds for processing
  text_quality_threshold = 0.4, -- Minimum confidence to accept extracted text
  text_quality_min_length = 10, -- Minimum text length to apply quality filtering
  text_quality_enabled = true, -- Enable text quality filtering
}

-- Used to process patterns found in PDF
-- positions for functional processors should be a iter/table from trie matcher in form
---- [{n1, pat_idx1}, ... {nn, pat_idxn}] where
---- pat_idxn is pattern index and n1 ... nn are match positions
local processors = {}
-- PDF objects outer grammar in LPEG style (performing table captures)
local pdf_outer_grammar
local pdf_text_grammar

-- Used to match objects
local object_re = rspamd_regexp.create_cached([=[/(\d+)\s+(\d+)\s+obj\s*/]=])

local function config_module()
  local opts = rspamd_config:get_all_opt('lua_content')

  if opts and opts.pdf then
    config = lua_util.override_defaults(config, opts.pdf)
  end
end

local function compile_tries()
  local default_compile_flags = bit.bor(rspamd_trie.flags.re,
      rspamd_trie.flags.dot_all,
      rspamd_trie.flags.no_start)
  local function compile_pats(patterns, indexes, compile_flags)
    local strs = {}
    for what, data in pairs(patterns) do
      for i, pat in ipairs(data.patterns) do
        strs[#strs + 1] = pat
        indexes[#indexes + 1] = { what, data, pat, i }
      end
    end

    return rspamd_trie.create(strs, compile_flags or default_compile_flags)
  end

  if not pdf_trie then
    pdf_trie = compile_pats(pdf_patterns, pdf_indexes)
  end
  if not pdf_cmap_trie then
    pdf_cmap_trie = compile_pats(pdf_cmap_patterns, pdf_cmap_indexes)
  end
end

-- Marks a table that is an indirect reference. It is a value that no content
-- of a file can produce: a string would be forged by an array of strings
local pdf_ref_marker = {}

local function generic_grammar_elts()
  local P = lpeg.P
  local R = lpeg.R
  local S = lpeg.S
  local V = lpeg.V
  local C = lpeg.C
  local D = R '09' -- Digits

  local grammar_elts = {}

  -- Helper functions
  local function pdf_hexstring_unescape(s)
    -- White space is allowed between the digits
    -- (`%z` is not a class in Lua 5.2 and later: all that is not a digit goes)
    if s:find('%X') then
      s = s:gsub('%X', '')
    end
    if #s % 2 == 1 then
      -- The last digit of an odd run stands for a high nibble
      s = s .. '0'
    end

    return (lua_util.unhex(s))
  end

  local simple_escapes = {
    n = '\n', r = '\r', t = '\t', b = '\b', f = '\f',
    -- A backslash at the end of a line continues the string
    ['\n'] = '', ['\r'] = '',
  }

  local function pdf_string_unescape(s)
    if not s:find('\\', 1, true) then
      return s
    end

    if s:find('\\\r\n', 1, true) then
      s = s:gsub('\\\r\n', '')
    end

    -- One pass, so that an escaped backslash is not read again: a backslash,
    -- the character after it and up to two more digits of an octal code
    return (s:gsub('\\(.?)([0-7]?[0-7]?)', function(c, more)
      if c:find('^[0-7]$') then
        -- A value over 255 loses its high order bits, as in a reader
        return string.char(tonumber(c .. more, 8) % 256)
      end

      -- A backslash before any other character is dropped
      return (simple_escapes[c] or c) .. more
    end))
  end

  local function pdf_id_unescape(s)
    if not s:find('#', 1, true) then
      return s
    end

    return (s:gsub('#(%x%x)', function(cc)
      return string.char(tonumber(cc, 16))
    end))
  end

  local delim = S '()<>[]{}/%'
  grammar_elts.ws = S '\0 \r\n\t\f'
  local hex = R 'af' + R 'AF' + D
  -- Comments.
  local eol = P '\r\n' + '\n'
  local line = (1 - S '\r\n\f') ^ 0 * eol ^ -1
  grammar_elts.comment = P '%' * line

  -- Numbers.
  local sign = S '+-' ^ -1
  local decimal = D ^ 1
  local float = D ^ 1 * P '.' * D ^ 0 + P '.' * D ^ 1
  grammar_elts.number = C(sign * (float + decimal)) / tonumber

  -- String
  grammar_elts.str = P { "(" * C(((1 - S "()\\") + (P '\\' * 1) + V(1)) ^ 0) / pdf_string_unescape * ")" }
  grammar_elts.hexstr = P { "<" * C((hex + grammar_elts.ws) ^ 0) / pdf_hexstring_unescape * ">" }

  -- Identifier
  local regular = 1 - (delim + grammar_elts.ws)
  -- The empty name is a valid one
  grammar_elts.id = P { '/' * C(regular ^ 0) / pdf_id_unescape }

  -- Booleans (who care about them?) and null. Any other bare word is not a
  -- part of the syntax, but it must not cost the dictionary around it
  grammar_elts.regular = regular
  grammar_elts.boolean = C((P("true") + P("false") + P("null")) * -regular)
  grammar_elts.keyword = C(regular ^ 1)

  -- Stupid references: any white space separates the parts
  grammar_elts.ref = lpeg.Ct { lpeg.Cc(pdf_ref_marker) * C(D ^ 1) * grammar_elts.ws ^ 1 *
      C(D ^ 1) * grammar_elts.ws ^ 1 * "R" * -regular }

  return grammar_elts
end


-- Generates a grammar to parse outer elements (external objects in PDF notation)
local function gen_outer_grammar()
  local V = lpeg.V
  local gen = generic_grammar_elts()
  -- A comment is white space wherever it stands, between a key and its value
  -- as well
  local sp = (gen.ws + gen.comment) ^ 0

  return lpeg.P {
    "EXPR";
    EXPR = gen.ws ^ 0 * V("ELT") ^ 0 * gen.ws ^ 0,
    ELT = V("ARRAY") + V("DICT") + V("ATOM"),
    ATOM = gen.ws ^ 0 * (gen.comment + gen.boolean + gen.ref +
        gen.number * -gen.regular + V("STRING") + gen.id + gen.keyword) * gen.ws ^ 0,
    DICT = "<<" * sp * lpeg.Cf(lpeg.Ct("") * V("KV_PAIR") ^ 0, rawset) * sp * ">>",
    KV_PAIR = lpeg.Cg(gen.id * sp * V("ELT") * sp),
    ARRAY = "[" * gen.ws ^ 0 * lpeg.Ct(V("ELT") ^ 0) * gen.ws ^ 0 * "]",
    STRING = lpeg.P { gen.str + gen.hexstr },
  }
end

-- Calculate text quality confidence score using UTF-8 aware analysis
-- Returns a score between 0.0 (garbage) and 1.0 (high quality text)
local function calculate_text_confidence(text)
  if not text or #text < config.text_quality_min_length then
    return 1.0 -- Don't filter short text
  end

  local stats = rspamd_util.get_text_quality(text)
  if not stats or stats.total == 0 then
    return 0.0
  end

  local score = 0.0
  local non_ws = stats.total - stats.spaces

  -- Printable ratio (weight: 0.25) - target > 0.95
  local printable_ratio = stats.printable / stats.total
  score = score + math.min(printable_ratio / 0.95, 1.0) * 0.25

  -- Letter ratio (weight: 0.20) - target > 0.6
  local letter_ratio = 0
  if non_ws > 0 then
    letter_ratio = stats.letters / non_ws
  end
  score = score + math.min(letter_ratio / 0.6, 1.0) * 0.20

  -- Word ratio (weight: 0.25) - target > 0.7
  local word_ratio = 0
  if non_ws > 0 then
    word_ratio = stats.word_chars / non_ws
  end
  score = score + math.min(word_ratio / 0.7, 1.0) * 0.25

  -- Average word length (weight: 0.15) - ideal: 3-10
  local avg_word_len = 0
  if stats.words > 0 then
    avg_word_len = stats.word_chars / stats.words
  end
  local word_len_score = 0
  if avg_word_len >= 3 and avg_word_len <= 10 then
    word_len_score = 1.0
  elseif avg_word_len >= 2 and avg_word_len < 3 then
    word_len_score = 0.7
  elseif avg_word_len > 10 and avg_word_len <= 15 then
    word_len_score = 0.5
  else
    word_len_score = 0.2
  end
  score = score + word_len_score * 0.15

  -- Space ratio (weight: 0.15) - ideal: 0.08-0.25
  local space_ratio = stats.spaces / stats.total
  local space_score = 0
  if space_ratio >= 0.08 and space_ratio <= 0.25 then
    space_score = 1.0
  elseif space_ratio > 0.25 and space_ratio <= 0.4 then
    space_score = 0.6
  elseif space_ratio > 0 and space_ratio < 0.08 then
    space_score = 0.5
  else
    space_score = 0.2
  end
  score = score + space_score * 0.15

  return score
end

-- Marks the start of a text object in the instructions of a content stream
local text_object_start = { '%bt%' }

-- Generates a grammar that reads a content stream as a whole.
--
-- A content stream is a flat sequence of operands followed by an operator.
-- The operators that draw or place text are turned into instructions, and
-- everything else is walked over: an operator that is not known here, the
-- operands of a graphics operator, an inline image, marked content. Nothing
-- of that may stop the reading, as the text after it is as visible as the
-- text before it.
--
-- The match ends early only at a string, an array, a dictionary or an inline
-- image that is never closed, which is where a reader loses the rest of the
-- stream too.
-- The position where it ends is the last value returned.
local function gen_text_grammar()
  local V = lpeg.V
  local P = lpeg.P
  local R = lpeg.R
  local S = lpeg.S
  local C = lpeg.C
  local Cc = lpeg.Cc
  local Ct = lpeg.Ct
  local gen = generic_grammar_elts()
  local regular = gen.regular
  -- A comment is white space
  local sp = (gen.ws + gen.comment) ^ 0
  local sp1 = (gen.ws + gen.comment) ^ 1
  local op_end = -regular

  -- Tokens that are walked over without a capture
  local num = S '+-' ^ -1 * (R '09' ^ 1 * (P '.' * R '09' ^ 0) ^ -1 + P '.' * R '09' ^ 1) * op_end
  local name = P '/' * regular ^ 0
  local literal = P { '(' * ((1 - S '()\\') + P '\\' * 1 + V(1)) ^ 0 * ')' }
  local hexstring = P '<' * (R '09' + R 'af' + R 'AF' + gen.ws) ^ 0 * P '>'
  local keyword = regular ^ 1
  local operand = P {
    'ARG';
    ARG = num + literal + V 'DICT' + hexstring + name + V 'ARRAY',
    ELT = V 'ARG' + keyword,
    ARRAY = '[' * sp * (V 'ELT' * sp) ^ 0 * ']',
    -- Keys and values alike: there is no need to pair them to walk over
    DICT = '<<' * sp * (V 'ELT' * sp) ^ 0 * '>>',
  }
  -- The data of an inline image is binary and ends at `EI` between white space
  local image_start = P 'BI' * op_end
  local inline_image = image_start *
      (1 - (gen.ws * P 'EI' * (gen.ws + -P(1)))) ^ 0 * gen.ws * P 'EI'
  local operator = (R 'az' + R 'AZ' + S '*\'"') ^ 1 - image_start

  -- Text operators cannot be decoded here: the meaning of a character code
  -- depends on the font that is current at this point in the stream, which
  -- only the replay knows. So emit an instruction and let the decoder run
  -- once per page, over one buffer.
  local function text_op_handler(t, op)
    -- The pieces of a TJ array stay apart: its numbers are positioning
    -- adjustments, not character codes, so a word gap must not be spliced into
    -- the code stream. A multi byte code would lose its framing from that
    -- point on. `false` marks a gap for the replay to add structurally.
    local pieces = {}

    for _, chunk in ipairs(t) do
      if type(chunk) == 'string' and #chunk > 0 then
        pieces[#pieces + 1] = chunk
      elseif type(chunk) == 'number' and chunk < -200 then
        pieces[#pieces + 1] = false
      end
    end

    if #pieces == 0 then
      if op == "'" or op == '"' then
        return '\n'
      end

      return
    end

    return {
      '%text%',
      pieces,
      op == "'" or op == '"',
    }
  end

  -- The operators that take numbers only: where the text goes and how it is
  -- painted. The operands are the last numbers before the operator
  local function number_op_handler(t)
    local n = #t - 1
    local op = t[n + 1]

    if op == 'Td' or op == 'TD' then
      if n >= 2 then
        return { '%move%', t[n - 1], t[n] }
      end
    elseif op == 'Tm' then
      if n >= 6 then
        return { '%matrix%', t[n - 5], t[n - 4], t[n - 1], t[n] }
      end
    elseif op == 'Tr' then
      if n >= 1 then
        return { '%mode%', t[n] }
      end
    end
  end

  local text_arg = Ct(gen.str + gen.hexstr) +
      '[' * sp * Ct(((gen.number + gen.str + gen.hexstr) * sp) ^ 0) * ']'
  local text = (text_arg * sp * C(P 'Tj' + P 'TJ' + S '\'"') * op_end) / text_op_handler
  -- The font name is kept: it selects the encoding for the text that follows,
  -- and the size is the measure of the moves between the pieces of text
  local font = Ct(Cc '%font%' * gen.id * sp1 * gen.number) * sp1 * P 'Tf' * op_end
  local form = Ct(Cc '%do%' * gen.id) * sp1 * P 'Do' * op_end
  local number_op = Ct((gen.number * sp1) ^ 1 * C(P 'Td' + P 'TD' + P 'Tm' + P 'Tr') * op_end) /
      number_op_handler
  local numbers = (num * sp) ^ 1
  -- Anything that starts no token. A bracket that is not closed ends the
  -- match, and so does an image without an end: looking for the end of each
  -- of a run of those would read the rest of the stream every time
  local junk = 1 - S '([<' - image_start

  local command = text + font + form + number_op + numbers +
      P 'BT' * op_end * Cc(text_object_start) +
      P 'ET' * op_end * Cc '\n' +
      P 'T*' * op_end * Cc '\n' +
      inline_image + operand + operator + junk

  return sp * Ct((command * sp) ^ 0) * lpeg.Cp()
end


-- Arrays, dictionaries and the brackets of a string nest, and the matcher
-- gives up with an error at its default depth of a few hundred, which loses
-- what was read before it. Real files nest a few levels; this is the depth
-- that a file made to hit the limit has to reach
if lpeg.setmaxstack then
  lpeg.setmaxstack(8192)
end

-- Call immediately on require
compile_tries()
config_module()
pdf_outer_grammar = gen_outer_grammar()
pdf_text_grammar = gen_text_grammar()

local function extract_text_data(specific)
  local res = {}

  -- In the order of the pages, which is not the order of the objects
  if specific.text_pages then
    for i, text in ipairs(specific.text_pages) do
      res[i] = tostring(text)
    end
  end

  return res
end

-- Generates index for major/minor pair
local function obj_ref(major, minor)
  return major * 10.0 + 1.0 / (minor + 1.0)
end

-- Return indirect object reference (if needed)
local function maybe_dereference_object(elt, pdf, task)
  if type(elt) == 'table' and elt[1] == pdf_ref_marker then
    local ref = obj_ref(elt[2], elt[3])

    if pdf.ref[ref] then
      -- No recursion!
      return pdf.ref[ref]
    else
      lua_util.debugm(N, task, 'cannot dereference %s:%s -> %s, no object',
          elt[2], elt[3], obj_ref(elt[2], elt[3]))
      return nil
    end
  end

  return elt
end

-- Returns true if the deadline of this pdf has passed and remembers that
local function pdf_deadline_exceeded(pdf)
  if not pdf.end_timestamp then
    return false
  end

  local now = rspamd_util.get_ticks()

  if now >= pdf.end_timestamp then
    pdf.timeout_processing = now - pdf.start_timestamp

    return true
  end

  return false
end

-- Apply PDF stream filter
local function apply_pdf_filter(input, filt)
  -- Validate input before processing
  if not input or #input == 0 then
    return nil
  end

  if filt == 'FlateDecode' or filt == 'Fl' then
    -- The second value tells what is wrong with the data
    return (rspamd_util.inflate(input, config.max_extraction_size))
  elseif filt == 'ASCIIHexDecode' or filt == 'AHx' then
    if #input > config.max_extraction_size * 2 + 1024 then
      -- Cannot decode into what a stream is allowed to be
      return nil
    end
    -- The input is a text or a string, and only a string has `gsub`
    local to_decode = tostring(input)
    -- The data ends at `>`, and whatever is not a hex digit is skipped
    local eod = to_decode:find('>', 1, true)
    if eod then
      to_decode = to_decode:sub(1, eod - 1)
    end
    to_decode = to_decode:gsub('%X', '')
    if #to_decode % 2 == 1 then
      -- The last digit of an odd run stands for a high nibble
      to_decode = to_decode .. '0'
    end
    if #to_decode == 0 then
      return nil
    end
    return (lua_util.unhex(to_decode))
  elseif filt == 'ASCII85Decode' or filt == 'A85' then
    return rspamd_util.decode_ascii85(input, config.max_extraction_size)
  end

  return nil
end

-- Conditionally apply a pipeline of stream filters and return uncompressed data
local function maybe_apply_filter(dict, data, pdf, task)
  local uncompressed = data

  if dict.Filter then
    local filt = dict.Filter
    local filts = {}

    if type(filt) == 'string' then
      filts = { filt }
    elseif type(filt) == 'table' then
      filts = filt
    end

    -- Each filter of a chain is a full pass that allocates its output outside
    -- of what the collector accounts for, and a chain of stored deflate blocks
    -- costs a sender nothing: real files use one filter, or two for text
    -- armour over compression
    if #filts > config.max_stream_filters then
      pdf.flags.decode_limit = true
      return nil, string.format('too many filters: %d', #filts)
    end

    if dict.DecodeParms then
      local decode_params = maybe_dereference_object(dict.DecodeParms, pdf, task)

      if type(decode_params) == 'table' then
        if decode_params.Predictor then
          local predictor = tonumber(decode_params.Predictor) or 1
          if predictor > 1 then
            pdf.flags.undecoded_streams = (pdf.flags.undecoded_streams or 0) + 1
            return nil, 'predictor exists: ' .. tostring(predictor)
          end
        end
      end
    end

    for _, f in ipairs(filts) do
      if pdf.decoded_size >= config.max_decoded_size then
        pdf.flags.decode_limit = true
        return nil, 'decoded data limit is reached'
      end

      local next_uncompressed = apply_pdf_filter(uncompressed, f)

      if next_uncompressed then
        uncompressed = next_uncompressed
        -- Every stage is charged: the output of each one is allocated
        pdf.decoded_size = pdf.decoded_size + #next_uncompressed
      else
        pdf.flags.undecoded_streams = (pdf.flags.undecoded_streams or 0) + 1
        return nil, 'filter failed: ' .. tostring(f)
      end
    end
  end

  return uncompressed, nil
end

-- Conditionally extract stream data from object and attach it as obj.uncompressed
local function maybe_extract_object_stream(obj, pdf, task)
  if pdf.encrypted then
    -- TODO add decryption some day
    return nil
  end
  if not obj.stream then
    return nil
  end
  -- One stream is commonly shared: pages reference the same content, fonts
  -- reference the same cmap. Decoding is the expensive part of the pipeline, so
  -- the outcome is remembered here, failures included, and a file that
  -- references a bomb a thousand times only pays for it once
  if obj.uncompressed then
    return obj.uncompressed
  end
  if obj.stream_undecodable then
    return nil
  end
  -- Decoding is where the time goes, and the loops that lead here look at the
  -- clock once per many objects. A stream that is skipped for the lack of time
  -- is not marked as undecodable: that is not what it is
  if pdf_deadline_exceeded(pdf) then
    return nil
  end
  -- Defensive checks for stream structure
  if not obj.stream.data or not obj.stream.len then
    lua_util.debugm(N, task, 'malformed stream in object %s:%s',
        obj.major, obj.minor)
    obj.stream_undecodable = true
    return nil
  end
  local dict = obj.dict or {}
  local len = obj.stream.len
  if dict.Length then
    local decl_len = maybe_dereference_object(dict.Length, pdf, task)
    if decl_len then
      local nlen = type(decl_len) ~= 'table' and tonumber(decl_len)
      if nlen and nlen > 0 and nlen < len then
        -- The stream ends at `endstream`. A declared length is taken only if
        -- it ends there too, give or take the line end before the keyword:
        -- a reader that finds no keyword at the declared length looks for
        -- the keyword, so a short length would hide the rest of the data
        local honest = len - nlen <= 2

        if honest then
          for i = nlen + 1, len do
            local b = obj.stream.data:byte(i)

            if b ~= 13 and b ~= 10 then
              honest = false
              break
            end
          end
        end

        if honest then
          len = nlen
        else
          lua_util.debugm(N, task, 'object %s:%s declares a stream of %s bytes, but it has %s',
              obj.major, obj.minor, nlen, len)
        end
      end
    end
  end

  if len > 0 then
    -- Wrap stream extraction in pcall to handle malformed data
    local ret, real_stream = pcall(function()
      return obj.stream.data:span(1, len)
    end)
    if not ret or not real_stream then
      lua_util.debugm(N, task, 'cannot extract stream span from object %s:%s: %s',
          obj.major, obj.minor, real_stream)
      obj.stream_undecodable = true
      return nil
    end

    local uncompressed, filter_err = maybe_apply_filter(dict, real_stream, pdf, task)

    if uncompressed then
      obj.uncompressed = uncompressed
      lua_util.debugm(N, task, 'extracted object %s:%s: (%s -> %s)',
          obj.major, obj.minor, len, #uncompressed)
      return obj.uncompressed
    else
      lua_util.debugm(N, task, 'cannot extract object %s:%s; len = %s; filter = %s: %s',
          obj.major, obj.minor, len, dict.Filter, filter_err)
      obj.stream_undecodable = true
    end
  else
    lua_util.debugm(N, task, 'cannot extract object %s:%s; len = %s',
        obj.major, obj.minor, len)
    obj.stream_undecodable = true
  end
end

local dict_start_patt = lpeg.S('\0 \r\n\t\f') ^ 0 * lpeg.P('<<')

local function parse_object_grammar(obj, task, pdf)
  -- Parse grammar
  local obj_dict_span
  if obj.stream then
    obj_dict_span = obj.data:span(1, obj.stream.start - obj.start)
  else
    obj_dict_span = obj.data
  end

  if obj_dict_span:len() < config.max_processing_size then
    local ret, obj_or_err = pcall(pdf_outer_grammar.match, pdf_outer_grammar, obj_dict_span)

    if ret then
      if type(obj_or_err) ~= 'table' and dict_start_patt:match(obj_dict_span) then
        -- An object may be a number or a string, but this one starts as a
        -- dictionary that the grammar could not read to its end
        pdf.flags.unparsed_objects = (pdf.flags.unparsed_objects or 0) + 1
      end

      if obj.stream then
        if type(obj_or_err) == 'table' then
          obj.dict = obj_or_err
        else
          obj.dict = {}
        end

        lua_util.debugm(N, task, 'stream object %s:%s is parsed to: %s',
            obj.major, obj.minor, obj_or_err)
      else
        -- Direct object
        if type(obj_or_err) == 'table' then
          obj.dict = obj_or_err
          obj.uncompressed = obj_or_err
          lua_util.debugm(N, task, 'direct object %s:%s is parsed to: %s',
              obj.major, obj.minor, obj_or_err)
          pdf.ref[obj_ref(obj.major, obj.minor)] = obj
        else
          lua_util.debugm(N, task, 'direct object %s:%s is parsed to raw data: %s',
              obj.major, obj.minor, obj_or_err)
          pdf.ref[obj_ref(obj.major, obj.minor)] = obj_or_err
          obj.dict = {}
          obj.uncompressed = obj_or_err
        end
      end
    else
      pdf.flags.unparsed_objects = (pdf.flags.unparsed_objects or 0) + 1
      lua_util.debugm(N, task, 'object %s:%s cannot be parsed: %s',
          obj.major, obj.minor, obj_or_err)
    end
  else
    pdf.flags.unparsed_objects = (pdf.flags.unparsed_objects or 0) + 1
    lua_util.debugm(N, task, 'object %s:%s cannot be parsed: too large %s',
        obj.major, obj.minor, obj_dict_span:len())
  end
end

-- Extracts font data and process /ToUnicode mappings
-- NYI in fact as cmap is ridiculously stupid and complicated
--[[
local function process_font(task, pdf, font, fname)
  local dict = font
  if font.dict then
    dict = font.dict
  end

  if type(dict) == 'table' and dict.ToUnicode then
    local cmap = maybe_dereference_object(dict.ToUnicode, pdf, task)

    if cmap and cmap.dict then
      maybe_extract_object_stream(cmap, pdf, task)
      lua_util.debugm(N, task, 'found cmap for font %s: %s',
          fname, cmap.uncompressed)
    end
  end
end
--]]

-- Forward declarations
local process_dict
local process_inline_action

-- This function processes javascript string and returns JS hash and JS rspamd_text
local function process_javascript(task, pdf, js, obj)
  local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
  if type(js) == 'string' then
    js = rspamd_text.fromstring(js):oneline()
  elseif type(js) == 'userdata' then
    -- This is the object's own decoded stream, which stays cached and readable
    -- for the rest of the run; without the explicit copy an owned buffer is
    -- compacted in place and every later reader gets the leftovers
    js = js:oneline(true)
  else
    return nil
  end

  local hash = rspamd_cryptobox_hash.create(js)
  local bin_hash = hash:bin()

  if not pdf.scripts then
    pdf.scripts = {}
  end

  if pdf.scripts[bin_hash] then
    -- Duplicate
    return pdf.scripts[bin_hash]
  end

  local njs = {
    data = js,
    hash = hash:hex(),
    bin_hash = bin_hash,
    object = obj,
  }
  pdf.scripts[bin_hash] = njs
  return njs
end

-- Extract interesting stuff from /Action, e.g. javascript
local function process_action(task, pdf, obj)
  if not (obj.js or obj.launch) and (obj.dict and (obj.dict.JS or obj.dict.F or obj.dict.Win)) then
    local js = obj.dict.JS and maybe_dereference_object(obj.dict.JS, pdf, task)

    if js then
      if type(js) == 'table' then
        local extracted_js = maybe_extract_object_stream(js, pdf, task)

        if not extracted_js then
          lua_util.debugm(N, task, 'invalid type for JavaScript from %s:%s: %s',
              obj.major, obj.minor, js)
        else
          js = extracted_js
        end
      end

      js = process_javascript(task, pdf, js, obj)
      if js then
        obj.js = js
        lua_util.debugm(N, task, 'extracted javascript from %s:%s: %s',
            obj.major, obj.minor, obj.js.data)
      else
        lua_util.debugm(N, task, 'invalid type for JavaScript from %s:%s: %s',
            obj.major, obj.minor, js)
      end
    elseif obj.dict.S == 'Launch' and (obj.dict.F or obj.dict.Win) then
      -- The application is a file specification: a string, or a dictionary
      -- that names the file, also inside of the parameters for Windows
      local launch = maybe_dereference_object(obj.dict.F or obj.dict.Win, pdf, task)

      for _ = 1, 2 do
        if type(launch) == 'table' and launch[1] ~= pdf_ref_marker then
          local spec = launch.dict or launch
          launch = maybe_dereference_object(spec.F or spec.UF, pdf, task)
        end
      end

      if launch then
        if type(launch) == 'string' then
          obj.launch = rspamd_text.fromstring(launch):exclude_chars('%n%c')
          lua_util.debugm(N, task, 'extracted launch from %s:%s: %s',
              obj.major, obj.minor, obj.launch)
        elseif type(launch) == 'userdata' then
          -- Same as the javascript above: an owned buffer is rewritten in place
          -- unless the copy is asked for, and this one is the cached stream
          obj.launch = launch:exclude_chars('%n%c', true)
          lua_util.debugm(N, task, 'extracted launch from %s:%s: %s',
              obj.major, obj.minor, obj.launch)
        else
          lua_util.debugm(N, task, 'invalid type for launch from %s:%s: %s',
              obj.major, obj.minor, launch)
        end
      end
    else

      lua_util.debugm(N, task, 'no JS attribute in action %s:%s',
          obj.major, obj.minor)
    end
  end
end

-- Extract interesting stuff from /Catalog, e.g. javascript in /OpenAction
local function process_catalog(task, pdf, obj)
  if obj.dict then
    if obj.dict.OpenAction then
      local action = maybe_dereference_object(obj.dict.OpenAction, pdf, task)

      if action and type(action) == 'table' and not action.dict and not action.major then
        -- Written in place: a dictionary, or an array for a destination
        action = process_inline_action(task, pdf, obj, action, 1)
      end

      if action and type(action) == 'table' then
        -- This also processes action js (if not already processed)
        process_dict(task, pdf, action, action.dict)
        if action.js then
          lua_util.debugm(N, task, 'found openaction JS in %s:%s: %s',
              obj.major, obj.minor, action.js)
          pdf.openaction = action.js
          pdf.has_openaction = true
          action.js.object = obj
        elseif action.launch then
          lua_util.debugm(N, task, 'found openaction launch in %s:%s: %s',
              obj.major, obj.minor, action.launch)
          pdf.launch = action.launch
          pdf.has_openaction = true
        else
          lua_util.debugm(N, task, 'no JS in openaction %s:%s: %s',
              obj.major, obj.minor, action)
        end
      else
        lua_util.debugm(N, task, 'cannot find openaction %s:%s: %s -> %s',
            obj.major, obj.minor, obj.dict.OpenAction, action)
      end
    else
      lua_util.debugm(N, task, 'no openaction in catalog %s:%s',
          obj.major, obj.minor)
    end
  end
end

local function process_xref(task, pdf, obj)
  if obj.dict then
    if obj.dict.Encrypt then
      local encrypt = maybe_dereference_object(obj.dict.Encrypt, pdf, task)
      lua_util.debugm(N, task, 'found encrypt: %s in xref object %s:%s',
          encrypt, obj.major, obj.minor)
      pdf.encrypted = true
    end
  end
end

-- An action can be written in place, as a dictionary inside of the object
-- that triggers it, and not only as an object of its own: the catalog
-- (/OpenAction), a page or an annotation (/A), and the additional actions of
-- any of them (/AA, a dictionary of actions by event)
process_inline_action = function(task, pdf, obj, value, depth)
  local action = maybe_dereference_object(value, pdf, task)

  if type(action) ~= 'table' or action[1] == pdf_ref_marker then
    return nil
  end

  if action.dict or action.major then
    -- An object: the loop over the objects deals with it
    return action
  end

  if not action.S then
    return nil
  end

  -- Looks like an object for the code that processes actions
  local wrapper = {
    major = obj.major,
    minor = obj.minor,
    dict = action,
  }

  process_dict(task, pdf, wrapper, action)

  if action.Next and depth < 4 then
    -- A chain of actions: one or an array of them
    local next_action = maybe_dereference_object(action.Next, pdf, task)

    if type(next_action) == 'table' and not next_action.dict and not next_action.major then
      if next_action.S then
        process_inline_action(task, pdf, obj, next_action, depth + 1)
      else
        for i = 1, math.min(#next_action, 16) do
          process_inline_action(task, pdf, obj, next_action[i], depth + 1)
        end
      end
    end
  end

  return wrapper
end

local function process_inline_actions(task, pdf, obj, dict)
  if dict.A then
    process_inline_action(task, pdf, obj, dict.A, 1)
  end

  local additional = dict.AA and maybe_dereference_object(dict.AA, pdf, task)

  if type(additional) == 'table' then
    additional = additional.dict or additional

    local n = 0

    for _, v in pairs(additional) do
      n = n + 1
      if n > 32 then
        break
      end
      process_inline_action(task, pdf, obj, v, 1)
    end
  end
end

process_dict = function(task, pdf, obj, dict)
  if not obj.type and type(dict) == 'table' then
    if (dict.A or dict.AA) and not obj.inline_actions_done then
      obj.inline_actions_done = true
      process_inline_actions(task, pdf, obj, dict)
    end

    if dict.Type and type(dict.Type) == 'string' then
      -- Common stuff
      obj.type = dict.Type
    end

    if not obj.type then
      -- Defensive: check obj.dict exists before accessing its fields
      if obj.dict and type(obj.dict) == 'table' and obj.dict.S == 'Launch' and
          (obj.dict.F or obj.dict.Win) then
        -- An action without a type of its own, as the ones written in place
        obj.type = 'Action'
      elseif obj.dict and type(obj.dict) == 'table' and obj.dict.S and obj.dict.JS then
        obj.type = 'Javascript'
        lua_util.debugm(N, task, 'implicit type for JavaScript object %s:%s',
            obj.major, obj.minor)
      else
        lua_util.debugm(N, task, 'no type for %s:%s',
            obj.major, obj.minor)
        return
      end
    end

    lua_util.debugm(N, task, 'processed stream dictionary for object %s:%s -> %s',
        obj.major, obj.minor, obj.type)
    local contents = dict.Contents
    if contents and type(contents) == 'table' then
      if contents[1] == pdf_ref_marker then
        -- Single reference
        contents = { contents }
      end
      obj.contents = {}

      for _, c in ipairs(contents) do
        local cobj = maybe_dereference_object(c, pdf, task)
        if cobj and type(cobj) == 'table' then
          obj.contents[#obj.contents + 1] = cobj
          -- Only a stream without a type of its own is content and nothing
          -- else. A reader takes no content from an object that is not a
          -- stream, so a page that names an action or a catalog here must not
          -- stop that object from being looked at
          if cobj.stream and not cobj.type and
              not (type(cobj.dict) == 'table' and cobj.dict.Type) then
            cobj.parent = obj
            cobj.type = 'content'
          end
        end
      end

      lua_util.debugm(N, task, 'found content objects for %s:%s -> %s',
          obj.major, obj.minor, #obj.contents)
    end

    local resources = dict.Resources
    if resources and type(resources) == 'table' then
      local res_ref = maybe_dereference_object(resources, pdf, task)

      if type(res_ref) ~= 'table' then
        lua_util.debugm(N, task, 'cannot parse resources from pdf: %s',
            resources)
        obj.resources = {}
      elseif res_ref.dict then
        obj.resources = res_ref.dict
      else
        -- An inline dictionary is the resources themselves, not an object
        obj.resources = res_ref
      end
    else
      -- Fucking pdf: we need to inherit from parent
      resources = {}
      if dict.Parent then
        local parent = maybe_dereference_object(dict.Parent, pdf, task)

        if parent and type(parent) == 'table' and parent.dict then
          if parent.resources then
            lua_util.debugm(N, task, 'propagated resources from %s:%s to %s:%s',
                parent.major, parent.minor, obj.major, obj.minor)
            resources = parent.resources
          end
        end
      end

      obj.resources = resources
    end



    -- Fonts are needed to decode text: a character code means nothing without
    -- the /Encoding of the font that drew it
    if config.text_extraction and type(obj.resources) == 'table' then
      local fonts = maybe_dereference_object(obj.resources.Font, pdf, task)

      if type(fonts) == 'table' then
        local fonts_dict = fonts.dict or fonts

        obj.fonts = {}

        for k, v in pairs(fonts_dict) do
          local font = maybe_dereference_object(v, pdf, task)

          if type(font) == 'table' then
            obj.fonts[k] = font
            lua_util.debugm(N, task, 'found font "%s" for object %s:%s',
                k, obj.major, obj.minor)
          end
        end
      end
    end

    lua_util.debugm(N, task, 'found resources for object %s:%s (%s): %s',
        obj.major, obj.minor, obj.type, obj.resources)

    if obj.type == 'Action' then
      process_action(task, pdf, obj)
    elseif obj.type == 'Catalog' then
      process_catalog(task, pdf, obj)
    elseif obj.type == 'XRef' then
      -- XRef stream instead of trailer from PDF 1.5 (thanks Adobe)
      process_xref(task, pdf, obj)
    elseif obj.type == 'Javascript' then
      local js = maybe_dereference_object(obj.dict.JS, pdf, task)

      if js then
        if type(js) == 'table' then
          local extracted_js = maybe_extract_object_stream(js, pdf, task)

          if not extracted_js then
            lua_util.debugm(N, task, 'invalid type for JavaScript from %s:%s: %s',
                obj.major, obj.minor, js)
          else
            js = extracted_js
          end
        end

        js = process_javascript(task, pdf, js, obj)
        if js then
          obj.js = js
          lua_util.debugm(N, task, 'extracted javascript from %s:%s: %s',
              obj.major, obj.minor, obj.js.data)
        else
          lua_util.debugm(N, task, 'invalid type for JavaScript from %s:%s: %s',
              obj.major, obj.minor, js)
        end
      end
    end
  end -- Already processed dict (obj.type is not empty)
end

-- This function is intended to unpack objects from ObjStm crappy structure
local compound_obj_grammar
local function compound_obj_grammar_gen()
  if not compound_obj_grammar then
    local gen = generic_grammar_elts()
    compound_obj_grammar = gen.ws ^ 0 * (gen.comment * gen.ws ^ 1) ^ 0 *
        lpeg.Ct(lpeg.Ct(gen.number * gen.ws ^ 1 * gen.number * gen.ws ^ 0) ^ 1)
  end

  return compound_obj_grammar
end
local function pdf_compound_object_unpack(_, uncompressed, pdf, task, first, nobjs)
  -- First, we need to parse data line by line likely to find a line
  -- that consists of pairs of numbers
  compound_obj_grammar_gen()

  local stored = #pdf.objects

  -- The pairs are the /N first things of the stream and end before /First.
  -- The grammar builds a table per pair, so it is given no more than the
  -- members that can be stored need: a stream of digits alone would otherwise
  -- cost a quarter of a million tables, whatever /N says
  nobjs = math.min(nobjs, config.max_total_pdf_objects - stored)
  if nobjs < 1 or first < 1 then
    return
  end
  local header_len = math.min(first, #uncompressed, nobjs * 32)
  local header_ok, header = pcall(uncompressed.span, uncompressed, 1, header_len)
  if not header_ok or not header then
    return
  end
  -- Wrap grammar match in pcall for safety
  local match_ok, elts = pcall(compound_obj_grammar.match, compound_obj_grammar, header)
  if not match_ok then
    lua_util.debugm(N, task, 'compound object grammar match failed: %s', elts)
    return
  end
  if elts and type(elts) == 'table' and #elts > 0 then
    lua_util.debugm(N, task, 'compound elts (chunk length %s): %s',
        #uncompressed, elts)

    for i = #elts, nobjs + 1, -1 do
      elts[i] = nil
    end

    for i, pair in ipairs(elts) do
      -- An ObjStm is the cheapest way to manufacture objects: a small
      -- compressed stream expands into as many members as it likes, so both the
      -- global ceiling and the deadline have to be honoured while unpacking
      if stored >= config.max_total_pdf_objects then
        lua_util.debugm(N, task, 'pdf: reached the total object limit (%s) while unpacking a compound object',
            config.max_total_pdf_objects)
        break
      end

      if i % 100 == 0 then
        local now = rspamd_util.get_ticks()

        if now >= pdf.end_timestamp then
          pdf.timeout_processing = now - pdf.start_timestamp

          lua_util.debugm(N, task, 'pdf: timeout unpacking a compound object after spending %s seconds, ' ..
              '%s elements processed',
              pdf.timeout_processing, i)
          break
        end
      end

      -- Defensive: check pair is a valid table
      if type(pair) ~= 'table' or not pair[1] or not pair[2] then
        lua_util.debugm(N, task, 'invalid pair in compound object at index %s', i)
      else
        local obj_number, offset = pair[1], pair[2]

        offset = offset + first
        if offset < #uncompressed then
          local span_len
          if i == #elts then
            span_len = #uncompressed - offset
          else
            local next_pair = elts[i + 1]
            if type(next_pair) == 'table' and next_pair[2] then
              span_len = (next_pair[2] + first) - offset
            else
              span_len = #uncompressed - offset
            end
          end

          if span_len > 0 and offset + span_len <= #uncompressed then
            -- Wrap span extraction in pcall
            local span_ok, span_data = pcall(function()
              return uncompressed:span(offset + 1, span_len)
            end)
            if not span_ok or not span_data then
              lua_util.debugm(N, task, 'cannot extract span for compound object %s', obj_number)
            else
              local obj = {
                major = obj_number,
                minor = 0, -- Implicit
                data = span_data,
                ref = obj_ref(obj_number, 0)
              }
              parse_object_grammar(obj, task, pdf)

              if obj.dict then
                stored = stored + 1
                pdf.objects[stored] = obj
              end
            end
          else
            lua_util.debugm(N, task, 'invalid span_len for compound object %s:%s; offset = %s, len = %s',
                pair[1], pair[2], offset + span_len, #uncompressed)
          end
        end
      end
    end
  end
end

-- PDF 1.5 ObjStmt
local function extract_pdf_compound_objects(task, pdf)
  for i, obj in ipairs(pdf.objects or {}) do
    if obj.stream and obj.dict and type(obj.dict) == 'table' then
      local t = obj.dict.Type
      if t and t == 'ObjStm' and #pdf.objects < config.max_total_pdf_objects then
        -- Each of these is a stream to decode and to unpack, so the clock is
        -- looked at for every one of them and not once per hundred objects
        if pdf_deadline_exceeded(pdf) then
          lua_util.debugm(N, task, 'pdf: timeout processing compound objects after spending %s seconds, ' ..
              '%s elements processed',
              pdf.timeout_processing, i)
          break
        end
        -- We are in troubles sir...
        -- The values come from the file: anything can be there
        local function dict_number(v)
          v = maybe_dereference_object(v, pdf, task)
          if type(v) == 'number' or type(v) == 'string' then
            return tonumber(v)
          end
          return nil
        end
        local nobjs = dict_number(obj.dict.N)
        local first = dict_number(obj.dict.First)

        if nobjs and first then
          --local extend = maybe_dereference_object(obj.dict.Extends, pdf, task)
          lua_util.debugm(N, task, 'extract ObjStm with %s objects (%s first) %s extend',
              nobjs, first, obj.dict.Extends)

          local uncompressed = maybe_extract_object_stream(obj, pdf, task)

          if type(uncompressed) == 'userdata' then
            -- An error in one object must not hide the objects after it
            local ok, err = pcall(pdf_compound_object_unpack, obj, uncompressed, pdf, task, first, nobjs)
            if not ok then
              pdf.flags.object_errors = (pdf.flags.object_errors or 0) + 1
              lua_util.debugm(N, task, 'pdf: cannot unpack ObjStm %s:%s: %s',
                  obj.major, obj.minor, err)
            end
          end
        else
          lua_util.debugm(N, task, 'ObjStm object %s:%s has bad dict: %s',
              obj.major, obj.minor, obj.dict)
        end
      end
    end
  end
end

-- The data of a stream is opaque, and whatever looks like a marker in it is
-- not one. A stream whose dictionary gives its length as a number, with
-- `endstream` found right where that length ends, is known for certain, so the
-- markers inside of it are dropped before the objects are paired: a line with
-- `endobj` in the data would otherwise end the object in the middle of its
-- stream, and one with `1 0 obj` would start an object that is not there.
-- A length given by a reference is not resolved at this point, and such a
-- stream is left to the pairing of the markers, as before
local stream_length_re = rspamd_regexp.create_cached([=[/\/Length\s+(\d+)\b(?!\s+\d+\s+R\b)/]=])

local function drop_markers_in_streams(task, input, pdf)
  local starts = pdf.start_streams

  if not starts or #starts == 0 then
    return
  end

  local ranges = {}
  local nranges = 0
  local prev_end = 0
  local input_len = #input

  for i, sp in ipairs(starts) do
    if i % 256 == 0 and pdf_deadline_exceeded(pdf) then
      return
    end

    -- A `stream` keyword inside of a known stream is data as well
    if sp > prev_end then
      local window_start = math.max(1, sp - 1024, prev_end + 1)
      local matches = stream_length_re:search(input:span(window_start, sp - window_start + 1), true, true)

      if matches and matches[1] then
        local declared = tonumber(tostring(matches[#matches][2]))
        -- The keyword is followed by CRLF or by LF, and the pattern ends at
        -- the first byte of that
        local data_start = sp + 1

        if input:byte(sp) == 13 and input:byte(sp + 1) == 10 then
          data_start = sp + 2
        end

        if declared and declared > 0 and data_start + declared + 8 <= input_len then
          local after = data_start + declared

          -- An end of line may stand before the keyword
          for _ = 1, 2 do
            local b = input:byte(after)

            if b ~= 13 and b ~= 10 then
              break
            end

            after = after + 1
          end

          if after + 8 <= input_len and tostring(input:span(after, 9)) == 'endstream' then
            nranges = nranges + 1
            ranges[nranges] = { data_start, data_start + declared - 1 }
            prev_end = data_start + declared - 1
          end
        end
      end
    end
  end

  if nranges == 0 then
    return
  end

  local dropped = 0

  local function filter(key)
    local positions = pdf[key]

    if not positions then
      return
    end

    local out = {}
    local nout = 0
    local r = 1

    for _, pos in ipairs(positions) do
      while r <= nranges and ranges[r][2] < pos do
        r = r + 1
      end

      if r <= nranges and pos >= ranges[r][1] then
        dropped = dropped + 1
      else
        nout = nout + 1
        out[nout] = pos
      end
    end

    pdf[key] = out
  end

  filter('start_objects')
  filter('end_objects')
  filter('start_streams')
  filter('end_streams')

  if dropped > 0 then
    lua_util.debugm(N, task, 'pdf: dropped %s markers found inside of %s streams', dropped, nranges)
  end
end

-- This function arranges starts and ends of all objects and process them into initial
-- set of objects
local function extract_outer_objects(task, input, pdf)
  local start_pos, end_pos = 1, 1
  local obj_count = 0
  local stored = 0
  local total_start = #pdf.start_objects
  local total_end = #pdf.end_objects

  lua_util.debugm(N, task, "pdf: extract objects from %s start positions and %s end positions",
      total_start, total_end)

  while start_pos <= total_start and end_pos <= total_end do
    -- Timeout check every 500 iterations
    if start_pos % 500 == 0 then
      local now = rspamd_util.get_ticks()
      if now >= pdf.end_timestamp then
        pdf.timeout_processing = now - pdf.start_timestamp
        lua_util.debugm(N, task, 'pdf: timeout extracting objects after %s seconds, ' ..
            '%s stored, %s/%s positions',
            pdf.timeout_processing, stored, start_pos, total_start)
        break
      end
    end

    local first = pdf.start_objects[start_pos]
    local last = pdf.end_objects[end_pos]

    local next_first = pdf.start_objects[start_pos + 1]
    local implied_end = false

    -- 7 is length of `endobj\n`
    if first + 6 < last then
      local len = last - first - 6

      if next_first and next_first < last and next_first > first + 7 then
        -- Another object starts before this one ends: this one has no
        -- `endobj`, and it ends where the next one starts. Taking the end of
        -- the next object instead shifts every pair after it, and the last
        -- objects of the file are lost. The shortest header, `1 0 obj`, is
        -- left out; what is left of a longer one is a number after the object
        len = next_first - first - 7
        implied_end = true
      end

      -- The budget below deliberately ignores tiny objects, so on its own it
      -- bounds nothing: a file made of padding stores as many as it can fit
      if stored >= config.max_total_pdf_objects then
        lua_util.debugm(N, task, 'pdf: reached the total object limit (%s), stop extracting',
            config.max_total_pdf_objects)
        break
      end

      -- Only count non-tiny objects toward the limit; small objects (e.g. padding)
      -- are still stored but don't consume the budget
      if len >= config.min_obj_content_size then
        if obj_count >= config.max_pdf_objects then
          break
        end
        obj_count = obj_count + 1
      end

      -- Also get the starting span and try to match it versus obj re to get numbers
      -- Any amount of white space can stand between the parts of the header
      local obj_line_potential = first - 256
      if obj_line_potential < 1 then
        obj_line_potential = 1
      end
      local prev_obj_end = pdf.end_objects[end_pos - 1]
      if end_pos > 1 and prev_obj_end >= obj_line_potential and prev_obj_end < first then
        obj_line_potential = prev_obj_end + 1
      end

      local obj_line_span = input:span(obj_line_potential, first - obj_line_potential + 1)
      local matches = object_re:search(obj_line_span, true, true)

      if matches and matches[1] then
        -- The header of this object is the last one in the window
        local header = matches[#matches]
        stored = stored + 1
        local nobj = {
          start = first,
          len = len,
          data = input:span(first, len),
          major = tonumber(header[2]),
          minor = tonumber(header[3]),
        }
        pdf.objects[stored] = nobj
        if nobj.major and nobj.minor then
          -- Add reference
          local ref = obj_ref(nobj.major, nobj.minor)
          nobj.ref = ref -- Our internal reference
          pdf.ref[ref] = nobj
        end
      end

      start_pos = start_pos + 1
      if not implied_end then
        end_pos = end_pos + 1
      end
    elseif first > last then
      end_pos = end_pos + 1
    else
      start_pos = start_pos + 1
      end_pos = end_pos + 1
    end
  end

  lua_util.debugm(N, task, 'pdf: stored %s objects (%s non-tiny toward limit) from %s positions',
      stored, obj_count, total_start)
end

-- This function attaches streams to objects and processes outer pdf grammar
local function attach_pdf_streams(task, input, pdf)
  if pdf.start_streams and pdf.end_streams then
    local start_pos, end_pos = 1, 1
    local total_start = #pdf.start_streams
    local total_end = #pdf.end_streams
    local iter_count = 0

    for _, obj in ipairs(pdf.objects) do
      while start_pos <= total_start and end_pos <= total_end do
        -- Timeout check every 500 iterations
        iter_count = iter_count + 1
        if iter_count % 500 == 0 then
          local now = rspamd_util.get_ticks()
          if now >= pdf.end_timestamp then
            pdf.timeout_processing = now - pdf.start_timestamp
            lua_util.debugm(N, task, 'pdf: timeout attaching streams after %s seconds',
                pdf.timeout_processing)
            return
          end
        end

        local first = pdf.start_streams[start_pos]
        local last = pdf.end_streams[end_pos]
        last = last - 10 -- Exclude endstream\n pattern
        lua_util.debugm(N, task, "start: %s, end: %s; obj: %s-%s",
            first, last, obj.start, obj.start + obj.len)
        if first > obj.start and last < obj.start + obj.len and last > first then
          -- In case if we have fake endstream :(
          while pdf.end_streams[end_pos + 1] and pdf.end_streams[end_pos + 1] < obj.start + obj.len do
            end_pos = end_pos + 1
            last = pdf.end_streams[end_pos] - 10
          end
          -- Strip the first \n
          while first < last do
            local chr = input:byte(first)
            if chr ~= 13 and chr ~= 10 then
              break
            end
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
    end
  end
end

-- Processes PDF objects: extracts streams, object numbers, process outer grammar,
-- augment object types
local function postprocess_pdf_objects(task, input, pdf)
  pdf.objects = {} -- objects table
  pdf.ref = {} -- references table
  drop_markers_in_streams(task, input, pdf)
  extract_outer_objects(task, input, pdf)

  -- Now we have objects and we need to attach streams that are in bounds
  attach_pdf_streams(task, input, pdf)
  -- Parse grammar for outer objects
  for i, obj in ipairs(pdf.objects) do
    -- The clock is looked at once in a while, and before every large object
    if i > 0 and (i % 100 == 0 or obj.len > 32768) then
      local now = rspamd_util.get_ticks()

      if now >= pdf.end_timestamp then
        pdf.timeout_processing = now - pdf.start_timestamp
        lua_util.debugm(N, task, 'pdf: timeout processing grammars after spending %s seconds, ' ..
            '%s elements processed',
            pdf.timeout_processing, i)
        break
      end
    end
    if obj.ref then
      parse_object_grammar(obj, task, pdf)

      -- Special early handling
      if obj.dict and obj.dict.Type and obj.dict.Type == 'XRef' then
        -- An error in one object must not hide the objects after it
        local ok, err = pcall(process_xref, task, pdf, obj)
        if not ok then
          pdf.flags.object_errors = (pdf.flags.object_errors or 0) + 1
          lua_util.debugm(N, task, 'pdf: cannot process xref object %s:%s: %s',
              obj.major, obj.minor, err)
        end
      end
    end
  end

  if not pdf.timeout_processing then
    extract_pdf_compound_objects(task, pdf)
  else
    -- ENOTIME
    return
  end

  -- Now we might probably have all objects being processed
  for i, obj in ipairs(pdf.objects) do
    if obj.dict then
      -- Types processing
      if i > 0 and i % 100 == 0 then
        local now = rspamd_util.get_ticks()

        if now >= pdf.end_timestamp then
          pdf.timeout_processing = now - pdf.start_timestamp

          lua_util.debugm(N, task, 'pdf: timeout processing dicts after spending %s seconds, ' ..
              '%s elements processed',
              pdf.timeout_processing, i)
          break
        end
      end
      -- An error in one object must not hide the objects after it
      local ok, err = pcall(process_dict, task, pdf, obj, obj.dict)
      if not ok then
        pdf.flags.object_errors = (pdf.flags.object_errors or 0) + 1
        lua_util.debugm(N, task, 'pdf: cannot process object %s:%s: %s',
            obj.major, obj.minor, err)
      end
    end
  end
end

-- Returns the text and whether it is already UTF-8. A UTF-16 string is
-- decoded here; anything else is left as raw character codes for the font
-- encoding to interpret.
local function sanitize_pdf_text(s)
  if not s or #s < 4 then return s, false end

  local nulls_odd = 0
  local nulls_even = 0
  local len = #s

  local limit = math.min(len, 16)
  for i = 1, limit do
    local b = string.byte(s, i)
    if b == 0 then
      if i % 2 == 1 then
        nulls_odd = nulls_odd + 1
      else
        nulls_even = nulls_even + 1
      end
    end
  end

  if len > 32 then
    for i = len - 15, len do
      local b = string.byte(s, i)
      if b == 0 then
        if i % 2 == 1 then
          nulls_odd = nulls_odd + 1
        else
          nulls_even = nulls_even + 1
        end
      end
    end
  elseif len > 16 then
    for i = 17, len do
      local b = string.byte(s, i)
      if b == 0 then
        if i % 2 == 1 then
          nulls_odd = nulls_odd + 1
        else
          nulls_even = nulls_even + 1
        end
      end
    end
  end

  local total_checked = (len > 32) and 32 or len
  local total_odd = math.ceil(total_checked / 2)
  local total_even = math.floor(total_checked / 2)

  if len > 32 then
      total_odd = 16
      total_even = 16
  end

  local ratio_odd = nulls_odd / total_odd
  local ratio_even = nulls_even / total_even
  local charset

  if ratio_odd > 0.8 and ratio_even < 0.2 then
     charset = 'UTF-16BE'
  elseif ratio_even > 0.8 and ratio_odd < 0.2 then
     charset = 'UTF-16LE'
  end

  if charset and rspamd_util.to_utf8 then
     local conv = rspamd_util.to_utf8(s, charset)
     if conv then
        local garbage_limit = 0
        local clen = #conv
        for i = 1, clen do
          local b = conv:byte(i)
          if b < 32 and b ~= 9 and b ~= 10 and b ~= 13 then
            garbage_limit = garbage_limit + 1
          end
        end

        if garbage_limit > 0 then
           return '', false
        end

        return conv, true
     end
  end

  -- Everything else is character codes: control codes are .notdef in every
  -- simple font encoding, so the decoder drops them without a scan here.
  return s, false
end

-- Resolves a font into a decoder for its character codes.
--
-- A composite font addresses glyphs by index, so only its /ToUnicode CMap can
-- recover text and it takes precedence. A simple font is decoded through its
-- /Encoding: one of the base encoding names, or a dictionary with a
-- /BaseEncoding and a /Differences array. Anything unresolved falls back to the
-- built-in encoding of the font, which for Latin text fonts is
-- StandardEncoding.
--
-- Returns an encoding and a cmap, both only for a simple font that has a
-- cmap, and whether the font is a simple one; caches the answer on the font.
local function font_decoder_of(font, pdf, task)
  if type(font) ~= 'table' then
    return nil, nil
  end

  if font.rspamd_decoder ~= nil then
    -- false stands for "resolved to nothing", so it is not retried
    if font.rspamd_decoder == false then
      return nil, nil
    end

    return font.rspamd_decoder.encoding, font.rspamd_decoder.cmap, font.rspamd_decoder.simple
  end

  local dict = font.dict or font
  local enc, cmap

  local tounicode = maybe_dereference_object(dict.ToUnicode, pdf, task)

  if type(tounicode) == 'table' then
    -- Fonts of one document routinely share a /ToUnicode stream, so the parsed
    -- cmap lives on the stream object rather than on each font that wants it
    local cached = tounicode.rspamd_cmap

    if cached ~= nil then
      if type(cached) == 'userdata' then
        cmap = cached
      end
    else
      maybe_extract_object_stream(tounicode, pdf, task)

      -- A CMap that inherits from another names it in the stream dictionary; the
      -- base is a resource that is not in the file, so the local overrides on
      -- their own would decode part of the text and silently lose the rest
      local tu_dict = tounicode.dict or tounicode

      if type(tu_dict) == 'table' and tu_dict.UseCMap then
        lua_util.debugm(N, task, 'ignoring ToUnicode cmap that inherits via /UseCMap')
      elseif type(tounicode.uncompressed) ~= 'userdata' then
        lua_util.debugm(N, task, 'ToUnicode is not a stream')
      elseif pdf.cmap_size + #tounicode.uncompressed > config.max_cmap_size then
        -- A parsed cmap is several times its source and lives outside of what
        -- the collector accounts for, and a file can carry any number of them
        pdf.flags.decode_limit = true
        lua_util.debugm(N, task, 'ignoring ToUnicode cmap of %s bytes: %s bytes are already parsed',
            #tounicode.uncompressed, pdf.cmap_size)
      else
        local err
        pdf.cmap_size = pdf.cmap_size + #tounicode.uncompressed
        cmap, err = rspamd_pdf_text.cmap(tounicode.uncompressed)

        if cmap then
          lua_util.debugm(N, task, 'parsed ToUnicode cmap with %s codes', cmap:size())
        else
          lua_util.debugm(N, task, 'cannot use ToUnicode cmap: %s', err)
        end
      end

      -- false stands for "resolved to nothing", so it is not retried
      tounicode.rspamd_cmap = cmap or false
    end
  end

  -- The codes of a composite font are what its cmap says. Any other font is
  -- a simple one: a code is a byte, whatever the codespace of the cmap, and
  -- its encoding stands for the codes that the cmap leaves out
  local simple = dict.Subtype ~= 'Type0'

  if not cmap or simple then
    local spec = maybe_dereference_object(dict.Encoding, pdf, task)
    local base, diffs

    if type(spec) == 'string' then
      base = spec
    elseif type(spec) == 'table' then
      local enc_dict = spec.dict or spec
      base = enc_dict.BaseEncoding
      diffs = maybe_dereference_object(enc_dict.Differences, pdf, task)

      if type(diffs) == 'table' and diffs.dict then
        -- An array that is an object of its own
        diffs = diffs.dict
      end
    end

    if type(base) == 'string' then
      enc = rspamd_pdf_text.encoding(base)

      if not enc then
        lua_util.debugm(N, task, 'unsupported font encoding: %s', base)
      end
    end

    if type(diffs) == 'table' then
      -- Differences still need a base encoding to override
      enc = enc or rspamd_pdf_text.encoding('StandardEncoding')

      if enc then
        local napplied = enc:apply_differences(diffs)
        lua_util.debugm(N, task, 'applied %s differences to font encoding', napplied)
      end
    end
  end

  if enc or cmap then
    font.rspamd_decoder = { encoding = enc, cmap = cmap, simple = simple }
  else
    font.rspamd_decoder = false
  end

  return enc, cmap, simple
end

-- Characters that take no space and leave no mark: they tell nothing about
-- the quality of a text, and enough of them would sink the score of any page
local function strip_invisible_chars(text)
  text = text:gsub('\226\128[\139-\143\170-\174]', '') -- U+200B..200F, U+202A..202E
  text = text:gsub('\226\129[\160-\164]', '') -- U+2060..2064
  text = text:gsub('\239\187\191', '') -- U+FEFF
  text = text:gsub('\194\173', '') -- U+00AD

  return text
end

-- Reads a content stream into instructions, once per stream: pages share
-- streams, and so do the forms that pages draw
local function content_stream_ops(task, pdf, tobj)
  if tobj.rspamd_ops ~= nil then
    return tobj.rspamd_ops or nil
  end

  -- Not known yet, or not to be known: a stream that is skipped for the lack
  -- of time or budget is not marked, and a later page does not retry it
  -- either, as both conditions only get worse
  tobj.rspamd_ops = false

  if pdf.text_size >= config.max_extracted_text_size then
    pdf.flags.text_truncated = true
    return nil
  end

  local uncompressed = maybe_extract_object_stream(tobj, pdf, task)

  if type(uncompressed) ~= 'userdata' and type(uncompressed) ~= 'string' then
    return nil
  end

  local len = #uncompressed

  local ops = {}
  local pos = 1
  -- The grammar stops at a bracket that is never closed. The byte is skipped
  -- and the reading goes on. Every attempt may walk to the end of the stream
  -- to learn that the bracket is not closed, so the attempts are bounded by
  -- what they may read in total, a few times the stream, and not by their
  -- number: a few brackets at the start must not hide the text after them
  local work, max_work = 0, 8 * len + 65536
  local complete = false

  while work <= max_work do
    work = work + (len - pos + 1) + 64

    local ok, chunk, stopped = pcall(pdf_text_grammar.match, pdf_text_grammar, uncompressed, pos)

    if not ok or type(chunk) ~= 'table' then
      -- Brackets nested deeper than the matcher goes
      pdf.flags.object_errors = (pdf.flags.object_errors or 0) + 1
      lua_util.debugm(N, task, 'content of %s:%s cannot be parsed: %s',
          tobj.major, tobj.minor, chunk)
      break
    end

    if #ops == 0 then
      ops = chunk
    else
      local n = #ops
      for i, op in ipairs(chunk) do
        ops[n + i] = op
      end
    end

    if type(stopped) ~= 'number' or stopped > len then
      complete = true
      break
    end

    pos = stopped + 1
  end

  if not complete then
    -- Some of the stream is not read
    pdf.flags.text_truncated = true
  end

  tobj.rspamd_ops = ops

  return ops
end

-- Fonts of a resources dictionary by their names
local function resources_fonts(task, pdf, resources)
  if type(resources) ~= 'table' then
    return nil
  end

  local fonts = maybe_dereference_object(resources.Font, pdf, task)

  if type(fonts) ~= 'table' then
    return nil
  end

  if fonts.rspamd_fonts then
    return fonts.rspamd_fonts
  end

  local res = {}

  for k, v in pairs(fonts.dict or fonts) do
    local font = maybe_dereference_object(v, pdf, task)

    if type(font) == 'table' then
      res[k] = font
    end
  end

  fonts.rspamd_fonts = res

  return res
end

local function own_resources(task, pdf, dict)
  local resources = maybe_dereference_object(dict.Resources, pdf, task)

  if type(resources) == 'table' and resources[1] ~= pdf_ref_marker then
    return resources.dict or resources
  end

  return nil
end

-- Pages in the order of the document.
--
-- The pages of a document are the leaves of the tree that its catalog points
-- to. An object that says it is a page and hangs on no tree is not shown by
-- any reader, and a file may carry any number of those before the real pages:
-- taking the pages in the order of the objects lets them use up the budget
-- of the text. Resources are inherited down the tree.
local function collect_pages(task, pdf)
  local pages = {}
  local seen = {}
  local nnodes = 0

  local function walk(node, resources, depth)
    if type(node) ~= 'table' or seen[node] or depth > 32 or nnodes >= 100000 then
      return
    end

    local dict = node.dict

    if type(dict) ~= 'table' then
      return
    end

    seen[node] = true
    nnodes = nnodes + 1
    resources = own_resources(task, pdf, dict) or resources

    local kids = maybe_dereference_object(dict.Kids, pdf, task)

    if type(kids) == 'table' and dict.Type ~= 'Page' then
      kids = kids.dict or kids

      for i = 1, #kids do
        walk(maybe_dereference_object(kids[i], pdf, task), resources, depth + 1)
      end
    elseif node.contents then
      pages[#pages + 1] = { obj = node, resources = resources }
    end
  end

  -- The catalog is what the last trailer or cross reference stream names
  local roots = {}

  for _, obj in ipairs(pdf.objects) do
    if obj.type == 'XRef' and type(obj.dict) == 'table' and obj.dict.Root then
      roots[#roots + 1] = { obj.start or 0, obj.dict.Root }
    end
  end

  for _, r in ipairs(pdf.trailer_roots or {}) do
    roots[#roots + 1] = r
  end

  table.sort(roots, function(a, b)
    return a[1] > b[1]
  end)

  for _, r in ipairs(roots) do
    local catalog = maybe_dereference_object(r[2], pdf, task)

    if type(catalog) == 'table' and type(catalog.dict) == 'table' then
      walk(maybe_dereference_object(catalog.dict.Pages, pdf, task), nil, 1)

      if #pages > 0 then
        return pages
      end
    end
  end

  -- No usable trailer: any catalog, the last one first
  for i = #pdf.objects, 1, -1 do
    local obj = pdf.objects[i]

    if obj.type == 'Catalog' and type(obj.dict) == 'table' then
      walk(maybe_dereference_object(obj.dict.Pages, pdf, task), nil, 1)

      if #pages > 0 then
        return pages
      end
    end
  end

  -- No tree at all, as in a file that is cut or damaged: whatever says it
  -- is a page
  for _, obj in ipairs(pdf.objects) do
    if obj.type == 'Page' and obj.contents and type(obj.dict) == 'table' then
      pages[#pages + 1] = { obj = obj, resources = own_resources(task, pdf, obj.dict) or obj.resources }
    end
  end

  return pages
end

local function search_text(task, pdf, mpart)
  -- Bytes of content read out of streams so far, each stream counted once
  pdf.text_size = 0
  -- Bytes of text that the pages have produced. A cmap can turn two bytes of
  -- content into over a hundred, and every page that shares a stream decodes
  -- it again, so the content read does not bound the text written
  local text_out = 0
  local text_pages = {}
  local invisible = 0

  for _, page in ipairs(collect_pages(task, pdf)) do
    local obj = page.obj

    if text_out >= config.max_extracted_text_size then
      pdf.flags.text_truncated = true
      lua_util.debugm(N, task, 'pdf: produced %s bytes of text, stop extracting', text_out)
      break
    end

    -- Text extraction inflates and reparses content streams, which is as
    -- expensive as anything the object phases do, so it observes the same
    -- deadline instead of running until it happens to finish
    if pdf_deadline_exceeded(pdf) then
      lua_util.debugm(N, task, 'pdf: timeout extracting text after spending %s seconds',
          pdf.timeout_processing)
      break
    end

    local builder = rspamd_pdf_text.builder(1024)
    local timed_out = false
    local nops = 0
    local nforms = 0
    -- The state of the text as the instructions change it
    local st = {
      size = 0, -- font size
      scale = 1, -- of the text matrix
      drawn = 0, -- character codes drawn since the last move
      have_pos = false,
      invisible = false,
    }
    local use_cmap = false

    local function select_font(fonts, fname)
      local font = fonts and fname and fonts[fname]
      local enc, cmap, simple = font_decoder_of(font, pdf, task)

      if cmap and simple then
        builder:set_cmap(cmap, enc or true)
        use_cmap = false
      elseif cmap then
        builder:set_cmap(cmap)
        use_cmap = true
      else
        builder:set_encoding(enc)
        use_cmap = false
      end
    end

    -- Replays instructions into the buffer, decoding each run with the
    -- encoding of the font that was current when it was drawn
    local function replay(ops, resources, depth)
      local fonts = resources_fonts(task, pdf, resources)
      local font_name

      for _, chunk in ipairs(ops) do
        nops = nops + 1

        if nops % 4096 == 0 and (pdf_deadline_exceeded(pdf) or builder:len() > config.max_extracted_text_size) then
          timed_out = pdf.timeout_processing ~= nil
          return false
        end

        if chunk == '\n' then
          -- Structural text produced by an operator, not by a glyph
          builder:add_char('\n')
          st.drawn = 0
        elseif chunk == text_object_start then
          st.have_pos = false
          st.scale = 1
          st.drawn = 0
        else
          local kind = chunk[1]

          if kind == '%text%' then
            if chunk[3] then
              builder:add_char('\n')
              st.drawn = 0
            end

            for _, piece in ipairs(chunk[2]) do
              if piece == false then
                -- A word gap from a TJ offset, not a character
                builder:add_char(' ')
              else
                if st.invisible then
                  invisible = invisible + #piece
                end

                if use_cmap then
                  -- A composite font emits multi byte codes, which look like
                  -- UTF-16 to a byte level heuristic; the cmap is authoritative
                  builder:add_encoded(piece)
                  st.drawn = st.drawn + builder:count_codes(piece)
                else
                  local decoded, is_utf8 = sanitize_pdf_text(piece)

                  if decoded and #decoded > 0 then
                    if is_utf8 then
                      builder:add_utf8(decoded)
                    else
                      builder:add_encoded(decoded)
                    end
                  end

                  st.drawn = st.drawn + #piece
                end
              end
            end
          elseif kind == '%font%' then
            font_name = chunk[2]
            st.size = math.abs(tonumber(chunk[3]) or 0)
            select_font(fonts, font_name)
          elseif kind == '%move%' then
            -- An offset from the start of the current line, in the units that
            -- the font size is in. A move down or up is a new line. A move
            -- along the line is a gap between words if it goes further than
            -- what was drawn takes, by the measure of an average glyph of half
            -- the font size: producers place words, parts of words and single
            -- glyphs this way, and only the first of these is a space
            local tx, ty = chunk[2], chunk[3]

            if ty ~= 0 then
              builder:add_char('\n')
            elseif tx > st.size * (0.5 * st.drawn + 0.3) or tx < -0.3 * st.size then
              if st.drawn > 0 then
                builder:add_char(' ')
              end
            end

            if st.have_pos then
              st.px = st.px + tx * st.scale
              st.py = st.py + ty * st.scale
            end

            st.drawn = 0
          elseif kind == '%matrix%' then
            -- An absolute position; the same reasoning, by the distance from
            -- the previous position, in the units of the page
            local a, b, e, f = chunk[2], chunk[3], chunk[4], chunk[5]
            local scale = math.sqrt(a * a + b * b)

            if scale == 0 then
              scale = 1
            end

            local size = st.size * scale

            if st.have_pos then
              local dx, dy = e - st.px, f - st.py

              if math.abs(dy) > 0.4 * size then
                builder:add_char('\n')
              elseif dx > size * (0.5 * st.drawn + 0.3) or dx < -0.3 * size then
                if st.drawn > 0 then
                  builder:add_char(' ')
                end
              end
            end

            st.px, st.py, st.scale = e, f, scale
            st.have_pos = true
            st.drawn = 0
          elseif kind == '%mode%' then
            -- Neither filled nor stroked: the text is there for a search or
            -- for a selection, and is not seen
            st.invisible = chunk[2] == 3 or chunk[2] == 7
          elseif kind == '%do%' and depth < 4 and nforms < 256 then
            -- A form is a content stream of its own that a page draws
            local xobjects = type(resources) == 'table' and
                maybe_dereference_object(resources.XObject, pdf, task)

            if type(xobjects) == 'table' then
              local form = maybe_dereference_object((xobjects.dict or xobjects)[chunk[2]], pdf, task)

              if type(form) == 'table' and form.stream and type(form.dict) == 'table' and
                  form.dict.Subtype == 'Form' then
                local form_ops = content_stream_ops(task, pdf, form)

                if form_ops and #form_ops > 0 then
                  nforms = nforms + 1

                  if not replay(form_ops, own_resources(task, pdf, form.dict) or resources, depth + 1) then
                    return false
                  end

                  -- Back to the font of this stream
                  select_font(fonts, font_name)
                end
              end
            end
          end
        end
      end

      return true
    end

    for _, tobj in ipairs(obj.contents) do
      local ops = content_stream_ops(task, pdf, tobj)

      if pdf.timeout_processing then
        timed_out = true
        break
      end

      if ops and not replay(ops, page.resources, 1) then
        break
      end
    end

    -- A page whose content ran out of time is dropped: half of the
    -- instructions decode into text that was never on the page
    if timed_out then
      lua_util.debugm(N, task, 'pdf: timeout extracting content of %s:%s after spending %s seconds',
          obj.major, obj.minor, pdf.timeout_processing)
      break
    end

    local res = tostring(builder:finish())

    if #res > 0 and config.text_quality_enabled and #res >= config.text_quality_min_length then
      -- Page-level confidence check before storing text
      local page_confidence = calculate_text_confidence(strip_invisible_chars(res))

      if page_confidence < config.text_quality_threshold then
        -- The page as a whole reads as garbage, which is what a font that
        -- cannot be decoded gives. The lines that read as text are kept
        -- nevertheless: garbage added to a page must not take its text away
        local kept = {}

        for line in res:gmatch('[^\n]+') do
          if #line >= config.text_quality_min_length and
              calculate_text_confidence(strip_invisible_chars(line)) >= config.text_quality_threshold then
            kept[#kept + 1] = line
          end
        end

        lua_util.debugm(N, task, 'low confidence page text for %s:%s (%.2f), %s lines are kept',
            obj.major, obj.minor, page_confidence, #kept)

        if #kept > 0 then
          kept[#kept + 1] = ''
          res = table.concat(kept, '\n')
        else
          res = ''
        end
      end
    end

    if text_out + #res > config.max_extracted_text_size then
      -- Keep what fits, cut between characters
      local keep = config.max_extracted_text_size - text_out

      while keep > 0 do
        local b = res:byte(keep + 1)
        if not b or b < 0x80 or b >= 0xc0 then
          break
        end
        keep = keep - 1
      end

      res = res:sub(1, keep)
      pdf.flags.text_truncated = true
    end

    text_out = text_out + #res

    if #res > 0 then
      obj.text = rspamd_text.fromstring(res)
      text_pages[#text_pages + 1] = obj.text
      lua_util.debugm(N, task, 'object %s:%s is parsed to: %s',
          obj.major, obj.minor, obj.text)
    end
  end

  pdf.text_pages = text_pages

  if invisible > 0 then
    -- Bytes of the strings drawn in the invisible mode
    pdf.flags.invisible_text = invisible
  end

  if task.inject_part and #text_pages > 0 then
    task:inject_part('text', text_pages, mpart)
  end
end

-- This function searches objects for `/URI` key and parses it's content
local function search_urls(task, pdf, mpart)
  local function recursive_object_traverse(obj, dict, rec)
    if rec > 10 then
      lua_util.debugm(N, task, 'object %s:%s recurses too much',
          obj.major, obj.minor)
      return
    end
    -- Defensive: ensure dict is actually a table we can iterate
    if type(dict) ~= 'table' then
      return
    end

    for k, v in pairs(dict) do
      if type(v) == 'table' then
        recursive_object_traverse(obj, v, rec + 1)
      elseif k == 'URI' then
        v = maybe_dereference_object(v, pdf, task)
        if type(v) == 'string' then
          -- Wrap URL creation in pcall to handle malformed URLs
          local url_ok, url = pcall(rspamd_url.create, task:get_mempool(), v, { 'content' })

          if url_ok and url then
            lua_util.debugm(N, task, 'found url %s in object %s:%s',
                v, obj.major, obj.minor)
            task:inject_url(url, mpart)
          end
        elseif type(v) == 'userdata' then
          -- Handle rspamd_text objects
          local str_ok, str_v = pcall(tostring, v)
          if str_ok and str_v then
            local url_ok, url = pcall(rspamd_url.create, task:get_mempool(), str_v, { 'content' })
            if url_ok and url then
              lua_util.debugm(N, task, 'found url %s in object %s:%s',
                  str_v, obj.major, obj.minor)
              task:inject_url(url, mpart)
            end
          end
        end
      end
    end
  end

  for _, obj in ipairs(pdf.objects) do
    if obj.dict and type(obj.dict) == 'table' then
      -- Wrap the traversal in pcall to handle any unexpected errors
      local ok, err = pcall(recursive_object_traverse, obj, obj.dict, 0)
      if not ok then
        lua_util.debugm(N, task, 'error traversing object %s:%s for URLs: %s',
            obj.major, obj.minor, err)
      end
    end
  end
end

local function process_pdf(input, mpart, task)
  if not config.enabled then
    -- Skip processing
    return {}
  end

  -- Matching and collecting the occurrences is where the time goes on a file
  -- built to waste it, so the deadline starts before that work, not after
  local start_ts = rspamd_util.get_ticks()
  local matches = pdf_trie:match(input)

  if matches then
    -- Temp object used to share data between pdf extraction methods
    local pdf_object = {
      tag = 'pdf',
      extract_text = extract_text_data,
      start_timestamp = start_ts,
      end_timestamp = start_ts + config.pdf_process_timeout,
      -- Bytes that the stream filters have produced, and those of them that
      -- went into the cmaps
      decoded_size = 0,
      cmap_size = 0,
      -- Shared with the output object
      flags = {},
    }
    -- Output object that excludes all internal stuff
    local pdf_output = lua_util.shallowcopy(pdf_object)
    local grouped_processors = {}
    for npat, matched_positions in pairs(matches) do
      if type(matched_positions) ~= 'table' then
        -- Skip malformed match results
        lua_util.debugm(N, task, 'skipping malformed trie match result: %s', type(matched_positions))
      else
        local index = pdf_indexes[npat]

        local proc_key, loc_npat = index[1], index[4]

        if not grouped_processors[proc_key] then
          grouped_processors[proc_key] = {
            processor_func = processors[proc_key],
            offsets = {},
          }
        end
        local proc = grouped_processors[proc_key]
        -- Fill offsets
        -- A marker can occur once per byte, and every occurrence costs a table
        -- here plus its share of the sort below, all of it before any of the
        -- per-object limits get a say
        local noffsets = #proc.offsets

        for _, pos in ipairs(matched_positions) do
          if noffsets >= config.max_pattern_matches then
            lua_util.debugm(N, task, "pdf: stop collecting %s matches at %s occurrences",
                proc_key, noffsets)
            break
          end

          noffsets = noffsets + 1
          proc.offsets[noffsets] = { pos, loc_npat }
        end
      end
    end

    for name, processor in pairs(grouped_processors) do
      local now = rspamd_util.get_ticks()

      if now >= pdf_object.end_timestamp then
        pdf_object.timeout_processing = now - pdf_object.start_timestamp
        lua_util.debugm(N, task, "pdf: timeout before processing group %s after spending %s seconds",
            name, pdf_object.timeout_processing)
        break
      end

      -- Sort by offset
      lua_util.debugm(N, task, "pdf: process group %s with %s matches",
          name, #processor.offsets)
      table.sort(processor.offsets, function(e1, e2)
        return e1[1] < e2[1]
      end)
      -- Wrap processor call in pcall to handle any errors gracefully
      local proc_ok, proc_err = pcall(processor.processor_func, input, task, processor.offsets, pdf_object, pdf_output)
      if not proc_ok then
        lua_util.debugm(N, task, "pdf: processor %s failed: %s", name, proc_err)
      end
    end

    if pdf_object.start_objects and pdf_object.end_objects then
      if #pdf_object.start_objects > config.max_pdf_objects then
        pdf_output.many_objects = #pdf_object.start_objects
        -- Trim
      end

      -- Postprocess objects - wrap in pcall for safety
      local pp_ok, pp_err = pcall(postprocess_pdf_objects, task, input, pdf_object)
      if not pp_ok then
        lua_util.debugm(N, task, "pdf: postprocess_pdf_objects failed: %s", pp_err)
      end
      pdf_output.objects = pdf_object.objects
      -- Skip text extraction if timeout occurred - partial results would be incorrect
      if config.text_extraction and not pdf_object.timeout_processing then
        -- Wrap in pcall for safety
        local st_ok, st_err = pcall(search_text, task, pdf_object, mpart)
        if not st_ok then
          lua_util.debugm(N, task, "pdf: search_text failed: %s", st_err)
        end
      end
      if config.url_extraction then
        -- Wrap in pcall for safety
        local su_ok, su_err = pcall(search_urls, task, pdf_object, mpart, pdf_output)
        if not su_ok then
          lua_util.debugm(N, task, "pdf: search_urls failed: %s", su_err)
        end
      end

      if config.js_fuzzy and pdf_object.scripts then
        pdf_output.fuzzy_hashes = {}
        if config.openaction_fuzzy_only then
          -- OpenAction only
          if pdf_object.openaction and pdf_object.openaction.bin_hash then
            if config.min_js_fuzzy and #pdf_object.openaction.data >= config.min_js_fuzzy then
              lua_util.debugm(N, task, "pdf: add fuzzy hash from openaction: %s; size = %s; object: %s:%s",
                  pdf_object.openaction.hash,
                  #pdf_object.openaction.data,
                  pdf_object.openaction.object.major, pdf_object.openaction.object.minor)
              table.insert(pdf_output.fuzzy_hashes, pdf_object.openaction.bin_hash)
            else
              lua_util.debugm(N, task, "pdf: skip fuzzy hash from JavaScript: %s, too short: %s",
                  pdf_object.openaction.hash, #pdf_object.openaction.data)
            end
          end
        else
          -- All hashes
          for h, sc in pairs(pdf_object.scripts) do
            if config.min_js_fuzzy and #sc.data >= config.min_js_fuzzy then
              lua_util.debugm(N, task, "pdf: add fuzzy hash from JavaScript: %s; size = %s; object: %s:%s",
                  sc.hash,
                  #sc.data,
                  sc.object.major, sc.object.minor)
              table.insert(pdf_output.fuzzy_hashes, h)
            else
              lua_util.debugm(N, task, "pdf: skip fuzzy hash from JavaScript: %s, too short: %s",
                  sc.hash, #sc.data)
            end
          end

        end
      end
    else
      pdf_output.flags.no_objects = true
    end

    -- Propagate from object to output
    if pdf_object.encrypted then
      pdf_output.encrypted = true
    end
    if pdf_object.scripts then
      pdf_output.scripts = true
    end
    -- The same goes for what the document does when it is opened
    pdf_output.text_pages = pdf_object.text_pages
    if pdf_object.has_openaction then
      pdf_output.openaction = true
    end
    if pdf_object.launch then
      pdf_output.launch = true
    end
    -- The output object is copied from the processing one before any work
    -- starts, so a deadline that trips during processing only ever lands on the
    -- processing object; without this PDF_TIMEOUT can never fire
    if pdf_object.timeout_processing then
      pdf_output.timeout_processing = pdf_object.timeout_processing
    end

    return pdf_output
  end
end

-- Processes the PDF trailer
-- The key of a trailer that tells that the file is encrypted, followed by
-- whatever can start its value
local encrypt_re = rspamd_regexp.create_cached([=[/\/Encrypt(?:[\s\x00<\[\(\/]|$)/]=])

local root_re = rspamd_regexp.create_cached([=[/\/Root\s+(\d+)\s+(\d+)\s+R\b/]=])

processors.trailer = function(input, task, positions, pdf_object, pdf_output)
  -- Defensive checks
  if not positions or #positions == 0 then
    return
  end

  -- A file has a trailer per update, and a reader starts from the one that
  -- `startxref` leads to, which is not always the last one in the file: a few
  -- bytes after the end of the file that look like a trailer must not hide
  -- the real one. The dictionary follows the keyword at once
  for i = math.max(1, #positions - 16), #positions do
    local pos = positions[i]

    if type(pos) == 'table' and pos[1] then
      local span_ok, head = pcall(input.span, input, pos[1],
          math.min(4096, #input - pos[1] + 1))

      if span_ok and head then
        -- The catalog that this trailer names
        local root = root_re:search(head, true, true)

        if root and root[1] then
          pdf_object.trailer_roots = pdf_object.trailer_roots or {}
          table.insert(pdf_object.trailer_roots, { pos[1],
                                                   { pdf_ref_marker, tostring(root[1][2]), tostring(root[1][3]) } })
        end
      end

      if i < #positions and span_ok and head and encrypt_re:match(head) then
        lua_util.debugm(N, task, "pdf: found encrypted trailer at %s", pos[1])
        pdf_output.encrypted = true
        pdf_object.encrypted = true
        break
      end
    end
  end
  local last_pos = positions[#positions]
  if not last_pos or type(last_pos) ~= 'table' or not last_pos[1] then
    return
  end

  local trailer_len = #input - last_pos[1]

  lua_util.debugm(N, task, 'pdf: process trailer at position %s (%s trailer bytes, %s total length)',
      last_pos[1], trailer_len, #input)

  -- The limit bounds the trailer itself, not where the file happens to put it:
  -- a large document with an ordinary trailer must still be checked for /Encrypt
  if trailer_len > config.max_pdf_trailer then
    pdf_output.long_trailer = trailer_len
    return
  end

  -- Wrap span extraction in pcall
  local span_ok, last_span = pcall(input.span, input, last_pos[1])
  if not span_ok or not last_span then
    lua_util.debugm(N, task, 'pdf: cannot extract trailer span')
    return
  end

  local lines_checked = 0
  -- Wrap lines iteration in pcall
  local iter_ok, iter_err = pcall(function()
    -- Lines are taken as spans rather than strings: stringifying copies a line
    -- of any length into lua before the guards here get to run, and a trailer
    -- with no newline in it is one line
    for line in last_span:lines() do
      local head = line

      if line:len() > config.max_pdf_trailer_line then
        head = line:span(1, config.max_pdf_trailer_line)
      end

      if encrypt_re:match(head) then
        lua_util.debugm(N, task, "pdf: found encrypted line in trailer: %s",
            head)
        pdf_output.encrypted = true
        pdf_object.encrypted = true
        break
      end
      lines_checked = lines_checked + 1

      if lines_checked > config.max_pdf_trailer_lines then
        lua_util.debugm(N, task, "pdf: trailer has too many lines, stop checking")
        pdf_output.long_trailer = trailer_len
        break
      end
    end
  end)
  if not iter_ok then
    lua_util.debugm(N, task, 'pdf: error iterating trailer lines: %s', iter_err)
  end
end

processors.suspicious = function(input, task, positions, pdf_object, pdf_output)
  -- Defensive check for positions
  if not positions or type(positions) ~= 'table' then
    return
  end

  local suspicious_factor = 0.0
  local nexec = 0
  local nencoded = 0
  local close_encoded = 0
  local last_encoded
  for _, match in ipairs(positions) do
    -- Defensive check for match structure
    if type(match) ~= 'table' or not match[1] or not match[2] then
      goto continue_suspicious
    end

    if match[2] == 1 then
      -- netsh
      suspicious_factor = suspicious_factor + 0.5
    elseif match[2] == 2 then
      nexec = nexec + 1
    elseif match[2] == 3 then
      -- Wrap input:sub in pcall for safety
      local sub_ok, enc_data = pcall(input.sub, input, match[1] - 2, match[1] - 1)
      local legal_escape = false

      if sub_ok and enc_data then
        -- Two hex digits
        enc_data = tonumber(tostring(enc_data), 16)

        if enc_data then
          -- Legit encode cases are non printable characters (e.g. spaces)
          if enc_data < 0x21 or enc_data >= 0x7f then
            legal_escape = true
          end
        end
      end

      if not legal_escape then
        nencoded = nencoded + 1

        if last_encoded then
          if match[1] - last_encoded < 8 then
            -- likely consecutive encoded chars, increase factor
            close_encoded = close_encoded + 1
          end
        end
        last_encoded = match[1]

      end
    end
    ::continue_suspicious::
  end

  if nencoded > 10 then
    suspicious_factor = suspicious_factor + nencoded / 10
  end
  if nexec > 1 then
    suspicious_factor = suspicious_factor + nexec / 2.0
  end
  if close_encoded > 4 and nencoded - close_encoded < 5 then
    -- Too many close encoded comparing to the total number of encoded characters
    suspicious_factor = suspicious_factor + 0.5
  end

  lua_util.debugm(N, task, 'pdf: found a suspicious patterns: %s exec, %s encoded (%s close), ' ..
      '%s final factor',
      nexec, nencoded, close_encoded, suspicious_factor)

  if suspicious_factor > 1.0 then
    suspicious_factor = 1.0
  end

  pdf_output.suspicious = suspicious_factor
end

local function generic_table_inserter(positions, pdf_object, output_key, delta)
  -- Defensive checks
  if not positions or type(positions) ~= 'table' then
    return
  end
  if not pdf_object or type(pdf_object) ~= 'table' then
    return
  end
  if not pdf_object[output_key] then
    pdf_object[output_key] = {}
  end
  local shift = #pdf_object[output_key]
  for i, pos in ipairs(positions) do
    -- Check pos is a table with valid first element
    if type(pos) == 'table' and pos[1] then
      pdf_object[output_key][i + shift] = pos[1] + (delta or 0)
    end
  end
end

processors.start_object = function(_, task, positions, pdf_object)
  -- The pattern ends at the last letter of the keyword, and the users of the
  -- positions count from the byte after it
  generic_table_inserter(positions, pdf_object, 'start_objects', 1)
end

processors.end_object = function(_, task, positions, pdf_object)
  generic_table_inserter(positions, pdf_object, 'end_objects', 1)
end

processors.start_stream = function(_, task, positions, pdf_object)
  generic_table_inserter(positions, pdf_object, 'start_streams')
end

processors.end_stream = function(_, task, positions, pdf_object)
  generic_table_inserter(positions, pdf_object, 'end_streams', 1)
end

exports.process = process_pdf
-- Exposed so that tests can lower a limit without waiting for the real one
exports.config = config

return exports