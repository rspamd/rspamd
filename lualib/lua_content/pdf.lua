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
local rspamd_url = require "rspamd_url"
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
  suspicious = {
    patterns = {
      [[netsh\s]],
      [[echo\s]],
      [=[\/[A-Za-z]*#\d\d[#A-Za-z<>/\s]]=], -- Hex encode obfuscation
    }
  },
  start_object = {
    patterns = {
      [=[[\r\n\0]\s*\d+\s+\d+\s+obj[\s<]]=]
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
local pdf_text_indexes = {}
local pdf_cmap_indexes = {}

local pdf_trie
local pdf_text_trie
local pdf_cmap_trie

local exports = {}

local config = {
  max_extraction_size = 512 * 1024,
  max_processing_size = 32 * 1024,
  text_extraction = false, -- NYI feature
  url_extraction = true,
  enabled = true,
  js_fuzzy = true, -- Generate fuzzy hashes from PDF javascripts
  min_js_fuzzy = 256, -- Minimum size of js to be considered as a fuzzy
  openaction_fuzzy_only = false, -- Generate fuzzy from all scripts
  max_pdf_objects = 10000, -- Maximum number of objects to be considered
  max_pdf_trailer = 10 * 1024 * 1024, -- Maximum trailer size (to avoid abuse)
  max_pdf_trailer_lines = 100, -- Maximum number of lines in pdf trailer
  pdf_process_timeout = 1.0, -- Timeout in seconds for processing
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
  if not pdf_cmap_trie then
    pdf_cmap_trie = compile_pats(pdf_cmap_patterns, pdf_cmap_indexes)
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
    local function ue_single(cc)
      if cc == '\\r' then
        return '\r'
      elseif cc == '\\n' then
        return '\n'
      else
        return cc:gsub(2, 2)
      end
    end
    -- simple unescape \char
    s = s:gsub('\\[^%d]', ue_single)
    -- unescape octal
    local function ue_octal(cc)
      -- Replace unknown stuff with '?'
      return string.char(tonumber(cc:sub(2), 8) or 63)
    end
    s = s:gsub('\\%d%d?%d?', ue_octal)

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
  grammar_elts.str = P{ "(" * C(((1 - S"()\\") + (P '\\' * 1) + V(1))^0) / pdf_string_unescape * ")" }
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

  return P("q") + P("Q") + P("h")
      + S("WSsFfBb") * P("*")^0 + P("n")

end
local function gen_graphics_binary()
  local P = lpeg.P
  local S = lpeg.S

  return S("gGwJjMi") +
      P("M") + P("ri") + P("gs") +
      P("CS") + P("cs") + P("sh")
end
local function gen_graphics_ternary()
  local P = lpeg.P
  local S = lpeg.S

  return P("d") + P("m") + S("lm")
end
local function gen_graphics_nary()
  local P = lpeg.P
  local S = lpeg.S

  return P("SC") + P("sc") + P("SCN") + P("scn") + P("k") + P("K") + P("re") + S("cvy") +
      P("RG") + P("rg")
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
  local ternary_ops = P("TD") + P("Td") + gen_graphics_ternary()
  local nary_op = P("Tm") + gen_graphics_nary()
  local text_binary_op = P("Tj") + P("TJ") + P("'")
  local text_quote_op = P('"')
  local font_op = P("Tf")

  return lpeg.P{
    "EXPR";
    EXPR = gen.ws^0 * lpeg.Ct(V("COMMAND")^0),
    COMMAND = (V("UNARY") + V("BINARY") + V("TERNARY") + V("NARY") + V("TEXT") +
        V("FONT") + gen.comment) * gen.ws^0,
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
    FONT = (V("FONT_ARG") * gen.ws^1 * (gen.number / 0) * gen.ws^1 * font_op),
    FONT_ARG = lpeg.Ct(lpeg.Cc("%font%") * gen.id),
    TEXT_ARG = lpeg.Ct(V("STRING")) + V("TEXT_ARRAY"),
    TEXT_ARRAY = "[" *
        lpeg.Ct(((gen.ws^0 * (gen.ws^0 * (gen.number / 0)^0 * gen.ws^0 * (gen.str + gen.hexstr)))^1)) * gen.ws^0 * "]",
  }
end


-- Call immediately on require
compile_tries()
config_module()
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
local function maybe_dereference_object(elt, pdf, task)
  if type(elt) == 'table' and elt[1] == '%REF%' then
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

-- Apply PDF stream filter
local function apply_pdf_filter(input, filt)
  if filt == 'FlateDecode' then
    return rspamd_util.inflate(input, config.max_extraction_size)
  end

  return nil
end

-- Conditionally apply a pipeline of stream filters and return uncompressed data
local function maybe_apply_filter(dict, data, pdf, task)
  local uncompressed = data

  if dict.Filter then
    local filt = dict.Filter
    if type(filt) == 'string' then
      filt = {filt}
    end

    if dict.DecodeParms then
      local decode_params = maybe_dereference_object(dict.DecodeParms, pdf, task)

      if type(decode_params) == 'table' then
        if decode_params.Predictor then
          return nil,'predictor exists'
        end
      end
    end

    for _,f in ipairs(filt) do
      uncompressed = apply_pdf_filter(uncompressed, f)

      if not uncompressed then break end
    end
  end

  return uncompressed,nil
end

-- Conditionally extract stream data from object and attach it as obj.uncompressed
local function maybe_extract_object_stream(obj, pdf, task)
  if pdf.encrypted then
    -- TODO add decryption some day
    return nil
  end
  local dict = obj.dict
  if dict.Length and type(obj.stream) == 'table' then
    local len = math.min(obj.stream.len,
        tonumber(maybe_dereference_object(dict.Length, pdf, task)) or 0)
    local real_stream = obj.stream.data:span(1, len)

    local uncompressed,filter_err = maybe_apply_filter(dict, real_stream, pdf, task)

    if uncompressed then
      obj.uncompressed = uncompressed
      lua_util.debugm(N, task, 'extracted object %s:%s: (%s -> %s)',
          obj.major, obj.minor, len, uncompressed:len())
      return obj.uncompressed
    else
      lua_util.debugm(N, task, 'cannot extract object %s:%s; len = %s; filter = %s: %s',
          obj.major, obj.minor, len, dict.Filter, filter_err)
    end
  end
end


local function parse_object_grammar(obj, task, pdf)
  -- Parse grammar
  local obj_dict_span
  if obj.stream then
    obj_dict_span = obj.data:span(1, obj.stream.start - obj.start)
  else
    obj_dict_span = obj.data
  end

  if obj_dict_span:len() < config.max_processing_size then
    local ret,obj_or_err = pcall(pdf_outer_grammar.match, pdf_outer_grammar, obj_dict_span)

    if ret then
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
      lua_util.debugm(N, task, 'object %s:%s cannot be parsed: %s',
          obj.major, obj.minor, obj_or_err)
    end
  else
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

-- Forward declaration
local process_dict

-- This function processes javascript string and returns JS hash and JS rspamd_text
local function process_javascript(task, pdf, js, obj)
  local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
  if type(js) == 'string' then
    js = rspamd_text.fromstring(js):oneline()
  elseif type(js) == 'userdata' then
    js = js:oneline()
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
  if not (obj.js or obj.launch) and (obj.dict and obj.dict.JS) then
    local js = maybe_dereference_object(obj.dict.JS, pdf, task)

    if js then
      if type(js) == 'table' then
        local extracted_js = maybe_extract_object_stream(js, pdf, task)

        if not extracted_js then
          lua_util.debugm(N, task, 'invalid type for javascript from %s:%s: %s',
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
        lua_util.debugm(N, task, 'invalid type for javascript from %s:%s: %s',
            obj.major, obj.minor, js)
      end
    elseif obj.dict.F then
      local launch = maybe_dereference_object(obj.dict.F, pdf, task)

      if launch then
        if type(launch) == 'string' then
          obj.launch = rspamd_text.fromstring(launch):exclude_chars('%n%c')
          lua_util.debugm(N, task, 'extracted launch from %s:%s: %s',
              obj.major, obj.minor, obj.launch)
        elseif type(launch) == 'userdata' then
          obj.launch = launch:exclude_chars('%n%c')
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

      if action and type(action) == 'table' then
        -- This also processes action js (if not already processed)
        process_dict(task, pdf, action, action.dict)
        if action.js then
          lua_util.debugm(N, task, 'found openaction JS in %s:%s: %s',
              obj.major, obj.minor, action.js)
          pdf.openaction = action.js
          action.js.object = obj
        elseif action.launch then
          lua_util.debugm(N, task, 'found openaction launch in %s:%s: %s',
              obj.major, obj.minor, action.launch)
          pdf.launch = action.launch
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

process_dict = function(task, pdf, obj, dict)
  if not obj.type and type(dict) == 'table' then
    if dict.Type and type(dict.Type) == 'string' then
      -- Common stuff
      obj.type = dict.Type
    end

    if not obj.type then

      if obj.dict.S and obj.dict.JS then
        obj.type = 'Javascript'
        lua_util.debugm(N, task, 'implicit type for Javascript object %s:%s',
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
      if contents[1] == '%REF%' then
        -- Single reference
        contents = {contents}
      end
      obj.contents = {}

      for _,c in ipairs(contents) do
        local cobj = maybe_dereference_object(c, pdf, task)
        if cobj and type(cobj) == 'table' then
          obj.contents[#obj.contents + 1] = cobj
          cobj.parent = obj
          cobj.type = 'content'
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
        obj.resources = {}
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



--[[Disabled fonts extraction
     local fonts = obj.resources.Font
     if fonts and type(fonts) == 'table' then
      obj.fonts = {}
      for k,v in pairs(fonts) do
        obj.fonts[k] = maybe_dereference_object(v, pdf, task)

        if obj.fonts[k] then
          local font = obj.fonts[k]

          if config.text_extraction then
            process_font(task, pdf, font, k)
            lua_util.debugm(N, task, 'found font "%s" for object %s:%s -> %s',
                k, obj.major, obj.minor, font)
          end
        end
      end
    end
]]

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
            lua_util.debugm(N, task, 'invalid type for javascript from %s:%s: %s',
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
          lua_util.debugm(N, task, 'invalid type for javascript from %s:%s: %s',
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
    compound_obj_grammar = gen.ws^0 * (gen.comment * gen.ws^1)^0 *
        lpeg.Ct(lpeg.Ct(gen.number * gen.ws^1 * gen.number * gen.ws^0)^1)
  end

  return compound_obj_grammar
end
local function pdf_compound_object_unpack(_, uncompressed, pdf, task, first)
  -- First, we need to parse data line by line likely to find a line
  -- that consists of pairs of numbers
  compound_obj_grammar_gen()
  local elts = compound_obj_grammar:match(uncompressed)
  if elts and #elts > 0 then
    lua_util.debugm(N, task, 'compound elts (chunk length %s): %s',
        #uncompressed, elts)

    for i,pair in ipairs(elts) do
      local obj_number,offset = pair[1], pair[2]

      offset = offset + first
      if offset < #uncompressed then
        local span_len
        if i == #elts then
          span_len = #uncompressed - offset
        else
          span_len = (elts[i + 1][2] + first) - offset
        end

        if span_len > 0 and offset + span_len <= #uncompressed then
          local obj = {
            major = obj_number,
            minor = 0, -- Implicit
            data = uncompressed:span(offset + 1, span_len),
            ref = obj_ref(obj_number, 0)
          }
          parse_object_grammar(obj, task, pdf)

          if obj.dict then
            pdf.objects[#pdf.objects + 1] = obj
          end
        else
          lua_util.debugm(N, task, 'invalid span_len for compound object %s:%s; offset = %s, len = %s',
              pair[1], pair[2], offset + span_len, #uncompressed)
        end
      end
    end
  end
end

-- PDF 1.5 ObjStmt
local function extract_pdf_compound_objects(task, pdf)
  for i,obj in ipairs(pdf.objects or {}) do
    if i > 0 and i % 100 == 0 then
      local now = rspamd_util.get_ticks()

      if now >= pdf.end_timestamp then
        pdf.timeout_processing = now - pdf.start_timestamp

        lua_util.debugm(N, task, 'pdf: timeout processing compound objects after spending %s seconds, ' ..
            '%s elements processed',
            pdf.timeout_processing, i)
        break
      end
    end
    if obj.stream and obj.dict and type(obj.dict) == 'table' then
      local t = obj.dict.Type
      if t and t == 'ObjStm' then
        -- We are in troubles sir...
        local nobjs = tonumber(maybe_dereference_object(obj.dict.N, pdf, task))
        local first = tonumber(maybe_dereference_object(obj.dict.First, pdf, task))

        if nobjs and first then
          --local extend = maybe_dereference_object(obj.dict.Extends, pdf, task)
          lua_util.debugm(N, task, 'extract ObjStm with %s objects (%s first) %s extend',
              nobjs, first, obj.dict.Extends)

          local uncompressed = maybe_extract_object_stream(obj, pdf, task)

          if uncompressed then
            pdf_compound_object_unpack(obj, uncompressed, pdf, task, first)
          end
        else
          lua_util.debugm(N, task, 'ObjStm object %s:%s has bad dict: %s',
              obj.major, obj.minor, obj.dict)
        end
      end
    end
  end
end

-- This function arranges starts and ends of all objects and process them into initial
-- set of objects
local function extract_outer_objects(task, input, pdf)
  local start_pos, end_pos = 1, 1
  local max_start_pos, max_end_pos
  local obj_count = 0

  max_start_pos = math.min(config.max_pdf_objects, #pdf.start_objects)
  max_end_pos = math.min(config.max_pdf_objects, #pdf.end_objects)
  lua_util.debugm(N, task, "pdf: extract objects from %s start positions and %s end positions",
      max_start_pos, max_end_pos)

  while start_pos <= max_start_pos and end_pos <= max_end_pos do
    local first = pdf.start_objects[start_pos]
    local last = pdf.end_objects[end_pos]

    -- 7 is length of `endobj\n`
    if first + 6 < last then
      local len = last - first - 6

      -- Also get the starting span and try to match it versus obj re to get numbers
      local obj_line_potential = first - 32
      if obj_line_potential < 1 then obj_line_potential = 1 end
      local prev_obj_end = pdf.end_objects[end_pos - 1]
      if end_pos > 1 and prev_obj_end >= obj_line_potential and prev_obj_end < first then
        obj_line_potential = prev_obj_end + 1
      end

      local obj_line_span = input:span(obj_line_potential, first - obj_line_potential + 1)
      local matches = object_re:search(obj_line_span, true, true)

      if matches and matches[1] then
        local nobj = {
          start = first,
          len = len,
          data = input:span(first, len),
          major = tonumber(matches[1][2]),
          minor = tonumber(matches[1][3]),
        }
        pdf.objects[obj_count + 1] = nobj
        if nobj.major and nobj.minor then
          -- Add reference
          local ref = obj_ref(nobj.major, nobj.minor)
          nobj.ref = ref -- Our internal reference
          pdf.ref[ref] = nobj
        end
      end

      obj_count = obj_count + 1
      start_pos = start_pos + 1
      end_pos = end_pos + 1
    elseif first > last then
      end_pos = end_pos + 1
    else
      start_pos = start_pos + 1
      end_pos = end_pos + 1
    end
  end
end

-- This function attaches streams to objects and processes outer pdf grammar
local function attach_pdf_streams(task, input, pdf)
  if pdf.start_streams and pdf.end_streams then
    local start_pos, end_pos = 1, 1
    local max_start_pos, max_end_pos

    max_start_pos = math.min(config.max_pdf_objects, #pdf.start_streams)
    max_end_pos = math.min(config.max_pdf_objects, #pdf.end_streams)

    for _,obj in ipairs(pdf.objects) do
      while start_pos <= max_start_pos and end_pos <= max_end_pos do
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
            local chr = input:byte(first)
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
    end
  end
end

-- Processes PDF objects: extracts streams, object numbers, process outer grammar,
-- augment object types
local function postprocess_pdf_objects(task, input, pdf)
  pdf.objects = {} -- objects table
  pdf.ref = {} -- references table
  extract_outer_objects(task, input, pdf)

  -- Now we have objects and we need to attach streams that are in bounds
  attach_pdf_streams(task, input, pdf)
  -- Parse grammar for outer objects
  for i,obj in ipairs(pdf.objects) do
    if i > 0 and i % 100 == 0 then
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
        process_xref(task, pdf, obj)
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
  for i,obj in ipairs(pdf.objects) do
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
      process_dict(task, pdf, obj, obj.dict)
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
    elseif first > last then
      end_pos = end_pos + 1
    else
      -- Not ordered properly!
      break
    end
  end
end

local function search_text(task, pdf)
  for _,obj in ipairs(pdf.objects) do
    if obj.type == 'Page' and obj.contents then
      local text = {}
      for _,tobj in ipairs(obj.contents) do
        maybe_extract_object_stream(tobj, pdf, task)
        local matches = pdf_text_trie:match(tobj.uncompressed or '')
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

            bl.data = tobj.uncompressed:span(bl.start, bl.len)
            --lua_util.debugm(N, task, 'extracted text from object %s:%s: %s',
            --    tobj.major, tobj.minor, bl.data)

            if bl.len < config.max_processing_size then
              local ret,obj_or_err = pcall(pdf_text_grammar.match, pdf_text_grammar,
                  bl.data)

              if ret then
                text[#text + 1] = obj_or_err
                lua_util.debugm(N, task, 'attached %s from content object %s:%s to %s:%s',
                    obj_or_err, tobj.major, tobj.minor, obj.major, obj.minor)
              else
                lua_util.debugm(N, task, 'object %s:%s cannot be parsed: %s',
                    obj.major, obj.minor, obj_or_err)
              end

            end
          end
        end
      end

      -- Join all text data together
      if #text > 0 then
        obj.text = rspamd_text.fromtable(text)
        lua_util.debugm(N, task, 'object %s:%s is parsed to: %s',
            obj.major, obj.minor, obj.text)
      end
    end
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

    for k,v in pairs(dict) do
      if type(v) == 'table' then
        recursive_object_traverse(obj, v, rec + 1)
      elseif k == 'URI' then
        v = maybe_dereference_object(v, pdf, task)
        if type(v) == 'string' then
          local url =  rspamd_url.create(task:get_mempool(), v, {'content'})

          if url then
            lua_util.debugm(N, task, 'found url %s in object %s:%s',
                v, obj.major, obj.minor)
            task:inject_url(url, mpart)
          end
        end
      end
    end
  end

  for _,obj in ipairs(pdf.objects) do
    if obj.dict and type(obj.dict) == 'table' then
      recursive_object_traverse(obj, obj.dict, 0)
    end
  end
end

local function process_pdf(input, mpart, task)

  if not config.enabled then
    -- Skip processing
    return {}
  end

  local matches = pdf_trie:match(input)

  if matches then
    local start_ts = rspamd_util.get_ticks()
    -- Temp object used to share data between pdf extraction methods
    local pdf_object = {
      tag = 'pdf',
      extract_text = extract_text_data,
      start_timestamp = start_ts,
      end_timestamp = start_ts + config.pdf_process_timeout,
    }
    -- Output object that excludes all internal stuff
    local pdf_output = lua_util.shallowcopy(pdf_object)
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
      processor.processor_func(input, task, processor.offsets, pdf_object, pdf_output)
    end

    pdf_output.flags = {}

    if pdf_object.start_objects and pdf_object.end_objects then
      if #pdf_object.start_objects > config.max_pdf_objects then
        pdf_output.many_objects = #pdf_object.start_objects
        -- Trim
      end

      -- Postprocess objects
      postprocess_pdf_objects(task, input, pdf_object)
      if config.text_extraction then
        search_text(task, pdf_object, pdf_output)
      end
      if config.url_extraction then
        search_urls(task, pdf_object, mpart, pdf_output)
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
              lua_util.debugm(N, task, "pdf: skip fuzzy hash from Javascript: %s, too short: %s",
                  pdf_object.openaction.hash, #pdf_object.openaction.data)
            end
          end
        else
          -- All hashes
          for h,sc in pairs(pdf_object.scripts) do
            if config.min_js_fuzzy and #sc.data >= config.min_js_fuzzy then
              lua_util.debugm(N, task, "pdf: add fuzzy hash from Javascript: %s; size = %s; object: %s:%s",
                  sc.hash,
                  #sc.data,
                  sc.object.major, sc.object.minor)
              table.insert(pdf_output.fuzzy_hashes, h)
            else
              lua_util.debugm(N, task, "pdf: skip fuzzy hash from Javascript: %s, too short: %s",
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

    return pdf_output
  end
end

-- Processes the PDF trailer
processors.trailer = function(input, task, positions, pdf_object, pdf_output)
  local last_pos = positions[#positions]

  lua_util.debugm(N, task, 'pdf: process trailer at position %s (%s total length)',
      last_pos, #input)

  if last_pos[1] > config.max_pdf_trailer then
    pdf_output.long_trailer = #input - last_pos[1]
    return
  end

  local last_span = input:span(last_pos[1])
  local lines_checked = 0
  for line in last_span:lines(true) do
    if line:find('/Encrypt ') then
      lua_util.debugm(N, task, "pdf: found encrypted line in trailer: %s",
          line)
      pdf_output.encrypted = true
      pdf_object.encrypted = true
      break
    end
    lines_checked = lines_checked + 1

    if lines_checked > config.max_pdf_trailer_lines then
      lua_util.debugm(N, task, "pdf: trailer has too many lines, stop checking")
      pdf_output.long_trailer = #input - last_pos[1]
      break
    end
  end
end

processors.suspicious = function(input, task, positions, pdf_object, pdf_output)
  local suspicious_factor = 0.0
  local nexec = 0
  local nencoded = 0
  local close_encoded = 0
  local last_encoded
  for _,match in ipairs(positions) do
    if match[2] == 1 then
      -- netsh
      suspicious_factor = suspicious_factor + 0.5
    elseif match[2] == 2 then
      nexec = nexec + 1
    elseif match[2] == 3 then
      local enc_data = input:sub(match[1] - 2, match[1] - 1)
      local legal_escape = false

      if enc_data then
        enc_data = enc_data:strtoul()

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

local function generic_table_inserter(positions, pdf_object, output_key)
  if not pdf_object[output_key] then
    pdf_object[output_key] = {}
  end
  local shift = #pdf_object[output_key]
  for i,pos in ipairs(positions) do
    pdf_object[output_key][i + shift] = pos[1]
  end
end

processors.start_object = function(_, task, positions, pdf_object)
  generic_table_inserter(positions, pdf_object, 'start_objects')
end

processors.end_object = function(_, task, positions, pdf_object)
  generic_table_inserter(positions, pdf_object, 'end_objects')
end

processors.start_stream = function(_, task, positions, pdf_object)
  generic_table_inserter(positions, pdf_object, 'start_streams')
end

processors.end_stream = function(_, task, positions, pdf_object)
  generic_table_inserter(positions, pdf_object, 'end_streams')
end

exports.process = process_pdf

return exports