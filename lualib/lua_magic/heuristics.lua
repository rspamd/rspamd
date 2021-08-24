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
local zip_trie
local zip_patterns = {
  -- https://lists.oasis-open.org/archives/office/200505/msg00006.html
  odt = {
    [[mimetypeapplication/vnd\.oasis\.opendocument\.text]],
    [[mimetypeapplication/vnd\.oasis\.opendocument\.image]],
    [[mimetypeapplication/vnd\.oasis\.opendocument\.graphic]]
  },
  ods = {
    [[mimetypeapplication/vnd\.oasis\.opendocument\.spreadsheet]],
    [[mimetypeapplication/vnd\.oasis\.opendocument\.formula]],
    [[mimetypeapplication/vnd\.oasis\.opendocument\.chart]]
  },
  odp = {[[mimetypeapplication/vnd\.oasis\.opendocument\.presentation]]},
  epub = {[[epub\+zip]]},
  asice = {[[mimetypeapplication/vnd\.etsi\.asic-e\+zipPK]]},
  asics = {[[mimetypeapplication/vnd\.etsi\.asic-s\+zipPK]]},
}

local txt_trie
local txt_patterns = {
  html = {
    {[[(?i)<html\b]], 32},
    {[[(?i)<script\b]], 20}, -- Commonly used by spammers
    {[[<script\s+type="text\/javascript">]], 31}, -- Another spammy pattern
    {[[(?i)<\!DOCTYPE HTML\b]], 33},
    {[[(?i)<body\b]], 20},
    {[[(?i)<table\b]], 20},
    {[[(?i)<a\b]], 10},
    {[[(?i)<p\b]], 10},
    {[[(?i)<div\b]], 10},
    {[[(?i)<span\b]], 10},
  },
  csv = {
    {[[(?:[-a-zA-Z0-9_]+\s*,){2,}(?:[-a-zA-Z0-9_]+,?[ ]*[\r\n])]], 20}
  },
  ics = {
    {[[^BEGIN:VCALENDAR\r?\n]], 40},
  },
  vcf = {
    {[[^BEGIN:VCARD\r?\n]], 40},
  },
  xml = {
    {[[<\?xml\b.+\?>]], 31},
  }
}

-- Used to match pattern index and extension
local msoffice_clsid_indexes = {}
local msoffice_patterns_indexes = {}
local zip_patterns_indexes = {}
local txt_patterns_indexes = {}

local exports = {}

local function compile_tries()
  local default_compile_flags = bit.bor(rspamd_trie.flags.re,
      rspamd_trie.flags.dot_all,
      rspamd_trie.flags.single_match,
      rspamd_trie.flags.no_start)
  local function compile_pats(patterns, indexes, transform_func, compile_flags)
    local strs = {}
    for ext,pats in pairs(patterns) do
      for _,pat in ipairs(pats) do
        -- These are utf16 strings in fact...
        strs[#strs + 1] = transform_func(pat)
        indexes[#indexes + 1] = {ext, pat}
      end
    end

    return rspamd_trie.create(strs, compile_flags or default_compile_flags)
  end

  if not msoffice_trie then
    -- Directory names
    local function msoffice_pattern_transform(pat)
      return '^' ..
          table.concat(
              fun.totable(
                  fun.map(function(c) return c .. [[\x{00}]] end,
                      fun.iter(pat))))
    end
    local function msoffice_clsid_transform(pat)
      local hex_table = {}
      for i=1,#pat,2 do
        local subc = pat:sub(i, i + 1)
        hex_table[#hex_table + 1] = string.format('\\x{%s}', subc)
      end

      return '^' .. table.concat(hex_table) .. '$'
    end
    -- Directory entries
    msoffice_trie = compile_pats(msoffice_patterns, msoffice_patterns_indexes,
        msoffice_pattern_transform)
    -- Clsids
    msoffice_trie_clsid = compile_pats(msoffice_clsids, msoffice_clsid_indexes,
        msoffice_clsid_transform)
    -- Misc zip patterns at the initial fragment
    zip_trie = compile_pats(zip_patterns, zip_patterns_indexes,
        function(pat) return pat end)
    -- Text patterns at the initial fragment
    txt_trie = compile_pats(txt_patterns, txt_patterns_indexes,
        function(pat_tbl) return pat_tbl[1] end,
        bit.bor(rspamd_trie.flags.re,
            rspamd_trie.flags.dot_all,
            rspamd_trie.flags.no_start))
  end
end

-- Call immediately on require
compile_tries()

local function detect_ole_format(input, log_obj, _, part)
  local inplen = #input
  if inplen < 0x31 + 4 then
    lua_util.debugm(N, log_obj, "short length: %s", inplen)
    return nil
  end

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
    local dtype = input:byte(offset + 66)
    lua_util.debugm(N, log_obj, "dtype: %s, offset: %s", dtype, offset)

    if dtype then
      if dtype == 5 then
        -- Extract clsid
        local matches = msoffice_trie_clsid:match(input:span(offset + 80, 16))
        if matches then
          for n,_ in pairs(matches) do
            if msoffice_clsid_indexes[n] then
              lua_util.debugm(N, log_obj, "found valid clsid for %s",
                  msoffice_clsid_indexes[n][1])
              return true,msoffice_clsid_indexes[n][1]
            end
          end
        end
        return true,nil
      elseif dtype == 2 then
        local matches = msoffice_trie:match(input:span(offset, 64))
        if matches then
          for n,_ in pairs(matches) do
            if msoffice_patterns_indexes[n] then
              return true,msoffice_patterns_indexes[n][1]
            end
          end
        end
        return true,nil
      elseif dtype >= 0 and dtype < 5 then
        -- Bad type
        return true,nil
      end
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

local function process_top_detected(res)
  local extensions = lua_util.keys(res)

  if #extensions > 0 then
    table.sort(extensions, function(ex1, ex2)
      return res[ex1] > res[ex2]
    end)

    return extensions[1],res[extensions[1]]
  end

  return nil
end

local function detect_archive_flaw(part, arch, log_obj, _)
  local arch_type = arch:get_type()
  local res = {
    docx = 0,
    xlsx = 0,
    pptx = 0,
    jar = 0,
    odt = 0,
    odp = 0,
    ods = 0,
    apk = 0,
  } -- ext + confidence pairs

  -- General msoffice patterns
  local function add_msoffice_confidence(incr)
    res.docx = res.docx + incr
    res.xlsx = res.xlsx + incr
    res.pptx = res.pptx + incr
  end

  if arch_type == 'zip' then
    -- Find specific files/folders in zip file
    local files = arch:get_files(100) or {}
    for _,file in ipairs(files) do
      if file == '[Content_Types].xml' then
        add_msoffice_confidence(10)
      elseif file:sub(1, 3) == 'xl/' then
        res.xlsx = res.xlsx + 30
      elseif file:sub(1, 5) == 'word/' then
        res.docx = res.docx + 30
      elseif file:sub(1, 4) == 'ppt/' then
        res.pptx = res.pptx + 30
      elseif file == 'META-INF/MANIFEST.MF' then
        res.jar = res.jar + 40
      elseif file == 'AndroidManifest.xml' then
        res.apk = res.apk + 60
      end
    end

    local ext,weight = process_top_detected(res)

    if weight >= 40 then
      return ext,weight
    end

    -- Apply misc Zip detection logic
    local content = part:get_content()

    if #content > 128 then
      local start_span = content:span(1, 128)

      local matches = zip_trie:match(start_span)
      if matches then
        for n,_ in pairs(matches) do
          if zip_patterns_indexes[n] then
            lua_util.debugm(N, log_obj, "found zip pattern for %s",
                zip_patterns_indexes[n][1])
            return zip_patterns_indexes[n][1],40
          end
        end
      end
    end
  end

  return arch_type:lower(),40
end

exports.mime_part_heuristic = function(part, log_obj, _)
  if part:is_archive() then
    local arch = part:get_archive()
    return detect_archive_flaw(part, arch, log_obj)
  end

  return nil
end

exports.text_part_heuristic = function(part, log_obj, _)
  -- We get some span of data and check it
  local function is_span_text(span)
    -- We examine 8 bit content, and we assume it might be localized text
    -- if it has more than 3 subsequent 8 bit characters
    local function rough_8bit_check(bytes, idx, remain, len)
      local b = bytes[idx]
      local n8bit = 0

      while b >= 127 and idx < len do
        -- utf8 part
        if bit.band(b, 0xe0) == 0xc0 and remain > 1 and
                bit.band(bytes[idx + 1], 0xc0) == 0x80 then
          return true,1
        elseif bit.band(b, 0xf0) == 0xe0 and remain > 2 and
                bit.band(bytes[idx + 1], 0xc0) == 0x80 and
                bit.band(bytes[idx + 2], 0xc0) == 0x80 then
          return true,2
        elseif bit.band(b, 0xf8) == 0xf0 and remain > 3 and
                bit.band(bytes[idx + 1], 0xc0) == 0x80 and
                bit.band(bytes[idx + 2], 0xc0) == 0x80 and
                bit.band(bytes[idx + 3], 0xc0) == 0x80 then
          return true,3
        end

        n8bit = n8bit + 1
        idx = idx + 1
        b = bytes[idx]
        remain = remain - 1
      end

      if n8bit >= 3 then
        return true,n8bit
      end

      return false,0
    end

    -- Convert to string as LuaJIT can optimise string.sub (and fun.iter) but not C calls
    local tlen = #span
    local non_printable = 0
    local bytes = span:bytes()
    local i = 1
    repeat
      local b = bytes[i]

      if (b < 0x20) and not (b == 0x0d or b == 0x0a or b == 0x09) then
        non_printable = non_printable + 1
      elseif b >= 127 then
        local c,nskip = rough_8bit_check(bytes, i, tlen - i, tlen)

        if not c then
          non_printable = non_printable + 1
        else
          i = i + nskip
        end
      end
      i = i + 1
    until i > tlen

    lua_util.debugm(N, log_obj, "text part check: %s printable, %s non-printable, %s total",
        tlen - non_printable, non_printable, tlen)
    if non_printable / tlen > 0.0078125 then
      return false
    end

    return true
  end

  local parent = part:get_parent()

  if parent then
    local parent_type,parent_subtype = parent:get_type()

    if parent_type == 'multipart' and parent_subtype == 'encrypted' then
      -- Skip text heuristics for encrypted parts
      lua_util.debugm(N, log_obj, "text part check: parent is encrypted, not a text part")

      return false
    end
  end

  local content = part:get_content()
  local mtype,msubtype = part:get_type()
  local clen = #content
  local is_text

  if clen > 0 then
    if clen > 80 * 3 then
      -- Use chunks
      is_text = is_span_text(content:span(1, 160)) and is_span_text(content:span(clen - 80, 80))
    else
      is_text = is_span_text(content)
    end

    if is_text and mtype ~= 'message' then
      -- Try patterns
      local span_len = math.min(4096, clen)
      local start_span = content:span(1, span_len)
      local matches = txt_trie:match(start_span)
      local res = {}
      local fname = part:get_filename()

      if matches then
        -- Require at least 2 occurrences of those patterns
        for n,positions in pairs(matches) do
          local ext,weight = txt_patterns_indexes[n][1], txt_patterns_indexes[n][2][2]
          if ext then
            res[ext] = (res[ext] or 0) + weight * #positions
            lua_util.debugm(N, log_obj, "found txt pattern for %s: %s, total: %s; %s/%s announced",
                ext, weight * #positions, res[ext], mtype, msubtype)
          end
        end

        if res.html and res.html >= 40  then
          -- HTML has priority over something like js...
          return 'html', res.html
        end

        local ext, weight = process_top_detected(res)

        if weight then
          if weight >= 40 then
            return ext, weight
          elseif fname and weight >= 20 then
            return ext, weight
          end
        end
      end

      -- Content type stuff
      if (mtype == 'text' or mtype == 'application') and
              (msubtype == 'html' or msubtype == 'xhtml+xml') then
        return 'html', 21
      end

      -- Extension stuff
      local function has_extension(file, ext)
        local ext_len = ext:len()
        return file:len() > ext_len + 1
                and file:sub(-ext_len):lower() == ext
                and file:sub(-ext_len - 1, -ext_len - 1) == '.'
      end

      if fname and (has_extension(fname, 'htm') or has_extension(fname, 'html')) then
        return 'html',21
      end

      if mtype ~= 'text' then
        -- Do not treat non text patterns as text
        return nil
      end

      return 'txt',40
    end
  end
end

exports.pdf_format_heuristic = function(input, log_obj, pos, part)
  local weight = 10
  local ext = string.match(part:get_filename() or '', '%.([^.]+)$')
  -- If we found a pattern at the beginning
  if pos <= 10 then
    weight = weight + 30
  end
  -- If the announced extension is `pdf`
  if ext and ext:lower() == 'pdf' then
    weight = weight + 30
  end

  return 'pdf',weight
end

exports.pe_part_heuristic = function(input, log_obj, pos, part)
  if not input then
    return
  end

  -- pe header should start at the offset that is placed in msdos header at position 60..64
  local pe_ptr_bin = input:sub(60, 64)
  if #pe_ptr_bin ~= 4 then
    return
  end

  -- it is an LE 32 bit integer
  local pe_ptr = rspamd_util.unpack("<I4", pe_ptr_bin)
  -- if pe header magic matches the offset, it is definitely a PE file
  if pe_ptr ~= pos then
    return
  end

  return 'exe',30
end

return exports
