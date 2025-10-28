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
-- @module lua_mime
-- This module contains helper functions to modify mime parts
--]]

local logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_text = require "rspamd_text"
local ucl = require "ucl"

local exports = {}

local function newline(task)
  local t = task:get_newlines_type()

  if t == 'cr' then
    return '\r'
  elseif t == 'lf' then
    return '\n'
  end

  return '\r\n'
end

local function do_append_footer(task, part, footer, is_multipart, out, state)
  local tp = part:get_text()
  local ct = 'text/plain'
  local cte = 'quoted-printable'
  local newline_s = state.newline_s

  if tp:is_html() then
    ct = 'text/html'
  end

  local encode_func = function(input)
    return rspamd_util.encode_qp(input, 80, task:get_newlines_type())
  end

  if part:get_cte() == '7bit' then
    cte = '7bit'
    encode_func = function(input)
      if type(input) == 'userdata' then
        return input
      else
        return rspamd_text.fromstring(input)
      end
    end
  end

  if is_multipart then
    out[#out + 1] = string.format('Content-Type: %s; charset=utf-8%s' ..
        'Content-Transfer-Encoding: %s',
        ct, newline_s, cte)
    out[#out + 1] = ''
  else
    state.new_cte = cte
  end

  local content = tp:get_content('raw_utf') or ''
  local double_nline = newline_s .. newline_s
  local nlen = #double_nline
  -- Hack, if part ends with 2 newline, then we append it after footer
  if content:sub(-(nlen), nlen + 1) == double_nline then
    -- content without last newline
    content = content:sub(-(#newline_s), #newline_s + 1) .. footer
    out[#out + 1] = { encode_func(content), true }
    out[#out + 1] = ''
  else
    content = content .. footer
    out[#out + 1] = { encode_func(content), true }
    out[#out + 1] = ''
  end

end

--[[[
-- @function lua_mime.add_text_footer(task, html_footer, text_footer)
-- Adds a footer to all text parts in a message. It returns a table with the following
-- fields:
-- * out: new content (body only)
-- * need_rewrite_ct: boolean field that means if we must rewrite content type
-- * new_ct: new content type (type => string, subtype => string)
-- * new_cte: new content-transfer encoding (string)
--]]
exports.add_text_footer = function(task, html_footer, text_footer)
  local newline_s = newline(task)
  local state = {
    newline_s = newline_s
  }
  local out = {}
  local text_parts = task:get_text_parts()

  if not (html_footer or text_footer) or not (text_parts and #text_parts > 0) then
    return false
  end

  if html_footer or text_footer then
    -- We need to take extra care about content-type and cte
    local ct = task:get_header('Content-Type')
    if ct then
      ct = rspamd_util.parse_content_type(ct, task:get_mempool())
    end

    if ct then
      if ct.type and ct.type == 'text' then
        if ct.subtype then
          if html_footer and (ct.subtype == 'html' or ct.subtype == 'htm') then
            state.need_rewrite_ct = true
          elseif text_footer and ct.subtype == 'plain' then
            state.need_rewrite_ct = true
          end
        else
          if text_footer then
            state.need_rewrite_ct = true
          end
        end

        state.new_ct = ct
      end
    else

      if text_parts then

        if #text_parts == 1 then
          state.need_rewrite_ct = true
          state.new_ct = {
            type = 'text',
            subtype = 'plain'
          }
        elseif #text_parts > 1 then
          -- XXX: in fact, it cannot be
          state.new_ct = {
            type = 'multipart',
            subtype = 'mixed'
          }
        end
      end
    end
  end

  local boundaries = {}
  local cur_boundary
  for _, part in ipairs(task:get_parts()) do
    local boundary = part:get_boundary()
    local part_ct = part:get_header('Content-Type')
    if part_ct then
      part_ct = rspamd_util.parse_content_type(part_ct, task:get_mempool())
    end
    if part:is_multipart() then
      if cur_boundary then
        out[#out + 1] = string.format('--%s',
            boundaries[#boundaries].boundary)
      end

      boundaries[#boundaries + 1] = {
        boundary = boundary or '--XXX',
        ct_type = part_ct.type or '',
        ct_subtype = part_ct.subtype or '',
      }
      cur_boundary = boundary

      local rh = part:get_raw_headers()
      if #rh > 0 then
        out[#out + 1] = { rh, true }
      end
    elseif part:is_message() then
      if boundary then
        if cur_boundary and boundary ~= cur_boundary then
          -- Need to close boundary
          out[#out + 1] = string.format('--%s--%s',
              boundaries[#boundaries].boundary, newline_s)
          table.remove(boundaries)
          cur_boundary = nil
        end
        out[#out + 1] = string.format('--%s',
            boundary)
      end

      out[#out + 1] = { part:get_raw_headers(), true }
    else
      local append_footer = false
      local skip_footer = part:is_attachment()

      local parent = part:get_parent()
      if parent then
        local t, st = parent:get_type()

        if t == 'multipart' and st == 'signed' then
          -- Do not modify signed parts
          skip_footer = true
        end
      end
      if text_footer and part:is_text() then
        local tp = part:get_text()

        if not tp:is_html() then
          append_footer = text_footer
        end
      end

      if html_footer and part:is_text() then
        local tp = part:get_text()

        if tp:is_html() then
          append_footer = html_footer
        end
      end

      if boundary then
        if cur_boundary and boundary ~= cur_boundary then
          
          local has_more_parts = false
          for j = i + 1, #parts do
            if not parts[j]:is_multipart() and not parts[j]:is_message() then
              has_more_parts = true
              break
            end
          end
          
          if #boundaries > 1 or (#boundaries == 1 and not has_more_parts) then
            out[#out + 1] = string.format('--%s--%s',
                boundaries[#boundaries].boundary, newline_s)
            
            if #boundaries > 1 and boundaries[#boundaries].ct_type == "multipart" and boundaries[#boundaries].ct_subtype == "related" then
              out[#out + 1] = string.format('--%s--%s',
                  boundaries[#boundaries - 1].boundary, newline_s)
              table.remove(boundaries)
            end
            table.remove(boundaries)
          end
          
          cur_boundary = boundary
        end
        out[#out + 1] = string.format('--%s',
            boundary)
      end
      if append_footer and not skip_footer then
        do_append_footer(task, part, append_footer,
            parent and parent:is_multipart(), out, state)
      else
        out[#out + 1] = { part:get_raw_headers(), true }
        out[#out + 1] = { part:get_raw_content(), false }
      end
    end
  end

      if append_footer and not skip_footer then
        do_append_footer(task, part, append_footer,
            parent and parent:is_multipart(), out, state)
      else
        out[#out + 1] = { part:get_raw_headers(), true }
        out[#out + 1] = { part:get_raw_content(), false }
      end
    end
  end

  -- Close remaining
  local b = table.remove(boundaries)
  while b do
    out[#out + 1] = string.format('--%s--', b.boundary)
    if #boundaries > 0 then
      out[#out + 1] = ''
    end
    b = table.remove(boundaries)
  end

  state.out = out

  return state
end

local function do_replacement (task, part, mp, replacements,
                               is_multipart, out, state)

  local tp = part:get_text()
  local ct = 'text/plain'
  local cte = 'quoted-printable'
  local newline_s = state.newline_s

  if tp:is_html() then
    ct = 'text/html'
  end

  local encode_func = function(input)
    return rspamd_util.encode_qp(input, 80, task:get_newlines_type())
  end

  if part:get_cte() == '7bit' then
    cte = '7bit'
    encode_func = function(input)
      if type(input) == 'userdata' then
        return input
      else
        return rspamd_text.fromstring(input)
      end
    end
  end

  local content = tp:get_content('raw_utf') or rspamd_text.fromstring('')
  local match_pos = mp:match(content, true)

  if match_pos then
    -- sort matches and form the table:
    -- start .. end for inclusion position
    local matches_flattened = {}
    for npat, matches in pairs(match_pos) do
      for _, m in ipairs(matches) do
        table.insert(matches_flattened, { m, npat })
      end
    end

    -- Handle the case of empty match
    if #matches_flattened == 0 then
      out[#out + 1] = { part:get_raw_headers(), true }
      out[#out + 1] = { part:get_raw_content(), false }

      return
    end

    if is_multipart then
      out[#out + 1] = { string.format('Content-Type: %s; charset="utf-8"%s' ..
          'Content-Transfer-Encoding: %s',
          ct, newline_s, cte), true }
      out[#out + 1] = { '', true }
    else
      state.new_cte = cte
    end

    state.has_matches = true
    -- now sort flattened by start of match and eliminate all overlaps
    table.sort(matches_flattened, function(m1, m2)
      return m1[1][1] < m2[1][1]
    end)

    for i = 1, #matches_flattened - 1 do
      local st = matches_flattened[i][1][1] -- current start of match
      local e = matches_flattened[i][1][2] -- current end of match
      local max_npat = matches_flattened[i][2]
      for j = i + 1, #matches_flattened do
        if matches_flattened[j][1][1] == st then
          -- overlap
          if matches_flattened[j][1][2] > e then
            -- larger exclusion and switch replacement
            e = matches_flattened[j][1][2]
            max_npat = matches_flattened[j][2]
          end
        else
          break
        end
      end
      -- Maximum overlap for all matches
      for j = i, #matches_flattened do
        if matches_flattened[j][1][1] == st then
          if e > matches_flattened[j][1][2] then
            matches_flattened[j][1][2] = e
            matches_flattened[j][2] = max_npat
          end
        else
          break
        end
      end
    end
    -- Off-by one: match returns 0 based positions while we use 1 based in Lua
    for _, m in ipairs(matches_flattened) do
      m[1][1] = m[1][1] + 1
      m[1][2] = m[1][2] + 1
    end

    -- Now flattened match table is sorted by start pos and has the maximum overlapped pattern
    -- Matches with the same start and end are covering the same replacement
    -- e.g. we had something like [1 .. 2] -> replacement 1 and [1 .. 4] -> replacement 2
    -- after flattening we should have [1 .. 4] -> 2 and [1 .. 4] -> 2
    -- we can safely ignore those duplicates in the following code

    local cur_start = 1
    local fragments = {}
    for _, m in ipairs(matches_flattened) do
      if m[1][1] >= cur_start then
        fragments[#fragments + 1] = content:sub(cur_start, m[1][1] - 1)
        fragments[#fragments + 1] = replacements[m[2]]
        cur_start = m[1][2] -- end of match
      end
    end

    -- last part
    if cur_start < #content then
      fragments[#fragments + 1] = content:span(cur_start)
    end

    -- Final stuff
    out[#out + 1] = { encode_func(rspamd_text.fromtable(fragments)), false }
  else
    -- No matches
    out[#out + 1] = { part:get_raw_headers(), true }
    out[#out + 1] = { part:get_raw_content(), false }
  end
end

--[[[
-- @function lua_mime.multipattern_text_replace(task, mp, replacements)
-- Replaces text according to multipattern matches. It returns a table with the following
-- fields:
-- * out: new content (body only)
-- * need_rewrite_ct: boolean field that means if we must rewrite content type
-- * new_ct: new content type (type => string, subtype => string)
-- * new_cte: new content-transfer encoding (string)
--]]
exports.multipattern_text_replace = function(task, mp, replacements)
  local newline_s = newline(task)
  local state = {
    newline_s = newline_s
  }
  local out = {}
  local text_parts = task:get_text_parts()

  if not mp or not (text_parts and #text_parts > 0) then
    return false
  end

  -- We need to take extra care about content-type and cte
  local ct = task:get_header('Content-Type')
  if ct then
    ct = rspamd_util.parse_content_type(ct, task:get_mempool())
  end

  if ct then
    if ct.type and ct.type == 'text' then
      state.need_rewrite_ct = true
      state.new_ct = ct
    end
  else
    -- No explicit CT, need to guess
    if text_parts then
      if #text_parts == 1 then
        state.need_rewrite_ct = true
        state.new_ct = {
          type = 'text',
          subtype = 'plain'
        }
      elseif #text_parts > 1 then
        -- XXX: in fact, it cannot be
        state.new_ct = {
          type = 'multipart',
          subtype = 'mixed'
        }
      end
    end
  end

  local boundaries = {}
  local cur_boundary
  for _, part in ipairs(task:get_parts()) do
    local boundary = part:get_boundary()
    if part:is_multipart() then
      if cur_boundary then
        out[#out + 1] = { string.format('--%s',
            boundaries[#boundaries]), true }
      end

      boundaries[#boundaries + 1] = boundary or '--XXX'
      cur_boundary = boundary

      local rh = part:get_raw_headers()
      if #rh > 0 then
        out[#out + 1] = { rh, true }
      end
    elseif part:is_message() then
      if boundary then
        if cur_boundary and boundary ~= cur_boundary then
          -- Need to close boundary
          out[#out + 1] = { string.format('--%s--',
              boundaries[#boundaries]), true }
          table.remove(boundaries)
          cur_boundary = nil
        end
        out[#out + 1] = { string.format('--%s',
            boundary), true }
      end

      out[#out + 1] = { part:get_raw_headers(), true }
    else
      local skip_replacement = part:is_attachment()

      local parent = part:get_parent()
      if parent then
        local t, st = parent:get_type()

        if t == 'multipart' and st == 'signed' then
          -- Do not modify signed parts
          skip_replacement = true
        end
      end
      if not part:is_text() then
        skip_replacement = true
      end

      if boundary then
        if cur_boundary and boundary ~= cur_boundary then
          -- Need to close boundary
          out[#out + 1] = { string.format('--%s--',
              boundaries[#boundaries]), true }
          table.remove(boundaries)
          cur_boundary = boundary
        end
        out[#out + 1] = { string.format('--%s',
            boundary), true }
      end

      if not skip_replacement then
        do_replacement(task, part, mp, replacements,
            parent and parent:is_multipart(), out, state)
      else
        -- Append as is
        out[#out + 1] = { part:get_raw_headers(), true }
        out[#out + 1] = { part:get_raw_content(), false }
      end
    end
  end

  -- Close remaining
  local b = table.remove(boundaries)
  while b do
    out[#out + 1] = { string.format('--%s--', b), true }
    if #boundaries > 0 then
      out[#out + 1] = { '', true }
    end
    b = table.remove(boundaries)
  end

  state.out = out

  return state
end

--[[[
-- @function lua_mime.modify_headers(task, {add = {hname = {value = 'value', order = 1}}, remove = {hname = {1,2}}})
-- Adds/removes headers both internal and in the milter reply
-- Mode defines to be compatible with Rspamd <=3.2 and is the default (equal to 'compat')
--]]
exports.modify_headers = function(task, hdr_alterations, mode)
  -- Assume default mode compatibility
  if not mode then
    mode = 'compat'
  end
  local add = hdr_alterations.add or {}
  local remove = hdr_alterations.remove or {}

  local add_headers = {} -- For Milter reply
  local hdr_flattened = {} -- For C API

  local function flatten_add_header(hname, hdr)
    if not add_headers[hname] then
      add_headers[hname] = {}
    end
    if not hdr_flattened[hname] then
      hdr_flattened[hname] = { add = {} }
    end
    local add_tbl = hdr_flattened[hname].add
    if hdr.value then
      table.insert(add_headers[hname], {
        order = (tonumber(hdr.order) or -1),
        value = hdr.value,
      })
      table.insert(add_tbl, { tonumber(hdr.order) or -1, hdr.value })
    elseif type(hdr) == 'table' then
      for _, v in ipairs(hdr) do
        flatten_add_header(hname, v)
      end
    elseif type(hdr) == 'string' then
      table.insert(add_headers[hname], {
        order = -1,
        value = hdr,
      })
      table.insert(add_tbl, { -1, hdr })
    else
      logger.errx(task, 'invalid modification of header: %s', hdr)
    end

    if mode == 'compat' and #add_headers[hname] == 1 then
      -- Switch to the compatibility mode
      add_headers[hname] = add_headers[hname][1]
    end
  end
  if hdr_alterations.order then
    -- Get headers alterations ordered
    for _, hname in ipairs(hdr_alterations.order) do
      flatten_add_header(hname, add[hname])
    end
  else
    for hname, hdr in pairs(add) do
      flatten_add_header(hname, hdr)
    end
  end

  for hname, hdr in pairs(remove) do
    if not hdr_flattened[hname] then
      hdr_flattened[hname] = { remove = {} }
    end
    if not hdr_flattened[hname].remove then
      hdr_flattened[hname].remove = {}
    end
    local remove_tbl = hdr_flattened[hname].remove
    local t_hdr = type(hdr)
    if t_hdr == 'number' then
      table.insert(remove_tbl, hdr)
    elseif t_hdr == 'userdata' then
      hdr_alterations.remove[hname] = nil
    else
      for _, num in ipairs(hdr) do
        table.insert(remove_tbl, num)
      end
    end
  end

  if mode == 'compat' then
    -- Clear empty alterations in the compat mode
    if add_headers and not next(add_headers) then
      add_headers = nil
    end
    if hdr_alterations.remove and not next(hdr_alterations.remove) then
      hdr_alterations.remove = nil
    end
  end
  task:set_milter_reply({
    add_headers = add_headers,
    remove_headers = hdr_alterations.remove
  })

  for hname, flat_rules in pairs(hdr_flattened) do
    task:modify_header(hname, flat_rules)
  end
end

--[[[
-- @function lua_mime.message_to_ucl(task, [stringify_content])
-- Exports a message to an ucl object
--]]
exports.message_to_ucl = function(task, stringify_content)
  local E = {}

  local maybe_stringify_f = stringify_content and
      tostring or function(t)
    return t
  end
  local result = {
    size = task:get_size(),
    digest = task:get_digest(),
    newlines = task:get_newlines_type(),
    headers = task:get_headers(true)
  }

  -- Utility to convert ip addr to a string or nil if invalid/absent
  local function maybe_stringify_ip(addr)
    if addr and addr:is_valid() then
      return addr:to_string()
    end

    return nil
  end

  -- Envelope (smtp) information from email (nil if empty)
  result.envelope = {
    from_smtp = (task:get_from('smtp') or E)[1],
    recipients_smtp = task:get_recipients('smtp'),
    helo = task:get_helo(),
    hostname = task:get_hostname(),
    client_ip = maybe_stringify_ip(task:get_client_ip()),
    from_ip = maybe_stringify_ip(task:get_from_ip()),
  }
  if not next(result.envelope) then
    result.envelope = ucl.null
  end

  local parts = task:get_parts() or E
  result.parts = {}
  for _, part in ipairs(parts) do
    if not part:is_multipart() and not part:is_message() then
      local p = {
        size = part:get_length(),
        type = string.format('%s/%s', part:get_type()),
        detected_type = string.format('%s/%s', part:get_detected_type()),
        filename = part:get_filename(),
        content = maybe_stringify_f(part:get_content()),
        headers = part:get_headers(true) or E,
        boundary = part:get_enclosing_boundary(),
      }
      table.insert(result.parts, p)
    else
      -- Service part: multipart container or message/rfc822
      local p = {
        type = string.format('%s/%s', part:get_type()),
        headers = part:get_headers(true) or E,
        boundary = part:get_enclosing_boundary(),
        size = 0,
      }

      if part:is_multipart() then
        p.multipart_boundary = part:get_boundary()
      end

      table.insert(result.parts, p)
    end
  end

  return result
end

--[[[
-- @function lua_mime.message_to_ucl_schema()
-- Returns schema for a message to verify result/document fields
--]]
exports.message_to_ucl_schema = function()
  local ts = require("tableshape").types

  local function headers_schema()
    return ts.shape {
      order = ts.integer:describe('Header order in a message'),
      raw = ts.string:describe('Raw header value'):is_optional(),
      empty_separator = ts.boolean:describe('Whether header has an empty separator'),
      separator = ts.string:describe('Separator between a header and a value'),
      decoded = ts.string:describe('Decoded value'):is_optional(),
      value = ts.string:describe('Decoded value'):is_optional(),
      name = ts.string:describe('Header name'),
      tab_separated = ts.boolean:describe('Whether header has tab as a separator')
    }
  end

  local function part_schema()
    return ts.shape {
      content = ts.string:describe('Decoded content'):is_optional(),
      multipart_boundary = ts.string:describe('Multipart service boundary'):is_optional(),
      size = ts.integer:describe('Size of the part'),
      type = ts.string:describe('Announced type'):is_optional(),
      detected_type = ts.string:describe('Detected type'):is_optional(),
      boundary = ts.string:describe('Eclosing boundary'):is_optional(),
      filename = ts.string:describe('File name for attachments'):is_optional(),
      headers = ts.array_of(headers_schema()):describe('Part headers'),
    }
  end

  local function email_addr_schema()
    return ts.shape {
      addr = ts.string:describe('Parsed address'):is_optional(),
      raw = ts.string:describe('Raw address'),
      flags = ts.shape {
        valid = ts.boolean:describe('Valid address'):is_optional(),
        ip = ts.boolean:describe('IP like address'):is_optional(),
        braced = ts.boolean:describe('Have braces around address'):is_optional(),
        quoted = ts.boolean:describe('Have quotes around address'):is_optional(),
        empty = ts.boolean:describe('Empty address'):is_optional(),
        backslash = ts.boolean:describe('Backslash in address'):is_optional(),
        ['8bit'] = ts.boolean:describe('8 bit characters in address'):is_optional(),
      },
      user = ts.string:describe('Parsed user part'):is_optional(),
      name = ts.string:describe('Displayed name'):is_optional(),
      domain = ts.string:describe('Parsed domain part'):is_optional(),
    }
  end
  local function envelope_schema()
    return ts.shape {
      from_smtp = email_addr_schema():describe('SMTP from'):is_optional(),
      recipients_smtp = ts.array_of(email_addr_schema()):describe('SMTP recipients'):is_optional(),
      helo = ts.string:describe('SMTP Helo'):is_optional(),
      hostname = ts.string:describe('Sender hostname'):is_optional(),
      client_ip = ts.string:describe('Client ip'):is_optional(),
      from_ip = ts.string:describe('Sender ip'):is_optional(),
    }
  end

  return ts.shape {
    headers = ts.array_of(headers_schema()),
    parts = ts.array_of(part_schema()),
    digest = ts.pattern(string.format('^%s$', string.rep('%x', 32)))
               :describe('Message digest'),
    newlines = ts.one_of({ "cr", "lf", "crlf" }):describe('Newlines type'),
    size = ts.integer:describe('Size of the message in bytes'),
    envelope = envelope_schema()
  }
end

--[[[
-- @function lua_mime.remove_attachments(task, settings)
-- Removes all attachments from a message, keeping only text parts
-- @param {task} task Rspamd task object
-- @param {table} settings Table with the following fields:
--   * keep_images: boolean, whether to keep inline images (default: false)
--   * min_text_size: number, minimum text part size to keep (default: 0)
--   * max_text_size: number, maximum text part size to keep (default: inf)
-- @return {table} modified message state similar to other modification functions:
-- * out: new content (body only)
--]]
exports.remove_attachments = function(task, settings)
  local newline_s = newline(task)
  local state = {
    newline_s = newline_s
  }
  local out = {}

  settings = settings or {}
  local keep_images = settings.keep_images or false
  local min_text_size = settings.min_text_size or 0
  local max_text_size = settings.max_text_size or math.huge

  -- Process message structure
  local boundaries = {}
  local cur_boundary
  local has_attachments = false
  local parts_to_keep = {}
  local parts_indexes_to_keep = {}

  -- First pass: identify parts to keep
  for i, part in ipairs(task:get_parts()) do
    local keep_part = false

    if part:is_text() and not part:is_attachment() then
      local length = part:get_length()
      if length >= min_text_size and length <= max_text_size then
        keep_part = true
      end
    elseif keep_images and part:is_image() then
      local cd = part:get_header('Content-Disposition')
      if cd and cd:lower():match('inline') then
        keep_part = true
      end
    end

    if keep_part then
      table.insert(parts_to_keep, part)
      parts_indexes_to_keep[i] = true
    else
      has_attachments = true
    end
  end

  -- If no attachments found, return false to indicate that no alterations are required
  if not has_attachments then
    return false
  end

  -- Second pass: reconstruct message
  for i, part in ipairs(task:get_parts()) do
    local boundary = part:get_boundary()
    if part:is_multipart() then
      if cur_boundary then
        out[#out + 1] = { string.format('--%s',
            boundaries[#boundaries]), true }
      end

      boundaries[#boundaries + 1] = boundary or '--XXX'
      cur_boundary = boundary

      local rh = part:get_raw_headers()
      if #rh > 0 then
        out[#out + 1] = { rh, true }
      end
    elseif part:is_message() then
      if boundary then
        if cur_boundary and boundary ~= cur_boundary then
          -- Need to close boundary
          out[#out + 1] = { string.format('--%s--',
              boundaries[#boundaries]), true }
          table.remove(boundaries)
          cur_boundary = nil
        end
        out[#out + 1] = { string.format('--%s',
            boundary), true }
      end

      out[#out + 1] = { part:get_raw_headers(), true }
    else
      if parts_indexes_to_keep[i] then
        if boundary then
          if cur_boundary and boundary ~= cur_boundary then
            -- Need to close previous boundary
            out[#out + 1] = { string.format('--%s--',
                boundaries[#boundaries]), true }
            table.remove(boundaries)
            cur_boundary = boundary
          end
          out[#out + 1] = { string.format('--%s',
              boundary), true }
        end
        -- Add part headers
        local headers = part:get_raw_headers()

        if headers then
          out[#out + 1] = {
            headers,
            true
          }
        end

        -- Add content
        out[#out + 1] = {
          part:get_raw_content(),
          false
        }
      end

    end
  end

  -- Close remaining boundaries
  local b = table.remove(boundaries)
  while b do
    out[#out + 1] = { string.format('--%s--', b), true }
    if #boundaries > 0 then
      out[#out + 1] = { '', true }
    end
    b = table.remove(boundaries)
  end

  state.out = out

  return state
end

--[[[
-- @function lua_mime.get_displayed_text_part(task)
-- Returns the most relevant displayed content from an email
-- @param {task} task Rspamd task object
-- @return {text_part} a selected part
--]]
exports.get_displayed_text_part = function(task)
  local text_parts = task:get_text_parts()
  if not text_parts then
    return nil
  end

  local html_part
  local text_part
  local html_attachment

  -- First pass: categorize parts
  for _, part in ipairs(text_parts) do
    local mp = part:get_mimepart()
    if not mp:is_attachment() then
      if part:is_html() then
        html_part = part
      else
        text_part = text_part or part
      end
    else
      -- Check for HTML attachments
      if part:is_html() and mp:get_length() < 102400 then
        -- 100KB limit, as long ones are likely not something that we should check
        html_attachment = part
      end
    end
  end

  -- Decision logic
  if html_part then
    local word_count = html_part:get_words_count() or 0
    if word_count >= 10 then
      -- Arbitrary minimum threshold, e.g. I believe it's minimum sane
      return html_part
    end
  end

  if text_part then
    local word_count = text_part:get_words_count() or 0
    if word_count >= 10 then
      -- Arbitrary minimum threshold, e.g. I believe it's minimum sane
      return text_part
    end
  end

  if html_attachment then
    return html_attachment
  end

  -- Only short parts, but still let's try our best
  return html_part or text_part
end

--[[[
-- @function lua_mime.get_distinct_text_parts(task)
-- Returns the list of parts that are visible or have a distinct content
-- @param {task} task Rspamd task object
-- @return array of {text_part} a selected part
--]]
exports.get_distinct_text_parts = function(task)
  local text_parts = task:get_text_parts()
  if not text_parts then
    return {}
  end

  local text_part_idx

  local distance = task:get_mempool():get_variable('parts_distance', 'double')
  if not distance then
    return text_parts
  end
  distance = tonumber(distance)

  if distance > 0.5 then
    -- Parts are distinct
    return text_parts
  end

  -- First pass: categorize parts
  for i, part in ipairs(text_parts) do
    local mp = part:get_mimepart()
    if not mp:is_attachment() then
      if not part:is_html() then
        -- Found text part that is similar to html part
        text_part_idx = i
      end
    end
  end

  if text_part_idx then
    table.remove(text_parts, text_part_idx)
  end

  return text_parts
end

--[[[
-- @function lua_mime.anonymize_message(task, settings)
-- Anonymizes message content by replacing sensitive data
-- @param {task} task Rspamd task object
-- @param {table} settings Table with the following fields:
--   * strip_attachments: boolean, whether to strip all attachments
--   * custom_header_process: table of header_name => function(orig_header) pairs
-- @return {table} modified message state similar to other modification functions
--]]
exports.anonymize_message = function(task, settings)
  local rspamd_re = require "rspamd_regexp"
  local lua_util = require "lua_util"

  logger.debugm('lua_mime', task, 'anonymize_message: starting, gpt mode: %s', settings.gpt or false)

  -- We exclude words with digits, currency symbols and so on
  local exclude_words_re = rspamd_re.create_cached([=[/^(?:\d+|\d+\D{1,3}|\p{Sc}.*|(\+?\d{1,3}[\s\-]?)?)$/(:?^[[:alpha:]]*\d{4,}.*$)/u]=])
  local newline_s = newline(task)
  local state = {
    newline_s = newline_s
  }
  local out = {}

  -- Default header processors
  local function anonymize_email_header(hdr)
    local addrs = rspamd_util.parse_mail_address(hdr.value, task:get_mempool())
    if addrs and addrs[1] then
      local modified = {}
      for _, addr in ipairs(addrs) do
        table.insert(modified, string.format('anonymous@%s', addr.domain or 'example.com'))
      end

      return table.concat(modified, ',')
    end
    return 'anonymous@example.com'
  end

  local function anonymize_received_header(hdr)
    local processed = string.gsub(hdr.value, '%d+%.%d+%.%d+%.%d+', 'x.x.x.x')
    processed = string.gsub(processed, '%x+:%x+:%x+:%x+:%x+:%x+:%x+:%x+', 'x:x:x:x:x:x:x:x')
    -- Anonymize email addresses in "for <email@domain.com>" clauses
    processed = string.gsub(processed, 'for%s+<([^@>]+)@([^>]+)>', 'for <anonymous@%2>')
    -- Anonymize email addresses in "envelope-from <email@domain.com>" clauses
    processed = string.gsub(processed, 'envelope%-from%s+<([^@>]+)@([^>]+)>', 'envelope-from <anonymous@%2>')
    return processed
  end

  local function remove_header(hdr)
    -- Return nil to remove the header
    return nil
  end

  local function anonymize_subject_header(hdr)
    -- Will be replaced by LLM anonymization if GPT mode is enabled
    -- Otherwise use generic subject
    return 'Email message'
  end

  local default_header_process = {
    ['from'] = anonymize_email_header,
    ['to'] = anonymize_email_header,
    ['cc'] = anonymize_email_header,
    ['bcc'] = anonymize_email_header,
    ['return-path'] = anonymize_email_header,
    ['delivered-to'] = anonymize_email_header,
    ['received'] = anonymize_received_header,
    ['dkim-signature'] = remove_header,
    ['arc-seal'] = remove_header,
    ['arc-message-signature'] = remove_header,
    ['arc-authentication-results'] = remove_header,
    ['authentication-results'] = remove_header,
    ['x-spamd-result'] = remove_header,
    ['x-rspamd-server'] = remove_header,
    ['x-rspamd-queue-id'] = remove_header,
    ['subject'] = anonymize_subject_header,
    ['thread-topic'] = anonymize_subject_header,
  }

  -- Merge with custom processors
  local header_processors = settings.custom_header_process or {}
  for k, v in pairs(default_header_process) do
    if not header_processors[k] then
      header_processors[k] = v
    end
  end

  -- Process headers
  local all_include = true
  local all_exclude = false

  -- Convert strings list to a list of globs where possible
  local function process_exceptions_list(list)
    if list and #list > 0 then
      for i, hdr in ipairs(list) do
        local gl = rspamd_re.import_glob(hdr, 'i')
        if gl then
          list[i] = gl
        end
      end
      return true
    end
  end

  local function maybe_match_header(hdr, list)
    if not list then
      return false
    end
    for _, expr in ipairs(list) do
      if type(expr) == 'userdata' then
        if expr:match(hdr) then
          return true
        end
      else
        if expr:lower() == hdr:lower() then
          return true
        end
      end
    end
    return false
  end

  if process_exceptions_list(settings.include_header) then
    all_include = false
    all_exclude = true
  end
  if process_exceptions_list(settings.exclude_header) then
    all_exclude = true
  end

  local modified_headers = {}
  local function process_hdr(name, hdr)
    local include_hdr = (all_include and not maybe_match_header(name, settings.exclude_header)) or
        (all_exclude and maybe_match_header(name, settings.include_header))
    if include_hdr then
      local processor = header_processors[name:lower()]
      if processor then
        local new_value = processor(hdr)
        if new_value then
          table.insert(modified_headers, {
            name = name,
            value = new_value
          })
        end
      else
        table.insert(modified_headers, {
          name = name,
          value = hdr.value
        })
      end
    end
  end

  task:headers_foreach(process_hdr, { full = true })

  logger.debugm('lua_mime', task, 'anonymize_message: processed %s headers', #modified_headers)

  -- Create new text content
  local text_content = {}
  local urls = {}
  local emails = {}

  local sel_part = exports.get_displayed_text_part(task)

  if not sel_part then
    logger.warnx(task, 'anonymize_message: no displayed text part found')
    return false
  end

  logger.debugm('lua_mime', task, 'anonymize_message: selected text part, is_html: %s, length: %s',
      sel_part:is_html(), sel_part:get_length())

  if settings.gpt then
    -- LLM version
    logger.debugm('lua_mime', task, 'anonymize_message: using GPT mode')
    local gpt_settings = rspamd_config:get_all_opt('gpt')

    if not gpt_settings then
      logger.errx(task, 'anonymize_message: no gpt settings found in config')
      return false
    end

    logger.debugm('lua_mime', task, 'anonymize_message: loaded gpt settings, type: %s', gpt_settings.type)

    -- Get original Subject and Thread-Topic for anonymization
    local orig_subject = task:get_header('Subject') or ''
    local orig_thread_topic = task:get_header('Thread-Topic') or ''

    -- Prepare the LLM request
    local function send_to_llm(input_content, subject, thread_topic)
      local rspamd_http = require 'rspamd_http'

      logger.debugm('lua_mime', task, 'anonymize_message: preparing LLM request, content length: %s bytes',
          #tostring(input_content))

      -- settings for LLM API
      local llm_settings = lua_util.override_defaults(gpt_settings, {
        api_key = settings.api_key,
        model = settings.model,
        timeout = settings.timeout,
        url = settings.url,
      })

      -- Check for model-specific parameters
      if gpt_settings.model_parameters and llm_settings.model then
        local model_params = gpt_settings.model_parameters[llm_settings.model]
        if model_params then
          logger.debugm('lua_mime', task, 'anonymize_message: found model-specific parameters for %s',
              llm_settings.model)
          llm_settings = lua_util.override_defaults(llm_settings, model_params)
        end
      end

      logger.debugm('lua_mime', task, 'anonymize_message: using LLM %s, model: %s, url: %s',
          llm_settings.type or 'unknown', llm_settings.model or 'default', llm_settings.url)

      -- Build the system prompt with subject information
      local base_prompt = settings.prompt or [[You are a privacy-focused email anonymization assistant. Your task is to remove all personally identifiable information (PII) from emails while preserving their structure and meaning.

Remove or anonymize:
- Real names (replace with "Person A", "Person B", etc.)
- Email addresses (replace with "email@example.com" format)
- Phone numbers (replace with "XXX-XXX-XXXX" format)
- Physical addresses (replace with "City, Country" format)
- Organization names (replace with generic terms like "Company A", "Organization B")
- Account numbers, IDs, and credentials
- IP addresses (replace with "X.X.X.X" format)
- Dates that could identify individuals (keep year if relevant to context)
- URLs (keep domain only if relevant, anonymize paths)

Preserve:
- The overall message structure and flow
- Technical terms and generic concepts
- The general topic and context
- Sentiment and tone

Response format:
First line must be: "SUBJECT: <anonymized subject line>"
Then a blank line
Then the anonymized email content

The anonymized subject should preserve the general topic but remove all PII. Keep it concise and relevant.

Example:
SUBJECT: Discussion about project timeline

<anonymized email content here>

Return ONLY the response in this format without any explanations, markdown formatting, or meta-commentary.]]

      -- Add subject context to the prompt
      llm_settings.prompt = base_prompt .. string.format("\n\nThe original email subject is: %s",
          subject and subject ~= '' and subject or 'No subject')

      logger.debugm('lua_mime', task, 'anonymize_message: prepared LLM prompt with subject: %s',
          subject and subject ~= '' and subject or 'No subject')

      local request_body
      if llm_settings.type == 'anthropic' or llm_settings.type == 'claude' then
        -- Claude/Anthropic API format
        request_body = {
          model = llm_settings.model,
          max_tokens = llm_settings.max_tokens or llm_settings.max_completion_tokens or 4096,
          system = llm_settings.prompt,
          messages = {
            {
              role = 'user',
              content = input_content
            }
          }
        }
        -- Add temperature if configured
        if llm_settings.temperature then
          request_body.temperature = llm_settings.temperature
        end
      else
        -- OpenAI/Ollama API format
        request_body = {
          model = llm_settings.model,
          messages = {
            {
              role = 'system',
              content = llm_settings.prompt
            },
            {
              role = 'user',
              content = input_content
            }
          }
        }
      end

      -- Add temperature if configured (only for OpenAI/Ollama, Claude handles it above)
      if llm_settings.temperature and llm_settings.type ~= 'anthropic' and llm_settings.type ~= 'claude' then
        request_body.temperature = llm_settings.temperature
      end

      -- Add max tokens parameter - only for OpenAI/Ollama (Claude already has it)
      if not (llm_settings.type == 'anthropic' or llm_settings.type == 'claude') then
        if llm_settings.max_completion_tokens then
          -- Model-specific config uses new parameter name
          request_body.max_completion_tokens = llm_settings.max_completion_tokens
        elseif llm_settings.max_tokens then
          -- Use legacy parameter or convert based on API type
          if llm_settings.type == 'openai' then
            request_body.max_completion_tokens = llm_settings.max_tokens
          else
            request_body.max_tokens = llm_settings.max_tokens
          end
        end
      end

      -- Ollama-specific settings
      if llm_settings.type == 'ollama' then
        request_body.stream = false
        logger.debugm('lua_mime', task, 'anonymize_message: disabled streaming for ollama')
      end

      -- Prepare HTTP headers based on API type
      local headers
      if llm_settings.type == 'anthropic' or llm_settings.type == 'claude' then
        headers = {
          ['x-api-key'] = llm_settings.api_key,
          ['anthropic-version'] = llm_settings.anthropic_version or '2023-06-01',
          ['Content-Type'] = 'application/json'
        }
      else
        headers = {
          ['Authorization'] = 'Bearer ' .. llm_settings.api_key,
          ['Content-Type'] = 'application/json'
        }
      end

      -- Make the HTTP request to the LLM API
      local http_params = {
        url = llm_settings.url,
        headers = headers,
        body = ucl.to_format(request_body, 'json-compact'),
        method = 'POST',
        task = task,
        timeout = llm_settings.timeout,
      }

      logger.debugm('lua_mime', task, 'anonymize_message: sending HTTP request to LLM, timeout: %s',
          llm_settings.timeout or 'default')

      local err, data = rspamd_http.request(http_params)

      if err then
        logger.errx(task, 'anonymize_message: LLM request failed: %s', err)
        return false
      end

      logger.debugm('lua_mime', task, 'anonymize_message: LLM response received, size: %s bytes',
          data.content and #data.content or 0)

      local parser = ucl.parser()
      local res, parse_err = parser:parse_string(data.content)
      if not res then
        logger.errx(task, 'anonymize_message: cannot parse LLM response: %s', parse_err)
        return false
      end

      local reply = parser:get_object()
      logger.debugm('lua_mime', task, 'anonymize_message: parsed LLM response successfully')

      -- Log the response structure for debugging
      logger.debugm('lua_mime', task, 'anonymize_message: response structure: %s',
          logger.slog('%1', reply))

      -- Check for API errors in response
      if reply.error then
        logger.errx(task, 'anonymize_message: LLM API returned error: %s (type: %s, code: %s)',
            reply.error.message or 'unknown', reply.error.type or 'unknown', reply.error.code or 'unknown')
        return false
      end

      local anonymized_content
      local finish_reason
      if llm_settings.type == 'anthropic' or llm_settings.type == 'claude' then
        logger.debugm('lua_mime', task, 'anonymize_message: extracting content from Claude/Anthropic response')
        logger.debugm('lua_mime', task, 'anonymize_message: reply.content exists: %s, type: %s',
            reply.content ~= nil, type(reply.content))
        if reply.content and reply.content[1] then
          logger.debugm('lua_mime', task, 'anonymize_message: reply.content[1] exists, has text: %s',
              reply.content[1].text ~= nil)
          anonymized_content = reply.content[1].text
          finish_reason = reply.stop_reason
        end
      elseif llm_settings.type == 'openai' then
        logger.debugm('lua_mime', task, 'anonymize_message: extracting content from OpenAI response')
        logger.debugm('lua_mime', task, 'anonymize_message: reply.choices exists: %s, type: %s',
            reply.choices ~= nil, type(reply.choices))
        if reply.choices and reply.choices[1] then
          logger.debugm('lua_mime', task, 'anonymize_message: reply.choices[1] exists, has message: %s',
              reply.choices[1].message ~= nil)
          if reply.choices[1].message then
            logger.debugm('lua_mime', task, 'anonymize_message: reply.choices[1].message.content exists: %s',
                reply.choices[1].message.content ~= nil)
          end
          anonymized_content = reply.choices[1].message and reply.choices[1].message.content
          finish_reason = reply.choices[1].finish_reason
        end
      elseif llm_settings.type == 'ollama' then
        logger.debugm('lua_mime', task, 'anonymize_message: extracting content from Ollama response')
        logger.debugm('lua_mime', task, 'anonymize_message: reply.message exists: %s',
            reply.message ~= nil)
        anonymized_content = reply.message and reply.message.content
        finish_reason = reply.finish_reason
      else
        logger.warnx(task, 'anonymize_message: unknown LLM type: %s', llm_settings.type)
      end

      if anonymized_content and #tostring(anonymized_content) > 0 then
        logger.debugm('lua_mime', task,
            'anonymize_message: successfully extracted anonymized content, length: %s bytes',
            #tostring(anonymized_content))

        -- Parse the subject from the LLM response
        -- Expected format: "SUBJECT: <anonymized subject>\n\n<content>"
        local anonymized_subject = 'Email message' -- default fallback
        local body_content = anonymized_content

        local subject_pattern = '^SUBJECT:%s*([^\n]+)\n\n(.*)$'
        local subj, content = string.match(tostring(anonymized_content), subject_pattern)
        if subj and content then
          anonymized_subject = subj
          body_content = content
          logger.debugm('lua_mime', task, 'anonymize_message: extracted anonymized subject: %s', anonymized_subject)
        else
          logger.debugm('lua_mime', task,
              'anonymize_message: could not extract subject from LLM response, using default')
        end

        -- Update the subject header in modified_headers with LLM-anonymized value
        for i, hdr in ipairs(modified_headers) do
          if hdr.name:lower() == 'subject' or hdr.name:lower() == 'thread-topic' then
            modified_headers[i].value = anonymized_subject
            logger.debugm('lua_mime', task, 'anonymize_message: updated %s header with LLM-anonymized value',
                hdr.name)
          end
        end

        -- Create new message with anonymized content
        local cur_boundary = '--XXX'

        -- Add headers
        out[#out + 1] = {
          string.format('Content-Type: multipart/mixed; boundary="%s"', cur_boundary),
          true
        }
        for _, hdr in ipairs(modified_headers) do
          if hdr.name:lower() ~= 'content-type' then
            out[#out + 1] = {
              string.format('%s: %s', hdr.name, hdr.value),
              true
            }
          end
        end
        out[#out + 1] = { '', true }

        -- Add text part with anonymized content
        out[#out + 1] = {
          string.format('--%s', cur_boundary),
          true
        }
        out[#out + 1] = {
          'Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable',
          true
        }
        out[#out + 1] = { '', true }
        out[#out + 1] = {
          rspamd_util.encode_qp(body_content, 76, task:get_newlines_type()),
          true
        }

        -- Close boundaries
        out[#out + 1] = {
          string.format('--%s--', cur_boundary),
          true
        }

        state.out = out
        state.need_rewrite_ct = true
        state.new_ct = {
          type = 'multipart',
          subtype = 'mixed'
        }

        logger.debugm('lua_mime', task, 'anonymize_message: GPT anonymization complete, %s output parts', #out)
        return state
      else
        -- Provide helpful error message based on finish_reason/stop_reason
        if finish_reason == 'length' or finish_reason == 'max_tokens' then
          logger.errx(task,
              'anonymize_message: LLM response was truncated due to token limit (finish_reason: %s), increase max_tokens in GPT config',
              finish_reason)
        elseif finish_reason then
          logger.errx(task, 'anonymize_message: LLM returned empty content (finish_reason: %s)', finish_reason)
        else
          logger.errx(task, 'anonymize_message: no anonymized content extracted from LLM response')
        end
      end

      return false
    end

    -- Send content to LLM with subject
    logger.debugm('lua_mime', task, 'anonymize_message: sending content to LLM with subject: %s',
        orig_subject ~= '' and orig_subject or 'No subject')
    return send_to_llm(sel_part:get_content(), orig_subject, orig_thread_topic)
  else
    logger.debugm('lua_mime', task, 'anonymize_message: using regex-based anonymization')

    if sel_part then
      text_content = sel_part:get_words('norm')
      for i, w in ipairs(text_content) do
        if exclude_words_re:match(w) then
          text_content[i] = string.rep('x', #w)
        end
      end
    end

    -- Process URLs
    local function process_url(url)
      local clean_url = url:get_host()
      local path = url:get_path()
      if path and path ~= "/" then
        clean_url = string.format("%s/%s", clean_url, path)
      end
      return string.format('https://%s', clean_url)
    end

    local url_list = task:get_urls(true) or {}
    logger.debugm('lua_mime', task, 'anonymize_message: processing %s URLs', #url_list)
    for _, url in ipairs(url_list) do
      urls[process_url(url)] = true
    end

    -- Process emails
    local function process_email(email)
      return string.format('nobody@%s', email.domain or 'example.com')
    end

    local email_list = task:get_emails() or {}
    logger.debugm('lua_mime', task, 'anonymize_message: processing %s emails', #email_list)
    for _, email in ipairs(email_list) do
      emails[process_email(email)] = true
    end

    -- Construct new message
    table.insert(text_content, '\nurls:')
    table.insert(text_content, table.concat(lua_util.keys(urls), ', '))
    table.insert(text_content, '\nemails:')
    table.insert(text_content, table.concat(lua_util.keys(emails), ', '))
    local new_text = table.concat(text_content, ' ')

    -- Create new message structure
    local cur_boundary = '--XXX'

    -- Add headers
    out[#out + 1] = {
      string.format('Content-Type: multipart/mixed; boundary="%s"', cur_boundary),
      true
    }
    for _, hdr in ipairs(modified_headers) do
      if hdr.name ~= 'Content-Type' then
        out[#out + 1] = {
          string.format('%s: %s', hdr.name, hdr.value),
          true
        }
      end
    end
    out[#out + 1] = { '', true }

    -- Add text part
    out[#out + 1] = {
      string.format('--%s', cur_boundary),
      true
    }
    out[#out + 1] = {
      'Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable',
      true
    }
    out[#out + 1] = { '', true }
    out[#out + 1] = {
      rspamd_util.encode_qp(new_text, 76, task:get_newlines_type()),
      true
    }

    -- Close boundaries
    out[#out + 1] = {
      string.format('--%s--', cur_boundary),
      true
    }

    state.out = out
    state.need_rewrite_ct = true
    state.new_ct = {
      type = 'multipart',
      subtype = 'mixed'
    }

    logger.debugm('lua_mime', task,
        'anonymize_message: regex anonymization complete, %s output parts, %s unique URLs, %s unique emails',
        #out, lua_util.table_len(urls), lua_util.table_len(emails))
    return state
  end
end

return exports
