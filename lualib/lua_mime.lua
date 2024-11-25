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
    if part:is_multipart() then
      if cur_boundary then
        out[#out + 1] = string.format('--%s',
            boundaries[#boundaries])
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
          out[#out + 1] = string.format('--%s--%s',
              boundaries[#boundaries], newline_s)
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
          -- Need to close boundary
          out[#out + 1] = string.format('--%s--%s',
              boundaries[#boundaries], newline_s)
          table.remove(boundaries)
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

  -- Close remaining
  local b = table.remove(boundaries)
  while b do
    out[#out + 1] = string.format('--%s--', b)
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
-- * need_rewrite_ct: boolean field that means if we must rewrite content type
-- * new_ct: new content type (type => string, subtype => string)
-- * new_cte: new content-transfer encoding (string)
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

    if part:is_text() then
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

  -- Prepare new message structure
  local need_multipart = false
  local text_parts_count = 0
  for _, part in ipairs(parts_to_keep) do
    if part:is_text() then
      text_parts_count = text_parts_count + 1
    end
  end
  need_multipart = text_parts_count > 1 or (keep_images and next(parts_to_keep))

  -- Set content type
  if need_multipart then
    state.new_ct = {
      type = 'multipart',
      subtype = 'mixed'
    }
    cur_boundary = '--XXX'
    boundaries[1] = cur_boundary

    out[#out + 1] = {
      string.format('Content-Type: multipart/mixed; boundary="%s"%s',
          cur_boundary, newline_s),
      true
    }
    out[#out + 1] = { '', true }
  else
    -- Single part message
    for _, part in ipairs(parts_to_keep) do
      if part:is_text() then
        state.new_ct = {
          type = 'text',
          subtype = part:get_text():is_html() and 'html' or 'plain'
        }
        break
      end
    end
  end

  -- Second pass: reconstruct message
  for i, part in ipairs(task:get_parts()) do
    if part:is_multipart() then
      -- Skip multipart containers
      local boundary = part:get_boundary()
      if boundary then
        if cur_boundary and boundary ~= cur_boundary then
          out[#out + 1] = {
            string.format('--%s--', boundaries[#boundaries]),
            true
          }
          table.remove(boundaries)
        end
      end
    elseif parts_indexes_to_keep[i] then
      if need_multipart then
        out[#out + 1] = {
          string.format('--%s', cur_boundary),
          true
        }
      end

      -- Add part headers
      local headers = {}
      for _, h in ipairs(part:get_header_array()) do
        table.insert(headers, string.format('%s: %s', h.name, h.value))
      end

      if #headers > 0 then
        out[#out + 1] = {
          table.concat(headers, newline_s),
          true
        }
      end

      -- Add empty line between headers and content
      out[#out + 1] = { '', true }

      -- Add content
      out[#out + 1] = {
        part:get_raw_content(),
        false
      }
    end
  end

  -- Close remaining boundaries
  if need_multipart then
    out[#out + 1] = {
      string.format('--%s--', cur_boundary),
      true
    }
  end

  state.out = out
  state.need_rewrite_ct = true

  return state
end

return exports
