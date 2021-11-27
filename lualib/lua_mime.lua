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
-- @module lua_mime
-- This module contains helper functions to modify mime parts
--]]

local rspamd_util = require "rspamd_util"
local rspamd_text = require "rspamd_text"

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
    out[#out + 1] = string.format('Content-Type: %s; charset=utf-8%s'..
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
    out[#out + 1] = {encode_func(content), true}
    out[#out + 1] = ''
  else
    content = content .. footer
    out[#out + 1] = {encode_func(content), true}
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
  for _,part in ipairs(task:get_parts()) do
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
        out[#out + 1] = {rh, true}
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

      out[#out + 1] = {part:get_raw_headers(), true}
    else
      local append_footer = false
      local skip_footer = part:is_attachment()

      local parent = part:get_parent()
      if parent then
        local t,st = parent:get_type()

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
        out[#out + 1] = {part:get_raw_headers(), true}
        out[#out + 1] = {part:get_raw_content(), false}
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
    for npat,matches in pairs(match_pos) do
      for _,m in ipairs(matches) do
        table.insert(matches_flattened, {m, npat})
      end
    end

    -- Handle the case of empty match
    if #matches_flattened == 0 then
      out[#out + 1] = {part:get_raw_headers(), true}
      out[#out + 1] = {part:get_raw_content(), false}

      return
    end

    if is_multipart then
      out[#out + 1] = {string.format('Content-Type: %s; charset="utf-8"%s'..
          'Content-Transfer-Encoding: %s',
          ct, newline_s, cte), true}
      out[#out + 1] = {'', true}
    else
      state.new_cte = cte
    end

    state.has_matches = true
    -- now sort flattened by start of match and eliminate all overlaps
    table.sort(matches_flattened, function(m1, m2) return m1[1][1] < m2[1][1] end)

    for i=1,#matches_flattened - 1 do
      local st = matches_flattened[i][1][1] -- current start of match
      local e = matches_flattened[i][1][2] -- current end of match
      local max_npat = matches_flattened[i][2]
      for j=i+1,#matches_flattened do
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
      for j=i,#matches_flattened do
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
    for _,m in ipairs(matches_flattened) do
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
    for _,m in ipairs(matches_flattened) do
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
    out[#out + 1] = {encode_func(rspamd_text.fromtable(fragments)), false}
  else
    -- No matches
    out[#out + 1] = {part:get_raw_headers(), true}
    out[#out + 1] = {part:get_raw_content(), false}
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
  for _,part in ipairs(task:get_parts()) do
    local boundary = part:get_boundary()
    if part:is_multipart() then
      if cur_boundary then
        out[#out + 1] = {string.format('--%s',
            boundaries[#boundaries]), true}
      end

      boundaries[#boundaries + 1] = boundary or '--XXX'
      cur_boundary = boundary

      local rh = part:get_raw_headers()
      if #rh > 0 then
        out[#out + 1] = {rh, true}
      end
    elseif part:is_message() then
      if boundary then
        if cur_boundary and boundary ~= cur_boundary then
          -- Need to close boundary
          out[#out + 1] = {string.format('--%s--',
              boundaries[#boundaries]), true}
          table.remove(boundaries)
          cur_boundary = nil
        end
        out[#out + 1] = {string.format('--%s',
            boundary), true}
      end

      out[#out + 1] = {part:get_raw_headers(), true}
    else
      local skip_replacement = part:is_attachment()

      local parent = part:get_parent()
      if parent then
        local t,st = parent:get_type()

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
          out[#out + 1] = {string.format('--%s--',
              boundaries[#boundaries]), true}
          table.remove(boundaries)
          cur_boundary = boundary
        end
        out[#out + 1] = {string.format('--%s',
            boundary), true}
      end

      if not skip_replacement then
        do_replacement(task, part, mp, replacements,
            parent and parent:is_multipart(), out, state)
      else
        -- Append as is
        out[#out + 1] = {part:get_raw_headers(), true}
        out[#out + 1] = {part:get_raw_content(), false}
      end
    end
  end

  -- Close remaining
  local b = table.remove(boundaries)
  while b do
    out[#out + 1] = {string.format('--%s--', b), true}
    if #boundaries > 0 then
      out[#out + 1] = {'', true}
    end
    b = table.remove(boundaries)
  end

  state.out = out

  return state
end

--[[[
-- @function lua_mime.modify_headers(task, {add = {hname = {value = 'value', order = 1}}, remove = {hname = {1,2}}})
-- Adds/removes headers both internal and in the milter reply
--]]
exports.modify_headers = function(task, hdr_alterations)
  local add = hdr_alterations.add or {}
  local remove = hdr_alterations.remove or {}

  local hdr_flattened = {} -- For C API

  local function flatten_add_header(hname, hdr)
    if not hdr_flattened[hname] then
      hdr_flattened[hname] = {add = {}}
    end
    local add_tbl = hdr_flattened[hname].add
    if hdr.value then
      table.insert(add_tbl, {hdr.order or -1, hdr.value})
    elseif type(hdr) == 'table' then
      for _,v in ipairs(hdr) do
        table.insert(add_tbl, {-1, v})
      end
    end
  end
  if hdr_alterations.order then
    -- Get headers alterations ordered
    for _,hname in ipairs(hdr_alterations.order) do
      flatten_add_header(hname, add[hname])
    end
  else
    for hname,hdr in pairs(add) do
      flatten_add_header(hname, hdr)
    end
  end


  for hname,hdr in pairs(remove) do
    if not hdr_flattened[hname] then
      hdr_flattened[hname] = {remove = {}}
    end
    if not hdr_flattened[hname].remove then
      hdr_flattened[hname].remove = {}
    end
    local remove_tbl = hdr_flattened[hname].remove
    if type(hdr) == 'number' then
      table.insert(remove_tbl, hdr)
    else
      for _,num in ipairs(hdr) do
        table.insert(remove_tbl, num)
      end
    end
  end

  task:set_milter_reply({
    add_headers = hdr_alterations.add,
    remove_headers = hdr_alterations.remove
  })

  for hname,flat_rules in pairs(hdr_flattened) do
    task:modify_header(hname, flat_rules)
  end
end

--[[[
-- @function lua_mime.message_to_ucl(task, [stringify_content])
-- Exports a message to an ucl object
--]]
exports.message_to_ucl = function(task, stringify_content)
  local E = {}

  local function flatten_headers(hdrs)
    local res = {}

    for _,e in ipairs(hdrs) do
      if type(e) == 'table' and e[1] then
        for _,h in ipairs(e) do table.insert(res, h) end
      else
        table.insert(res, e)
      end
    end

    return res
  end
  local maybe_stringify_f = stringify_content and
    tostring or function(t) return t  end
  local result = {
    size = task:get_size(),
    digest = task:get_digest(),
    newlines = task:get_newlines_type(),
    headers = flatten_headers(task:get_headers(true) or E)
  }

  -- Utility to convert ip addr to a string or nil if invalid/absent
  local function maybe_stringify_ip(addr)
    if addr and addr:is_valid() then
      return addr:to_string()
    end

    return nil
  end
  -- Envelope (smtp) information form email
  result.envelope = {
    from_smtp = (task:get_from('smtp') or E)[1],
    recipients_smtp = task:get_recipients('smtp'),
    helo = task:get_helo(),
    hostname = task:get_hostname(),
    client_ip = maybe_stringify_ip(task:get_client_ip()),
    from_ip = maybe_stringify_ip(task:get_from_ip()),
  }

  local parts = task:get_parts() or E
  result.parts = {}
  for _,part in ipairs(parts) do
    local l = part:get_length()
    if l > 0 then
      local p = {
        size = l,
        type = string.format('%s/%s', part:get_type()),
        detected_type = string.format('%s/%s', part:get_detected_type()),
        filename = part:get_filename(),
        content = maybe_stringify_f(part:get_content()),
        headers =  flatten_headers(part:get_headers(true) or E),
        boundary = part:get_enclosing_boundary()
      }
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
    return ts.shape{
      order =  ts.integer:describe('Header order in a message'),
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
    return ts.shape{
      content =  ts.string:describe('Decoded content'),
      size = ts.integer:describe('Size of the part'),
      type = ts.string:describe('Announced type'):is_optional(),
      detected_type = ts.string:describe('Detected type'):is_optional(),
      boundary = ts.string:describe('Eclosing boundary'):is_optional(),
      filename = ts.string:describe('File name for attachments'):is_optional(),
      headers = ts.array_of(headers_schema()):describe('Part headers'),
    }
  end

  local function email_addr_schema()
    return ts.shape{
      addr =  ts.string:describe('Parsed address'):is_optional(),
      raw = ts.string:describe('Raw address'),
      flags = ts.shape{
        valid = ts.boolean:describe('Valid address'):is_optional(),
        ip = ts.boolean:describe('IP like address'):is_optional(),
        braced = ts.boolean:describe('Have braces around address'):is_optional(),
        quoted = ts.boolean:describe('Have quotes around address'):is_optional(),
        empty = ts.boolean:describe('Empty address'):is_optional(),
        backslash = ts.boolean:describe('Backslash in address'):is_optional(),
        ['8bit'] = ts.boolean:describe('8 bit characters in address'):is_optional(),
      },
      user =  ts.string:describe('Parsed user part'):is_optional(),
      name =  ts.string:describe('Displayed name'):is_optional(),
      domain =  ts.string:describe('Parsed domain part'):is_optional(),
    }
  end
  local function envelope_schema()
    return ts.shape{
      from_smtp = email_addr_schema():describe('SMTP from'):is_optional(),
      recipients_smtp = ts.array_of(email_addr_schema()):describe('SMTP recipients'):is_optional(),
      helo = ts.string:describe('SMTP Helo'):is_optional(),
      hostname = ts.string:describe('Sender hostname'):is_optional(),
      client_ip = ts.string:describe('Client ip'):is_optional(),
      from_ip = ts.string:describe('Sender ip'):is_optional(),
    }
  end

  return ts.shape{
    headers = ts.array_of(headers_schema()),
    parts = ts.array_of(part_schema()),
    digest = ts.pattern(string.format('^%s$', string.rep('%x', 32)))
        :describe('Message digest'),
    newlines = ts.one_of({"cr", "lf", "crlf"}):describe('Newlines type'),
    size = ts.integer:describe('Size of the message in bytes'),
    envelope = envelope_schema()
  }
end

return exports
