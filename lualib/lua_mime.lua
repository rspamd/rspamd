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


--[[[
-- @function lua_mime.add_text_footer(task, html_footer, text_footer)
-- Adds a footer to all text parts in a message. It returns a table with the following
-- fields:
-- * out: new content (body only)
-- * need_rewrite_ct: boolean field that means if we must rewrite content type
-- * new_ct: new content type (type => string, subtype => string)
--]]
exports.add_text_footer = function(task, html_footer, text_footer)
  local newline_s = newline(task)
  local res = {}
  local out = {}
  local text_parts = task:get_text_parts()

  if not (html_footer or text_footer) or not (text_parts and #text_parts > 0) then
    return false
  end

  local function do_append_footer(part, footer, is_multipart)
    local tp = part:get_text()
    local ct = 'text/plain'
    local cte = 'quoted-printable'

    if tp:is_html() then
      ct = 'text/html'
    end

    if part:get_cte() == '7bit' then
      cte = '7bit'
    end

    if is_multipart then
      out[#out + 1] = string.format('Content-Type: %s; charset=utf-8%s'..
          'Content-Transfer-Encoding: %s',
          ct, newline_s, cte)
      out[#out + 1] = ''
    end

    local content = tostring(tp:get_content('raw_utf') or '')
    local double_nline = newline_s .. newline_s
    local nlen = #double_nline
    -- Hack, if part ends with 2 newline, then we append it after footer
    if content:sub(-(nlen), nlen + 1) == double_nline then
      content = string.format('%s%s',
          content:sub(-(#newline_s), #newline_s + 1), -- content without last newline
          footer)
      out[#out + 1] = {rspamd_util.encode_qp(content,
          80, task:get_newlines_type()), true}
      out[#out + 1] = ''
    else
      content = content .. footer
      out[#out + 1] = {rspamd_util.encode_qp(content,
          80, task:get_newlines_type()), true}
      out[#out + 1] = ''
    end

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
            res.need_rewrite_ct = true
          elseif text_footer and ct.subtype == 'plain' then
            res.need_rewrite_ct = true
          end
        else
          if text_footer then
            res.need_rewrite_ct = true
          end
        end

        res.new_ct = ct
      end
    else

      if text_parts then

        if #text_parts == 1 then
          res.need_rewrite_ct = true
          res.new_ct = {
            type = 'text',
            subtype = 'plain'
          }
        elseif #text_parts > 1 then
          -- XXX: in fact, it cannot be
          res.new_ct = {
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
        do_append_footer(part, append_footer,
            parent and parent:is_multipart())
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

  res.out = out

  return res
end

return exports