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
      m[1][1] = m[1][1] - 1
      m[1][2] = m[1][2] - 1
    end

    -- Now flattened match table is sorted by start pos and has the maximum overlapped pattern
    -- Matches with the same start and end are covering the same replacement
    -- e.g. we had something like [1 .. 2] -> replacement 1 and [1 .. 4] -> replacement 2
    -- after flattening we should have [1 .. 4] -> 2 and [1 .. 4] -> 2
    -- we can safely ignore those duplicates in the following code

    local cur_start = 1
    local fragments = {}
    for _,m in ipairs(matches_flattened) do
      if m[1][1] > cur_start then
        fragments[#fragments + 1] = content:span(cur_start, m[1][1] - cur_start)
        fragments[#fragments + 1] = replacements[m[2]]
        cur_start = m[1][2] + 1 -- end of match
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

-- All mime extensions with corresponding content types
exports.full_extensions_map = {
  {"323", "text/h323"},
  {"3g2", "video/3gpp2"},
  {"3gp", "video/3gpp"},
  {"3gp2", "video/3gpp2"},
  {"3gpp", "video/3gpp"},
  {"7z", {"application/x-7z-compressed", "application/7z"}},
  {"aa", "audio/audible"},
  {"AAC", "audio/aac"},
  {"aaf", "application/octet-stream"},
  {"aax", "audio/vnd.audible.aax"},
  {"ac3", "audio/ac3"},
  {"aca", "application/octet-stream"},
  {"accda", "application/msaccess.addin"},
  {"accdb", "application/msaccess"},
  {"accdc", "application/msaccess.cab"},
  {"accde", "application/msaccess"},
  {"accdr", "application/msaccess.runtime"},
  {"accdt", "application/msaccess"},
  {"accdw", "application/msaccess.webapplication"},
  {"accft", "application/msaccess.ftemplate"},
  {"acx", "application/internet-property-stream"},
  {"AddIn", "text/xml"},
  {"ade", "application/msaccess"},
  {"adobebridge", "application/x-bridge-url"},
  {"adp", "application/msaccess"},
  {"ADT", "audio/vnd.dlna.adts"},
  {"ADTS", "audio/aac"},
  {"afm", "application/octet-stream"},
  {"ai", "application/postscript"},
  {"aif", "audio/aiff"},
  {"aifc", "audio/aiff"},
  {"aiff", "audio/aiff"},
  {"air", "application/vnd.adobe.air-application-installer-package+zip"},
  {"amc", "application/mpeg"},
  {"anx", "application/annodex"},
  {"apk", "application/vnd.android.package-archive" },
  {"application", "application/x-ms-application"},
  {"art", "image/x-jg"},
  {"asa", "application/xml"},
  {"asax", "application/xml"},
  {"ascx", "application/xml"},
  {"asd", "application/octet-stream"},
  {"asf", "video/x-ms-asf"},
  {"ashx", "application/xml"},
  {"asi", "application/octet-stream"},
  {"asm", "text/plain"},
  {"asmx", "application/xml"},
  {"aspx", "application/xml"},
  {"asr", "video/x-ms-asf"},
  {"asx", "video/x-ms-asf"},
  {"atom", "application/atom+xml"},
  {"au", "audio/basic"},
  {"avi", "video/x-msvideo"},
  {"axa", "audio/annodex"},
  {"axs", "application/olescript"},
  {"axv", "video/annodex"},
  {"bas", "text/plain"},
  {"bcpio", "application/x-bcpio"},
  {"bin", "application/octet-stream"},
  {"bmp", {"image/bmp", "image/x-ms-bmp"}},
  {"c", "text/plain"},
  {"cab", "application/octet-stream"},
  {"caf", "audio/x-caf"},
  {"calx", "application/vnd.ms-office.calx"},
  {"cat", "application/vnd.ms-pki.seccat"},
  {"cc", "text/plain"},
  {"cd", "text/plain"},
  {"cdda", "audio/aiff"},
  {"cdf", "application/x-cdf"},
  {"cer", "application/x-x509-ca-cert"},
  {"cfg", "text/plain"},
  {"chm", "application/octet-stream"},
  {"class", "application/x-java-applet"},
  {"clp", "application/x-msclip"},
  {"cmd", "text/plain"},
  {"cmx", "image/x-cmx"},
  {"cnf", "text/plain"},
  {"cod", "image/cis-cod"},
  {"config", "application/xml"},
  {"contact", "text/x-ms-contact"},
  {"coverage", "application/xml"},
  {"cpio", "application/x-cpio"},
  {"cpp", "text/plain"},
  {"crd", "application/x-mscardfile"},
  {"crl", "application/pkix-crl"},
  {"crt", "application/x-x509-ca-cert"},
  {"cs", "text/plain"},
  {"csdproj", "text/plain"},
  {"csh", "application/x-csh"},
  {"csproj", "text/plain"},
  {"css", "text/css"},
  {"csv", {"application/vnd.ms-excel", "text/csv", "text/plain"}},
  {"cur", "application/octet-stream"},
  {"cxx", "text/plain"},
  {"dat", {"application/octet-stream", "application/ms-tnef"}},
  {"datasource", "application/xml"},
  {"dbproj", "text/plain"},
  {"dcr", "application/x-director"},
  {"def", "text/plain"},
  {"deploy", "application/octet-stream"},
  {"der", "application/x-x509-ca-cert"},
  {"dgml", "application/xml"},
  {"dib", "image/bmp"},
  {"dif", "video/x-dv"},
  {"dir", "application/x-director"},
  {"disco", "text/xml"},
  {"divx", "video/divx"},
  {"dll", "application/x-msdownload"},
  {"dll.config", "text/xml"},
  {"dlm", "text/dlm"},
  {"doc", "application/msword"},
  {"docm", "application/vnd.ms-word.document.macroEnabled.12"},
  {"docx", {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "application/vnd.ms-word.document.12",
    "application/octet-stream",
  }},
  {"dot", "application/msword"},
  {"dotm", "application/vnd.ms-word.template.macroEnabled.12"},
  {"dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
  {"dsp", "application/octet-stream"},
  {"dsw", "text/plain"},
  {"dtd", "text/xml"},
  {"dtsConfig", "text/xml"},
  {"dv", "video/x-dv"},
  {"dvi", "application/x-dvi"},
  {"dwf", "drawing/x-dwf"},
  {"dwg", {"application/acad", "image/vnd.dwg"}},
  {"dwp", "application/octet-stream"},
  {"dxf", "application/x-dxf" },
  {"dxr", "application/x-director"},
  {"eml", "message/rfc822"},
  {"emz", "application/octet-stream"},
  {"eot", "application/vnd.ms-fontobject"},
  {"eps", "application/postscript"},
  {"etl", "application/etl"},
  {"etx", "text/x-setext"},
  {"evy", "application/envoy"},
  {"exe", {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
  }},
  {"exe.config", "text/xml"},
  {"fdf", "application/vnd.fdf"},
  {"fif", "application/fractals"},
  {"filters", "application/xml"},
  {"fla", "application/octet-stream"},
  {"flac", "audio/flac"},
  {"flr", "x-world/x-vrml"},
  {"flv", "video/x-flv"},
  {"fsscript", "application/fsharp-script"},
  {"fsx", "application/fsharp-script"},
  {"generictest", "application/xml"},
  {"gif", "image/gif"},
  {"gpx", "application/gpx+xml"},
  {"group", "text/x-ms-group"},
  {"gsm", "audio/x-gsm"},
  {"gtar", "application/x-gtar"},
  {"gz", {"application/gzip", "application/x-gzip"}},
  {"h", "text/plain"},
  {"hdf", "application/x-hdf"},
  {"hdml", "text/x-hdml"},
  {"hhc", "application/x-oleobject"},
  {"hhk", "application/octet-stream"},
  {"hhp", "application/octet-stream"},
  {"hlp", "application/winhlp"},
  {"hpp", "text/plain"},
  {"hqx", "application/mac-binhex40"},
  {"hta", "application/hta"},
  {"htc", "text/x-component"},
  {"htm", "text/html"},
  {"html", "text/html"},
  {"htt", "text/webviewhtml"},
  {"hxa", "application/xml"},
  {"hxc", "application/xml"},
  {"hxd", "application/octet-stream"},
  {"hxe", "application/xml"},
  {"hxf", "application/xml"},
  {"hxh", "application/octet-stream"},
  {"hxi", "application/octet-stream"},
  {"hxk", "application/xml"},
  {"hxq", "application/octet-stream"},
  {"hxr", "application/octet-stream"},
  {"hxs", "application/octet-stream"},
  {"hxt", "text/html"},
  {"hxv", "application/xml"},
  {"hxw", "application/octet-stream"},
  {"hxx", "text/plain"},
  {"i", "text/plain"},
  {"ico", "image/x-icon"},
  {"ics", {"text/calendar", "application/ics", "application/octet-stream"}},
  {"idl", "text/plain"},
  {"ief", "image/ief"},
  {"iii", "application/x-iphone"},
  {"inc", "text/plain"},
  {"inf", "application/octet-stream"},
  {"ini", "text/plain"},
  {"inl", "text/plain"},
  {"ins", "application/x-internet-signup"},
  {"ipa", "application/x-itunes-ipa"},
  {"ipg", "application/x-itunes-ipg"},
  {"ipproj", "text/plain"},
  {"ipsw", "application/x-itunes-ipsw"},
  {"iqy", "text/x-ms-iqy"},
  {"isp", "application/x-internet-signup"},
  {"ite", "application/x-itunes-ite"},
  {"itlp", "application/x-itunes-itlp"},
  {"itms", "application/x-itunes-itms"},
  {"itpc", "application/x-itunes-itpc"},
  {"IVF", "video/x-ivf"},
  {"jar", "application/java-archive"},
  {"java", "application/octet-stream"},
  {"jck", "application/liquidmotion"},
  {"jcz", "application/liquidmotion"},
  {"jfif", "image/pjpeg"},
  {"jnlp", "application/x-java-jnlp-file"},
  {"jpb", "application/octet-stream"},
  {"jpe", {"image/jpeg", "image/pjpeg"}},
  {"jpeg", {"image/jpeg", "image/pjpeg"}},
  {"jpg", {"image/jpeg", "image/pjpeg"}},
  {"js", "application/javascript"},
  {"json", "application/json"},
  {"jsx", "text/jscript"},
  {"jsxbin", "text/plain"},
  {"latex", "application/x-latex"},
  {"library-ms", "application/windows-library+xml"},
  {"lit", "application/x-ms-reader"},
  {"loadtest", "application/xml"},
  {"lpk", "application/octet-stream"},
  {"lsf", "video/x-la-asf"},
  {"lst", "text/plain"},
  {"lsx", "video/x-la-asf"},
  {"lzh", "application/octet-stream"},
  {"m13", "application/x-msmediaview"},
  {"m14", "application/x-msmediaview"},
  {"m1v", "video/mpeg"},
  {"m2t", "video/vnd.dlna.mpeg-tts"},
  {"m2ts", "video/vnd.dlna.mpeg-tts"},
  {"m2v", "video/mpeg"},
  {"m3u", "audio/x-mpegurl"},
  {"m3u8", "audio/x-mpegurl"},
  {"m4a", {"audio/m4a", "audio/x-m4a"}},
  {"m4b", "audio/m4b"},
  {"m4p", "audio/m4p"},
  {"m4r", "audio/x-m4r"},
  {"m4v", "video/x-m4v"},
  {"mac", "image/x-macpaint"},
  {"mak", "text/plain"},
  {"man", "application/x-troff-man"},
  {"manifest", "application/x-ms-manifest"},
  {"map", "text/plain"},
  {"master", "application/xml"},
  {"mbox", "application/mbox"},
  {"mda", "application/msaccess"},
  {"mdb", "application/x-msaccess"},
  {"mde", "application/msaccess"},
  {"mdp", "application/octet-stream"},
  {"me", "application/x-troff-me"},
  {"mfp", "application/x-shockwave-flash"},
  {"mht", "message/rfc822"},
  {"mhtml", "message/rfc822"},
  {"mid", "audio/mid"},
  {"midi", "audio/mid"},
  {"mix", "application/octet-stream"},
  {"mk", "text/plain"},
  {"mmf", "application/x-smaf"},
  {"mno", "text/xml"},
  {"mny", "application/x-msmoney"},
  {"mod", "video/mpeg"},
  {"mov", "video/quicktime"},
  {"movie", "video/x-sgi-movie"},
  {"mp2", "video/mpeg"},
  {"mp2v", "video/mpeg"},
  {"mp3", "audio/mpeg"},
  {"mp4", "video/mp4"},
  {"mp4v", "video/mp4"},
  {"mpa", "video/mpeg"},
  {"mpe", "video/mpeg"},
  {"mpeg", "video/mpeg"},
  {"mpf", "application/vnd.ms-mediapackage"},
  {"mpg", "video/mpeg"},
  {"mpp", "application/vnd.ms-project"},
  {"mpv2", "video/mpeg"},
  {"mqv", "video/quicktime"},
  {"ms", "application/x-troff-ms"},
  {"msg", "application/vnd.ms-outlook"},
  {"msi", {"application/x-msi", "application/octet-stream"}},
  {"mso", "application/octet-stream"},
  {"mts", "video/vnd.dlna.mpeg-tts"},
  {"mtx", "application/xml"},
  {"mvb", "application/x-msmediaview"},
  {"mvc", "application/x-miva-compiled"},
  {"mxp", "application/x-mmxp"},
  {"nc", "application/x-netcdf"},
  {"nsc", "video/x-ms-asf"},
  {"nws", "message/rfc822"},
  {"ocx", "application/octet-stream"},
  {"oda", "application/oda"},
  {"odb", "application/vnd.oasis.opendocument.database"},
  {"odc", "application/vnd.oasis.opendocument.chart"},
  {"odf", "application/vnd.oasis.opendocument.formula"},
  {"odg", "application/vnd.oasis.opendocument.graphics"},
  {"odh", "text/plain"},
  {"odi", "application/vnd.oasis.opendocument.image"},
  {"odl", "text/plain"},
  {"odm", "application/vnd.oasis.opendocument.text-master"},
  {"odp", "application/vnd.oasis.opendocument.presentation"},
  {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
  {"odt", "application/vnd.oasis.opendocument.text"},
  {"oga", "audio/ogg"},
  {"ogg", "audio/ogg"},
  {"ogv", "video/ogg"},
  {"ogx", "application/ogg"},
  {"one", "application/onenote"},
  {"onea", "application/onenote"},
  {"onepkg", "application/onenote"},
  {"onetmp", "application/onenote"},
  {"onetoc", "application/onenote"},
  {"onetoc2", "application/onenote"},
  {"opus", "audio/ogg"},
  {"orderedtest", "application/xml"},
  {"osdx", "application/opensearchdescription+xml"},
  {"otf", "application/font-sfnt"},
  {"otg", "application/vnd.oasis.opendocument.graphics-template"},
  {"oth", "application/vnd.oasis.opendocument.text-web"},
  {"otp", "application/vnd.oasis.opendocument.presentation-template"},
  {"ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
  {"ott", "application/vnd.oasis.opendocument.text-template"},
  {"oxt", "application/vnd.openofficeorg.extension"},
  {"p10", "application/pkcs10"},
  {"p12", "application/x-pkcs12"},
  {"p7b", "application/x-pkcs7-certificates"},
  {"p7c", "application/pkcs7-mime"},
  {"p7m", "application/pkcs7-mime"},
  {"p7r", "application/x-pkcs7-certreqresp"},
  {"p7s", {"application/pkcs7-signature", "text/plain"}},
  {"pbm", "image/x-portable-bitmap"},
  {"pcast", "application/x-podcast"},
  {"pct", "image/pict"},
  {"pcx", "application/octet-stream"},
  {"pcz", "application/octet-stream"},
  {"pdf", "application/pdf"},
  {"pfb", "application/octet-stream"},
  {"pfm", "application/octet-stream"},
  {"pfx", "application/x-pkcs12"},
  {"pgm", "image/x-portable-graymap"},
  {"pic", "image/pict"},
  {"pict", "image/pict"},
  {"pkgdef", "text/plain"},
  {"pkgundef", "text/plain"},
  {"pko", "application/vnd.ms-pki.pko"},
  {"pls", "audio/scpls"},
  {"pma", "application/x-perfmon"},
  {"pmc", "application/x-perfmon"},
  {"pml", "application/x-perfmon"},
  {"pmr", "application/x-perfmon"},
  {"pmw", "application/x-perfmon"},
  {"png", "image/png"},
  {"pnm", "image/x-portable-anymap"},
  {"pnt", "image/x-macpaint"},
  {"pntg", "image/x-macpaint"},
  {"pnz", "image/png"},
  {"pot", "application/vnd.ms-powerpoint"},
  {"potm", "application/vnd.ms-powerpoint.template.macroEnabled.12"},
  {"potx", "application/vnd.openxmlformats-officedocument.presentationml.template"},
  {"ppa", "application/vnd.ms-powerpoint"},
  {"ppam", "application/vnd.ms-powerpoint.addin.macroEnabled.12"},
  {"ppm", "image/x-portable-pixmap"},
  {"pps", "application/vnd.ms-powerpoint"},
  {"ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"},
  {"ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
  {"ppt", "application/vnd.ms-powerpoint"},
  {"pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"},
  {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
  {"prf", "application/pics-rules"},
  {"prm", "application/octet-stream"},
  {"prx", "application/octet-stream"},
  {"ps", "application/postscript"},
  {"psc1", "application/PowerShell"},
  {"psd", "application/octet-stream"},
  {"psess", "application/xml"},
  {"psm", "application/octet-stream"},
  {"psp", "application/octet-stream"},
  {"pst", "application/vnd.ms-outlook"},
  {"pub", "application/x-mspublisher"},
  {"pwz", "application/vnd.ms-powerpoint"},
  {"qht", "text/x-html-insertion"},
  {"qhtm", "text/x-html-insertion"},
  {"qt", "video/quicktime"},
  {"qti", "image/x-quicktime"},
  {"qtif", "image/x-quicktime"},
  {"qtl", "application/x-quicktimeplayer"},
  {"qxd", "application/octet-stream"},
  {"ra", "audio/x-pn-realaudio"},
  {"ram", "audio/x-pn-realaudio"},
  {"rar", {"application/x-rar-compressed", "application/x-rar", "application/octet-stream"}},
  {"ras", "image/x-cmu-raster"},
  {"rat", "application/rat-file"},
  {"rc", "text/plain"},
  {"rc2", "text/plain"},
  {"rct", "text/plain"},
  {"rdlc", "application/xml"},
  {"reg", "text/plain"},
  {"resx", "application/xml"},
  {"rf", "image/vnd.rn-realflash"},
  {"rgb", "image/x-rgb"},
  {"rgs", "text/plain"},
  {"rm", "application/vnd.rn-realmedia"},
  {"rmi", "audio/mid"},
  {"rmp", "application/vnd.rn-rn_music_package"},
  {"roff", "application/x-troff"},
  {"rpm", "audio/x-pn-realaudio-plugin"},
  {"rqy", "text/x-ms-rqy"},
  {"rtf", {"application/rtf","application/msword", "text/richtext", "text/rtf"}},
  {"rtx", "text/richtext"},
  {"rvt", "application/octet-stream" },
  {"ruleset", "application/xml"},
  {"s", "text/plain"},
  {"safariextz", "application/x-safari-safariextz"},
  {"scd", "application/x-msschedule"},
  {"scr", "text/plain"},
  {"sct", "text/scriptlet"},
  {"sd2", "audio/x-sd2"},
  {"sdp", "application/sdp"},
  {"sea", "application/octet-stream"},
  {"searchConnector-ms", "application/windows-search-connector+xml"},
  {"setpay", "application/set-payment-initiation"},
  {"setreg", "application/set-registration-initiation"},
  {"settings", "application/xml"},
  {"sgimb", "application/x-sgimb"},
  {"sgml", "text/sgml"},
  {"sh", "application/x-sh"},
  {"shar", "application/x-shar"},
  {"shtml", "text/html"},
  {"sit", "application/x-stuffit"},
  {"sitemap", "application/xml"},
  {"skin", "application/xml"},
  {"skp", "application/x-koan" },
  {"sldm", "application/vnd.ms-powerpoint.slide.macroEnabled.12"},
  {"sldx", "application/vnd.openxmlformats-officedocument.presentationml.slide"},
  {"slk", "application/vnd.ms-excel"},
  {"sln", "text/plain"},
  {"slupkg-ms", "application/x-ms-license"},
  {"smd", "audio/x-smd"},
  {"smi", "application/octet-stream"},
  {"smx", "audio/x-smd"},
  {"smz", "audio/x-smd"},
  {"snd", "audio/basic"},
  {"snippet", "application/xml"},
  {"snp", "application/octet-stream"},
  {"sol", "text/plain"},
  {"sor", "text/plain"},
  {"spc", "application/x-pkcs7-certificates"},
  {"spl", "application/futuresplash"},
  {"spx", "audio/ogg"},
  {"src", "application/x-wais-source"},
  {"srf", "text/plain"},
  {"SSISDeploymentManifest", "text/xml"},
  {"ssm", "application/streamingmedia"},
  {"sst", "application/vnd.ms-pki.certstore"},
  {"stl", "application/vnd.ms-pki.stl"},
  {"sv4cpio", "application/x-sv4cpio"},
  {"sv4crc", "application/x-sv4crc"},
  {"svc", "application/xml"},
  {"svg", "image/svg+xml"},
  {"swf", "application/x-shockwave-flash"},
  {"step", "application/step"},
  {"stp", "application/step"},
  {"t", "application/x-troff"},
  {"tar", "application/x-tar"},
  {"tcl", "application/x-tcl"},
  {"testrunconfig", "application/xml"},
  {"testsettings", "application/xml"},
  {"tex", "application/x-tex"},
  {"texi", "application/x-texinfo"},
  {"texinfo", "application/x-texinfo"},
  {"tgz", "application/x-compressed"},
  {"thmx", "application/vnd.ms-officetheme"},
  {"thn", "application/octet-stream"},
  {"tif", {"image/tiff", "application/octet-stream"}},
  {"tiff", "image/tiff"},
  {"tlh", "text/plain"},
  {"tli", "text/plain"},
  {"toc", "application/octet-stream"},
  {"tr", "application/x-troff"},
  {"trm", "application/x-msterminal"},
  {"trx", "application/xml"},
  {"ts", "video/vnd.dlna.mpeg-tts"},
  {"tsv", "text/tab-separated-values"},
  {"ttf", "application/font-sfnt"},
  {"tts", "video/vnd.dlna.mpeg-tts"},
  {"txt", "text/plain"},
  {"u32", "application/octet-stream"},
  {"uls", "text/iuls"},
  {"user", "text/plain"},
  {"ustar", "application/x-ustar"},
  {"vb", "text/plain"},
  {"vbdproj", "text/plain"},
  {"vbk", "video/mpeg"},
  {"vbproj", "text/plain"},
  {"vbs", "text/vbscript"},
  {"vcf", {"text/x-vcard", "text/vcard"}},
  {"vcproj", "application/xml"},
  {"vcs", "text/plain"},
  {"vcxproj", "application/xml"},
  {"vddproj", "text/plain"},
  {"vdp", "text/plain"},
  {"vdproj", "text/plain"},
  {"vdx", "application/vnd.ms-visio.viewer"},
  {"vml", "text/xml"},
  {"vscontent", "application/xml"},
  {"vsct", "text/xml"},
  {"vsd", "application/vnd.visio"},
  {"vsi", "application/ms-vsi"},
  {"vsix", "application/vsix"},
  {"vsixlangpack", "text/xml"},
  {"vsixmanifest", "text/xml"},
  {"vsmdi", "application/xml"},
  {"vspscc", "text/plain"},
  {"vss", "application/vnd.visio"},
  {"vsscc", "text/plain"},
  {"vssettings", "text/xml"},
  {"vssscc", "text/plain"},
  {"vst", "application/vnd.visio"},
  {"vstemplate", "text/xml"},
  {"vsto", "application/x-ms-vsto"},
  {"vsw", "application/vnd.visio"},
  {"vsx", "application/vnd.visio"},
  {"vtx", "application/vnd.visio"},
  {"wav", "audio/wav"},
  {"wave", "audio/wav"},
  {"wax", "audio/x-ms-wax"},
  {"wbk", "application/msword"},
  {"wbmp", "image/vnd.wap.wbmp"},
  {"wcm", "application/vnd.ms-works"},
  {"wdb", "application/vnd.ms-works"},
  {"wdp", "image/vnd.ms-photo"},
  {"webarchive", "application/x-safari-webarchive"},
  {"webm", "video/webm"},
  {"webp", "image/webp"},
  {"webtest", "application/xml"},
  {"wiq", "application/xml"},
  {"wiz", "application/msword"},
  {"wks", "application/vnd.ms-works"},
  {"WLMP", "application/wlmoviemaker"},
  {"wlpginstall", "application/x-wlpg-detect"},
  {"wlpginstall3", "application/x-wlpg3-detect"},
  {"wm", "video/x-ms-wm"},
  {"wma", "audio/x-ms-wma"},
  {"wmd", "application/x-ms-wmd"},
  {"wmf", "application/x-msmetafile"},
  {"wml", "text/vnd.wap.wml"},
  {"wmlc", "application/vnd.wap.wmlc"},
  {"wmls", "text/vnd.wap.wmlscript"},
  {"wmlsc", "application/vnd.wap.wmlscriptc"},
  {"wmp", "video/x-ms-wmp"},
  {"wmv", "video/x-ms-wmv"},
  {"wmx", "video/x-ms-wmx"},
  {"wmz", "application/x-ms-wmz"},
  {"woff", "application/font-woff"},
  {"wpl", "application/vnd.ms-wpl"},
  {"wps", "application/vnd.ms-works"},
  {"wri", "application/x-mswrite"},
  {"wrl", "x-world/x-vrml"},
  {"wrz", "x-world/x-vrml"},
  {"wsc", "text/scriptlet"},
  {"wsdl", "text/xml"},
  {"wvx", "video/x-ms-wvx"},
  {"x", "application/directx"},
  {"xaf", "x-world/x-vrml"},
  {"xaml", "application/xaml+xml"},
  {"xap", "application/x-silverlight-app"},
  {"xbap", "application/x-ms-xbap"},
  {"xbm", "image/x-xbitmap"},
  {"xdr", "text/plain"},
  {"xht", "application/xhtml+xml"},
  {"xhtml", "application/xhtml+xml"},
  {"xla", "application/vnd.ms-excel"},
  {"xlam", "application/vnd.ms-excel.addin.macroEnabled.12"},
  {"xlc", "application/vnd.ms-excel"},
  {"xld", "application/vnd.ms-excel"},
  {"xlk", "application/vnd.ms-excel"},
  {"xll", "application/vnd.ms-excel"},
  {"xlm", "application/vnd.ms-excel"},
  {"xls", {
    "application/excel",
    "application/vnd.ms-excel",
    "application/vnd.ms-office",
    "application/x-excel",
    "application/octet-stream"
  }},
  {"xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12"},
  {"xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"},
  {"xlsx", {
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel.12",
    "application/octet-stream"
  }},
  {"xlt", "application/vnd.ms-excel"},
  {"xltm", "application/vnd.ms-excel.template.macroEnabled.12"},
  {"xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
  {"xlw", "application/vnd.ms-excel"},
  {"xml", {"application/xml", "text/xml", "application/octet-stream"}},
  {"xmp", "application/octet-stream" },
  {"xmta", "application/xml"},
  {"xof", "x-world/x-vrml"},
  {"XOML", "text/plain"},
  {"xpm", "image/x-xpixmap"},
  {"xps", "application/vnd.ms-xpsdocument"},
  {"xrm-ms", "text/xml"},
  {"xsc", "application/xml"},
  {"xsd", "text/xml"},
  {"xsf", "text/xml"},
  {"xsl", "text/xml"},
  {"xslt", "text/xml"},
  {"xsn", "application/octet-stream"},
  {"xss", "application/xml"},
  {"xspf", "application/xspf+xml"},
  {"xtp", "application/octet-stream"},
  {"xwd", "image/x-xwindowdump"},
  {"z", "application/x-compress"},
  {"zip", {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream"
  }},
  {"zlib", "application/zlib"},
}

-- Used to match extension by content type
exports.reversed_extensions_map = {
  ["text/html"] = "html",
  ["text/css"] = "css",
  ["text/xml"] = "xml",
  ["image/gif"] = "gif",
  ["image/jpeg"] = "jpeg",
  ["application/javascript"] = "js",
  ["application/atom+xml"] = "atom",
  ["application/rss+xml"] = "rss",
  ["application/csv"] = "csv",
  ["text/mathml"] = "mml",
  ["text/plain"] = "txt",
  ["text/vnd.sun.j2me.app-descriptor"] = "jad",
  ["text/vnd.wap.wml"] = "wml",
  ["text/x-component"] = "htc",
  ["image/png"] = "png",
  ["image/svg+xml"] = "svg",
  ["image/tiff"] = "tiff",
  ["image/vnd.wap.wbmp"] = "wbmp",
  ["image/webp"] = "webp",
  ["image/x-icon"] = "ico",
  ["image/x-jng"] = "jng",
  ["image/x-ms-bmp"] = "bmp",
  ["font/woff"] = "woff",
  ["font/woff2"] = "woff2",
  ["application/java-archive"] = "jar",
  ["application/json"] = "json",
  ["application/mac-binhex40"] = "hqx",
  ["application/msword"] = "doc",
  ["application/pdf"] = "pdf",
  ["application/postscript"] = "ps",
  ["application/rtf"] = "rtf",
  ["application/vnd.apple.mpegurl"] = "m3u8",
  ["application/vnd.google-earth.kml+xml"] = "kml",
  ["application/vnd.google-earth.kmz"] = "kmz",
  ["application/vnd.ms-excel"] = "xls",
  ["application/vnd.ms-fontobject"] = "eot",
  ["application/vnd.ms-powerpoint"] = "ppt",
  ["application/vnd.oasis.opendocument.graphics"] = "odg",
  ["application/vnd.oasis.opendocument.presentation"] = "odp",
  ["application/vnd.oasis.opendocument.spreadsheet"] = "ods",
  ["application/vnd.oasis.opendocument.text"] = "odt",
  ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
  ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
  ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
  ["application/x-7z-compressed"] = "7z",
  ["application/x-cocoa"] = "cco",
  ["application/x-java-archive-diff"] = "jardiff",
  ["application/x-java-jnlp-file"] = "jnlp",
  ["application/x-makeself"] = "run",
  ["application/x-perl"] = "pl",
  ["application/x-pilot"] = "pdb",
  ["application/x-rar-compressed"] = "rar",
  ["application/x-redhat-package-manager"] = "rpm",
  ["application/x-sea"] = "sea",
  ["application/x-shockwave-flash"] = "swf",
  ["application/x-stuffit"] = "sit",
  ["application/x-tcl"] = "tcl",
  ["application/x-x509-ca-cert"] = "crt",
  ["application/x-xpinstall"] = "xpi",
  ["application/xhtml+xml"] = "xhtml",
  ["application/xspf+xml"] = "xspf",
  ["application/zip"] = "zip",
  ["application/x-dosexec"] = "exe",
  ["application/x-msdownload"] = "exe",
  ["application/x-executable"] = "exe",
  ["text/x-msdos-batch"] = "bat",

  ["audio/midi"] = "mid",
  ["audio/mpeg"] = "mp3",
  ["audio/ogg"] = "ogg",
  ["audio/x-m4a"] = "m4a",
  ["audio/x-realaudio"] = "ra",
  ["video/3gpp"] = "3gpp",
  ["video/mp2t"] = "ts",
  ["video/mp4"] = "mp4",
  ["video/mpeg"] = "mpeg",
  ["video/quicktime"] = "mov",
  ["video/webm"] = "webm",
  ["video/x-flv"] = "flv",
  ["video/x-m4v"] = "m4v",
  ["video/x-mng"] = "mng",
  ["video/x-ms-asf"] = "asx",
  ["video/x-ms-wmv"] = "wmv",
  ["video/x-msvideo"] = "avi",
}

return exports
