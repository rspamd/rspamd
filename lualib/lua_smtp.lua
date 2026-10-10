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

local rspamd_tcp = require "rspamd_tcp"
local rspamd_text = require "rspamd_text"
local rspamd_util = require "rspamd_util"
local rspamd_mempool = require "rspamd_mempool"
local lua_util = require "lua_util"

local exports = {}

local CRLF = '\r\n'
local default_timeout = 10.0

-- Every octet with the high bit set, as a reject set for rspamd_text:memcspn
local high_octets
do
  local chars = {}
  for i = 128, 255 do
    chars[#chars + 1] = string.char(i)
  end
  high_octets = table.concat(chars)
end

-- Whether a message (string, rspamd_text or array of those) has 8-bit data
local function has_8bit(data)
  local dtype = type(data)
  if dtype == 'string' then
    return string.find(data, '[\128-\255]') ~= nil
  elseif dtype == 'userdata' then
    return data:memcspn(high_octets) < data:len()
  elseif dtype == 'table' then
    for _, chunk in ipairs(data) do
      if has_8bit(chunk) then
        return true
      end
    end
  end
  return false
end

-- rspamd's MIME parser gives up past this nesting depth, so does the downgrade
local max_nesting = 64

-- Returns the lowercased media type (nil when the header is missing or
-- invalid, RFC 2045 5.2 then makes it the default type), the boundary
-- parameter and the lowercased transfer encoding declared by a header block
local function entity_content_info(headers, pool)
  local unfolded = string.gsub(headers, '\r?\n[ \t]+', ' ')
  local ctype, boundary, cte

  for line in string.gmatch(unfolded .. '\n', '([^\n]*)\n') do
    local name, value = string.match(line, '^([^:]+):[ \t]*(.-)[ \t\r]*$')
    if name then
      name = string.lower(name)
      if name == 'content-type' then
        local parsed = rspamd_util.parse_content_type(value, pool)
        ctype, boundary = nil, nil
        if parsed and parsed.type and parsed.subtype then
          ctype = string.lower(parsed.type .. '/' .. parsed.subtype)
          boundary = parsed.boundary
        end
      elseif name == 'content-transfer-encoding' then
        cte = string.lower(value)
      end
    end
  end

  return ctype, boundary, cte
end

-- Replaces (or adds) the Content-Transfer-Encoding header of a header block
local function set_cte(headers, cte)
  local cte_line = 'Content-Transfer-Encoding: ' .. cte
  if headers == '' then
    return cte_line
  end

  local out = {}
  local replaced, in_cte = false, false
  for line in string.gmatch(headers .. '\n', '([^\n]*)\n') do
    if not (in_cte and string.find(line, '^[ \t]')) then
      local name = string.match(line, '^([^:]+):')
      in_cte = name ~= nil and string.lower(name) == 'content-transfer-encoding'
      if not in_cte then
        out[#out + 1] = line
      elseif not replaced then
        out[#out + 1] = cte_line
        replaced = true
      end
    end
  end
  if not replaced then
    out[#out + 1] = cte_line
  end

  return table.concat(out, '\n')
end

-- Raised for data that cannot be converted, as opposed to a Lua error
local function cannot_convert(reason)
  error({ reason = reason }, 0)
end

-- Converts a message string in one forward pass. Delimiter lines are matched
-- against the stack of open multipart boundaries, so the delimiter that ends
-- a body part is found by the same scan that walks its content, and an outer
-- delimiter also ends an unterminated inner multipart; each byte is scanned
-- once whatever the nesting.
local function downgrade_message(msg, pool)
  local len = #msg
  local out = {}
  local boundaries = {} -- open multipart boundaries, innermost last

  local function emit(s, e)
    if e >= s then
      out[#out + 1] = string.sub(msg, s, e)
    end
  end

  -- Position of the first 8-bit octet at or after `pos`. Queries only move
  -- forward, so a single cached search result serves all of them.
  local cached_from, cached_at = 0, nil
  local function first_8bit(pos)
    if cached_at == nil or pos < cached_from or (cached_at and pos > cached_at) then
      cached_from = pos
      cached_at = string.find(msg, '[\128-\255]', pos) or false
    end
    return cached_at or len + 1
  end

  local function has_8bit_range(s, e)
    return s <= e and first_8bit(s) <= e
  end

  -- Level of the open boundary whose delimiter is the line at `s`, and
  -- whether it is the close delimiter
  local function match_delimiter(s, line_end)
    if string.byte(msg, s) ~= 45 or string.byte(msg, s + 1) ~= 45 then
      return nil
    end
    for level = #boundaries, 1, -1 do
      local b = boundaries[level]
      if string.sub(msg, s + 2, s + 1 + #b) == b then
        local tail = string.sub(msg, s + 2 + #b, line_end)
        if string.find(tail, '^%-%-') then
          return level, true
        elseif string.find(tail, '^[ \t]*\r?\n?$') then
          return level, false
        end
      end
    end
    return nil
  end

  -- The next delimiter line at or after `from`, as { level, close,
  -- break_start, line_end }. The line break before it belongs to it
  -- (RFC 2046 5.1.1), unless that break lies before `from`.
  local function find_delimiter(from)
    if #boundaries == 0 then
      return nil
    end
    local s
    if from == 1 or string.byte(msg, from - 1) == 10 then
      s = from
    end
    local search = from
    while true do
      if not s then
        local nl = string.find(msg, '\n--', search, true)
        if not nl then
          return nil
        end
        s = nl + 1
      end
      local line_end = string.find(msg, '\n', s, true) or len
      local level, is_close = match_delimiter(s, line_end)
      if level then
        local break_start = s
        if s > from then
          break_start = s - 1
          if break_start > from and string.byte(msg, break_start - 1) == 13 then
            break_start = break_start - 1
          end
        end
        return { level = level, close = is_close, break_start = break_start, line_end = line_end }
      end
      search = line_end
      s = nil
    end
  end

  -- Splits the entity at `s` into its header block, the separator and the
  -- body start. Headers end at the first empty line; an entity that meets a
  -- delimiter or the end of the message first has no body.
  local function split_headers(s)
    local pos = s
    while pos <= len do
      local line_end = string.find(msg, '\n', pos, true) or len
      local c = string.byte(msg, pos)
      if c == 10 or (c == 13 and string.byte(msg, pos + 1) == 10) then
        if pos == s then
          return '', string.sub(msg, pos, line_end), line_end + 1
        end
        local sep_s = pos - 1
        if string.byte(msg, sep_s - 1) == 13 then
          sep_s = sep_s - 1
        end
        return string.sub(msg, s, sep_s - 1), string.sub(msg, sep_s, line_end), line_end + 1
      end
      if pos > s and match_delimiter(pos, line_end) then
        local hdr_e = pos - 2
        if string.byte(msg, hdr_e) == 13 then
          hdr_e = hdr_e - 1
        end
        return string.sub(msg, s, hdr_e), '', hdr_e + 1
      end
      pos = line_end + 1
    end
    return string.sub(msg, s, len), '', len + 1
  end

  local process_entity

  -- Walks a multipart body: the preamble, every body part, the epilogue.
  -- Returns the delimiter that ended it, which belongs to an outer level.
  local function process_multipart(body_s, boundary, part_ctype, depth)
    boundaries[#boundaries + 1] = boundary
    local level = #boundaries

    local d = find_delimiter(body_s)
    local preamble_e = d and d.break_start - 1 or len
    if has_8bit_range(body_s, preamble_e) then
      cannot_convert('8-bit data in a multipart preamble')
    end
    emit(body_s, preamble_e)

    while d and d.level == level and not d.close do
      emit(d.break_start, d.line_end)
      d = process_entity(d.line_end + 1, part_ctype, depth + 1)
    end

    if d and d.level == level then
      emit(d.break_start, d.line_end)
      boundaries[level] = nil
      local epilogue_s = d.line_end + 1
      d = find_delimiter(epilogue_s)
      local epilogue_e = d and d.break_start - 1 or len
      if has_8bit_range(epilogue_s, epilogue_e) then
        cannot_convert('8-bit data in a multipart epilogue')
      end
      emit(epilogue_s, epilogue_e)
      return d
    end

    -- Unterminated: an outer delimiter or the end of the message ends it
    boundaries[level] = nil
    return d
  end

  -- Converts the entity at `s`, whose media type defaults to `default_ctype`
  -- (text/plain when nil). Returns the delimiter that ended it, if any.
  process_entity = function(s, default_ctype, depth)
    if depth > max_nesting then
      cannot_convert('MIME nesting is too deep')
    end

    local headers, separator, body_s = split_headers(s)
    if string.find(headers, '[\128-\255]') then
      cannot_convert('8-bit data in message headers')
    end

    local ctype, boundary, cte = entity_content_info(headers, pool)
    ctype = ctype or default_ctype
    local is_multipart = ctype ~= nil and string.find(ctype, '^multipart/') ~= nil
    -- A composite entity is 7bit once all of its parts are
    local composite_headers = (cte == '8bit' or cte == 'binary') and set_cte(headers, '7bit') or headers

    if is_multipart and boundary and boundary ~= '' then
      out[#out + 1] = composite_headers .. separator
      -- RFC 2046 5.1.5: a multipart/digest body part is message/rfc822 by default
      return process_multipart(body_s, boundary,
          ctype == 'multipart/digest' and 'message/rfc822' or nil, depth)
    elseif ctype ~= nil and string.find(ctype, '^message/') then
      -- RFC 2046 5.2.1: message/* takes no encoding but 7bit/8bit/binary, so
      -- the embedded message is converted instead
      out[#out + 1] = composite_headers .. separator
      return process_entity(body_s, nil, depth + 1)
    end

    local d = find_delimiter(body_s)
    local body_e = d and d.break_start - 1 or len

    if not has_8bit_range(body_s, body_e) then
      out[#out + 1] = headers .. separator
      emit(body_s, body_e)
      return d
    end

    if is_multipart then
      cannot_convert('multipart entity without a boundary')
    elseif cte == 'base64' or cte == 'quoted-printable' then
      cannot_convert(string.format('8-bit data in a %s encoded part', cte))
    end

    -- Text keeps its line breaks under quoted-printable; anything else must
    -- survive byte for byte, which takes base64
    local body = string.sub(msg, body_s, body_e)
    local new_cte, encoded
    if ctype == nil or string.find(ctype, '^text/') then
      new_cte, encoded = 'quoted-printable', rspamd_util.encode_qp(body, 76, 'crlf')
    else
      new_cte, encoded = 'base64', rspamd_util.encode_base64(body, 76, 'crlf')
    end
    if headers == '' then
      -- The part gains its first header line, which needs its own line break
      separator = CRLF .. separator
    end
    out[#out + 1] = set_cte(headers, new_cte) .. separator .. encoded:str()
    return d
  end

  process_entity(1, nil, 0)

  return table.concat(out)
end

--[[[
-- @function lua_smtp.downgrade_to_7bit(message)
-- Converts a message to 7-bit data for a server that does not support
-- 8BITMIME (RFC 6152 section 3): 8bit/binary body parts are re-encoded,
-- text as quoted-printable and anything else as base64, multipart and
-- message/* entities are processed recursively, and everything else is kept
-- byte for byte.
-- @param {string|text|table} message message as a string, rspamd_text or an array of those
-- @return {string|nil} converted message, or nil and an error message if it has
-- 8-bit data that cannot be converted (in headers, for instance)
--]]
local function downgrade_to_7bit(message)
  local mtype = type(message)
  if mtype == 'userdata' then
    message = message:str()
  elseif mtype == 'table' then
    local chunks = {}
    for i, chunk in ipairs(message) do
      chunks[i] = type(chunk) == 'userdata' and chunk:str() or chunk
    end
    message = table.concat(chunks)
  end

  local pool = rspamd_mempool.create()
  local ok, res = pcall(downgrade_message, message, pool)
  pool:destroy()

  if not ok then
    if type(res) == 'table' and res.reason then
      return nil, res.reason
    end
    return nil, string.format('cannot convert the message: %s', tostring(res))
  end

  return res
end

--[[[
-- @function lua_smtp.sendmail(task, message, opts, callback)
--]]
local function sendmail(opts, message, callback)
  local stage = 'connect'

  local function mail_cb(err, data, conn)
    local function no_error_write(merr)
      if merr then
        callback(false, string.format('error on stage %s: %s',
            stage, merr))
        if conn then
          conn:close()
        end

        return false
      end

      return true
    end

    local function no_error_read(merr, mdata, wantcode)
      wantcode = wantcode or '2'
      if merr then
        callback(false, string.format('error on stage %s: %s',
            stage, merr))
        if conn then
          conn:close()
        end

        return false
      end
      if mdata then
        if type(mdata) ~= 'string' then
          mdata = tostring(mdata)
        end
        if string.sub(mdata, 1, 1) ~= wantcode then
          callback(false, string.format('bad smtp response on stage %s: "%s" when "%s" expected',
              stage, mdata, wantcode))
          if conn then
            conn:close()
          end
          return false
        end
      else
        callback(false, string.format('no data on stage %s',
            stage))
        if conn then
          conn:close()
        end
        return false
      end
      return true
    end

    -- After quit
    local function all_done_cb(merr, mdata)
      if conn then
        conn:close()
      end

      callback(true, nil)

      return true
    end

    -- QUIT stage
    local function quit_done_cb(_, _)
      conn:add_read(all_done_cb, CRLF)
    end
    local function quit_cb(merr, mdata)
      if no_error_read(merr, mdata) then
        conn:add_write(quit_done_cb, 'QUIT' .. CRLF)
      end
    end
    local function pre_quit_cb(merr, _)
      if no_error_write(merr) then
        stage = 'quit'
        conn:add_read(quit_cb, CRLF)
      end
    end

    -- DATA stage
    local function data_done_cb(merr, mdata)
      if no_error_read(merr, mdata, '3') then
        -- Normalize line endings to CRLF for SMTP compliance
        -- SMTP allows CR and LF only as CRLF: a bare CR becomes a line break
        -- too, so "<CR>.<CR><LF>" cannot slip past dot-stuffing below
        local function normalize_to_crlf(msg)
          if type(msg) == 'userdata' then
            -- rspamd_text object
            return msg:normalize_newlines("smtp")
          elseif type(msg) == 'string' then
            -- Convert string to text, normalize, back to string
            local txt = rspamd_text.fromstring(msg)
            txt:normalize_newlines("smtp")
            return txt:str()
          end
          return msg
        end

        -- RFC 5321 4.5.2 transparency: a line starting with '.' is transmitted
        -- with an extra leading '.', which the receiver strips. Without this a
        -- lone '.' line in the body would end the DATA phase early and
        -- truncate the message. Runs after CRLF normalization, so every line
        -- is known to end in CRLF.
        -- `at_line_start` carries line state across chunks of a split message
        -- so a '.' at the head of a chunk is only stuffed when the previous
        -- chunk actually ended a line.
        local function dot_stuff(msg, at_line_start)
          local mtype = type(msg)
          local len

          if mtype == 'userdata' then
            len = msg:len()
          elseif mtype == 'string' then
            len = #msg
          else
            return msg, at_line_start
          end

          if len == 0 then
            return msg, at_line_start
          end

          -- Matching on LF alone also covers CRLF, so stuffing stays correct
          -- even if the content reaches us with mixed line endings
          local leading_dot, embedded_dot
          if mtype == 'userdata' then
            -- len/at/find inspect the text in place; only stuffing copies it
            leading_dot = at_line_start and msg:at(1) == 46
            embedded_dot = msg:find('\n.') ~= nil
          else
            leading_dot = at_line_start and string.sub(msg, 1, 1) == '.'
            embedded_dot = string.find(msg, '\n.', 1, true) ~= nil
          end

          local ends_line
          if mtype == 'userdata' then
            ends_line = msg:at(len) == 10
          else
            ends_line = string.sub(msg, -1) == '\n'
          end

          if not leading_dot and not embedded_dot then
            return msg, ends_line
          end

          local str = mtype == 'userdata' and msg:str() or msg
          str = string.gsub(str, '\n%.', '\n..')
          if leading_dot then
            str = '.' .. str
          end

          return str, ends_line
        end

        if type(message) == 'string' or type(message) == 'userdata' then
          message = normalize_to_crlf(message)
          message = dot_stuff(message, true)
          conn:add_write(pre_quit_cb, { message, CRLF .. '.' .. CRLF })
        else
          -- Array of chunks
          local at_line_start = true
          for i = 1, #message do
            message[i] = normalize_to_crlf(message[i])
            message[i], at_line_start = dot_stuff(message[i], at_line_start)
          end
          table.insert(message, CRLF .. '.' .. CRLF)
          conn:add_write(pre_quit_cb, message)
        end
      end
    end
    local function data_cb(merr, _)
      if no_error_write(merr) then
        conn:add_read(data_done_cb, CRLF)
      end
    end

    -- RCPT phase
    local next_recipient
    local function rcpt_done_cb_gen(i)
      return function(merr, mdata)
        if no_error_read(merr, mdata) then
          if i == #opts.recipients then
            conn:add_write(data_cb, 'DATA' .. CRLF)
          else
            next_recipient(i + 1)
          end
        end
      end
    end

    local function rcpt_cb_gen(i)
      return function(merr, _)
        if no_error_write(merr, '2') then
          conn:add_read(rcpt_done_cb_gen(i), CRLF)
        end
      end
    end

    next_recipient = function(i)
      conn:add_write(rcpt_cb_gen(i),
          string.format('RCPT TO: <%s>%s', opts.recipients[i], CRLF))
    end

    -- FROM stage
    local function from_done_cb(merr, mdata)
      -- We need to iterate over recipients sequentially
      if no_error_read(merr, mdata, '2') then
        stage = 'rcpt'
        next_recipient(1)
      end
    end
    local function from_cb(merr, _)
      if no_error_write(merr) then
        conn:add_read(from_done_cb, CRLF)
      end
    end
    local supports_8bitmime = false

    -- RFC 6152 section 3: a server without 8BITMIME must not get 8-bit data,
    -- so convert the message to 7bit first, or fail if that is impossible
    local function prepare_message()
      if supports_8bitmime or not has_8bit(message) then
        return true
      end
      local converted, downgrade_err = downgrade_to_7bit(message)
      if not converted then
        callback(false, string.format('server does not support 8BITMIME and ' ..
            'the message cannot be converted to 7bit: %s', downgrade_err))
        if conn then
          conn:close()
        end
        return false
      end
      message = converted
      return true
    end

    local function send_mail_from()
      if not prepare_message() then
        return
      end
      stage = 'from'
      local mail_params = supports_8bitmime and ' BODY=8BITMIME' or ''
      conn:add_write(from_cb, string.format(
          'MAIL FROM: <%s>%s%s', opts.from, mail_params, CRLF))
    end

    -- HELO stage (fallback used when EHLO is rejected or unsupported)
    local function helo_done_cb(merr, mdata)
      if no_error_read(merr, mdata) then
        send_mail_from()
      end
    end
    local function helo_cb(merr)
      if no_error_write(merr) then
        conn:add_read(helo_done_cb, CRLF)
      end
    end
    local function send_helo()
      stage = 'helo'
      supports_8bitmime = false
      conn:add_write(helo_cb, string.format('HELO %s%s',
          opts.helo, CRLF))
    end

    -- EHLO stage
    local ehlo_done_cb
    local ehlo_ok = true
    ehlo_done_cb = function(merr, mdata)
      if merr then
        callback(false, string.format('error on stage %s: %s',
            stage, merr))
        if conn then
          conn:close()
        end
        return
      end
      if type(mdata) ~= 'string' then
        mdata = tostring(mdata)
      end
      -- RFC 5321 4.2: Reply-code [ SP textstring ] CRLF, so a final line may
      -- carry the code alone; only '-' marks a continuation
      local code, sep = string.match(mdata, '^(%d%d%d)([ %-]?)')
      if not code then
        callback(false, string.format('bad smtp response on stage %s: "%s"',
            stage, mdata))
        if conn then
          conn:close()
        end
        return
      end
      if string.sub(code, 1, 1) ~= '2' then
        ehlo_ok = false
      end
      local capability = string.match(mdata, '^%d%d%d[ %-]%s*([%w][%w-]*)')
      if capability and string.upper(capability) == '8BITMIME' then
        supports_8bitmime = true
      end
      if sep == '-' then
        conn:add_read(ehlo_done_cb, CRLF)
      elseif ehlo_ok then
        send_mail_from()
      else
        send_helo()
      end
    end
    local function ehlo_cb(merr)
      if no_error_write(merr) then
        conn:add_read(ehlo_done_cb, CRLF)
      end
    end
    local function send_ehlo()
      stage = 'ehlo'
      conn:add_write(ehlo_cb, string.format('EHLO %s%s',
          opts.helo, CRLF))
    end

    -- The greeting may span several lines ("220-..." up to "220 ..."); EHLO
    -- must wait for its last one, or every later reply is read one step late
    local function is_continuation(mdata)
      return string.match(tostring(mdata), '^%d%d%d%-') ~= nil
    end
    local function greeting_cb(merr, mdata)
      if no_error_read(merr, mdata) then
        if is_continuation(mdata) then
          conn:add_read(greeting_cb, CRLF)
        else
          send_ehlo()
        end
      end
    end
    if no_error_read(err, data) then
      if is_continuation(data) then
        conn:add_read(greeting_cb, CRLF)
      else
        send_ehlo()
      end
    end
  end

  if type(opts.recipients) == 'string' then
    opts.recipients = { opts.recipients }
  end

  local tcp_opts = lua_util.shallowcopy(opts)
  tcp_opts.stop_pattern = CRLF
  tcp_opts.timeout = opts.timeout or default_timeout
  -- connect_timeout/read_timeout/write_timeout, when given, are copied above
  -- and switch rspamd_tcp to per-phase timers. Without them `timeout` stays a
  -- single budget for the whole transaction, which keeps it within the time
  -- the caller (e.g. a symbol's timeout augmentation) reserved for it.
  tcp_opts.callback = mail_cb

  if not rspamd_tcp.request(tcp_opts) then
    callback(false, 'cannot make a TCP connection')
  end
end

exports.sendmail = sendmail
exports.downgrade_to_7bit = downgrade_to_7bit

return exports
