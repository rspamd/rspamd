--[[
Copyright (c) 2016-2026, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

if confighelp then
  return
end

-- A plugin that pushes metadata (or whole messages) to external services

local redis_params
local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local rspamd_tcp = require "rspamd_tcp"
local lua_redis = require "lua_redis"
local lua_mime = require "lua_mime"
local lua_selectors = require "lua_selectors"
local ucl = require "ucl"
local T = require "lua_shape.core"
local schema = require "plugins/metadata_exporter"
local E = {}
local N = 'metadata_exporter'
local HOSTNAME = rspamd_util.get_hostname()
local selector_cache = {}

-- Inlined values reach mail headers, URLs and Redis keys, so they must never
-- break framing: collapse every CR/LF run to a single space
local function sanitize_inline(str)
  return (string.gsub(str, '[\r\n]+', ' '))
end

local settings = {
  pusher_enabled = {},
  pusher_format = {},
  pusher_select = {},
  mime_type = 'text/plain',
  defer = false,
  mail_from = '',
  mail_to = 'postmaster@localhost',
  helo = 'rspamd',
  email_template = [[From: "Rspamd" <$mail_from>
To: $mail_to
Subject: Spam alert
Date: $date
MIME-Version: 1.0
Message-ID: <$our_message_id>
Content-type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Authenticated username: $user
IP: $ip
Queue ID: $qid
SMTP FROM: $from
SMTP RCPT: $rcpt
MIME From: $header_from
MIME To: $header_to
MIME Date: $header_date
Subject: $header_subject
Message-ID: $message_id
Action: $action
Score: $score
Symbols: $symbols]],
  timeout = 5.0,
  gzip = false,
  keepalive = false,
  no_ssl_verify = false,
  email_auto_encode_headers = true,
}

local variables = {
  content = function(task)
    local content = task:get_content()
    return content and content:str() or ''
  end,
  uid = function(task)
    return string.sub(task:get_uid(), 1, 6)
  end,
  local_date = function(_)
    return os.date("%c")
  end,
  our_boundary = function(_)
    return "----=_MIME_BOUNDARY_" .. rspamd_util.random_hex(15)
  end,
}

-- Custom variables are user code: an error in one must not escape the
-- exporter (skipping `defer` on the way), so it counts as returning no value
local function call_variable(task, name)
  local ok, res = pcall(variables[name], task)
  if not ok then
    rspamd_logger.errx(task, 'custom variable [%s] failed: %s', name, res)
    return nil
  end
  return res
end

local function get_selector(log_obj, expr)
  local selector = selector_cache[expr]
  if selector == nil then
    selector = lua_selectors.create_selector_closure(rspamd_config, expr, '', true) or false
    selector_cache[expr] = selector
    if not selector then
      rspamd_logger.errx(log_obj, 'could not create selector [%s]', expr)
    end
  end
  return selector or nil
end

-- Flattens a variable or selector result into `out`. Arrays (a selector-backed
-- list, for instance) are flattened depth-first, one entry per element, rather
-- than stringified as a table address; anything that cannot carry text is
-- rejected so the caller can fail instead of inserting junk.
local function flatten_value(value, out)
  local vtype = type(value)

  if vtype == 'table' then
    for _, elt in ipairs(value) do
      if not flatten_value(elt, out) then
        return false
      end
    end
    return true
  end

  if vtype == 'string' then
    table.insert(out, value)
    return true
  end

  if vtype == 'number' or vtype == 'boolean' then
    table.insert(out, tostring(value))
    return true
  end

  if vtype == 'userdata' then
    -- rspamd_text and friends carry their bytes behind :str(), other objects
    -- (an IP address, say) at least render through __tostring
    local ok, converted = pcall(function()
      return value:str()
    end)
    if ok and type(converted) == 'string' then
      table.insert(out, converted)
      return true
    end
    local mt = getmetatable(value)
    if type(mt) == 'table' and mt.__tostring then
      table.insert(out, tostring(value))
      return true
    end
  end

  return false
end

-- Converts a variable or selector result to text, joining array elements
-- with `sep`; returns nil when it cannot carry text
local function stringify_value(value, sep)
  if value == nil then
    return nil
  end

  local out = {}
  if not flatten_value(value, out) then
    return nil
  end

  -- A table with no array part carries no text; an empty one is just empty
  -- content, which is allowed
  if #out == 0 and type(value) == 'table' and next(value) ~= nil then
    return nil
  end

  return table.concat(out, sep)
end

-- Replaces every $name and ${expr} placeholder of `str` in a single pass, so
-- substituted text is never scanned for placeholders again: message data that
-- looks like "${header(...)}" or "$ip" stays literal. A name resolves to a
-- `meta` entry, then to a custom variable; ${expr} falls back to a selector.
-- Variable and selector results are collapsed to one line; `meta` values only
-- when `inline_meta` is set (header rendering), so a body keeps them verbatim.
-- An unknown $name is kept as is.
local function expand_placeholders(task, str, meta, inline_meta)
  if not str or not string.find(str, '$', 1, true) then
    return str
  end

  local function stringify(what, extracted)
    local str_val = stringify_value(extracted, ',')
    if str_val == nil then
      rspamd_logger.errx(task, '%s returned a value that cannot be converted to text', what)
      return '((error extracting value))'
    end
    return sanitize_inline(str_val)
  end

  local function resolve(name, braced)
    if meta and meta[name] ~= nil then
      local value = tostring(meta[name])
      return inline_meta and sanitize_inline(value) or value
    end
    if variables[name] then
      local extracted = call_variable(task, name)
      if extracted == nil then
        rspamd_logger.errx(task, 'custom variable [%s] returned no value', name)
        return '((error extracting value))'
      end
      return stringify(string.format('custom variable [%s]', name), extracted)
    end
    if not braced then
      return nil
    end
    local selector = get_selector(task, name)
    if not selector then
      return '((could not create selector))'
    end
    local extracted = selector(task)
    if not extracted then
      rspamd_logger.errx(task, 'could not extract value with selector [%s]', name)
      return '((error extracting value))'
    end
    return stringify(string.format('selector [%s]', name), extracted)
  end

  local out = {}
  local pos, len = 1, #str
  while pos <= len do
    local dollar = string.find(str, '$', pos, true)
    if not dollar then
      out[#out + 1] = string.sub(str, pos)
      break
    end
    out[#out + 1] = string.sub(str, pos, dollar - 1)

    local replacement, next_pos
    if string.sub(str, dollar + 1, dollar + 1) == '{' then
      local close = string.find(str, '}', dollar + 2, true)
      if close then
        replacement = resolve(string.sub(str, dollar + 2, close - 1), true)
        next_pos = close + 1
      end
    else
      local name_s, name_e = string.find(str, '^[A-Za-z0-9_]+', dollar + 1)
      if name_s then
        replacement = resolve(string.sub(str, name_s, name_e), false)
        next_pos = name_e + 1
      end
    end

    if replacement then
      out[#out + 1] = replacement
      pos = next_pos
    else
      out[#out + 1] = '$'
      pos = dollar + 1
    end
  end

  return table.concat(out)
end

local function expand_value(task, val)
  if type(val) == 'string' then
    return expand_placeholders(task, val)
  elseif type(val) == 'table' then
    local expanded = {}
    for k, elt in pairs(val) do
      expanded[k] = expand_value(task, elt)
    end
    return expanded
  end
  return val
end

-- Only per-message routing values may come from selectors or custom variables;
-- connection, credential and behaviour options stay literal by design
local expandable_rule_fields = {
  channel = true,
  helo = true,
  mail_from = true,
  mail_to = true,
  stream_key = true,
}

local settings_fallback_fields = {
  'auto_grouping',
  'channel',
  'connect_timeout',
  'defer',
  'email_auto_encode_headers',
  'gzip',
  'helo',
  'host',
  'keepalive',
  'list_key',
  'mail_from',
  'mail_to',
  'max_len',
  'mime_type',
  'no_ssl_verify',
  'port',
  'read_timeout',
  'smtp',
  'smtp_port',
  'ssl_timeout',
  'stream_key',
  'timeout',
  'url',
  'write_timeout',
}

local function resolve_rule(task, rule)
  local resolved = {}
  for name, val in pairs(rule) do
    if expandable_rule_fields[name] then
      resolved[name] = expand_value(task, val)
    else
      resolved[name] = val
    end
  end
  for _, name in ipairs(settings_fallback_fields) do
    if resolved[name] == nil and settings[name] ~= nil then
      if expandable_rule_fields[name] then
        resolved[name] = expand_value(task, settings[name])
      else
        resolved[name] = settings[name]
      end
    end
  end
  return resolved
end

-- Evaluates every custom variable the templates refer to exactly once, so all
-- occurrences (a MIME boundary used in a header and in the body, say) get the
-- same value, and stores it as text
local function add_template_variables(task, templates, meta)
  local requested = {}
  for _, tmpl in ipairs(templates) do
    for name in string.gmatch(tmpl, '%$([%w_]+)') do
      requested[name] = true
    end
    for name in string.gmatch(tmpl, '%${([%w_]+)}') do
      requested[name] = true
    end
  end
  for name in pairs(requested) do
    if meta[name] == nil and variables[name] then
      local value = stringify_value(call_variable(task, name), ',')
      if value == nil then
        rspamd_logger.errx(task, 'custom variable [%s] returned no usable value', name)
        value = '((error extracting value))'
      end
      meta[name] = value
    end
  end
end

-- Splits email_template at its first blank line into the header block, the
-- separator and the body; the separator is empty for a template without a body
local function split_template(tmpl)
  local sep_start, sep_end = string.find(tmpl, '\r?\n\r?\n')
  if not sep_start then
    return tmpl, '', ''
  end
  return string.sub(tmpl, 1, sep_start - 1), string.sub(tmpl, sep_start, sep_end),
      string.sub(tmpl, sep_end + 1)
end

-- Renders email_template. The header block and the body are rendered
-- separately: values substituted into the headers are collapsed to one line,
-- so neither a custom variable nor message metadata can add a header or move
-- the header/body boundary, while the body keeps values verbatim ($content
-- may carry a whole message). Returns the header block, the separator and the
-- body; the separator is empty for a template without a body.
local function render_email_template(task, tmpl, meta)
  local header_tmpl, separator, body_tmpl = split_template(tmpl)

  local header_block = expand_placeholders(task, header_tmpl, meta, true)
  local body = expand_placeholders(task, body_tmpl, meta, false)

  return header_block, separator, body
end

-- RFC 5321 4.1.1.3 has servers accept a bare "postmaster", and a plain SASL
-- username is a usual alert target: a local part without a domain is kept as
-- is. Only dot-atom characters qualify, so it cannot carry CR/LF or syntax.
local function is_bare_local_part(value)
  return string.find(value, "^[A-Za-z0-9!#$%%&'*+/=?^_`{|}~.-]+$") ~= nil
end

local function add_mail_targets(task, source, values, mail_targets, display_emails)
  if type(values) == 'table' then
    for _, value in ipairs(values) do
      add_mail_targets(task, source, value, mail_targets, display_emails)
    end
    return
  end

  if type(values) ~= 'string' or values == '' then
    rspamd_logger.errx(task, '%s returned no email address', source)
    return
  end

  if is_bare_local_part(values) then
    table.insert(mail_targets, values)
    table.insert(display_emails, string.format('<%s>', values))
    return
  end

  local parsed = rspamd_util.parse_mail_address(values, task:get_mempool())
  if not parsed or #parsed == 0 then
    rspamd_logger.errx(task, '%s returned an invalid email address: %s', source, values)
    return
  end

  for _, address in ipairs(parsed) do
    if address.flags and address.flags.valid and address.addr and address.addr ~= '' then
      table.insert(mail_targets, address.addr)
      table.insert(display_emails, string.format('<%s>', address.addr))
    else
      rspamd_logger.errx(task, '%s returned an invalid email address: %s', source,
        address.raw or values)
    end
  end
end

local function normalize_mail_from(task, value)
  if value == '' then
    return value
  end
  if type(value) ~= 'string' then
    rspamd_logger.errx(task, 'mail_from is not a string')
    return nil
  end
  if is_bare_local_part(value) then
    return value
  end

  local parsed = rspamd_util.parse_mail_address(value, task:get_mempool())
  if parsed and #parsed == 1 and parsed[1].flags and parsed[1].flags.valid then
    return parsed[1].addr
  end
  rspamd_logger.errx(task, 'mail_from is not a valid single email address: %s', value)
  return nil
end

local address_headers = {
  from = true,
  to = true,
  cc = true,
  bcc = true,
  sender = true,
  ['reply-to'] = true,
  ['resent-from'] = true,
  ['resent-to'] = true,
  ['resent-cc'] = true,
  ['resent-bcc'] = true,
  ['resent-sender'] = true,
}

local structured_headers = {
  ['authentication-results'] = true,
  ['arc-authentication-results'] = true,
  ['arc-message-signature'] = true,
  ['arc-seal'] = true,
  ['content-disposition'] = true,
  ['content-transfer-encoding'] = true,
  ['content-type'] = true,
  date = true,
  ['dkim-signature'] = true,
  ['in-reply-to'] = true,
  ['list-archive'] = true,
  ['list-help'] = true,
  ['list-id'] = true,
  ['list-owner'] = true,
  ['list-post'] = true,
  ['list-subscribe'] = true,
  ['list-unsubscribe'] = true,
  ['message-id'] = true,
  ['mime-version'] = true,
  received = true,
  references = true,
  ['resent-date'] = true,
  ['resent-message-id'] = true,
  ['return-path'] = true,
}

local function is_ascii(str)
  return not string.find(str, '[\128-\255]')
end

-- Joins folded continuation lines so each entry is one logical header. Lines
-- may end in CRLF (a template edited that way); the CR is dropped so it never
-- ends up inside a header value
local function split_logical_headers(header_block)
  local logical = {}
  for line in (header_block .. '\n'):gmatch('(.-)\r?\n') do
    if #logical > 0 and string.match(line, '^[ \t]') then
      logical[#logical] = logical[#logical] .. '\n' .. line
    else
      table.insert(logical, line)
    end
  end
  return logical
end

local function logical_header_name(entry)
  local name = string.match(entry, '^([^:]+):')
  return name and string.lower(name) or nil
end

local function logical_header_value(entry)
  local colon = string.find(entry, ':', 1, true)
  return colon and string.match(string.sub(entry, colon + 1), '^%s*(.-)%s*$') or ''
end

local function has_mime_parameter(value, name)
  local unfolded = string.lower(string.gsub(value, '\r?\n[ \t]+', ' '))
  for parameter in string.gmatch(unfolded, ';%s*([^=;%s]+)%s*=') do
    if parameter == name or string.match(parameter, '^' .. name .. '%*%d*%*?$') then
      return true
    end
  end
  return false
end

-- RFC 2047-encodes the rendered top-level header block, as 8BITMIME covers
-- message bodies only. Address lists get their display names and comments
-- encoded, unstructured fields their non-ASCII words. What has no RFC 2047
-- form - a non-ASCII address, non-ASCII in another structured field - makes
-- the alert unsendable rather than sent with raw 8-bit header octets.
local function encode_header_block(task, header_block)
  local out = {}
  for _, entry in ipairs(split_logical_headers(header_block)) do
    local colon = string.find(entry, ':', 1, true)
    if not colon then
      table.insert(out, entry)
    else
      local name = string.sub(entry, 1, colon - 1)
      local value = string.gsub(string.sub(entry, colon + 1), '\r?\n[ \t]+', ' ')
      value = string.match(value, '^[ \t]*(.*)$')
      local lname = string.lower(name)
      local encoded, unstructured
      if address_headers[lname] then
        encoded = rspamd_util.mime_header_encode(value, true)
      elseif structured_headers[lname] then
        encoded = value
      else
        encoded = rspamd_util.mime_header_encode(value, false)
        unstructured = true
      end
      if not is_ascii(encoded) then
        return nil, string.format('cannot encode %s header: its non-ASCII data has no RFC 2047 form', name)
      end
      if encoded == value then
        -- Refolding would only change a header nothing was wrong with
        table.insert(out, entry)
      else
        -- Generated content uses LF whatever the scanned message used;
        -- lua_smtp turns it into CRLF on the wire. Unstructured text folds
        -- only at existing whitespace, so it unfolds back unchanged; the
        -- structured folder may break after ',' and add whitespace there
        local fold = unstructured and rspamd_util.fold_header_unstructured or rspamd_util.fold_header
        table.insert(out, name .. ': ' .. fold(name, encoded, 'lf'))
      end
    end
  end

  return table.concat(out, '\n')
end

-- Classifies a part body in place, without copying it: `ascii` tells whether it
-- is free of 8-bit octets, `unsafe` whether 7bit/8bit would break framing on
-- the wire (NUL bytes or lines over the RFC 5322 998-octet limit), which
-- quoted-printable encodes and folds away. A bare "." line needs no handling
-- here: dot-stuffing is the SMTP transport's job and lua_smtp does it
-- (RFC 5321 4.5.2).
local function scan_part_content(content)
  local len = #content
  local ascii = not string.find(content, '[\128-\255]')
  -- Plain find of a literal NUL: the %z class was removed in Lua 5.2 and
  -- matches the letter 'z' there instead
  local unsafe = string.find(content, '\0', 1, true) ~= nil

  if not unsafe and len > 998 then
    local pos = 1
    while pos <= len do
      local nl = string.find(content, '\n', pos, true)
      local line_end = (nl or len + 1) - 1
      if line_end >= pos and string.byte(content, line_end) == 13 then
        line_end = line_end - 1
      end
      if line_end - pos + 1 > 998 then
        unsafe = true
        break
      end
      if not nl then
        break
      end
      pos = nl + 1
    end
  end

  return { ascii = ascii, unsafe = unsafe }
end

local function guess_text_cte(scan)
  if not scan.ascii or scan.unsafe then
    return 'quoted-printable'
  end
  return '7bit'
end

-- An explicitly configured encoding is honoured unless it violates its MIME
-- constraints or would corrupt the message on the wire.
local function sanitize_cte(task, label, cte, scan)
  if cte == '7bit' and (not scan.ascii or scan.unsafe) then
    rspamd_logger.warnx(task,
      '%s content is not valid 7bit data, using quoted-printable instead', label)
    return 'quoted-printable'
  elseif cte == '8bit' and scan.unsafe then
    rspamd_logger.warnx(task,
      '%s content has NUL bytes or over-long lines, using quoted-printable instead of 8bit', label)
    return 'quoted-printable'
  end
  return cte
end

local function encode_part_content(task, value, cte)
  local encoded
  if cte == 'base64' then
    encoded = rspamd_util.encode_base64(value, 76, 'lf')
  elseif cte == 'quoted-printable' then
    encoded = rspamd_util.encode_qp(value, 76, 'lf')
  else
    return value
  end
  -- encode_base64/encode_qp return rspamd_text userdata, not a Lua string
  return type(encoded) == 'string' and encoded or encoded:str()
end

-- RFC 2231 encoding of a header parameter. Long values are split into numbered
-- sections (only section 0 carries the charset prefix) and folded onto
-- continuation lines, so a selector-derived filename cannot push the header
-- past the 998-octet line limit. Sections are assembled from whole encoded
-- characters so a split never lands inside a %XX escape.
local function encode_rfc2231_parameter(name, value)
  local safe = "!#$&+-.^_`|~"
  local encoded = {}
  for i = 1, #value do
    local ch = string.sub(value, i, i)
    if string.match(ch, '[A-Za-z0-9]') or string.find(safe, ch, 1, true) then
      table.insert(encoded, ch)
    else
      table.insert(encoded, string.format('%%%02X', string.byte(ch)))
    end
  end

  local sections = {}
  local current = ''
  for _, chunk in ipairs(encoded) do
    if #current + #chunk > 60 then
      table.insert(sections, current)
      current = ''
    end
    current = current .. chunk
  end
  table.insert(sections, current)

  if #sections == 1 then
    return string.format("%s*=UTF-8''%s", name, sections[1])
  end

  local out = {}
  for i, section in ipairs(sections) do
    if i == 1 then
      table.insert(out, string.format("%s*0*=UTF-8''%s", name, section))
    else
      table.insert(out, string.format('%s*%d*=%s', name, i - 1, section))
    end
  end
  return table.concat(out, ';\n ')
end

local function build_part_header_lines(content_type, filename, disposition, cte)
  local lines = {}
  if filename then
    table.insert(lines, 'Content-Type: ' .. content_type .. ';\n ' ..
      encode_rfc2231_parameter('name', filename))
  else
    table.insert(lines, 'Content-Type: ' .. content_type)
  end
  table.insert(lines, 'Content-Transfer-Encoding: ' .. cte)
  if filename then
    table.insert(lines, string.format('Content-Disposition: %s;\n %s', disposition,
      encode_rfc2231_parameter('filename', filename)))
  else
    table.insert(lines, 'Content-Disposition: ' .. disposition)
  end
  return table.concat(lines, '\n')
end

-- Joins already-rendered MIME part blocks (header+blank+body each) behind one
-- boundary, RFC 2046 style: a boundary line before every part, a closing one
-- (with trailing "--") at the end.
local function render_multipart(parts, boundary)
  local body = {}
  for _, p in ipairs(parts) do
    table.insert(body, '--' .. boundary)
    table.insert(body, p)
  end
  table.insert(body, '--' .. boundary .. '--')
  return table.concat(body, '\n')
end

-- content/content_from_variables accept a single string or an array; the
-- schema does not normalize this (see lualib/plugins/metadata_exporter.lua)
local function part_content_names(value)
  if type(value) == 'table' then
    return value
  end
  return { value }
end

-- Renders the template's own body into a part block, returning its
-- classification kind alongside it for the layout planner
-- Content type of the template's own body part and its grouping kind
local function template_part_type(template_part_headers)
  local content_type = 'text/plain; charset=utf-8'
  if template_part_headers.content_type then
    for _, entry in ipairs(template_part_headers) do
      if logical_header_name(entry) == 'content-type' then
        content_type = logical_header_value(entry)
      end
    end
  end
  local has_filename = template_part_headers.filename or has_mime_parameter(content_type, 'name')
  return content_type, schema.classify_text_kind(content_type, has_filename, template_part_headers.disposition)
end

local function build_template_part(task, template_body, template_part_headers)
  local content_type, kind = template_part_type(template_part_headers)

  local headers = {}
  for _, entry in ipairs(template_part_headers) do
    table.insert(headers, entry)
  end
  if not template_part_headers.content_type then
    table.insert(headers, 'Content-Type: ' .. content_type)
  end
  if not template_part_headers.cte then
    local cte = guess_text_cte(scan_part_content(template_body))
    table.insert(headers, 'Content-Transfer-Encoding: ' .. cte)
    template_body = encode_part_content(task, template_body, cte)
  end
  local part = table.concat(headers, '\n') .. '\n\n' .. template_body
  return kind, part
end

-- Builds the multipart body for email_alert: an optional leading part from
-- the template's own body (skipped only when that body is truly empty - a
-- whitespace-only body still becomes a part), followed by one part per
-- rule.email_parts entry. A text/plain + text/html pair is wrapped in a
-- nested multipart/alternative unless rule.auto_grouping is false (see
-- lualib/plugins/metadata_exporter.lua plan_layout). Returns nil on any
-- unresolvable part so the caller aborts the whole message rather than
-- sending a report with a silently missing/garbled part.
local function assemble_email_parts(task, rule, template_body, template_part_headers, meta)
  local descriptors = {}

  if #template_body > 0 then
    local kind, part = build_template_part(task, template_body, template_part_headers)
    table.insert(descriptors, { kind = kind, part = part })
  end

  for i, entry in ipairs(rule.email_parts) do
    local value
    if entry.content_from_variables ~= nil then
      local resolved = {}
      for _, name in ipairs(part_content_names(entry.content_from_variables)) do
        if not variables[name] then
          rspamd_logger.errx(task, 'email_parts[%s] references unknown variable [%s]', i, name)
          return nil
        end
        -- A part body keeps one line per element of an array-valued variable
        local v = stringify_value(call_variable(task, name), '\n')
        if v == nil then
          rspamd_logger.errx(task, 'email_parts[%s] variable [%s] returned nil or unconvertible content',
            i, name)
          return nil
        end
        table.insert(resolved, v)
      end
      value = table.concat(resolved, '\n')
    else
      -- Literal/template content is expanded like the email template itself
      value = expand_placeholders(task, table.concat(part_content_names(entry.content), '\n'), meta, false)
    end

    local filename
    if entry.filename then
      filename = expand_placeholders(task, entry.filename, meta, false)
    end
    if filename == '' then
      filename = nil
    end
    -- Config-time validation always fills content_type in; the fallback only
    -- guards against a part that somehow reached here unvalidated
    local content_type = entry.content_type or 'application/octet-stream'
    local disposition = entry.disposition or (filename and 'attachment' or 'inline')
    local cte = entry.encoding
    if not cte or cte == 'auto' then
      -- MIME type names are case-insensitive, so match accordingly
      if string.match(string.lower(content_type), '^text/') then
        cte = guess_text_cte(scan_part_content(value))
      else
        cte = 'base64'
      end
    elseif cte == '7bit' or cte == '8bit' then
      -- Only verbatim encodings need the scan; base64/quoted-printable are
      -- always transport-safe
      cte = sanitize_cte(task, string.format('email_parts[%s]', i), cte, scan_part_content(value))
    end

    local part = build_part_header_lines(content_type, filename, disposition, cte)
      .. '\n\n' .. encode_part_content(task, value, cte)
    table.insert(descriptors, { kind = schema.classify_text_kind(content_type, filename, disposition), part = part })
  end

  if #descriptors == 0 then
    rspamd_logger.errx(task, 'email_alert with email_parts produced no parts to send')
    return nil
  end

  -- plan_layout returns either (subtype, tree) or (nil, error string)
  local subtype, tree_or_err = schema.plan_layout(descriptors, {
    auto_grouping = rule.auto_grouping,
    email_parts_type = rule.email_parts_type,
  })
  local tree = tree_or_err
  if not subtype then
    -- validate_rule rejects ambiguous layouts, so this only happens when the
    -- template's body headers are known after rendering (variables in them)
    rspamd_logger.warnx(task, 'email_alert: %s; using flat multipart/%s instead',
      tree_or_err, rule.email_parts_type or 'mixed')
    subtype = rule.email_parts_type or 'mixed'
    tree = {}
    for _, d in ipairs(descriptors) do
      table.insert(tree, { part = d.part })
    end
  end

  local top_level_parts = {}
  for _, node in ipairs(tree) do
    if node.alternative then
      local inner_boundary = rspamd_util.random_hex(16)
      local inner_parts = {}
      for _, leaf in ipairs(node.alternative) do
        table.insert(inner_parts, leaf.part)
      end
      table.insert(top_level_parts,
        string.format('Content-Type: multipart/alternative; boundary="%s"', inner_boundary)
        .. '\n\n' .. render_multipart(inner_parts, inner_boundary))
    else
      table.insert(top_level_parts, node.part)
    end
  end

  local boundary = rspamd_util.random_hex(16)
  return render_multipart(top_level_parts, boundary), subtype, boundary
end

-- email_parts owns the top-level MIME framing. The template's content headers
-- move to its body part so its media type and transfer encoding are preserved.
local function split_template_content_headers(header_block)
  local out = {}
  local template_part_headers = {}
  local has_mime_version = false

  for _, entry in ipairs(split_logical_headers(header_block)) do
    local name = logical_header_name(entry)
    if name == 'content-type' then
      template_part_headers.content_type = true
      table.insert(template_part_headers, entry)
    elseif name == 'content-transfer-encoding' then
      template_part_headers.cte = true
      table.insert(template_part_headers, entry)
    elseif name == 'content-disposition' then
      local value = logical_header_value(entry)
      template_part_headers.disposition = string.match(value, '^([^;%s]+)')
      template_part_headers.filename = has_mime_parameter(value, 'filename')
      table.insert(template_part_headers, entry)
    else
      if name == 'mime-version' then
        has_mime_version = true
      end
      table.insert(out, entry)
    end
  end

  return out, template_part_headers, has_mime_version
end

-- Appends MIME-Version (if not already declared) and the top-level
-- Content-Type once the final subtype/boundary are known from assemble_email_parts
local function finalize_multipart_headers(other_headers, has_mime_version, subtype, boundary)
  local out = {}
  for _, entry in ipairs(other_headers) do
    table.insert(out, entry)
  end
  if not has_mime_version then
    table.insert(out, 'MIME-Version: 1.0')
  end
  table.insert(out, string.format('Content-Type: multipart/%s; boundary="%s"', subtype, boundary))
  return table.concat(out, '\n')
end

local function get_general_metadata(task, flatten, no_content)
  local r = {}
  local ip = task:get_from_ip()
  if ip and ip:is_valid() then
    r.ip = tostring(ip)
  else
    r.ip = 'unknown'
  end
  r.user = task:get_user() or 'unknown'
  r.qid = task:get_queue_id() or 'unknown'
  r.subject = task:get_subject() or 'unknown'
  r.action = task:get_metric_action()
  r.rspamd_server = HOSTNAME

  local s = task:get_metric_score()[1]
  r.score = flatten and string.format('%.2f', s) or s

  local fuzzy = task:get_mempool():get_variable("fuzzy_hashes", "fstrings")
  if fuzzy and #fuzzy > 0 then
    local fz = {}
    for _, h in ipairs(fuzzy) do
      table.insert(fz, h)
    end
    if not flatten then
      r.fuzzy = fz
    else
      r.fuzzy = table.concat(fz, ', ')
    end
  else
    if not flatten then
      r.fuzzy = {}
    else
      r.fuzzy = ''
    end
  end

  local rcpt = task:get_recipients('smtp')
  if rcpt then
    local l = {}
    for _, a in ipairs(rcpt) do
      table.insert(l, a['addr'])
    end
    if not flatten then
      r.rcpt = l
    else
      r.rcpt = table.concat(l, ', ')
    end
  else
    r.rcpt = 'unknown'
  end
  local from = task:get_from('smtp')
  if ((from or E)[1] or E).addr then
    r.from = from[1].addr
  else
    r.from = 'unknown'
  end
  local syminf = task:get_symbols_all()
  local function format_symlist(list)
    local l = {}
    for _, sym in ipairs(list) do
      local txt
      if sym.options then
        local topt = table.concat(sym.options, ', ')
        txt = sym.name .. '(' .. string.format('%.2f', sym.score) .. ')' .. ' [' .. topt .. ']'
      else
        txt = sym.name .. '(' .. string.format('%.2f', sym.score) .. ')'
      end
      table.insert(l, txt)
    end
    return table.concat(l, '\n\t')
  end

  if flatten then
    local function copy_and_sort(list, cmp)
      local out = {}
      for i, v in ipairs(list) do
        out[i] = v
      end
      table.sort(out, cmp)
      return out
    end

    r.symbols = format_symlist(syminf)
    r.symbols_sorted = format_symlist(copy_and_sort(syminf, function(a, b) return a.name < b.name end))
    r.symbols_score = format_symlist(copy_and_sort(syminf, function(a, b) return a.score > b.score end))
  else
    r.symbols = syminf
  end
  local function process_header(name)
    local hdr = task:get_header_full(name)
    if hdr then
      local l = {}
      for _, h in ipairs(hdr) do
        table.insert(l, h.decoded)
      end
      if not flatten then
        return l
      else
        -- Fold duplicates the way format_symlist does: joining them with a bare
        -- '\n' lets an empty duplicate insert a blank line into the rendered
        -- email_template body
        local folded = {}
        for i, v in ipairs(l) do
          folded[i] = sanitize_inline(v)
        end
        return table.concat(folded, '\n\t')
      end
    else
      return 'unknown'
    end
  end

  local scan_real = task:get_scan_time()
  scan_real = math.floor(scan_real * 1000)
  if scan_real < 0 then
    rspamd_logger.messagex(task,
      'clock skew detected for message: %s ms real sca time (reset to 0)',
      scan_real)
    scan_real = 0
  end

  r.scan_time = scan_real
  local content = task:get_content()
  r.size = content and content:len() or 0

  if not no_content then
    r.header_from = process_header('from')
    r.header_to = process_header('to')
    r.header_subject = process_header('subject')
    r.header_date = process_header('date')
    r.message_id = task:get_message_id()
  end
  return r
end

local function maybe_defer(task, rule)
  if rule.defer then
    rspamd_logger.warnx(task, 'deferring message')
    task:set_pre_result('soft reject', 'deferred', N)
  end
end

local formatters = {
  default = function(task)
    return task:get_content(), {}
  end,
  email_alert = function(task, rule)
    -- An alert that cannot be built is a failed push as far as `defer` goes
    local function fail()
      maybe_defer(task, rule)
      return nil
    end
    local meta = get_general_metadata(task, true)
    local display_emails = {}
    local mail_targets = {}
    local tmpl = rule.email_template or settings.email_template
    local templates = { tmpl }
    for _, entry in ipairs(rule.email_parts or E) do
      if entry.content ~= nil then
        for _, text in ipairs(part_content_names(entry.content)) do
          table.insert(templates, text)
        end
      end
      if entry.filename then
        table.insert(templates, entry.filename)
      end
    end
    add_template_variables(task, templates, meta)
    meta.mail_from = normalize_mail_from(task, rule.mail_from)
    if not meta.mail_from then
      return fail()
    end
    add_mail_targets(task, 'mail_to', rule.mail_to, mail_targets, display_emails)
    if rule.email_alert_sender then
      local x = task:get_from('smtp')
      if x and string.len(x[1].addr) > 0 then
        add_mail_targets(task, 'email_alert_sender', x[1].addr, mail_targets, display_emails)
      end
    end
    if rule.email_alert_sender_variable then
      if variables[rule.email_alert_sender_variable] then
        local addr = call_variable(task, rule.email_alert_sender_variable)
        lua_util.debugm(N, task, 'email_alert_sender_variable: %s: %s', rule.email_alert_sender_variable, addr)
        add_mail_targets(task, 'email_alert_sender_variable', addr, mail_targets, display_emails)
      else
        rspamd_logger.errx(task, 'no such variable: %s', rule.email_alert_sender_variable)
      end
    end
    if rule.email_alert_user then
      local x = task:get_user()
      if x then
        add_mail_targets(task, 'email_alert_user', x, mail_targets, display_emails)
      end
    end
    if rule.email_alert_recipients then
      local x = task:get_recipients('smtp')
      if x then
        for _, e in ipairs(x) do
          if string.len(e.addr) > 0 then
            add_mail_targets(task, 'email_alert_recipients', e.addr, mail_targets, display_emails)
          end
        end
      end
    end
    if #mail_targets == 0 then
      rspamd_logger.errx(task, 'email alert has no valid recipients')
      return fail()
    end
    meta.mail_to = table.concat(display_emails, ', ')
    meta.our_message_id = rspamd_util.random_hex(12) .. '@rspamd'
    meta.date = rspamd_util.time_to_string(rspamd_util.get_time())
    local header_block, separator, body = render_email_template(task, tmpl, meta)

    if rule.email_parts and #rule.email_parts > 0 then
      if separator == '' then
        -- The template has no body of its own, so there is no implicit first
        -- part; drop a trailing newline so the separator is not doubled
        header_block = string.gsub(header_block, '\r?\n$', '')
        separator = '\n\n'
      end
      local other_headers, template_part_headers, has_mime_version = split_template_content_headers(header_block)
      if rule.email_auto_encode_headers then
        -- These move into a part, out of reach of encode_header_block below
        for _, entry in ipairs(template_part_headers) do
          if not is_ascii(entry) then
            rspamd_logger.errx(task, 'email alert is not sent: cannot encode %s header: '
                .. 'its non-ASCII data has no RFC 2047 form', string.match(entry, '^([^:]*)'))
            return fail()
          end
        end
      end
      local mp_body, subtype, boundary = assemble_email_parts(task, rule, body, template_part_headers, meta)
      if not mp_body then
        return fail()
      end
      header_block = finalize_multipart_headers(other_headers, has_mime_version, subtype, boundary)
      body = mp_body
    end

    if rule.email_auto_encode_headers then
      local encoded, err = encode_header_block(task, header_block)
      if not encoded then
        rspamd_logger.errx(task, 'email alert is not sent: %s', err)
        return fail()
      end
      header_block = encoded
    end

    return header_block .. separator .. body, { mail_targets = mail_targets }
  end,
  json = function(task)
    return ucl.to_format(get_general_metadata(task), 'json-compact')
  end,
  json_with_message = function(task)
    local meta = get_general_metadata(task, false, false)
    local content = task:get_content()
    if content then
      meta.message = rspamd_util.encode_base64(content)
    end
    return ucl.to_format(meta, 'json-compact')
  end,
  msgpack = function(task)
    local meta = get_general_metadata(task, false, false)
    local content = task:get_content()
    if content then
      meta.message = content
    end
    return ucl.to_format(meta, 'msgpack')
  end,
  multipart = function(task)
    local boundary = rspamd_util.random_hex(16)
    local meta = get_general_metadata(task, false, false)
    local content = task:get_content()
    local parts = {
      metadata = {
        data = ucl.to_format(meta, 'json-compact'),
        ['content-type'] = 'application/json'
      },
    }
    if content then
      parts.message = {
        data = content,
        filename = 'message.eml',
        ['content-type'] = 'message/rfc822'
      }
    end
    return lua_util.table_to_multipart_body(parts, boundary),
           { multipart_boundary = boundary }
  end,
  structured = function(task, rule)
    local meta = get_general_metadata(task, false, false)
    local zstd_compress = rule and rule.zstd_compress
    -- Correlation identifier
    local uuid = task:get_uuid()
    meta.uuid = uuid
    -- Inject X-Rspamd-UUID header for IMAP/external correlation
    lua_mime.modify_headers(task, {
      add = { ['X-Rspamd-UUID'] = { value = uuid, order = 0 } }
    })
    -- Extracted text (cleaned, reply-trimmed)
    local text_result = lua_mime.extract_text_limited(task, {
      max_bytes = 32768,
      smart_trim = true,
    })
    if text_result and text_result.text and #text_result.text > 0 then
      if zstd_compress then
        meta.text = rspamd_util.zstd_compress(text_result.text)
        meta.text_compressed = true
      else
        meta.text = text_result.text
      end
      meta.text_truncated = text_result.truncated or false
    end
    -- Attachments and images
    local attachments = {}
    local images = {}
    for _, part in ipairs(task:get_parts()) do
      local img = part:get_image()
      if img then
        local content = part:get_content()
        if zstd_compress and content and #content > 0 then
          content = rspamd_util.zstd_compress(content)
        end
        table.insert(images, {
          filename = img:get_filename() or '',
          content_type = img:get_type() or '',
          width = img:get_width(),
          height = img:get_height(),
          size = part:get_length(),
          content = content or '',
          content_compressed = zstd_compress or nil,
        })
      elseif part:is_attachment() then
        -- Prefer detected type over announced type if available
        local mime_type, mime_subtype = part:get_detected_type()
        if not mime_type then
          mime_type, mime_subtype = part:get_type()
        end
        local content = part:get_content()
        if zstd_compress and content and #content > 0 then
          content = rspamd_util.zstd_compress(content)
        end
        table.insert(attachments, {
          filename = part:get_filename() or '',
          content_type = string.format('%s/%s', mime_type or '', mime_subtype or ''),
          size = part:get_length(),
          digest = string.sub(part:get_digest(), 1, 16),
          content = content or '',
          content_compressed = zstd_compress or nil,
        })
      end
    end
    if #attachments > 0 then
      meta.attachments = attachments
    end
    if #images > 0 then
      meta.images = images
    end
    -- URLs
    local urls = lua_util.extract_specific_urls({
      task = task,
      limit = 100,
      esld_limit = 10,
      need_emails = false,
      need_images = false,
    })
    if urls and #urls > 0 then
      local url_list = {}
      for _, u in ipairs(urls) do
        table.insert(url_list, {
          url = u:get_text(),
          host = u:get_host(),
          tld = u:get_tld(),
        })
      end
      meta.urls = url_list
    end
    -- Reply detection
    local dominated_by = task:get_header('In-Reply-To')
    meta.is_reply = (dominated_by ~= nil)
    return ucl.to_format(meta, 'msgpack')
  end
}

local function is_spam(action)
  return (action == 'reject' or action == 'add header' or action == 'rewrite subject')
end

local selectors = {
  default = function(task)
    return true
  end,
  is_spam = function(task)
    local action = task:get_metric_action()
    return is_spam(action)
  end,
  is_spam_authed = function(task)
    if not task:get_user() then
      return false
    end
    local action = task:get_metric_action()
    return is_spam(action)
  end,
  is_reject = function(task)
    local action = task:get_metric_action()
    return (action == 'reject')
  end,
  is_reject_authed = function(task)
    if not task:get_user() then
      return false
    end
    local action = task:get_metric_action()
    return (action == 'reject')
  end,
  is_not_soft_reject = function(task)
    local action = task:get_metric_action()
    return (action ~= 'soft reject')
  end,
}

local pushers = {
  redis_pubsub = function(task, formatted, rule)
    local _, ret, upstream
    local function redis_pub_cb(err)
      if err then
        rspamd_logger.errx(task, 'got error %s when publishing on server %s',
          err, upstream:get_addr())
        return maybe_defer(task, rule)
      end
      return true
    end
    ret, _, upstream = lua_redis.redis_make_request(task,
      redis_params,                 -- connect params
      nil,                          -- hash key
      true,                         -- is write
      redis_pub_cb,                 --callback
      'PUBLISH',                    -- command
      { rule.channel, formatted }   -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, 'error connecting to redis')
      maybe_defer(task, rule)
    end
  end,
  http = function(task, formatted, rule, extra)
    local function http_callback(err, code)
      local valid_status = { 200, 201, 202, 204 }

      if err then
        rspamd_logger.errx(task, 'got error %s in http callback', err)
        return maybe_defer(task, rule)
      end
      for _, v in ipairs(valid_status) do
        if v == code then
          return true
        end
      end
      rspamd_logger.errx(task, 'got unexpected http status: %s', code)
      return maybe_defer(task, rule)
    end
    local hdrs = {}
    local mime_type = rule.mime_type

    if extra and extra.multipart_boundary then
      mime_type = string.format('multipart/form-data; boundary="%s"', extra.multipart_boundary)
    end

    if rule.meta_headers then
      local gm = get_general_metadata(task, false, true)
      local pfx = rule.meta_header_prefix or 'X-Rspamd-'
      for k, v in pairs(gm) do
        if type(v) == 'table' then
          hdrs[pfx .. k] = ucl.to_format(v, 'json-compact')
        else
          hdrs[pfx .. k] = rspamd_util.mime_header_encode(tostring(v) or '')
        end
      end
    end

    rspamd_http.request({
      task = task,
      url = rule.url,
      user = rule.user,
      password = rule.password,
      body = formatted,
      callback = http_callback,
      mime_type = mime_type,
      headers = hdrs,
      timeout = rule.timeout,
      gzip = rule.gzip,
      keepalive = rule.keepalive,
      no_ssl_verify = rule.no_ssl_verify,
      -- staged timeouts
      connect_timeout = rule.connect_timeout,
      ssl_timeout = rule.ssl_timeout,
      write_timeout = rule.write_timeout,
      read_timeout = rule.read_timeout,
    })
  end,
  send_mail = function(task, formatted, rule, extra)
    local lua_smtp = require "lua_smtp"
    local function sendmail_cb(ret, err)
      if not ret then
        rspamd_logger.errx(task, 'SMTP export error: %s', err)
        maybe_defer(task, rule)
      end
    end

    local mail_from = normalize_mail_from(task, rule.mail_from)
    if not mail_from then
      return maybe_defer(task, rule)
    end

    local recipients = extra and extra.mail_targets
    if not recipients then
      recipients = {}
      add_mail_targets(task, 'mail_to', rule.mail_to, recipients, {})
      if #recipients == 0 then
        rspamd_logger.errx(task, 'SMTP export has no valid recipients')
        return maybe_defer(task, rule)
      end
    end

    lua_smtp.sendmail({
      task = task,
      host = rule.smtp,
      port = rule.smtp_port or 25,
      from = mail_from,
      recipients = recipients,
      helo = rule.helo,
      timeout = rule.timeout,
      connect_timeout = rule.connect_timeout,
      read_timeout = rule.read_timeout,
      write_timeout = rule.write_timeout,
    }, formatted, sendmail_cb)
  end,
  json_raw_tcp = function(task, formatted, rule)
    local function json_raw_tcp_callback(err, code)
      if err then
        rspamd_logger.errx(task, 'got error %s in json_raw_tcp callback', err)
        return maybe_defer(task, rule)
      end
      return true
    end
    rspamd_tcp.request({
      task = task,
      host = rule.host,
      port = rule.port,
      data = formatted,
      callback = json_raw_tcp_callback,
      timeout = rule.timeout,
      read = false,
    })
  end,
  redis_list = function(task, formatted, rule)
    local function do_rpush(list_key)
      local _, ret, upstream
      local function redis_rpush_cb(err)
        if err then
          rspamd_logger.errx(task, 'got error %s when pushing to list on server %s',
            err, upstream:get_addr())
          return maybe_defer(task, rule)
        end
        if rule.max_len then
          -- Trim failures must be loud: unlike XADD MAXLEN, RPUSH cannot cap
          -- the list itself, so a persistently failing LTRIM silently defeats
          -- max_len and the list grows without bound.
          --
          -- Deliberately NO defer here. The RPUSH above already succeeded, so
          -- the message has been exported; deferring would re-run the whole
          -- exporter on retry and push a duplicate. A breached memory cap is
          -- recoverable, a duplicated export is not, so we log at error level
          -- and let the operator act.
          local trim_upstream
          local function redis_ltrim_cb(trim_err)
            if trim_err then
              rspamd_logger.errx(task, 'cannot trim list %s to %s entries on server %s: %s; '
                  .. 'max_len is NOT being enforced',
                list_key, rule.max_len,
                trim_upstream and trim_upstream:get_addr() or 'unknown', trim_err)
            end
          end
          -- note: assigns (not redeclares) trim_upstream so the callback's
          -- upvalue is the one that gets filled in
          local trim_ret
          trim_ret, _, trim_upstream = lua_redis.redis_make_request(task,
            redis_params,
            nil,
            true, -- is write
            redis_ltrim_cb,
            'LTRIM',
            { list_key, tostring(-rule.max_len), '-1' }
          )
          if not trim_ret then
            rspamd_logger.errx(task, 'cannot schedule trim of list %s to %s entries: '
                .. 'max_len is NOT being enforced', list_key, rule.max_len)
          end
        end
        return true
      end
      ret, _, upstream = lua_redis.redis_make_request(task,
        redis_params,
        nil,
        true, -- is write
        redis_rpush_cb,
        'RPUSH',
        { list_key, formatted }
      )
      if not ret then
        rspamd_logger.errx(task, 'error connecting to redis')
        maybe_defer(task, rule)
      end
    end
    if rule.per_recipient then
      local rcpt = task:get_recipients('smtp')
      if rcpt then
        for _, a in ipairs(rcpt) do
          if a.addr and #a.addr > 0 then
            do_rpush(rule.list_key .. ':' .. a.addr)
          end
        end
      else
        do_rpush(rule.list_key)
      end
    else
      do_rpush(rule.list_key)
    end
  end,
  redis_stream = function(task, formatted, rule)
    local function do_xadd(stream_key)
      local _, ret, upstream
      local function redis_xadd_cb(err)
        if err then
          rspamd_logger.errx(task, 'got error %s when publishing to stream on server %s',
            err, upstream:get_addr())
          return maybe_defer(task, rule)
        end
        return true
      end
      local args = { stream_key }
      if rule.max_len then
        table.insert(args, 'MAXLEN')
        table.insert(args, '~')
        table.insert(args, string.format('%d', math.floor(rule.max_len)))
      end
      table.insert(args, '*')
      table.insert(args, 'data')
      table.insert(args, formatted)
      ret, _, upstream = lua_redis.redis_make_request(task,
        redis_params,
        nil,
        true,
        redis_xadd_cb,
        'XADD',
        args
      )
      if not ret then
        rspamd_logger.errx(task, 'error connecting to redis')
        maybe_defer(task, rule)
      end
    end
    if rule.per_recipient then
      local rcpt = task:get_recipients('smtp')
      local stream_key = rule.stream_key
      if rcpt then
        for _, a in ipairs(rcpt) do
          if a.addr and #a.addr > 0 then
            do_xadd(stream_key .. ':' .. a.addr)
          end
        end
      else
        do_xadd(stream_key)
      end
    else
      do_xadd(rule.stream_key)
    end
  end,
}

-- custom_push may add pushers below; rules of those get an open schema
local builtin_pushers = {}
for name in pairs(pushers) do
  builtin_pushers[name] = true
end

local opts = rspamd_config:get_all_opt(N)
if not opts then
  return
end

-- Compiles a custom Lua snippet at config time, naming the chunk so a syntax
-- error or a non-function result is caught and reported here instead of
-- surfacing as a runtime crash on the first scanned message
local function compile_custom(kind, name, code)
  local chunkname = string.format('metadata_exporter %s[%s]', kind, name)
  local ok, fn_or_err = lua_util.callback_from_string(code, chunkname, true)
  if not ok then
    local msg = string.format('%s: invalid Lua code: %s', chunkname, tostring(fn_or_err))
    rspamd_logger.errx(rspamd_config, '%s', msg)
    lua_util.config_utils.push_config_error(N, msg)
    return nil
  end
  return fn_or_err
end

local process_settings = {
  select = function(val)
    local fn = compile_custom('select', 'custom', val)
    if fn then
      selectors.custom = fn
    end
  end,
  format = function(val)
    local fn = compile_custom('format', 'custom', val)
    if fn then
      formatters.custom = fn
    end
  end,
  push = function(val)
    local fn = compile_custom('push', 'custom', val)
    if fn then
      pushers.custom = fn
    end
  end,
  custom_push = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        local fn = compile_custom('custom_push', k, v)
        if fn then
          pushers[k] = fn
        end
      end
    end
  end,
  custom_variables = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        if variables[k] then
          rspamd_logger.warnx(rspamd_config, 'custom_variables[%s] shadows a builtin variable', k)
        end
        local fn = compile_custom('custom_variables', k, v)
        if fn then
          variables[k] = fn
        end
      end
    end
  end,
  custom_select = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        local fn = compile_custom('custom_select', k, v)
        if fn then
          selectors[k] = fn
        end
      end
    end
  end,
  custom_format = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        local fn = compile_custom('custom_format', k, v)
        if fn then
          formatters[k] = fn
        end
      end
    end
  end,
  pusher_enabled = function(val)
    if type(val) == 'string' then
      if pushers[val] then
        settings.pusher_enabled[val] = true
      else
        rspamd_logger.errx(rspamd_config, 'Pusher type: %s is invalid', val)
      end
    elseif type(val) == 'table' then
      for _, v in ipairs(val) do
        if pushers[v] then
          settings.pusher_enabled[v] = true
        else
          rspamd_logger.errx(rspamd_config, 'Pusher type: %s is invalid', val)
        end
      end
    end
  end,
}
for k, v in pairs(opts) do
  local f = process_settings[k]
  if f then
    f(opts[k])
  else
    settings[k] = v
  end
end
if type(settings.rules) ~= 'table' then
  -- Legacy config
  settings.rules = {}
  if not next(settings.pusher_enabled) then
    if pushers.custom then
      rspamd_logger.infox(rspamd_config, 'Custom pusher implicitly enabled')
      settings.pusher_enabled.custom = true
    else
      -- Check legacy options
      if settings.url then
        rspamd_logger.warnx(rspamd_config, 'HTTP pusher implicitly enabled')
        settings.pusher_enabled.http = true
      end
      if settings.channel then
        rspamd_logger.warnx(rspamd_config, 'Redis Pubsub pusher implicitly enabled')
        settings.pusher_enabled.redis_pubsub = true
      end
      if settings.smtp and settings.mail_to then
        rspamd_logger.warnx(rspamd_config, 'SMTP pusher implicitly enabled')
        settings.pusher_enabled.send_mail = true
      end
    end
  end
  if not next(settings.pusher_enabled) then
    rspamd_logger.errx(rspamd_config, 'No push backend enabled')
    return
  end
  if settings.formatter then
    settings.format = formatters[settings.formatter]
    if not settings.format then
      rspamd_logger.errx(rspamd_config, 'No such formatter: %s', settings.formatter)
      return
    end
  end
  if settings.selector then
    settings.select = selectors[settings.selector]
    if not settings.select then
      rspamd_logger.errx(rspamd_config, 'No such selector: %s', settings.selector)
      return
    end
  end
  for k in pairs(settings.pusher_enabled) do
    local formatter = settings.pusher_format[k]
    local selector = settings.pusher_select[k]
    if not formatter then
      settings.pusher_format[k] = settings.formatter or 'default'
      rspamd_logger.infox(rspamd_config, 'Using default formatter for %s pusher', k)
    else
      if not formatters[formatter] then
        rspamd_logger.errx(rspamd_config, 'No such formatter: %s - disabling %s', formatter, k)
        settings.pusher_enabled.k = nil
      end
    end
    if not selector then
      settings.pusher_select[k] = settings.selector or 'default'
      rspamd_logger.infox(rspamd_config, 'Using default selector for %s pusher', k)
    else
      if not selectors[selector] then
        rspamd_logger.errx(rspamd_config, 'No such selector: %s - disabling %s', selector, k)
        settings.pusher_enabled.k = nil
      end
    end
  end
  if settings.pusher_enabled.redis_pubsub then
    redis_params = lua_redis.parse_redis_server(N)
    if not redis_params then
      rspamd_logger.errx(rspamd_config, 'No redis servers are specified')
      settings.pusher_enabled.redis_pubsub = nil
    else
      local r = {}
      r.backend = 'redis_pubsub'
      r.channel = settings.channel
      r.defer = settings.defer
      r.selector = settings.pusher_select.redis_pubsub
      r.formatter = settings.pusher_format.redis_pubsub
      r.timeout = redis_params.timeout
      settings.rules[r.backend:upper()] = r
    end
  end
  if settings.pusher_enabled.http then
    if not settings.url then
      rspamd_logger.errx(rspamd_config, 'No URL is specified')
      settings.pusher_enabled.http = nil
    else
      local r = {}
      r.backend = 'http'
      r.url = settings.url
      r.mime_type = settings.mime_type
      r.defer = settings.defer
      r.selector = settings.pusher_select.http
      r.formatter = settings.pusher_format.http
      r.timeout = settings.timeout or 0.0
      settings.rules[r.backend:upper()] = r
    end
  end
  if settings.pusher_enabled.send_mail then
    if not (settings.mail_to and settings.smtp) then
      rspamd_logger.errx(rspamd_config, 'No mail_to and/or smtp setting is specified')
      settings.pusher_enabled.send_mail = nil
    else
      local r = {}
      r.backend = 'send_mail'
      r.mail_to = settings.mail_to
      r.mail_from = settings.mail_from
      r.helo = settings.hello
      r.smtp = settings.smtp
      r.smtp_port = settings.smtp_port
      r.email_template = settings.email_template
      r.defer = settings.defer
      r.selector = settings.pusher_select.send_mail
      r.formatter = settings.pusher_format.send_mail
      r.timeout = settings.timeout or 0.0
      settings.rules[r.backend:upper()] = r
    end
  end
  if settings.pusher_enabled.json_raw_tcp then
    if not (settings.host and settings.port) then
      rspamd_logger.errx(rspamd_config, 'No host and/or port is specified')
      settings.pusher_enabled.json_raw_tcp = nil
    else
      local r = {}
      r.backend = 'json_raw_tcp'
      r.host = settings.host
      r.port = settings.port
      r.defer = settings.defer
      r.selector = settings.pusher_select.json_raw_tcp
      r.formatter = settings.pusher_format.json_raw_tcp
      settings.rules[r.backend:upper()] = r
    end
  end
  if not next(settings.pusher_enabled) then
    rspamd_logger.errx(rspamd_config, 'No push backend enabled')
    return
  end
elseif not next(settings.rules) then
  lua_util.debugm(N, rspamd_config, 'No rules enabled')
  return
end
if not settings.rules or not next(settings.rules) then
  rspamd_logger.errx(rspamd_config, 'No rules enabled')
  return
end

-- Validates one email_parts entry; mutates it in place to fill in the
-- content_type default so runtime code never has to guess it again
local function validate_email_part(k, i, part)
  local has_content = part.content ~= nil
  local has_vars = part.content_from_variables ~= nil
  if has_content and has_vars then
    rspamd_logger.errx(rspamd_config,
      'rule %s: email_parts[%s] has both content and content_from_variables, use exactly one', k, i)
    return false
  end
  if not has_content and not has_vars then
    rspamd_logger.errx(rspamd_config,
      'rule %s: email_parts[%s] misses content or content_from_variables', k, i)
    return false
  end
  if has_vars then
    for _, name in ipairs(part_content_names(part.content_from_variables)) do
      if not variables[name] then
        rspamd_logger.errx(rspamd_config,
          'rule %s: email_parts[%s] references unknown variable %s', k, i, name)
        return false
      end
    end
  end
  -- content_from_variables may carry a binary blob; content is always literal/template text
  part.content_type = part.content_type or (has_content and 'text/plain; charset=utf-8' or 'application/octet-stream')
  local parsed_content_type
  if not string.find(part.content_type, '[\r\n]') then
    parsed_content_type = rspamd_util.parse_content_type(part.content_type, rspamd_config:get_mempool())
  end
  if not parsed_content_type or not parsed_content_type.type or not parsed_content_type.subtype then
    rspamd_logger.errx(rspamd_config, 'rule %s: email_parts[%s] has invalid content_type', k, i)
    return false
  end
  if part.disposition and (string.find(part.disposition, '[\r\n]') or
      not string.match(part.disposition, "^[%w!#$%%&'*+%-.%^_`|~]+$")) then
    rspamd_logger.errx(rspamd_config, 'rule %s: email_parts[%s] has invalid disposition', k, i)
    return false
  end
  return true
end

-- Dynamic checks that the schema cannot express: selector/formatter/backend
-- names are extensible at runtime via custom_select/custom_format/custom_push,
-- and per-backend required settings may be satisfied by a plugin-wide default
-- The literal (placeholder-free) address that fails to parse, if any
local function invalid_literal_address(value, single)
  if type(value) ~= 'string' or value == '' or string.find(value, '$', 1, true) or
      is_bare_local_part(value) then
    return nil
  end
  local parsed = rspamd_util.parse_mail_address(value, rspamd_config:get_mempool())
  if not parsed or #parsed == 0 or (single and #parsed ~= 1) then
    return value
  end
  for _, address in ipairs(parsed) do
    if not (address.flags and address.flags.valid) then
      return address.raw or value
    end
  end
  return nil
end

local function validate_rule(k, rule)
  for _, e in ipairs(schema.backend_required_elements[rule.backend] or E) do
    if rule[e] == nil and settings[e] == nil then
      rspamd_logger.errx(rspamd_config,
        'rule %s: misses required setting %s for backend %s', k, e, rule.backend)
      return false
    end
  end
  if not selectors[rule.selector or 'default'] then
    rspamd_logger.errx(rspamd_config, 'rule %s: has invalid selector %s', k, rule.selector)
    return false
  end
  if not formatters[rule.formatter or 'default'] then
    rspamd_logger.errx(rspamd_config, 'rule %s: has invalid formatter %s', k, rule.formatter)
    return false
  end
  if rule.backend == 'send_mail' or rule.formatter == 'email_alert' then
    -- Literal addresses are checked once here rather than failing every message
    local mail_from = rule.mail_from
    if mail_from == nil then
      mail_from = settings.mail_from
    end
    local bad = invalid_literal_address(mail_from, true)
    if bad then
      rspamd_logger.errx(rspamd_config, 'rule %s: mail_from is not a valid address: %s', k, bad)
      return false
    end
    local mail_to = rule.mail_to
    if mail_to == nil then
      mail_to = settings.mail_to
    end
    for _, value in ipairs(type(mail_to) == 'table' and mail_to or { mail_to }) do
      bad = invalid_literal_address(value)
      if bad then
        rspamd_logger.errx(rspamd_config, 'rule %s: mail_to is not a valid address: %s', k, bad)
        return false
      end
    end
  end
  if rule.meta_headers then
    rspamd_logger.warnx(rspamd_config,
      'rule %s: uses deprecated meta_headers option; use formatter = "multipart" or "json" instead', k)
  end
  if rule.email_parts then
    for i, part in ipairs(rule.email_parts) do
      if not validate_email_part(k, i, part) then
        return false
      end
    end
    local descriptors = {}
    -- The template's own body becomes the leading part, so it takes part in
    -- grouping just like at runtime
    local header_tmpl, _, body_tmpl = split_template(rule.email_template or settings.email_template)
    if #body_tmpl > 0 then
      local _, template_part_headers = split_template_content_headers(header_tmpl)
      local _, kind = template_part_type(template_part_headers)
      table.insert(descriptors, { kind = kind })
    end
    for _, part in ipairs(rule.email_parts) do
      table.insert(descriptors,
        { kind = schema.classify_text_kind(part.content_type, part.filename, part.disposition) })
    end
    -- Mirror the settings fallback resolve_rule applies at runtime, so a
    -- plugin-wide auto_grouping is honoured by this check too
    local auto_grouping = rule.auto_grouping
    if auto_grouping == nil then
      auto_grouping = settings.auto_grouping
    end
    local subtype, err = schema.plan_layout(descriptors,
      { auto_grouping = auto_grouping, email_parts_type = rule.email_parts_type })
    if not subtype then
      rspamd_logger.errx(rspamd_config, 'rule %s: %s', k, err)
      return false
    end
  end
  return true
end

for k, v in pairs(settings.rules) do
  if type(v) ~= 'table' then
    rspamd_logger.errx(rspamd_config, 'rule %s: has bad type: %s', k, type(v))
    lua_util.config_utils.push_config_error(N, string.format('rule %s: has bad type: %s', k, type(v)))
    settings.rules[k] = nil
  else
    local backend = v.backend
    if not backend then
      rspamd_logger.errx(rspamd_config, 'rule %s: has no backend', k)
      lua_util.config_utils.push_config_error(N, string.format('rule %s: has no backend', k))
      settings.rules[k] = nil
    elseif not pushers[backend] then
      rspamd_logger.errx(rspamd_config, 'rule %s: has invalid backend %s', k, backend)
      lua_util.config_utils.push_config_error(N, string.format('rule %s: has invalid backend %s', k, backend))
      settings.rules[k] = nil
    else
      local rule_schema = builtin_pushers[backend] and schema.rule_schema or schema.custom_rule_schema
      local res, err = rule_schema:transform(v)
      if not res then
        local msg = string.format('rule %s: invalid configuration -> rule DISABLED: %s', k, T.format_error(err))
        rspamd_logger.errx(rspamd_config, '%s', msg)
        lua_util.config_utils.push_config_error(N, msg)
        settings.rules[k] = nil
      else
        settings.rules[k] = res
        if (backend == 'redis_pubsub' or backend == 'redis_stream' or backend == 'redis_list') then
          if not redis_params then
            redis_params = rspamd_parse_redis_server(N)
          end
          if not redis_params then
            rspamd_logger.errx(rspamd_config, 'rule %s: no redis servers are specified', k)
            lua_util.config_utils.push_config_error(N, string.format('rule %s: no redis servers are specified', k))
            settings.rules[k] = nil
          else
            res.timeout = redis_params.timeout
          end
        end
        if settings.rules[k] and not validate_rule(k, res) then
          lua_util.config_utils.push_config_error(N,
            string.format('rule %s: invalid configuration -> rule DISABLED', k))
          settings.rules[k] = nil
        end
      end
    end
  end
end

if not next(settings.rules) then
  rspamd_logger.errx(rspamd_config, 'No rules enabled')
  lua_util.config_utils.push_config_error(N, 'no valid rules remain after validation')
  lua_util.disable_module(N, 'config')
  return
end

-- Compile selectors used by rules at config time to validate them and to keep them off the hot path
local function warm_selectors(val)
  if type(val) == 'table' then
    for _, elt in pairs(val) do
      warm_selectors(elt)
    end
  elseif type(val) == 'string' then
    for expr in string.gmatch(val, '%${(.-)}') do
      if not variables[expr] then
        get_selector(rspamd_config, expr)
      end
    end
  end
end

for _, r in pairs(settings.rules) do
  for name, val in pairs(r) do
    if expandable_rule_fields[name] or name == 'email_template' or name == 'email_parts' then
      warm_selectors(val)
    end
  end
end

local function gen_exporter(rule, rule_name)
  return function(task)
    if task:has_flag('skip') then
      return
    end
    local selector = rule.selector or 'default'
    local selected = selectors[selector](task)
    if selected then
      lua_util.debugm(N, task, 'rule %s: message selected for processing', rule_name)
      local formatter = rule.formatter or 'default'
      local resolved_rule = resolve_rule(task, rule)
      local formatted, extra = formatters[formatter](task, resolved_rule)
      if formatted then
        pushers[rule.backend](task, formatted, resolved_rule, extra)
      else
        lua_util.debugm(N, task, 'rule %s: formatter [%s] returned non-truthy value [%s]', rule_name, formatter, formatted)
      end
    else
      lua_util.debugm(N, task, 'rule %s: selector [%s] returned non-truthy value [%s]', rule_name, selector, selected)
    end
  end
end

for k, r in pairs(settings.rules) do
  local registration_timeout = tonumber(r.timeout) or tonumber(settings.timeout) or 0.0
  rspamd_config:register_symbol({
    name = 'EXPORT_METADATA_' .. k,
    type = 'idempotent',
    callback = gen_exporter(r, k),
    flags = 'empty,explicit_disable,ignore_passthrough',
    augmentations = { string.format("timeout=%f", registration_timeout) }
  })
end
