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
local E = {}
local N = 'metadata_exporter'
local HOSTNAME = rspamd_util.get_hostname()
local selector_cache = {}

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

local function expand_selectors(task, str, meta)
  if not str or not string.find(str, '$', 1, true) then
    return str
  end

  local function stringify(extracted)
    local str_val
    if type(extracted) == 'table' then
      str_val = table.concat(extracted, ',')
    else
      str_val = tostring(extracted)
    end
    -- Expanded values reach mail headers, URLs and Redis keys, so they must never break framing
    return (string.gsub(str_val, '[\r\n]+', ' '))
  end

  str = string.gsub(str, '%$([%w_]+)', function(name)
    if meta and meta[name] ~= nil then
      return '$' .. name
    end
    if variables[name] then
      local extracted = variables[name](task)
      if extracted ~= nil then
        return stringify(extracted)
      end
      rspamd_logger.errx(task, 'custom variable [%s] returned no value', name)
      return '((error extracting value))'
    end
    return '$' .. name
  end)

  local function process_placeholder(whole, expr)
    if meta and meta[expr] ~= nil then
      return whole
    end

    local extracted
    if variables[expr] then
      extracted = variables[expr](task)
    else
      local selector = get_selector(task, expr)
      if not selector then
        return '((could not create selector))'
      end
      extracted = selector(task)
    end
    if extracted then
      extracted = stringify(extracted)
    else
      rspamd_logger.errx(task, 'could not extract value with selector [%s]', expr)
      extracted = '((error extracting value))'
    end
    return extracted
  end

  return (string.gsub(str, '(%${(.-)})', process_placeholder))
end

local function expand_value(task, val)
  if type(val) == 'string' then
    return expand_selectors(task, val)
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
  'channel',
  'connect_timeout',
  'defer',
  'email_auto_encode_headers',
  'gzip',
  'helo',
  'host',
  'keepalive',
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

local function add_template_variables(task, tmpl, meta)
  local requested = {}
  for name in string.gmatch(tmpl, '%$([%w_]+)') do
    requested[name] = true
  end
  for name in string.gmatch(tmpl, '%${([%w_]+)}') do
    requested[name] = true
  end
  for name in pairs(requested) do
    if meta[name] == nil and variables[name] then
      meta[name] = variables[name](task)
    end
  end
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

local function encode_address_header(task, value)
  if string.find(value, '[():]') then
    return value
  end

  local parsed = rspamd_util.parse_mail_address(value, task:get_mempool())
  if not parsed or #parsed == 0 then
    return value
  end

  local changed = false
  local out = {}
  for _, a in ipairs(parsed) do
    if a.name and a.name ~= '' and not is_ascii(a.name) then
      changed = true
      local encoded_name = rspamd_util.mime_header_encode(a.name, true)
      if a.addr and a.addr ~= '' then
        table.insert(out, encoded_name .. ' <' .. a.addr .. '>')
      else
        table.insert(out, encoded_name)
      end
    else
      table.insert(out, a.raw)
    end
  end

  if not changed then
    return value
  end

  return table.concat(out, ', ')
end

local function encode_email_headers(task, text)
  local sep_start, sep_end = string.find(text, '\r?\n\r?\n')
  if not sep_start then
    return text
  end
  local header_block = string.sub(text, 1, sep_start - 1)
  local separator = string.sub(text, sep_start, sep_end)
  local body = string.sub(text, sep_end + 1)

  local logical = {}
  for line in (header_block .. '\n'):gmatch('(.-)\n') do
    if #logical > 0 and string.match(line, '^[ \t]') then
      logical[#logical] = logical[#logical] .. '\n' .. line
    else
      table.insert(logical, line)
    end
  end

  local out = {}
  for _, entry in ipairs(logical) do
    local colon = string.find(entry, ':', 1, true)
    if not colon then
      table.insert(out, entry)
    else
      local name = string.sub(entry, 1, colon - 1)
      local value = string.gsub(string.sub(entry, colon + 1), '\r?\n[ \t]+', ' ')
      value = string.match(value, '^[ \t]*(.*)$')
      local lname = string.lower(name)
      if address_headers[lname] then
        table.insert(out, name .. ': ' .. encode_address_header(task, value))
      elseif structured_headers[lname] then
        table.insert(out, name .. ': ' .. lua_util.fold_header_with_encoding(task, name, value, { encode = false }))
      else
        table.insert(out, name .. ': ' .. lua_util.fold_header_with_encoding(task, name, value, { encode = true }))
      end
    end
  end

  return table.concat(out, '\n') .. separator .. body
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
        return table.concat(l, '\n')
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

local formatters = {
  default = function(task)
    return task:get_content(), {}
  end,
  email_alert = function(task, rule)
    local meta = get_general_metadata(task, true)
    local display_emails = {}
    local mail_targets = {}
    local tmpl = rule.email_template or settings.email_template
    add_template_variables(task, tmpl, meta)
    meta.mail_from = normalize_mail_from(task, rule.mail_from)
    if not meta.mail_from then
      return nil
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
        local addr = variables[rule.email_alert_sender_variable](task)
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
      return nil
    end
    meta.mail_to = table.concat(display_emails, ', ')
    meta.our_message_id = rspamd_util.random_hex(12) .. '@rspamd'
    meta.date = rspamd_util.time_to_string(rspamd_util.get_time())
    tmpl = expand_selectors(task, tmpl, meta)
    local rendered = lua_util.template(tmpl, meta)
    if rule.email_auto_encode_headers then
      rendered = encode_email_headers(task, rendered)
    end
    return rendered, { mail_targets = mail_targets }
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

local function maybe_defer(task, rule)
  if rule.defer then
    rspamd_logger.warnx(task, 'deferring message')
    task:set_pre_result('soft reject', 'deferred', N)
  end
end

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

local opts = rspamd_config:get_all_opt(N)
if not opts then
  return
end
local process_settings = {
  select = function(val)
    selectors.custom = assert(load(val))()
  end,
  format = function(val)
    formatters.custom = assert(load(val))()
  end,
  push = function(val)
    pushers.custom = assert(load(val))()
  end,
  custom_push = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        pushers[k] = assert(load(v))()
      end
    end
  end,
  custom_variables = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        variables[k] = assert(load(v))()
      end
    end
  end,
  custom_select = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        selectors[k] = assert(load(v))()
      end
    end
  end,
  custom_format = function(val)
    if type(val) == 'table' then
      for k, v in pairs(val) do
        formatters[k] = assert(load(v))()
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
local backend_required_elements = {
  http = {
    'url',
  },
  smtp = {
    'mail_to',
    'smtp',
  },
  redis_pubsub = {
    'channel',
  },
  json_raw_tcp = {
    'host',
    'port',
  },
  redis_stream = {
    'stream_key',
  },
  redis_list = {
    'list_key',
  },
}
local check_element = {
  selector = function(k, v)
    if not selectors[v] then
      rspamd_logger.errx(rspamd_config, 'Rule %s has invalid selector %s', k, v)
      return false
    else
      return true
    end
  end,
  formatter = function(k, v)
    if not formatters[v] then
      rspamd_logger.errx(rspamd_config, 'Rule %s has invalid formatter %s', k, v)
      return false
    else
      return true
    end
  end,
  meta_headers = function(k, v)
    if v then
      rspamd_logger.warnx(rspamd_config,
        'Rule %s uses deprecated meta_headers option; use format = "multipart" or format = "json" instead', k)
    end
    return true
  end,
}
local backend_check = {
  default = function(k, rule)
    local reqset = backend_required_elements[rule.backend]
    if reqset then
      for _, e in ipairs(reqset) do
        if not rule[e] then
          rspamd_logger.errx(rspamd_config, 'Rule %s misses required setting %s', k, e)
          settings.rules[k] = nil
        end
      end
    end
    for sett, v in pairs(rule) do
      local f = check_element[sett]
      if f then
        if not f(sett, v) then
          settings.rules[k] = nil
        end
      end
    end
  end,
}
backend_check.redis_pubsub = function(k, rule)
  if not redis_params then
    redis_params = rspamd_parse_redis_server(N)
  end
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'No redis servers are specified')
    settings.rules[k] = nil
  else
    backend_check.default(k, rule)
    rule.timeout = redis_params.timeout
  end
end
backend_check.redis_stream = function(k, rule)
  if not redis_params then
    redis_params = rspamd_parse_redis_server(N)
  end
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'No redis servers are specified')
    settings.rules[k] = nil
  else
    backend_check.default(k, rule)
    rule.timeout = redis_params.timeout
  end
end
backend_check.redis_list = function(k, rule)
  if not redis_params then
    redis_params = rspamd_parse_redis_server(N)
  end
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'No redis servers are specified')
    settings.rules[k] = nil
  else
    backend_check.default(k, rule)
    rule.timeout = redis_params.timeout
  end
end
setmetatable(backend_check, {
  __index = function()
    return backend_check.default
  end,
})
for k, v in pairs(settings.rules) do
  if type(v) == 'table' then
    local backend = v.backend
    if not backend then
      rspamd_logger.errx(rspamd_config, 'Rule %s has no backend', k)
      settings.rules[k] = nil
    elseif not pushers[backend] then
      rspamd_logger.errx(rspamd_config, 'Rule %s has invalid backend %s', k, backend)
      settings.rules[k] = nil
    else
      local f = backend_check[backend]
      f(k, v)
    end
  else
    rspamd_logger.errx(rspamd_config, 'Rule %s has bad type: %s', k, type(v))
    settings.rules[k] = nil
  end
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
    if expandable_rule_fields[name] or name == 'email_template' then
      warm_selectors(val)
    end
  end
end

local function gen_exporter(rule)
  return function(task)
    if task:has_flag('skip') then
      return
    end
    local selector = rule.selector or 'default'
    local selected = selectors[selector](task)
    if selected then
      lua_util.debugm(N, task, 'Message selected for processing')
      local formatter = rule.formatter or 'default'
      local resolved_rule = resolve_rule(task, rule)
      local formatted, extra = formatters[formatter](task, resolved_rule)
      if formatted then
        pushers[rule.backend](task, formatted, resolved_rule, extra)
      else
        lua_util.debugm(N, task, 'Formatter [%s] returned non-truthy value [%s]', formatter, formatted)
      end
    else
      lua_util.debugm(N, task, 'Selector [%s] returned non-truthy value [%s]', selector, selected)
    end
  end
end

if not next(settings.rules) then
  rspamd_logger.errx(rspamd_config, 'No rules enabled')
  lua_util.disable_module(N, "config")
end
for k, r in pairs(settings.rules) do
  local registration_timeout = tonumber(r.timeout) or tonumber(settings.timeout) or 0.0
  rspamd_config:register_symbol({
    name = 'EXPORT_METADATA_' .. k,
    type = 'idempotent',
    callback = gen_exporter(r),
    flags = 'empty,explicit_disable,ignore_passthrough',
    augmentations = { string.format("timeout=%f", registration_timeout) }
  })
end
