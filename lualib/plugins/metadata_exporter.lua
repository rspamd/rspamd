--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"

-- Schema for metadata_exporter rules (validated per-rule in src/plugins/lua/metadata_exporter.lua)

local encodings = { 'auto', 'base64', 'quoted-printable', '7bit', '8bit' }

-- Accepts a single string or an array of strings; callers normalize to an
-- array themselves (see resolve part content in metadata_exporter.lua) since
-- lua_shape does not apply nested transforms when a schema is reused as the
-- inner type of another transform (the email_parts lone-object case below)
local content_source_schema = T.one_of({
  T.array(T.string(), { min_items = 1 }),
  T.string(),
}):optional()

local part_schema = T.table({
  content = content_source_schema
      :doc({ summary = "Literal/template body content, expanded like the email template" }),
  content_from_variables = content_source_schema
      :doc({ summary = "Name(s) of registered variables whose raw value becomes the part body" }),
  content_type = T.string():optional()
      :doc({ summary = "MIME content type of the part" }),
  filename = T.string():optional()
      :doc({ summary = "Attachment filename" }),
  disposition = T.string():optional()
      :doc({ summary = "Content-Disposition of the part (inline/attachment)" }),
  encoding = T.enum(encodings):optional()
      :doc({ summary = "Content-Transfer-Encoding to use for this part" }),
}):doc({ summary = "email_alert MIME part definition" })

-- A lone `email_parts { ... }` block arrives from UCL as a single object, not
-- an array of one; normalize it here so callers always see an array.
-- An empty table is array-like, so it would otherwise fall through to the
-- lone-object variant (every part field is optional) and be normalized into an
-- array holding one empty part; reject it here instead
local email_parts_schema = T.one_of({
  T.array(part_schema, { min_items = 1 }),
  T.transform(part_schema, function(part)
    if next(part) == nil then
      return nil
    end
    return { part }
  end),
}):optional()

local rule_schema = T.table({
  backend = T.string()
            :doc({ summary = "Push backend: http, send_mail, redis_pubsub, redis_stream, " ..
                "json_raw_tcp, or a custom_push name" }),
  selector = T.string():optional()
      :doc({ summary = "Selector name deciding which messages are exported" }),
  formatter = T.string():optional()
      :doc({ summary = "Formatter name producing the payload" }),
  defer = T.boolean():optional()
      :doc({ summary = "Soft-reject the message if the push fails" }),
  timeout = T.number():optional()
      :doc({ summary = "Network timeout for this rule" }),
  connect_timeout = T.number():optional()
      :doc({ summary = "Connect timeout override" }),
  read_timeout = T.number():optional()
      :doc({ summary = "Read timeout override" }),
  write_timeout = T.number():optional()
      :doc({ summary = "Write timeout override" }),
  ssl_timeout = T.number():optional()
      :doc({ summary = "TLS handshake timeout override" }),

  -- http backend
  url = T.string():optional()
      :doc({ summary = "URL to push data to (http backend)" }),
  user = T.string():optional()
      :doc({ summary = "HTTP basic auth user (http backend)" }),
  password = T.string():optional()
      :doc({ summary = "HTTP basic auth password (http backend)" }),
  mime_type = T.string():optional()
      :doc({ summary = "Content-Type sent with the HTTP push (http backend)" }),
  gzip = T.boolean():optional()
      :doc({ summary = "Gzip-compress the HTTP body (http backend)" }),
  keepalive = T.boolean():optional()
      :doc({ summary = "Reuse HTTP connections (http backend)" }),
  no_ssl_verify = T.boolean():optional()
      :doc({ summary = "Disable TLS certificate verification (http backend)" }),
  meta_headers = T.boolean():optional()
      :doc({ summary = "Deprecated: use formatter = multipart/json instead" }),
  meta_header_prefix = T.string():optional()
      :doc({ summary = "Header prefix used by the deprecated meta_headers option" }),

  -- send_mail backend
  smtp = T.string():optional()
      :doc({ summary = "SMTP server address (send_mail backend)" }),
  smtp_port = T.number():optional()
      :doc({ summary = "SMTP server port (send_mail backend)" }),
  helo = T.string():optional()
      :doc({ summary = "HELO/EHLO string (send_mail backend)" }),
  mail_from = T.string():optional()
      :doc({ summary = "Envelope sender (send_mail backend)" }),
  mail_to = T.one_of({ T.string(), T.array(T.string()) }):optional()
      :doc({ summary = "Envelope recipient(s) (send_mail backend)" }),
  email_template = T.string():optional()
      :doc({ summary = "Message template (send_mail backend)" }),
  email_alert_sender = T.boolean():optional()
      :doc({ summary = "Add the message's SMTP sender as a recipient" }),
  email_alert_sender_variable = T.string():optional()
      :doc({ summary = "Variable providing an extra recipient address" }),
  email_alert_user = T.boolean():optional()
      :doc({ summary = "Add the authenticated user as a recipient" }),
  email_alert_recipients = T.boolean():optional()
      :doc({ summary = "Add the message's SMTP recipients as recipients" }),
  email_auto_encode_headers = T.boolean():optional()
      :doc({ summary = "RFC 2047-encode non-ASCII header values" }),
  email_parts_type = T.string({ pattern = "^[%w!#$%%&'*+%-.%^_`|~]+$" }):optional()
      :doc({ summary = "multipart/<type> subtype for email_parts" }),
  email_parts = email_parts_schema
      :doc({ summary = "Extra MIME parts; use one array (email_parts = [ {...}, {...} ]), not repeated blocks" }),

  -- redis_pubsub backend
  channel = T.string():optional()
      :doc({ summary = "Redis channel to publish to (redis_pubsub backend)" }),

  -- redis_stream backend
  stream_key = T.string():optional()
      :doc({ summary = "Redis stream key (redis_stream backend)" }),
  per_recipient = T.boolean():optional()
      :doc({ summary = "Use one stream per recipient (redis_stream/redis_list backend)" }),
  max_len = T.number():optional()
      :doc({ summary = "XADD MAXLEN value / RPUSH LTRIM cap (redis_stream/redis_list backend)" }),
  zstd_compress = T.boolean():optional()
      :doc({ summary = "Compress the payload with zstd (redis_stream backend)" }),

  -- redis_list backend
  list_key = T.string():optional()
      :doc({ summary = "Redis list key (redis_list backend)" }),

  -- json_raw_tcp backend
  host = T.string():optional()
      :doc({ summary = "TCP host to push to (json_raw_tcp backend)" }),
  port = T.number():optional()
      :doc({ summary = "TCP port to push to (json_raw_tcp backend)" }),
}, { open = false }):doc({ summary = "metadata_exporter rule configuration" })

-- Required fields per backend, checked against a rule AFTER it has been
-- merged with plugin-wide defaults (a rule may rely on a global mail_to/smtp)
local backend_required_elements = {
  http = { 'url' },
  send_mail = { 'mail_to', 'smtp' },
  redis_pubsub = { 'channel' },
  json_raw_tcp = { 'host', 'port' },
  redis_stream = { 'stream_key' },
  redis_list = { 'list_key' },
}

PluginSchema.register("plugins.metadata_exporter.rule", rule_schema)
PluginSchema.register("plugins.metadata_exporter.part", part_schema)

return {
  rule_schema = rule_schema,
  part_schema = part_schema,
  backend_required_elements = backend_required_elements,
  encodings = encodings,
}
