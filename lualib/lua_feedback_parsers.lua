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

--[[[
-- @module lua_feedback_parsers
-- This module provides parsers for inbound feedback reports that arrive as
-- a regular message (MIME) on a task:
--
--   * RFC 3464 Delivery Status Notifications (DSN / bounces)
--   * RFC 5965 Abuse Reporting Format (ARF / FBL)
--
-- The parsers operate on a `task` object and return a structured Lua table
-- describing the report, or `nil` if the message is not a report of that
-- kind. Both parsers are defensive: malformed bodies will not raise an
-- error, they will produce a partial result at best (documented per
-- function) or `nil`.
--]]

local rspamd_logger = require 'rspamd_logger'
local lua_util = require 'lua_util'

local N = 'lua_feedback_parsers'
local str_trim = lua_util.str_trim
local str_split = lua_util.rspamd_str_split

local exports = {}

-- Strip a single pair of outermost angle brackets, e.g. `<id@example>`.
local function strip_angles(s)
  if not s then
    return nil
  end
  local inner = s:match('^%s*<(.-)>%s*$')
  if inner then
    return inner
  end
  return str_trim(s)
end

--[[
-- Parse an RFC 822 field block (a sequence of header-like lines terminated
-- by a blank line or end of input). Handles header folding: lines that
-- start with a tab or a space are continuations of the previous field.
--
-- Returns:
--   fields - map of lowercased field name -> value (trimmed string)
--   fields_multi - map of lowercased field name -> array of values (in order
--     of appearance); useful for repeated fields such as `Reported-URI`.
--   next_line - 1-based index of the first line AFTER the blank line that
--     terminated the block (or #lines + 1 if the block ran to end of input)
--
-- `start_line` is 1-based.
]]
local function parse_field_block(lines, start_line)
  local fields = {}
  local fields_multi = {}
  local current_name
  local current_value_parts
  local i = start_line or 1
  local n = #lines

  local function flush()
    if current_name then
      local value = str_trim(table.concat(current_value_parts, ' '))
      fields[current_name] = value
      local list = fields_multi[current_name]
      if not list then
        list = {}
        fields_multi[current_name] = list
      end
      list[#list + 1] = value
    end
    current_name = nil
    current_value_parts = nil
  end

  while i <= n do
    local line = lines[i]
    if line == '' then
      flush()
      return fields, fields_multi, i + 1
    end
    local first = line:sub(1, 1)
    if first == ' ' or first == '\t' then
      if current_name then
        current_value_parts[#current_value_parts + 1] = str_trim(line)
      end
      -- else: continuation with no preceding field - ignore
    else
      local name, value = line:match('^([^:]+):%s?(.*)$')
      if name then
        flush()
        current_name = name:lower():gsub('%s+$', '')
        current_value_parts = { value or '' }
      end
      -- else: malformed line - skip it
    end
    i = i + 1
  end

  flush()
  return fields, fields_multi, i
end

-- Split an entire body into an array of field blocks separated by blank
-- lines. Used for message/delivery-status bodies which consist of 1..N
-- blocks.
local function parse_field_blocks(body)
  if type(body) ~= 'string' then
    body = tostring(body or '')
  end
  -- Normalise line endings (drop CR) then split on LF.
  local lines = str_split(body:gsub('\r', ''), '\n')
  if not lines then
    return {}
  end
  local i = 1
  while i <= #lines and lines[i] == '' do
    i = i + 1
  end
  local blocks = {}
  while i <= #lines do
    local fields, fields_multi, next_i = parse_field_block(lines, i)
    if next(fields) ~= nil then
      blocks[#blocks + 1] = {
        fields = fields,
        fields_multi = fields_multi,
      }
    end
    if next_i <= i then
      break
    end
    i = next_i
    while i <= #lines and lines[i] == '' do
      i = i + 1
    end
  end
  return blocks
end

-- Find the topmost multipart/report part in a task that matches the given
-- `report-type` (case-insensitive). Returns the matching mime_part or nil.
local function find_multipart_report(task, wanted_report_type)
  for _, part in ipairs(task:get_parts() or {}) do
    local t, st, params = part:get_type_full()
    if t == 'multipart' and st == 'report' and type(params) == 'table' then
      local rt = params['report-type']
      if rt and rt:lower() == wanted_report_type then
        return part
      end
    end
  end
  return nil
end

-- Find the first sub-part whose Content-Type matches `wanted_type/wanted_subtype`
-- (case-insensitive). If `wanted_subtype` is nil, only `wanted_type` is
-- matched.
local function find_part_by_type(task, wanted_type, wanted_subtype)
  for _, part in ipairs(task:get_parts() or {}) do
    local t, st = part:get_type()
    if t and t:lower() == wanted_type and
        (not wanted_subtype or (st and st:lower() == wanted_subtype)) then
      return part
    end
  end
  return nil
end

-- Locate the embedded original message in a report.
-- Returns (part, kind) where kind is 'full' for message/rfc822|message/global
-- (headers+body) and 'headers' for text/rfc822-headers (headers only).
local function find_original_message_part(task)
  for _, part in ipairs(task:get_parts() or {}) do
    local t, st = part:get_type()
    if t and st then
      local lt = t:lower()
      local lst = st:lower()
      if lt == 'message' and (lst == 'rfc822' or lst == 'global') then
        return part, 'full'
      end
      if lt == 'text' and lst == 'rfc822-headers' then
        return part, 'headers'
      end
    end
  end
  return nil
end

-- Extract the standard subset of original-message headers we care about from
-- the content of a message/rfc822 (or text/rfc822-headers) sub-part.
local function extract_original_message(part)
  local content = part:get_content()
  if not content then
    return nil
  end
  content = tostring(content)
  if content == '' then
    return nil
  end
  local lines = str_split(content:gsub('\r', ''), '\n')
  if not lines then
    return nil
  end
  local headers = parse_field_block(lines, 1)
  if not headers or next(headers) == nil then
    return nil
  end
  local out = {
    message_id = strip_angles(headers['message-id']),
    from = strip_angles(headers['from']),
    to = strip_angles(headers['to']),
    subject = headers['subject'],
    date = headers['date'],
  }
  if not (out.message_id or out.from or out.to or out.subject or out.date) then
    return nil
  end
  return out
end

-- ----------------------------------------------------------------------------
-- DSN (RFC 3464)
-- ----------------------------------------------------------------------------

--[[[
-- @function lua_feedback_parsers.parse_dsn(task)
-- Parse an RFC 3464 Delivery Status Notification from the given task.
--
-- Detection: the task must contain either a `multipart/report` part with
-- `report-type=delivery-status`, or a `message/delivery-status` sub-part.
-- If neither is present, returns `nil`.
--
-- Malformed-body policy: if detection succeeds but the body cannot be
-- parsed into at least one non-empty field block, the function still
-- returns a table (with `recipients = {}`) so that callers can distinguish
-- "not a DSN" (nil) from "a DSN we couldn't fully parse" (table with
-- mostly-nil fields).
--
-- @param {rspamd_task} task message to inspect
-- @return {table|nil} parsed DSN, see module doc for the shape
--]]
function exports.parse_dsn(task)
  if not task then
    return nil
  end

  -- Detection: prefer the envelope multipart/report, but also accept a
  -- bare message/delivery-status (some MTAs emit non-standard shapes).
  local envelope = find_multipart_report(task, 'delivery-status')
  local status_part = find_part_by_type(task, 'message', 'delivery-status')
  if not envelope and not status_part then
    return nil
  end

  local result = {
    reporting_mta = nil,
    original_envelope_id = nil,
    arrival_date = nil,
    received_from_mta = nil,
    recipients = {},
    original_message = nil,
  }

  if status_part then
    local body = status_part:get_content()
    if body then
      local blocks = parse_field_blocks(tostring(body))
      if #blocks > 0 then
        local per_message = blocks[1].fields
        result.reporting_mta = per_message['reporting-mta']
        result.original_envelope_id = per_message['original-envelope-id']
        result.arrival_date = per_message['arrival-date']
        result.received_from_mta = per_message['received-from-mta']
        for j = 2, #blocks do
          local rf = blocks[j].fields
          result.recipients[#result.recipients + 1] = {
            original_recipient = rf['original-recipient'],
            final_recipient = rf['final-recipient'],
            action = rf['action'] and rf['action']:lower() or nil,
            status = rf['status'],
            diagnostic_code = rf['diagnostic-code'],
            remote_mta = rf['remote-mta'],
            last_attempt_date = rf['last-attempt-date'],
          }
        end
      else
        rspamd_logger.debugm(N, task, 'DSN detected but delivery-status body has no parseable blocks')
      end
    else
      rspamd_logger.debugm(N, task, 'DSN detected but delivery-status part content is empty')
    end
  end

  local orig_part = find_original_message_part(task)
  if orig_part then
    result.original_message = extract_original_message(orig_part)
  end

  return result
end

-- ----------------------------------------------------------------------------
-- ARF (RFC 5965)
-- ----------------------------------------------------------------------------

--[[[
-- @function lua_feedback_parsers.parse_arf(task)
-- Parse an RFC 5965 Abuse Reporting Format (ARF) feedback report.
--
-- Detection: the task must contain a `multipart/report` part with
-- `report-type=feedback-report` AND a sub-part with
-- `message/feedback-report`. If either is missing, returns `nil`.
--
-- Malformed-body policy: same as `parse_dsn`. If detection succeeds but
-- the feedback-report body is unparseable, a table is still returned (with
-- mostly-nil fields and `reported_uri = {}`).
--
-- @param {rspamd_task} task message to inspect
-- @return {table|nil} parsed ARF, see module doc for the shape
--]]
function exports.parse_arf(task)
  if not task then
    return nil
  end

  local envelope = find_multipart_report(task, 'feedback-report')
  if not envelope then
    return nil
  end
  local fb_part = find_part_by_type(task, 'message', 'feedback-report')
  if not fb_part then
    return nil
  end

  local result = {
    feedback_type = nil,
    version = nil,
    user_agent = nil,
    original_mail_from = nil,
    original_rcpt_to = nil,
    arrival_date = nil,
    source_ip = nil,
    reported_domain = nil,
    reported_uri = {},
    authentication_results = nil,
    original_envelope_id = nil,
    incidents = nil,
    original_message = nil,
  }

  local body = fb_part:get_content()
  if body then
    local blocks = parse_field_blocks(tostring(body))
    if #blocks > 0 then
      local f = blocks[1].fields
      local fm = blocks[1].fields_multi
      result.feedback_type = f['feedback-type'] and f['feedback-type']:lower() or nil
      result.version = f['version']
      result.user_agent = f['user-agent']
      result.original_mail_from = strip_angles(f['original-mail-from'])
      result.original_rcpt_to = strip_angles(f['original-rcpt-to'])
      result.arrival_date = f['arrival-date']
      result.source_ip = f['source-ip']
      result.reported_domain = f['reported-domain']
      result.authentication_results = f['authentication-results']
      result.original_envelope_id = f['original-envelope-id']
      if f['incidents'] then
        local n = tonumber(f['incidents'])
        if n then
          result.incidents = n
        end
      end
      if fm and fm['reported-uri'] then
        for _, v in ipairs(fm['reported-uri']) do
          result.reported_uri[#result.reported_uri + 1] = v
        end
      end
    else
      rspamd_logger.debugm(N, task, 'ARF detected but feedback-report body has no parseable blocks')
    end
  else
    rspamd_logger.debugm(N, task, 'ARF detected but feedback-report part content is empty')
  end

  local orig_part = find_original_message_part(task)
  if orig_part then
    local om = extract_original_message(orig_part)
    if om then
      -- RFC 5965 consumers typically only care about Message-ID and From.
      result.original_message = {
        message_id = om.message_id,
        from = om.from,
      }
    end
  end

  return result
end

-- Exposed for unit tests.
exports._parse_field_blocks = parse_field_blocks
exports._strip_angles = strip_angles

return exports
