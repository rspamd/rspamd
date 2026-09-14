--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>
Licensed under the Apache License, Version 2.0.
]]--

local ucl = require 'ucl'
local hostname = require('rspamd_util').get_hostname()

local exports = {}

-- Share the frozen decision and availability fields across metadata sinks.
function exports.get_terminal_metadata(task)
  local event = task:get_terminal_event()

  if not event then
    return nil
  end

  event.rspamd_server = hostname
  event.uuid = task:get_uuid()
  event.qid = event.queue_id or ucl.null
  event.from = event.sender or ucl.null
  event.rcpt = event.recipients
  event.score = event.partial_score
  event.scan_time = math.floor(event.early_time * 1000)

  for _, field in ipairs({ 'size', 'subject', 'message_id', 'header_from',
                           'header_to', 'header_subject', 'header_date' }) do
    event[field] = ucl.null
  end

  return event
end

return exports
