--[[
Copyright (c) 2020, Anton Yuzhaninov <citrin@citrin.ru>

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

-- Rule to detect bounces:
-- RFC 3464 Delivery status notifications and most common non-standard ones

local function make_subj_bounce_keywords_re()
  -- Words and phrases commonly used in Subjects for bounces
  -- We cannot practically test all localized Subjects, but luckily English is by far the most common here
  local keywords = {
    'could not send message',
    "couldn't be delivered",
    'delivery failed',
    'delivery failure',
    'delivery report',
    'delivery status',
    'delivery warning',
    'failure delivery',
    'failure notice',
    "hasn't been delivered",
    'mail failure',
    'returned mail',
    'undeliverable',
    'undelivered',
  }
  return string.format([[Subject=/\b(%s)\b/i{header}]], table.concat(keywords, '|'))
end

config.regexp.SUBJ_BOUNCE_WORDS = {
  re = make_subj_bounce_keywords_re(),
  group = 'headers',
  score = 0.0,
  description = 'Words/phrases typical for DSN'
}

rspamd_config.BOUNCE = {
  callback = function(task)
    local from = task:get_from('smtp')
    if from and from[1].addr ~= '' then
      -- RFC 3464:
      -- Whenever an SMTP transaction is used to send a DSN, the MAIL FROM
      -- command MUST use a NULL return address, i.e., "MAIL FROM:<>"
      -- In practise it is almost always the case for DSN
      return false
    end


    local parts = task:get_parts()
    local top_type, top_subtype, params = parts[1]:get_type_full()
    -- RFC 3464, RFC 8098
    if top_type == 'multipart' and top_subtype == 'report' and params and
       (params['report-type'] == 'delivery-status' or params['report-type'] == 'disposition-notification') then
      -- Assume that inner parts are OK, don't check them to save time
      return true, 1.0, 'DSN'
    end

    -- Apply heuristics for non-standard bounecs
    local bounce_sender
    local mime_from = task:get_from('mime')
    if mime_from then
      local from_user = mime_from[1].user:lower()
      -- Check common bounce senders
      if (from_user == 'postmaster' or from_user == 'mailer-daemon') then
        bounce_sender = from_user
      -- MDaemon >= 14.5 sends multipart/report (RFC 3464) DSN covered above,
      -- but older versions send non-standard bounces with localized subjects and they
      -- are still around
      elseif from_user == 'mdaemon' and task:has_header('X-MDDSN-Message') then
        return true, 1.0, 'MDaemon'
      end
    end

    local subj_keywords = task:has_symbol('SUBJ_BOUNCE_WORDS')

    if not (bounce_sender or subj_keywords) then
      return false
    end

    if bounce_sender and subj_keywords then
      return true, 0.5, bounce_sender .. '+subj'
    end

    -- Look for a message/rfc822(-headers) part inside
    local rfc822_part
    parts[10] = nil -- limit numbe of parts to check
    for _, p in ipairs(parts) do
      local mime_type, mime_subtype = p:get_type()
      if (mime_subtype == 'rfc822' or mime_subtype == 'rfc822-headers') and
          (mime_type == 'message' or mime_type == 'text') then
        rfc822_part = mime_type .. '/' .. mime_subtype
        break
      end
    end

    if rfc822_part and bounce_sender then
      return true, 0.5, bounce_sender .. '+' .. rfc822_part
    elseif rfc822_part and subj_keywords then
      return true, 0.2, rfc822_part .. '+subj'
    end
  end,
  description = '(Non) Delivery Status Notification',
  group = 'headers',
}

rspamd_config:register_dependency('BOUNCE', 'SUBJ_BOUNCE_WORDS')
