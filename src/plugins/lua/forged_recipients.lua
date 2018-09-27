--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Plugin for comparing smtp dialog recipients and sender with recipients and sender
-- in mime headers

if confighelp then
  return
end

local symbol_rcpt = 'FORGED_RECIPIENTS'
local symbol_sender = 'FORGED_SENDER'

local E = {}

local function check_forged_headers(task)
  local auser = task:get_user()
  local delivered_to = task:get_header('Delivered-To')
  local smtp_rcpt = task:get_recipients(1)
  local smtp_from = task:get_from(1)
  local res
  local score = 1.0

  if not smtp_rcpt then return end
  if #smtp_rcpt == 0 then return end
  local mime_rcpt = task:get_recipients(2)
  if not mime_rcpt then
    return
  elseif #mime_rcpt == 0 then
    local sra = smtp_rcpt[1].addr .. (#smtp_rcpt > 1 and ' ...' or '')
    task:insert_result(symbol_rcpt, score, '', sra)
    return
  end
  -- Find pair for each smtp recipient in To or Cc headers
  for _,sr in ipairs(smtp_rcpt) do
    res = false
    for _,mr in ipairs(mime_rcpt) do
      if mr['addr'] and sr['addr'] and
        string.lower(mr['addr']) == string.lower(sr['addr']) then
        res = true
        break
      elseif delivered_to and delivered_to == mr['addr'] then
        -- allow alias expansion and forwarding (Postfix)
        res = true
        break
      elseif auser and auser == sr['addr'] then
        -- allow user to BCC themselves
        res = true
        break
      elseif ((smtp_from or E)[1] or E).addr and
          smtp_from[1]['addr'] == sr['addr'] then
        -- allow sender to BCC themselves
        res = true
        break
      elseif mr['user'] and sr['user'] and
        string.lower(mr['user']) == string.lower(sr['user']) then
        -- If we have the same username but for another domain, then
        -- lower the overall score
        score = score / 2
      end
    end
    if not res then
      local mra = mime_rcpt[1].addr .. (#mime_rcpt > 1 and ' ..' or '')
      local sra = smtp_rcpt[1].addr .. (#smtp_rcpt > 1 and ' ...' or '')
      task:insert_result(symbol_rcpt, score, mra, sra)
      break
    end
  end
  -- Check sender
  if smtp_from and smtp_from[1] and smtp_from[1]['addr'] ~= '' then
    local mime_from = task:get_from(2)
    if not mime_from or not mime_from[1] or
      not (string.lower(mime_from[1]['addr']) == string.lower(smtp_from[1]['addr'])) then
      task:insert_result(symbol_sender, 1, ((mime_from or E)[1] or E).addr or '', smtp_from[1].addr)
    end
  end
end

-- Configuration
local opts =  rspamd_config:get_all_opt('forged_recipients')
if opts then
  if opts['symbol_rcpt'] or opts['symbol_sender'] then
    local id = rspamd_config:register_symbol({
      name = 'FORGED_CALLBACK',
      callback = check_forged_headers,
      type = 'callback',
    })
    if opts['symbol_rcpt'] then
      symbol_rcpt = opts['symbol_rcpt']
      rspamd_config:register_symbol({
        name = symbol_rcpt,
        type = 'virtual',
        parent = id,
      })
    end
    if opts['symbol_sender'] then
      symbol_sender = opts['symbol_sender']
       rspamd_config:register_symbol({
        name = symbol_sender,
        type = 'virtual',
        parent = id,
      })
    end
  end
end
