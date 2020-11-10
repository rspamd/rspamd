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
  rspamd_config:add_example(nil, 'forged_recipients',
      "Check forged recipients and senders (e.g. mime and smtp recipients mismatch)",
      [[
  forged_recipients {
    symbol_sender = "FORGED_SENDER"; # Symbol for a forged sender
    symbol_rcpt = "FORGED_RECIPIENTS"; # Symbol for a forged recipients
  }
  ]])
end

local symbol_rcpt = 'FORGED_RECIPIENTS'
local symbol_sender = 'FORGED_SENDER'

local E = {}

local function check_forged_headers(task)
  local auser = task:get_user()
  local delivered_to = task:get_header('Delivered-To')
  local smtp_rcpts = task:get_recipients(1)
  local smtp_from = task:get_from(1)

  if not smtp_rcpts then return end
  if #smtp_rcpts == 0 then return end

  local mime_rcpts = task:get_recipients({ 'mime', 'orig'})

  if not mime_rcpts then
    return
  elseif #mime_rcpts == 0 then
    return
  end

  -- Find pair for each smtp recipient in To or Cc headers
  if #smtp_rcpts > 100 or #mime_rcpts > 100 then
    -- Trim array, suggested by Anton Yuzhaninov
    smtp_rcpts[100] = nil
    mime_rcpts[100] = nil
  end

  -- map smtp recipient domains to a list of addresses for this domain
  local smtp_rcpt_domain_map = {}
  local smtp_rcpt_map = {}
  for _, smtp_rcpt in ipairs(smtp_rcpts) do
    local addr = smtp_rcpt.addr

    if addr and addr ~= '' then
      local dom = string.lower(smtp_rcpt.domain)
      addr = addr:lower()

      local dom_map = smtp_rcpt_domain_map[dom]
      if not dom_map then
        dom_map = {}
        smtp_rcpt_domain_map[dom] = dom_map
      end

      dom_map[addr] = smtp_rcpt
      smtp_rcpt_map[addr] = smtp_rcpt

      if auser and auser == addr then
        smtp_rcpt.matched = true
      end
      if ((smtp_from or E)[1] or E).addr and
          smtp_from[1]['addr'] == addr then
        -- allow sender to BCC themselves
        smtp_rcpt.matched = true
      end
    end
  end

  for _,mime_rcpt in ipairs(mime_rcpts) do
    if mime_rcpt.addr and mime_rcpt.addr ~= '' then
      local addr = string.lower(mime_rcpt.addr)
      local dom =  string.lower(mime_rcpt.domain)
      local matched_smtp_addr = smtp_rcpt_map[addr]
      if matched_smtp_addr then
        -- Direct match, go forward
        matched_smtp_addr.matched = true
        mime_rcpt.matched = true
      elseif delivered_to and delivered_to == addr then
        mime_rcpt.matched = true
      elseif auser and auser == addr then
        -- allow user to BCC themselves
        mime_rcpt.matched = true
      else
        local matched_smtp_domain = smtp_rcpt_domain_map[dom]

        if matched_smtp_domain then
          -- Same domain but another user, it is likely okay due to aliases substitution
          mime_rcpt.matched = true
          -- Special field
          matched_smtp_domain._seen_mime_domain = true
        end
      end
    end
  end

  -- Now go through all lists one more time and find unmatched stuff
  local opts = {}
  local seen_mime_unmatched = false
  local seen_smtp_unmatched = false
  for _,mime_rcpt in ipairs(mime_rcpts) do
    if not mime_rcpt.matched then
      seen_mime_unmatched = true
      table.insert(opts, 'm:' .. mime_rcpt.addr)
    end
  end
  for _,smtp_rcpt in ipairs(smtp_rcpts) do
    if not smtp_rcpt.matched then
      if not smtp_rcpt_domain_map[smtp_rcpt.domain:lower()]._seen_mime_domain then
        seen_smtp_unmatched = true
        table.insert(opts, 's:' .. smtp_rcpt.addr)
      end
    end
  end

  if seen_smtp_unmatched and seen_mime_unmatched then
    task:insert_result(symbol_rcpt, 1.0, opts)
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
      group = 'headers',
      score = 0.0,
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
