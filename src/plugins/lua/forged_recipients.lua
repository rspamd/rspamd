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

-- Plugin for comparing smtp dialog recipients and sender with recipients and sender
-- in mime headers

if confighelp then
  rspamd_config:add_example(nil, 'forged_recipients',
      "Check forged recipients and senders (e.g. mime and smtp recipients mismatch)",
      [[
  forged_recipients {
    symbol_sender = "FORGED_SENDER"; # Symbol for a forged sender
    symbol_rcpt = "FORGED_RECIPIENTS"; # Symbol for a forged recipients
    # Domains delivering to one mailbox namespace (e.g. googlemail.com and
    # gmail.com) are compared as equal; a map of "<alias> <canonical>" lines
    equivalent_domains = "https://maps.rspamd.com/rspamd/equivalent_domains.inc.zst";
  }
  ]])
end

local symbol_rcpt = 'FORGED_RECIPIENTS'
local symbol_sender = 'FORGED_SENDER'
local rspamd_util = require "rspamd_util"
local lua_aliases = require "lua_aliases"

local E = {}

-- Identity of a bare address string (authenticated user, Delivered-To):
-- the same comparison key that addresses parsed from the task get
local function string_identity(str)
  if type(str) ~= 'string' or str == '' then
    return nil
  end

  str = str:match('<([^>]*)>') or str
  str = str:match('^%s*(.-)%s*$')

  return lua_aliases.mailbox_identity(str)
end

-- Same mailbox up to case, equivalent domains and service-specific aliasing
local function same_mailbox(a, b)
  if not a or not b then
    return false
  end

  local ia, ib = lua_aliases.mailbox_identity(a), lua_aliases.mailbox_identity(b)

  if ia and ib then
    return rspamd_util.strequal_caseless_utf8(ia, ib)
  end

  return rspamd_util.strequal_caseless_utf8(a.addr or '', b.addr or '')
end

local function check_forged_headers(task)
  local auser = string_identity(task:get_user())
  local delivered_to = string_identity(task:get_header('Delivered-To'))
  -- Compare the envelope and the headers as they were transmitted: alias
  -- rewrites (e.g. a cross-domain virtual alias applied to the envelope
  -- recipients) must not make the wire To/Cc headers look forged.
  -- Addresses are matched by mailbox identity (lua_aliases.mailbox_identity),
  -- so the same account reached under an equivalent domain or through a
  -- dotted/tagged local part is not a mismatch either
  local smtp_rcpts = task:get_recipients({ 'smtp', 'orig' })
  local smtp_from = task:get_from({ 'smtp', 'orig' })

  if not smtp_rcpts then
    return
  end
  if #smtp_rcpts == 0 then
    return
  end

  local mime_rcpts = task:get_recipients({ 'mime', 'orig' })

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

  local smtp_from_id = lua_aliases.mailbox_identity((smtp_from or E)[1])

  -- map canonical smtp recipient domains to the identities seen in this domain
  local smtp_rcpt_domain_map = {}
  local smtp_rcpt_map = {}
  for _, smtp_rcpt in ipairs(smtp_rcpts) do
    local id, dom = lua_aliases.mailbox_identity(smtp_rcpt)

    if id then
      local dom_map = smtp_rcpt_domain_map[dom]
      if not dom_map then
        dom_map = {}
        smtp_rcpt_domain_map[dom] = dom_map
      end

      dom_map[id] = smtp_rcpt
      smtp_rcpt_map[id] = smtp_rcpt
      smtp_rcpt.dom_map = dom_map

      if auser and auser == id then
        smtp_rcpt.matched = true
      end
      if smtp_from_id and smtp_from_id == id then
        -- allow sender to BCC themselves
        smtp_rcpt.matched = true
      end
    end
  end

  for _, mime_rcpt in ipairs(mime_rcpts) do
    local id, dom = lua_aliases.mailbox_identity(mime_rcpt)

    if id then
      local matched_smtp_addr = smtp_rcpt_map[id]
      if matched_smtp_addr then
        -- Direct match, go forward
        matched_smtp_addr.matched = true
        mime_rcpt.matched = true
      elseif delivered_to and delivered_to == id then
        mime_rcpt.matched = true
      elseif auser and auser == id then
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
  for _, mime_rcpt in ipairs(mime_rcpts) do
    if not mime_rcpt.matched then
      seen_mime_unmatched = true
      table.insert(opts, 'm:' .. (mime_rcpt.addr or ''))
    end
  end
  for _, smtp_rcpt in ipairs(smtp_rcpts) do
    if not smtp_rcpt.matched then
      if not (smtp_rcpt.dom_map or E)._seen_mime_domain then
        seen_smtp_unmatched = true
        table.insert(opts, 's:' .. (smtp_rcpt.addr or ''))
      end
    end
  end

  if seen_smtp_unmatched and seen_mime_unmatched then
    task:insert_result(symbol_rcpt, 1.0, opts)
  end

  -- Check sender
  if smtp_from and smtp_from[1] and smtp_from[1]['addr'] ~= '' then
    local mime_from = task:get_from({ 'mime', 'orig' })
    if not same_mailbox((mime_from or E)[1], smtp_from[1]) then
      task:insert_result(symbol_sender, 1, ((mime_from or E)[1] or E).addr or '', smtp_from[1].addr)
    end
  end
end

-- Configuration
local opts = rspamd_config:get_all_opt('forged_recipients')
if opts then
  if opts['symbol_rcpt'] or opts['symbol_sender'] then
    if opts.equivalent_domains then
      lua_aliases.init_equivalent_domains(rspamd_config, opts.equivalent_domains)
    end

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
