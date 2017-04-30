--[[
Copyright (c) 2011-2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This is main lua config file for rspamd

local E = {}
local fun = require "fun"
local util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"

-- Different text parts
rspamd_config.R_PARTS_DIFFER = {
  callback = function(task)
    local distance = task:get_mempool():get_variable('parts_distance', 'double')

    if distance then
      local nd = tonumber(distance)
      -- ND is relation of different words to total words
      if nd >= 0.5 then
        local tw = task:get_mempool():get_variable('total_words', 'int')

        if tw then
          local score
          if tw > 30 then
            -- We are confident about difference
            score = (nd - 0.5) * 2.0
          else
            -- We are not so confident about difference
            score = (nd - 0.5)
          end
          task:insert_result('R_PARTS_DIFFER', score,
            string.format('%.1f%%', tostring(100.0 * nd)))
        end
      end
    end
    return false
  end,
  score = 1.0,
  description = 'Text and HTML parts differ',
  group = 'body'
}

-- Date issues
rspamd_config.MISSING_DATE = {
  callback = function(task)
    local date = task:get_header_raw('Date')
    if date == nil or date == '' then
      return true
    end
    return false
  end,
  score = 1.0,
  description = 'Message date is missing',
  group = 'date'
}

rspamd_config.DATE_IN_FUTURE = {
  callback = function(task)
    local dm = task:get_date{format = 'message', gmt = true}
    local dt = task:get_date{format = 'connect', gmt = true}
    -- 2 hours
    if dm > 0 and dm - dt > 7200 then
      return true
    end
    return false
  end,
  score = 4.0,
  description = 'Message date is in future',
  group = 'date'
}

rspamd_config.DATE_IN_PAST = {
  callback = function(task)
    local dm = task:get_date{format = 'message', gmt = true}
    local dt = task:get_date{format = 'connect', gmt = true}
    -- A day
    if dm > 0 and dt - dm > 86400 then
      return true
    end
    return false
  end,
  score = 1.0,
  description = 'Message date is in past',
  group = 'date'
}

rspamd_config.R_SUSPICIOUS_URL = {
  callback = function(task)
    local urls = task:get_urls()

    if urls then
      for _,u in ipairs(urls) do
        if u:is_obscured() then
          task:insert_result('R_SUSPICIOUS_URL', 1.0, u:get_host())
        end
      end
    end
    return false
  end,
  score = 5.0,
  one_shot = true,
  description = 'Obfusicated or suspicious URL has been found in a message',
  group = 'url'
}


rspamd_config.ENVFROM_PRVS = {
  callback = function (task)
    --[[
        Detect PRVS/BATV addresses to avoid FORGED_SENDER
        https://en.wikipedia.org/wiki/Bounce_Address_Tag_Validation

        Signature syntax:

        prvs=TAG=USER@example.com       BATV draft (https://tools.ietf.org/html/draft-levine-smtp-batv-01)
        prvs=USER=TAG@example.com
        btv1==TAG==USER@example.com     Barracuda appliance
        msprvs1=TAG=USER@example.com    Sparkpost email delivery service
        ]]--
    if not (task:has_from(1) and task:has_from(2)) then
      return false
    end
    local envfrom = task:get_from(1)
    local re_text = '^(?:(prvs|msprvs1)=([^=]+)=|btv1==[^=]+==)(.+@(.+))$'
    local re = rspamd_regexp.create_cached(re_text)
    local c = re:search(envfrom[1].addr:lower(), false, true)
    if not c then return false end
    local ef = c[1][4]
    -- See if it matches the From header
    local from = task:get_from(2)
    if ef == from[1].addr:lower() then
      return true
    end
    -- Check for prvs=USER=TAG@example.com
    local t = c[1][2]
    if t == 'prvs' then
      local efr = c[1][3] .. '@' .. c[1][5]
      if efr == from[1].addr:lower() then
        return true
      end
    end
    return false
  end,
  score = 0.0,
  description = "Envelope From is a PRVS address that matches the From address",
  group = 'prvs'
}

rspamd_config.ENVFROM_VERP = {
  callback = function (task)
    if not (task:has_from(1) and task:has_recipients(1)) then
      return false
    end
    local envfrom = task:get_from(1)
    local envrcpts = task:get_recipients(1)
    -- VERP only works for single recipient messages
    if #envrcpts > 1 then return false end
    -- Get recipient and compute VERP address
    local rcpt = envrcpts[1].addr:lower()
    local verp = rcpt:gsub('@','=')
    -- Get the user portion of the envfrom
    local ef_user = envfrom[1].user:lower()
    -- See if the VERP representation of the recipient appears in it
    if ef_user:find(verp, 1, true)
      and not ef_user:find('+caf_=' .. verp, 1, true) -- Google Forwarding
      and not ef_user:find('^srs[01]=')               -- SRS
    then
      return true
    end
    return false
  end,
  score = 0.0,
  description = "Envelope From is a VERP address",
  group = "mailing_list"
}

local check_rcvd = rspamd_config:register_symbol{
  name = 'CHECK_RCVD',
  callback = function (task)
    local rcvds = task:get_received_headers()
    if not rcvds then return false end

    local all_tls = fun.all(function(rc)
      return rc.flags and rc.flags['ssl']
    end, fun.filter(function(rc)
      return rc.by and rc.by ~= 'localhost'
    end, rcvds))

    -- See if only the last hop was encrypted
    if all_tls then
      task:insert_result('RCVD_TLS_ALL', 1.0)
    else
      local rcvd = rcvds[1]
      if rcvd.by and rcvd.by == 'localhost' then
        -- Ignore artificial header from Rmilter
        rcvd = rcvds[2]
      end
      if rcvd.flags and rcvd.flags['ssl'] then
        task:insert_result('RCVD_TLS_LAST', 1.0)
      else
        task:insert_result('RCVD_NO_TLS_LAST', 1.0)
      end
    end

    local auth = fun.any(function(rc)
      return rc.flags and rc.flags['authenticated']
    end, rcvds)

    if auth then
      task:insert_result('RCVD_VIA_SMTP_AUTH', 1.0)
    end
  end
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_TLS_ALL',
  description = 'All hops used encrypted transports',
  score = 0.0,
  group = 'encryption'
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_TLS_LAST',
  description = 'Last hop used encrypted transports',
  score = 0.0,
  group = 'encryption'
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_NO_TLS_LAST',
  description = 'Last hop did not use encrypted transports',
  score = 0.0,
  group = 'encryption'
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_VIA_SMTP_AUTH',
  description = 'Message injected via SMTP AUTH',
  score = 0.0,
  group = 'authentication'
}

rspamd_config.RCVD_HELO_USER = {
  callback = function (task)
    -- Check HELO argument from MTA
    local helo = task:get_helo()
    if (helo and helo:lower():find('^user$')) then
      return true
    end
    -- Check Received headers
    local rcvds = task:get_header_full('Received')
    if not rcvds then return false end
    for _, rcvd in ipairs(rcvds) do
      local r = rcvd['decoded']:lower()
      if (r:find("^%s*from%suser%s")) then return true end
      if (r:find("helo[%s=]user[%s%)]")) then return true end
    end
  end,
  description = 'HELO User spam pattern',
  score = 3.0
}

rspamd_config.URI_COUNT_ODD = {
  callback = function (task)
    local ct = task:get_header('Content-Type')
    if (ct and ct:lower():find('^multipart/alternative')) then
      local urls = task:get_urls() or {}
      local nurls = fun.filter(function(url)
        return not url:is_html_displayed()
      end, urls):foldl(function(acc, val) return acc + 1 end, 0)

      if nurls % 2 == 1 then
        return true, 1.0, tostring(nurls)
      end
    end
  end,
  description = 'Odd number of URIs in multipart/alternative message',
  score = 1.0
}

rspamd_config.HAS_ATTACHMENT = {
  callback = function (task)
    local parts = task:get_parts()
    if parts and #parts > 1 then
      for _, p in ipairs(parts) do
        local cd = p:get_header('Content-Disposition')
        if (cd and cd:lower():match('^attachment')) then
          return true
        end
      end
    end
  end,
  description = 'Message contains attachments'
}

-- Requires freemail maps loaded in multimap
local function freemail_reply_neq_from(task)
  local frt = task:get_symbol('FREEMAIL_REPLYTO')
  local ff  = task:get_symbol('FREEMAIL_FROM')
  if (frt and ff and frt['options'] and ff['options'] and
      frt['options'][1] ~= ff['options'][1])
  then
    return true
  end
  return false
end

local freemail_reply_neq_from_id = rspamd_config:register_symbol({
  name = 'FREEMAIL_REPLYTO_NEQ_FROM_DOM',
  callback = freemail_reply_neq_from,
  description = 'Freemail From and Reply-To, but to different Freemail services',
  score = 3.0
})
rspamd_config:register_dependency(freemail_reply_neq_from_id, 'FREEMAIL_REPLYTO')
rspamd_config:register_dependency(freemail_reply_neq_from_id, 'FREEMAIL_FROM')

rspamd_config.OMOGRAPH_URL = {
  callback = function(task)
    local urls = task:get_urls()

    if urls then
      local bad_omographs = 0
      local single_bad_omograps = 0
      local bad_urls = {}

      fun.each(function(u)
        if u:is_phished() then
          local h1 = u:get_host()
          local h2 = u:get_phished():get_host()
          if h1 and h2 then
            if util.is_utf_spoofed(h1, h2) then
              table.insert(bad_urls, string.format('%s->%s', h1, h2))
              bad_omographs = bad_omographs + 1
            end
          end
        end
        if not u:is_html_displayed() then
          local h = u:get_tld()

          if h then
            if util.is_utf_spoofed(h) then
              table.insert(bad_urls, string.format('%s', h))
              single_bad_omograps = single_bad_omograps + 1
            end
          end
        end
      end, urls)

      if bad_omographs > 0 then
        return true, 1.0, bad_urls
      elseif single_bad_omograps > 0 then
        return true, 0.5, bad_urls
      end
    end

    return false
  end,
  score = 5.0,
  description = 'Url contains both latin and non-latin characters'
}

rspamd_config.URL_IN_SUBJECT = {
  callback = function(task)
    local urls = task:get_urls()

    if urls then
      for _,u in ipairs(urls) do
        if u:is_subject() then
          local subject = task:get_subject()

          if subject then
            if tostring(u) == subject then
              return true,1.0,u:get_host()
            end
          end
          return true,0.25,u:get_host()
        end
      end
    end

    return false
  end,
  score = 4.0,
  description = 'Url found in Subject'
}

local aliases_id = rspamd_config:register_symbol{
  type = 'prefilter',
  name = 'EMAIL_PLUS_ALIASES',
  callback = function(task)
    local function check_address(addr)
      if addr.user then
        local cap, pluses = string.match(addr.user, '^([^%+][^%+]*)(%+.*)$')
        if cap then
          return cap, rspamd_str_split(pluses, '+')
        end
      end

      return nil
    end

    local function set_addr(addr, new_user)
      addr.user = new_user

      if addr.domain then
        addr.addr = string.format('%s@%s', addr.user, addr.domain)
      else
        addr.addr = string.format('%s@', addr.user)
      end

      if addr.name and #addr.name > 0 then
        addr.raw = string.format('"%s" <%s>', addr.name, addr.addr)
      else
        addr.raw = string.format('<%s>', addr.addr)
      end
    end

    local function check_from(type)
      if task:has_from(type) then
        local addr = task:get_from(type)[1]
        local na,tags = check_address(addr)
        if na then
          set_addr(addr, na)
          task:set_from(type, addr)
          task:insert_result('TAGGED_FROM', 1.0, fun.totable(
            fun.filter(function(t) return t and #t > 0 end, tags)))
        end
      end
    end

    check_from('smtp')
    check_from('mime')

    local function check_rcpt(type)
      if task:has_recipients(type) then
        local modified = false
        local all_tags = {}
        local addrs = task:get_recipients(type)

        for _, addr in ipairs(addrs) do
          local na,tags = check_address(addr)
          if na then
            set_addr(addr, na)
            modified = true
            fun.each(function(t) table.insert(all_tags, t) end,
              fun.filter(function(t) return t and #t > 0 end, tags))
          end
        end

        if modified then
          task:set_recipients(type, addrs)
          task:insert_result('TAGGED_RCPT', 1.0, all_tags)
        end
      end
    end

    check_rcpt('smtp')
    check_rcpt('mime')
  end,
  priority = 150,
  description = 'Removes plus aliases from the email',
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = aliases_id,
  name = 'TAGGED_RCPT',
  description = 'SMTP recipients have plus tags',
  score = 0,
}
rspamd_config:register_symbol{
  type = 'virtual',
  parent = aliases_id,
  name = 'TAGGED_FROM',
  description = 'SMTP from has plus tags',
  score = 0,
}

local check_from_display_name = rspamd_config:register_symbol{
  type = 'callback',
  callback = function (task)
    local from = task:get_from(2)
    if not (from and from[1] and from[1].name) then return false end
    -- See if we can parse an email address from the name
    local parsed = util.parse_mail_address(from[1].name)
    if not parsed then return false end
    if not (parsed[1] and parsed[1]['addr']) then return false end
    if parsed[1]['domain'] == nil or parsed[1]['domain'] == '' then return false end
    -- See if the parsed domains differ
    if not util.strequal_caseless(from[1]['domain'], parsed[1]['domain']) then
      -- See if the destination domain is the same as the spoof
      local to = task:get_recipients(2)
      if (to and to[1] and to[1]['domain']) then
        -- Be careful with undisclosed-recipients:; as domain will be an empty string
        if to[1]['domain'] ~= '' and util.strequal_caseless(to[1]['domain'], parsed[1]['domain']) then
          task:insert_result('SPOOF_DISPLAY_NAME', 1.0, from[1]['domain'], parsed[1]['domain'])
        else
          task:insert_result('FROM_NEQ_DISPLAY_NAME', 1.0, from[1]['domain'], parsed[1]['domain'])
        end
        return false
      else
        task:insert_result('FROM_NEQ_DISPLAY_NAME', 1.0, from[1]['domain'], parsed[1]['domain'])
      end
    end
    return false
  end,
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_from_display_name,
  name = 'SPOOF_DISPLAY_NAME',
  description = 'Display name is being used to spoof and trick the recipient',
  score = 8,
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_from_display_name,
  name = 'FROM_NEQ_DISPLAY_NAME',
  description = 'Display name contains an email address different to the From address',
  score = 4,
}

rspamd_config.SPOOF_REPLYTO = {
  callback = function (task)
    -- First check for a Reply-To header
    local rt = task:get_header_full('Reply-To')
    if not rt or not rt[1] then return false end
    -- Get From and To headers
    rt = rt[1]['value']
    local from = task:get_from(2)
    local to = task:get_recipients(2)
    if not (from and from[1] and from[1].addr) then return false end
    if (to and to[1] and to[1].addr) then
      -- Handle common case for Web Contact forms of From = To
      if util.strequal_caseless(from[1].addr, to[1].addr) then
        return false
      end
    end
    -- SMTP recipients must contain From domain
    to = task:get_recipients(1)
    if not to then return false end
    local found_fromdom = false
    for _, t in ipairs(to) do
      if util.strequal_caseless(t.domain, from[1].domain) then
        found_fromdom = true
        break
      end
    end
    if not found_fromdom then return false end
    -- Parse Reply-To header
    local parsed = ((util.parse_mail_address(rt) or E)[1] or E).domain
    if not parsed then return false end
    -- Reply-To domain must be different to From domain
    if not util.strequal_caseless(parsed, from[1].domain) then
      return true, from[1].domain, parsed
    end
    return false
  end,
  description = 'Reply-To is being used to spoof and trick the recipient to send an off-domain reply',
  score = 6.0
}

rspamd_config.INFO_TO_INFO_LU = {
  callback = function(task)
    local lu = task:get_header('List-Unsubscribe')
    if not lu then return false end
    local from = task:get_from('mime')
    if not (from and from[1] and util.strequal_caseless(from[1].user, 'info')) then
      return false
    end
    local to = task:get_recipients('smtp')
    if not to then return false end
    local found = false
    for _,r in ipairs(to) do
      if util.strequal_caseless(r['user'], 'info') then
        found = true
      end
    end
    if found then return true end
    return false
  end,
  description = 'info@ From/To address with List-Unsubscribe headers',
  score = 2.0
}

-- Detects bad content-transfer-encoding for text parts

rspamd_config.R_BAD_CTE_7BIT = {
  callback = function(task)
    local tp = task:get_text_parts() or {}

    for _,p in ipairs(tp) do
      local cte = p:get_mimepart():get_cte() or ''
      if cte ~= '8bit' and p:has_8bit_raw() then
        return true,1.0,cte
      end
    end

    return false
  end,
  score = 4.0,
  description = 'Detects bad content-transfer-encoding for text parts',
  group = 'header'
}
