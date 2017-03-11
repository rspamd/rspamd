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
    if rspamd_config:get_api_version() >= 5 then
      local date = task:get_header_raw('Date')
      if date == nil or date == '' then
        return true
      end
    end
    return false
  end,
  score = 1.0,
  description = 'Message date is missing',
  group = 'date'
}

rspamd_config.DATE_IN_FUTURE = {
  callback = function(task)
    if rspamd_config:get_api_version() >= 5 then
      local dm = task:get_date{format = 'message', gmt = true}
      local dt = task:get_date{format = 'connect', gmt = true}
      -- 2 hours
      if dm > 0 and dm - dt > 7200 then
        return true
      end
    end
    return false
  end,
  score = 4.0,
  description = 'Message date is in future',
  group = 'date'
}

rspamd_config.DATE_IN_PAST = {
  callback = function(task)
    if rspamd_config:get_api_version() >= 5 then
      local dm = task:get_date{format = 'message', gmt = true}
      local dt = task:get_date{format = 'connect', gmt = true}
      -- A day
      if dm > 0 and dt - dm > 86400 then
        return true
      end
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

rspamd_config.RCVD_TLS_ALL = {
  callback = function (task)
    local rcvds = task:get_header_full('Received')
    if not rcvds then return false end

    local ret = fun.all(function(rc)
      return rc.flags and (rc.flags['ssl'] or rc.flags['authenticated'])
    end, rcvds)

    return ret
  end,
  score = 0.0,
  description = "All hops used encrypted transports",
  group = "encryption"
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
      local urls = task:get_urls()
      if (urls and (#urls % 2 == 1)) then
        return true
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
      local bad_urls = {}

      fun.each(function(u)
        local h1 = u:get_host()
        local h2 = u:get_phished():get_host()
        if h1 and h2 then
          if util.is_utf_spoofed(h1, h2) then
            table.insert(bad_urls, string.format('%s->%s', h1, h2))
            bad_omographs = bad_omographs + 1
          end
        end
      end, fun.filter(function(u) return u:is_phished() end, urls))

      if bad_omographs > 0 then
        if bad_omographs > 1 then bad_omographs = 1.0 end
        return true, bad_omographs, bad_urls
      end
    end

    return false
  end,
  score = 5.0,
  description = 'Url contains both latin and non-latin characters'
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

      if addr.name then
        addr.raw = string.format('%s <%s>', addr.name, addr.addr)
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