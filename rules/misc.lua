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

-- Misc rules

local E = {}
local fun = require "fun"
local util = require "rspamd_util"
local rspamd_parsers = require "rspamd_parsers"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_lua_utils = require "lua_util"
local bit = require "bit"
local rspamd_url = require "rspamd_url"
local url_flags_tab = rspamd_url.flags

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
local date_id = rspamd_config:register_symbol({
  name = 'DATE_CB',
  type = 'callback,mime',
  callback = function(task)
    local date_time = task:get_header('Date')
    if date_time == nil or date_time == '' then
      task:insert_result('MISSING_DATE', 1.0)
      return
    end

    local dm, err = rspamd_parsers.parse_smtp_date(date_time)
    if err then
      task:insert_result('INVALID_DATE', 1.0)
      return
    end

    local dt = task:get_date({format = 'connect', gmt = true})
    local date_diff = dt - dm

    if date_diff > 86400 then
      -- Older than a day
      task:insert_result('DATE_IN_PAST', 1.0, tostring(math.floor(date_diff/3600)))
    elseif -date_diff > 7200 then
      -- More than 2 hours in the future
      task:insert_result('DATE_IN_FUTURE', 1.0, tostring(math.floor(-date_diff/3600)))
    end
  end
})

rspamd_config:register_symbol({
  name = 'MISSING_DATE',
  score = 1.0,
  description = 'Message date is missing',
  group = 'headers',
  type = 'virtual',
  parent = date_id,
})

rspamd_config:register_symbol({
  name = 'INVALID_DATE',
  score = 1.5,
  description = 'Malformed date header',
  group = 'headers',
  type = 'virtual',
  parent = date_id,
})

rspamd_config:register_symbol({
  name = 'DATE_IN_FUTURE',
  score = 4.0,
  description = 'Message date is in future',
  group = 'headers',
  type = 'virtual',
  parent = date_id,
})

rspamd_config:register_symbol({
  name = 'DATE_IN_PAST',
  score = 1.0,
  description = 'Message date is in past',
  group = 'headers',
  type = 'virtual',
  parent = date_id,
})

local obscured_id = rspamd_config:register_symbol{
  callback = function(task)
    local susp_urls = task:get_urls_filtered({ 'obscured', 'zw_spaces'})

    if susp_urls and susp_urls[1] then
      local obs_flag = url_flags_tab.obscured
      local zw_flag = url_flags_tab.zw_spaces

      for _,u in ipairs(susp_urls) do
        local fl = u:get_flags_num()
        if bit.band(fl, obs_flag) ~= 0 then
          task:insert_result('R_SUSPICIOUS_URL', 1.0, u:get_host())
        end
        if bit.band(fl, zw_flag) ~= 0 then
          task:insert_result('ZERO_WIDTH_SPACE_URL', 1.0, u:get_host())
        end
      end
    end

    return false
  end,
  name = 'R_SUSPICIOUS_URL',
  score = 5.0,
  one_shot = true,
  description = 'Obfuscated or suspicious URL has been found in a message',
  group = 'url'
}

rspamd_config:register_symbol{
  type = 'virtual',
  name = 'ZERO_WIDTH_SPACE_URL',
  score = 7.0,
  one_shot = true,
  description = 'Zero width space in url',
  group = 'url',
  parent = obscured_id,
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
  group = 'headers',
  type = 'mime',
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
  group = "headers",
  type = 'mime',
}

local check_rcvd = rspamd_config:register_symbol{
  name = 'CHECK_RCVD',
  group = 'headers',
  callback = function (task)
    local rcvds = task:get_received_headers()
    if not rcvds or #rcvds == 0 then return false end

    local all_tls = fun.all(function(rc)
      return rc.flags and rc.flags['ssl']
    end, fun.filter(function(rc)
      return rc.by_hostname and rc.by_hostname ~= 'localhost'
    end, rcvds))

    -- See if only the last hop was encrypted
    if all_tls then
      task:insert_result('RCVD_TLS_ALL', 1.0)
    else
      local rcvd = rcvds[1]
      if rcvd.by_hostname and rcvd.by_hostname == 'localhost' then
        -- Ignore artificial header from Rmilter
        rcvd = rcvds[2] or {}
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
  end,
  type = 'callback,mime',
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_TLS_ALL',
  description = 'All hops used encrypted transports',
  score = 0.0,
  group = 'headers'
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_TLS_LAST',
  description = 'Last hop used encrypted transports',
  score = 0.0,
  group = 'headers'
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_NO_TLS_LAST',
  description = 'Last hop did not use encrypted transports',
  score = 0.1,
  group = 'headers'
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_rcvd,
  name = 'RCVD_VIA_SMTP_AUTH',
  -- NB This does not mean sender was authenticated; see task:get_user()
  description = 'Authenticated hand-off was seen in Received headers',
  score = 0.0,
  group = 'headers'
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
  group = 'headers',
  type = 'mime',
  score = 3.0
}

rspamd_config.URI_COUNT_ODD = {
  callback = function (task)
    local ct = task:get_header('Content-Type')
    if (ct and ct:lower():find('^multipart/alternative')) then
      local urls = task:get_urls() or {}
      local nurls = fun.filter(function(url)
        return not url:is_html_displayed()
      end, urls):foldl(function(acc, val) return acc + val:get_count() end, 0)

      if nurls % 2 == 1 then
        return true, 1.0, tostring(nurls)
      end
    end
  end,
  description = 'Odd number of URIs in multipart/alternative message',
  score = 1.0,
  group = 'url',
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
  description = 'Message contains attachments',
  group = 'body',
}

-- Requires freemail maps loaded in multimap
local function freemail_reply_neq_from(task)
  if not task:has_symbol('FREEMAIL_REPLYTO') or not task:has_symbol('FREEMAIL_FROM') then
    return false
  end
  local frt = task:get_symbol('FREEMAIL_REPLYTO')
  local ff = task:get_symbol('FREEMAIL_FROM')
  local frt_opts = frt[1]['options']
  local ff_opts = ff[1]['options']
  return ( frt_opts and ff_opts and frt_opts[1] ~= ff_opts[1] )
end

rspamd_config:register_symbol({
  name = 'FREEMAIL_REPLYTO_NEQ_FROM_DOM',
  callback = freemail_reply_neq_from,
  description = 'Freemail From and Reply-To, but to different Freemail services',
  score = 3.0,
  group = 'headers',
})
rspamd_config:register_dependency('FREEMAIL_REPLYTO_NEQ_FROM_DOM', 'FREEMAIL_REPLYTO')
rspamd_config:register_dependency('FREEMAIL_REPLYTO_NEQ_FROM_DOM', 'FREEMAIL_FROM')

rspamd_config.OMOGRAPH_URL = {
  callback = function(task)
    local urls = task:get_urls()

    if urls then
      local bad_omographs = 0
      local single_bad_omograps = 0
      local bad_urls = {}
      local seen = {}

      fun.each(function(u)
        if u:is_phished() then

          local h1 = u:get_host()
          local h2 = u:get_phished()
          if h2 then -- Due to changes of the phished flag in 2.8
            h2 = h2:get_host()
          end
          if h1 and h2 then
            local selt = string.format('%s->%s', h1, h2)
            if not seen[selt] and util.is_utf_spoofed(h1, h2) then
              bad_urls[#bad_urls + 1] = selt
              bad_omographs = bad_omographs + 1
            end
            seen[selt] = true
          end
        end
        if not u:is_html_displayed() then
          local h = u:get_tld()

          if h then
            if not seen[h] and util.is_utf_spoofed(h) then
              bad_urls[#bad_urls + 1] = h
              single_bad_omograps = single_bad_omograps + 1
            end
            seen[h] = true
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
  group = 'url',
  description = 'Url contains both latin and non-latin characters'
}

rspamd_config.URL_IN_SUBJECT = {
  callback = function(task)
    local urls = task:get_urls()

    if urls then
      for _,u in ipairs(urls) do
        local flags = u:get_flags()
        if flags.subject then
          if flags.schemaless then
            return true,0.1,u:get_host()
          end
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
  group = 'subject',
  type = 'mime',
  description = 'URL found in Subject'

}

local aliases_id = rspamd_config:register_symbol{
  type = 'prefilter',
  name = 'EMAIL_PLUS_ALIASES',
  callback = function(task)
    local function check_from(type)
      if task:has_from(type) then
        local addr = task:get_from(type)[1]
        local na,tags = rspamd_lua_utils.remove_email_aliases(addr)
        if na then
          task:set_from(type, addr, 'alias')
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
          local na,tags = rspamd_lua_utils.remove_email_aliases(addr)
          if na then
            modified = true
            fun.each(function(t) table.insert(all_tags, t) end,
              fun.filter(function(t) return t and #t > 0 end, tags))
          end
        end

        if modified then
          task:set_recipients(type, addrs, 'alias')
          task:insert_result('TAGGED_RCPT', 1.0, all_tags)
        end
      end
    end

    check_rcpt('smtp')
    check_rcpt('mime')
  end,
  priority = 150,
  description = 'Removes plus aliases from the email',
  group = 'headers',
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = aliases_id,
  name = 'TAGGED_RCPT',
  description = 'SMTP recipients have plus tags',
  group = 'headers',
  score = 0.0,
}
rspamd_config:register_symbol{
  type = 'virtual',
  parent = aliases_id,
  name = 'TAGGED_FROM',
  description = 'SMTP from has plus tags',
  group = 'headers',
  score = 0.0,
}

local check_from_display_name = rspamd_config:register_symbol{
  type = 'callback,mime',
  name = 'FROM_DISPLAY_CALLBACK',
  callback = function (task)
    local from = task:get_from(2)
    if not (from and from[1] and from[1].name) then return false end
    -- See if we can parse an email address from the name
    local parsed = rspamd_parsers.parse_mail_address(from[1].name, task:get_mempool())
    if not parsed then return false end
    if not (parsed[1] and parsed[1]['addr']) then return false end
    -- Make sure we did not mistake e.g. <something>@<name> for an email address
    if not parsed[1]['domain'] or not parsed[1]['domain']:find('%.') then return false end
    -- See if the parsed domains differ
    if not util.strequal_caseless(from[1]['domain'], parsed[1]['domain']) then
      -- See if the destination domain is the same as the spoof
      local mto = task:get_recipients(2)
      local sto = task:get_recipients(1)
      if mto then
        for _, to in ipairs(mto) do
          if to['domain'] ~= '' and util.strequal_caseless(to['domain'], parsed[1]['domain']) then
            task:insert_result('SPOOF_DISPLAY_NAME', 1.0, from[1]['domain'], parsed[1]['domain'])
            return false
          end
        end
      end
      if sto then
        for _, to in ipairs(sto) do
          if to['domain'] ~= '' and util.strequal_caseless(to['domain'], parsed[1]['domain']) then
            task:insert_result('SPOOF_DISPLAY_NAME', 1.0, from[1]['domain'], parsed[1]['domain'])
            return false
          end
        end
      end
      task:insert_result('FROM_NEQ_DISPLAY_NAME', 1.0, from[1]['domain'], parsed[1]['domain'])
    end
    return false
  end,
  group = 'headers',
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_from_display_name,
  name = 'SPOOF_DISPLAY_NAME',
  description = 'Display name is being used to spoof and trick the recipient',
  group = 'headers',
  score = 8.0,
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_from_display_name,
  name = 'FROM_NEQ_DISPLAY_NAME',
  group = 'headers',
  description = 'Display name contains an email address different to the From address',
  score = 4.0,
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
    -- Try mitigate some possible FPs on mailing list posts
    if #to == 1 and util.strequal_caseless(to[1].addr, from[1].addr) then return false end
    local found_fromdom = false
    for _, t in ipairs(to) do
      if util.strequal_caseless(t.domain, from[1].domain) then
        found_fromdom = true
        break
      end
    end
    if not found_fromdom then return false end
    -- Parse Reply-To header
    local parsed = ((rspamd_parsers.parse_mail_address(rt, task:get_mempool()) or E)[1] or E).domain
    if not parsed then return false end
    -- Reply-To domain must be different to From domain
    if not util.strequal_caseless(parsed, from[1].domain) then
      return true, from[1].domain, parsed
    end
    return false
  end,
  group = 'headers',
  type = 'mime',
  description = 'Reply-To is being used to spoof and trick the recipient to send an off-domain reply',
  score = 6.0
}

rspamd_config.INFO_TO_INFO_LU = {
  callback = function(task)
    if not task:has_header('List-Unsubscribe') then
      return false
    end
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
  group = 'headers',
  score = 2.0,
  type = 'mime',
}

-- Detects bad content-transfer-encoding for text parts

rspamd_config.R_BAD_CTE_7BIT = {
  callback = function(task)
    local tp = task:get_text_parts() or {}

    for _,p in ipairs(tp) do
      local cte = p:get_mimepart():get_cte() or ''
      if cte ~= '8bit' and p:has_8bit_raw() then
        local _,_,attrs = p:get_mimepart():get_type_full()
        local mul = 1.0
        local params = {cte}
        if attrs then
          if attrs.charset and attrs.charset:lower() == "utf-8" then
            -- Penalise rule as people don't know that utf8 is surprisingly
            -- eight bit encoding
            mul = 0.3
            table.insert(params, "utf8")
          end
        end

        return true,mul,params
      end
    end

    return false
  end,
  score = 3.5,
  description = 'Detects bad content-transfer-encoding for text parts',
  group = 'headers',
  type = 'mime',
}


local check_encrypted_name = rspamd_config:register_symbol{
  name = 'BOGUS_ENCRYPTED_AND_TEXT',
  callback = function(task)
    local parts = task:get_parts() or {}
    local seen_encrypted, seen_text
    local opts = {}

    local function check_part(part)
      if part:is_multipart() then
        local children = part:get_children() or {}
        local text_kids = {}

        for _,cld in ipairs(children) do
          if cld:is_multipart() then
            check_part(cld)
          elseif cld:is_text() then
            seen_text = true
            text_kids[#text_kids + 1] = cld
          else
            local type,subtype,_ = cld:get_type_full()

            if type:lower() == 'application' then
              if string.find(subtype:lower(), 'pkcs7%-mime') then
                -- S/MIME encrypted part
                seen_encrypted = true
                table.insert(opts, 'smime part')
                task:insert_result('ENCRYPTED_SMIME', 1.0)
              elseif string.find(subtype:lower(), 'pkcs7%-signature') then
                task:insert_result('SIGNED_SMIME', 1.0)
              elseif string.find(subtype:lower(), 'pgp%-encrypted') then
                -- PGP/GnuPG encrypted part
                seen_encrypted = true
                table.insert(opts, 'pgp part')
                task:insert_result('ENCRYPTED_PGP', 1.0)
              elseif string.find(subtype:lower(), 'pgp%-signature') then
                task:insert_result('SIGNED_PGP', 1.0)
              end
            end
          end
          if seen_text and seen_encrypted then
            -- Ensure that our seen text is not really part of pgp #3205
            for _,tp in ipairs(text_kids) do
              local t,_ = tp:get_type()
              seen_text = false -- reset temporary
              if t and t == 'text' then
                seen_text = true
                break
              end
            end
          end
        end
      end
    end

    for _,part in ipairs(parts) do
      check_part(part)
    end

    if seen_text and seen_encrypted then
      return true, 1.0, opts
    end

    return false
  end,
  score = 10.0,
  description = 'Bogus mix of encrypted and text/html payloads',
  group = 'mime_types',
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_encrypted_name,
  name = 'ENCRYPTED_PGP',
  description = 'Message is encrypted with pgp',
  group = 'mime_types',
  score = -0.5,
  one_shot = true
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_encrypted_name,
  name = 'ENCRYPTED_SMIME',
  description = 'Message is encrypted with smime',
  group = 'mime_types',
  score = -0.5,
  one_shot = true
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_encrypted_name,
  name = 'SIGNED_PGP',
  description = 'Message is signed with pgp',
  group = 'mime_types',
  score = -2.0,
  one_shot = true
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_encrypted_name,
  name = 'SIGNED_SMIME',
  description = 'Message is signed with smime',
  group = 'mime_types',
  score = -2.0,
  one_shot = true
}
