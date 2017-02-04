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

-- This is main lua config file for rspamd

local util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"

-- Uncategorized rules
local subject_re = rspamd_regexp.create('/^(?:(?:Re|Fwd|Fw|Aw|Antwort|Sv):\\s*)+(.+)$/i')

-- Local functions


-- Subject issues
local function test_subject(task, check_function, rate)
  local function normalize_linear(a, x)
      local f = a * x
      return true, (( f < 1 ) and f or 1), tostring(x)
  end

  local sbj = task:get_header('Subject')

  if sbj then
    local stripped_subject = subject_re:search(sbj, false, true)
    if stripped_subject and stripped_subject[1] and stripped_subject[1][2] then
      sbj = stripped_subject[1][2]
    end

    local l = util.strlen_utf8(sbj)
    if check_function(sbj, l) then
      return normalize_linear(rate, l)
    end
  end

  return false
end

rspamd_config.SUBJ_ALL_CAPS = {
  callback = function(task)
    local caps_test = function(sbj)
      return util.is_uppercase(sbj)
    end
    return test_subject(task, caps_test, 1.0/40.0)
  end,
  score = 3.0,
  group = 'subject',
  description = 'All capital letters in subject'
}

rspamd_config.LONG_SUBJ = {
  callback = function(task)
    local length_test = function(_, len)
      return len > 200
    end
    return test_subject(task, length_test, 1.0/400.0)
  end,
  score = 3.0,
  group = 'subject',
  description = 'Subject is too long'
}

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
  score = 6.0,
  one_shot = true,
  description = 'Obfusicated or suspicious URL has been found in a message',
  group = 'url'
}

rspamd_config.BROKEN_HEADERS = {
  callback = function(task)
    return task:has_flag('broken_headers')
  end,
  score = 10.0,
  group = 'header',
  description = 'Headers structure is likely broken'
}

rspamd_config.HEADER_RCONFIRM_MISMATCH = {
  callback = function (task)
    local header_from = nil
    local cread = task:get_header('X-Confirm-Reading-To')

    if task:has_from('mime') then
      header_from  = task:get_from('mime')[1]
    end

    local header_cread = nil
    if cread then
      local headers_cread = util.parse_mail_address(cread)
      if headers_cread then header_cread = headers_cread[1] end
    end

    if header_from and header_cread then
      if not string.find(header_from['addr'], header_cread['addr']) then
        return true
      end
    end

    return false
  end,

  score = 2.0,
  group = 'header',
  description = 'Read confirmation address is different to from address'
}

rspamd_config.HEADER_FORGED_MDN = {
  callback = function (task)
    local mdn = task:get_header('Disposition-Notification-To')
    if not mdn then return false end
    local header_rp = nil

    if task:has_from('smtp') then
      header_rp = task:get_from('smtp')[1]
    end

    -- Parse mail addr
    local headers_mdn = util.parse_mail_address(mdn)

    if headers_mdn and not header_rp  then return true end
    if header_rp  and not headers_mdn then return false end
    if not headers_mdn and not header_rp then return false end

    local found_match = false
    for _, h in ipairs(headers_mdn) do
      if util.strequal_caseless(h['addr'], header_rp['addr']) then
        found_match = true
        break
      end
    end

    return (not found_match)
  end,

  score = 2.0,
  group = 'header',
  description = 'Read confirmation address is different to return path'
}

local headers_unique = {
  'Content-Type',
  'Content-Transfer-Encoding',
  -- https://tools.ietf.org/html/rfc5322#section-3.6
  'Date',
  'From',
  'Sender',
  'Reply-To',
  'To',
  'Cc',
  'Bcc',
  'Message-ID',
  'In-Reply-To',
  'References',
  'Subject'
}

rspamd_config.MULTIPLE_UNIQUE_HEADERS = {
  callback = function (task)
    local res = 0
    local res_tbl = {}

    for _,hdr in ipairs(headers_unique) do
      local h = task:get_header_full(hdr)

      if h and #h > 1 then
        res = res + 1
        table.insert(res_tbl, hdr)
      end
    end

    if res > 0 then
      return true,res,table.concat(res_tbl, ',')
    end

    return false
  end,

  score = 5.0,
  group = 'header',
  description = 'Repeated unique headers'
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
        local count = 0
        local encrypted = 0
        for _, rcvd in ipairs(rcvds) do
            count = count + 1
            local r = rcvd['decoded']:lower()
            local with = r:match('%swith%s+(e?smtps?a?)')
            if with and with:match('esmtps') then
                encrypted = encrypted + 1
            end
        end
        if (count > 0 and count == encrypted) then
            return true
        end
    end,
    score = 0.0,
    description = "All hops used encrypted transports",
    group = "encryption"
}

rspamd_config.MISSING_FROM = {
    callback = function(task)
      local from = task:get_header('From')
      if from == nil or from == '' then
        return true
      end
      return false
    end,
    score = 2.0,
    group = 'header',
    description = 'Missing From: header'
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

rspamd_config.MV_CASE = {
  callback = function (task)
    local mv = task:get_header('Mime-Version', true)
    if (mv) then return true end
  end,
  description = 'Mime-Version .vs. MIME-Version',
  score = 0.5
}

rspamd_config.FAKE_REPLY = {
  callback = function (task)
    local subject = task:get_header('Subject')
    if (subject and subject:lower():find('^re:')) then
      local ref = task:get_header('References')
      local rt  = task:get_header('In-Reply-To')
      if (not (ref or rt)) then return true end
    end
    return false
  end,
  description = 'Fake reply',
  score = 1.0
}

local check_from_id = rspamd_config:register_callback_symbol('CHECK_FROM', 1.0,
  function(task)
    local envfrom = task:get_from(1)
    local from = task:get_from(2)
    if (from and from[1] and not from[1].name) then
      task:insert_result('FROM_NO_DN', 1.0)
    elseif (from and from[1] and from[1].name and
            from[1].name:lower() == from[1].addr:lower()) then
      task:insert_result('FROM_DN_EQ_ADDR', 1.0)
    elseif (from and from[1] and from[1].name) then
      task:insert_result('FROM_HAS_DN', 1.0)
      -- Look for Mr/Mrs/Dr titles
      local n = from[1].name:lower()
      if (n:find('^mrs?[%.%s]') or n:find('^dr[%.%s]')) then
        task:insert_result('FROM_NAME_HAS_TITLE', 1.0)
      end
    end
    if (envfrom and from and envfrom[1] and from[1] and
        envfrom[1].addr:lower() == from[1].addr:lower())
    then
      task:insert_result('FROM_EQ_ENVFROM', 1.0)
    elseif (envfrom and envfrom[1] and envfrom[1].addr) then
      task:insert_result('FROM_NEQ_ENVFROM', 1.0, from and from[1].addr or '', envfrom[1].addr)
    end

    local to = task:get_recipients(2)
    if not (to and to[1] and #to == 1 and from) then return false end
    -- Check if FROM == TO
    if (to[1].addr:lower() == from[1].addr:lower()) then
      task:insert_result('TO_EQ_FROM', 1.0)
    elseif (to[1].domain and from[1].domain and
        to[1].domain:lower() == from[1].domain:lower()) then
      task:insert_result('TO_DOM_EQ_FROM_DOM', 1.0)
    end
  end
)

rspamd_config:register_virtual_symbol('FROM_NO_DN', 1.0, check_from_id)
rspamd_config:set_metric_symbol('FROM_NO_DN', 0, 'From header does not have a display name')
rspamd_config:register_virtual_symbol('FROM_DN_EQ_ADDR', 1.0, check_from_id)
rspamd_config:set_metric_symbol('FROM_DN_EQ_ADDR', 1.0, 'From header display name is the same as the address')
rspamd_config:register_virtual_symbol('FROM_HAS_DN', 1.0, check_from_id)
rspamd_config:set_metric_symbol('FROM_HAS_DN', 0, 'From header has a display name')
rspamd_config:register_virtual_symbol('FROM_NAME_HAS_TITLE', 1.0, check_from_id)
rspamd_config:set_metric_symbol('FROM_NAME_HAS_TITLE', 1.0, 'From header display name has a title (Mr/Mrs/Dr)')
rspamd_config:register_virtual_symbol('FROM_EQ_ENVFROM', 1.0, check_from_id)
rspamd_config:set_metric_symbol('FROM_EQ_ENVFROM', 0, 'From address is the same as the envelope')
rspamd_config:register_virtual_symbol('FROM_NEQ_ENVFROM', 1.0, check_from_id)
rspamd_config:set_metric_symbol('FROM_NEQ_ENVFROM', 0, 'From address is different to the envelope')
rspamd_config:register_virtual_symbol('TO_EQ_FROM', 1.0, check_from_id)
rspamd_config:set_metric_symbol('TO_EQ_FROM', 0, 'To address matches the From address')
rspamd_config:register_virtual_symbol('TO_DOM_EQ_FROM_DOM', 1.0, check_from_id)
rspamd_config:set_metric_symbol('TO_DOM_EQ_FROM_DOM', 0, 'To domain is the same as the From domain')

local check_to_cc_id = rspamd_config:register_callback_symbol('CHECK_TO_CC', 1.0,
  function(task)
    local rcpts = task:get_recipients(1)
    local to = task:get_recipients(2)
    local to_match_envrcpt = 0
    if (not to) then return false end
    -- Add symbol for recipient count
    if (#to > 50) then
      task:insert_result('RCPT_COUNT_GT_50', 1.0)
    else
      task:insert_result('RCPT_COUNT_' .. #to, 1.0)
    end
    -- Check for display names
    local to_dn_count = 0
    local to_dn_eq_addr_count = 0
    for _, toa in ipairs(to) do
      -- To: Recipients <noreply@dropbox.com>
      if (toa['name'] and (toa['name']:lower() == 'recipient'
          or toa['name']:lower() == 'recipients')) then
        task:insert_result('TO_DN_RECIPIENTS', 1.0)
      end
      if (toa['name'] and toa['name']:lower() == toa['addr']:lower()) then
        to_dn_eq_addr_count = to_dn_eq_addr_count + 1
      elseif (toa['name']) then
        to_dn_count = to_dn_count + 1
      end
      -- See if header recipients match envrcpts
      if (rcpts) then
        for _, rcpt in ipairs(rcpts) do
          if (toa and toa['addr'] and rcpt and rcpt['addr'] and
              rcpt['addr']:lower() == toa['addr']:lower())
          then
            to_match_envrcpt = to_match_envrcpt + 1
          end
        end
      end
    end
    if (to_dn_count == 0 and to_dn_eq_addr_count == 0) then
      task:insert_result('TO_DN_NONE', 1.0)
    elseif (to_dn_count == #to) then
      task:insert_result('TO_DN_ALL', 1.0)
    elseif (to_dn_count > 0) then
      task:insert_result('TO_DN_SOME', 1.0)
    end
    if (to_dn_eq_addr_count == #to) then
      task:insert_result('TO_DN_EQ_ADDR_ALL', 1.0)
    elseif (to_dn_eq_addr_count > 0) then
      task:insert_result('TO_DN_EQ_ADDR_SOME', 1.0)
    end

    -- See if header recipients match envelope recipients
    if (to_match_envrcpt == #to) then
      task:insert_result('TO_MATCH_ENVRCPT_ALL', 1.0)
    elseif (to_match_envrcpt > 0) then
      task:insert_result('TO_MATCH_ENVRCPT_SOME', 1.0)
    end
  end
)

rspamd_config:register_virtual_symbol('TO_DN_RECIPIENTS', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_DN_RECIPIENTS', 2.0, 'To header display name is "Recipients"')
rspamd_config:register_virtual_symbol('TO_DN_NONE', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_DN_NONE', 0, 'None of the recipients have display names')
rspamd_config:register_virtual_symbol('TO_DN_ALL', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_DN_ALL', 0, 'All of the recipients have display names')
rspamd_config:register_virtual_symbol('TO_DN_SOME', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_DN_SOME', 0, 'Some of the recipients have display names')
rspamd_config:register_virtual_symbol('TO_DN_EQ_ADDR_ALL', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_DN_EQ_ADDR_ALL', 0, 'All of the recipients have display names that are the same as their address')
rspamd_config:register_virtual_symbol('TO_DN_EQ_ADDR_SOME', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_DN_EQ_ADDR_SOME', 0, 'Some of the recipients have display names that are the same as their address')
rspamd_config:register_virtual_symbol('TO_MATCH_ENVRCPT_ALL', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_MATCH_ENVRCPT_ALL', 0, 'All of the recipients match the envelope')
rspamd_config:register_virtual_symbol('TO_MATCH_ENVRCPT_SOME', 1.0, check_to_cc_id)
rspamd_config:set_metric_symbol('TO_MATCH_ENVRCPT_SOME', 0, 'Some of the recipients match the envelope')

rspamd_config.CHECK_RECEIVED = {
  callback = function (task)
    local received = task:get_received_headers()
    task:insert_result('RCVD_COUNT_' .. #received, 1.0)
  end
}

rspamd_config.HAS_X_PRIO = {
  callback = function (task)
    local xprio = task:get_header('X-Priority');
    if not xprio then return false end
    local _,_,x = xprio:find('^%s?(%d+)');
    if (x) then
      task:insert_result('HAS_X_PRIO_' .. x, 1.0)
    end
  end
}

local check_replyto_id = rspamd_config:register_callback_symbol('CHECK_REPLYTO', 1.0,
  function (task)
    local replyto = task:get_header('Reply-To')
    if not replyto then return false end
    local rt = util.parse_mail_address(replyto)
    if not (rt and rt[1]) then
      task:insert_result('REPLYTO_UNPARSEABLE', 1.0)
      return false
    else
      task:insert_result('HAS_REPLYTO', 1.0)
    end

    -- See if Reply-To matches From in some way
    local from = task:get_from(2)
    local from_h = task:get_header('From')
    if not (from and from[1]) then return false end
    if (from_h and from_h == replyto) then
      -- From and Reply-To are identical
      task:insert_result('REPLYTO_EQ_FROM', 1.0)
    else
      if (from and from[1]) then
        -- See if From and Reply-To addresses match
        if (from[1].addr:lower() == rt[1].addr:lower()) then
          task:insert_result('REPLYTO_ADDR_EQ_FROM', 1.0)
        elseif from[1].domain and rt[1].domain then
          if (from[1].domain:lower() == rt[1].domain:lower()) then
            task:insert_result('REPLYTO_DOM_EQ_FROM_DOM', 1.0)
          else
            task:insert_result('REPLYTO_DOM_NEQ_FROM_DOM', 1.0)
          end
        end
        -- See if the Display Names match
        if (from[1].name and rt[1].name and from[1].name:lower() == rt[1].name:lower()) then
          task:insert_result('REPLYTO_DN_EQ_FROM_DN', 1.0)
        end
      end
    end
  end
)

rspamd_config:register_virtual_symbol('REPLYTO_UNPARSEABLE', 1.0, check_replyto_id)
rspamd_config:set_metric_symbol('REPLYTO_UNPARSEABLE', 1.0, 'Reply-To header could not be parsed')
rspamd_config:register_virtual_symbol('HAS_REPLYTO', 1.0, check_replyto_id)
rspamd_config:set_metric_symbol('HAS_REPLYTO', 0, 'Has Reply-To header')
rspamd_config:register_virtual_symbol('REPLYTO_EQ_FROM', 1.0, check_replyto_id)
rspamd_config:set_metric_symbol('REPLYTO_EQ_FROM', 0, 'Reply-To header is identical to From header')
rspamd_config:register_virtual_symbol('REPLYTO_ADDR_EQ_FROM', 1.0, check_replyto_id)
rspamd_config:set_metric_symbol('REPLYTO_ADDR_EQ_FROM', 0, 'Reply-To address is the same as From')
rspamd_config:register_virtual_symbol('REPLYTO_DOM_EQ_FROM_DOM', 1.0, check_replyto_id)
rspamd_config:set_metric_symbol('REPLYTO_DOM_EQ_FROM_DOM', 0, 'Reply-To domain matches the From domain')
rspamd_config:register_virtual_symbol('REPLYTO_DOM_NEQ_FROM_DOM', 1.0, check_replyto_id)
rspamd_config:set_metric_symbol('REPLYTO_DOM_NEQ_FROM_DOM', 0, 'Reply-To domain does not match the From domain')
rspamd_config:register_virtual_symbol('REPLYTO_DN_EQ_FROM_DN', 1.0, check_replyto_id)
rspamd_config:set_metric_symbol('REPLYTO_DN_EQ_FROM_DN', 0, 'Reply-To display name matches From')

local check_mime_id = rspamd_config:register_callback_symbol('CHECK_MIME', 1.0,
  function (task)
    local parts = task:get_parts()
    if not parts then return false end

    -- Make sure there is a MIME-Version header
    local mv = task:get_header('MIME-Version')
    if (not mv) then
      task:insert_result('MISSING_MIME_VERSION', 1.0)
    end

    local found_ma = false
    local found_plain = false
    local found_html = false

    for _,p in ipairs(parts) do
      local mtype,subtype = p:get_type()
      local ctype = mtype:lower() .. '/' .. subtype:lower()
      if (ctype == 'multipart/alternative') then
        found_ma = true
      end
      if (ctype == 'text/plain') then
        found_plain = true
      end
      if (ctype == 'text/html') then
        found_html = true
      end
    end

    if (found_ma) then
      if (not found_plain) then
        task:insert_result('MIME_MA_MISSING_TEXT', 1.0)
      end
      if (not found_html) then
        task:insert_result('MIME_MA_MISSING_HTML', 1.0)
      end
    end
  end
)

rspamd_config:register_virtual_symbol('MISSING_MIME_VERSION', 1.0, check_mime_id)
rspamd_config:set_metric_symbol('MISSING_MIME_VERSION', 2.0, 'MIME-Version header is missing')
rspamd_config:register_virtual_symbol('MIME_MA_MISSING_TEXT', 1.0, check_mime_id)
rspamd_config:set_metric_symbol('MIME_MA_MISSING_TEXT', 2.0, 'MIME multipart/alternative missing text/plain part')
rspamd_config:register_virtual_symbol('MIME_MA_MISSING_HTML', 1.0, check_mime_id)
rspamd_config:set_metric_symbol('MIME_MA_MISSING_HTML', 1.0, 'multipart/alternative missing text/html part')

-- Used to be called IS_LIST
rspamd_config.PREVIOUSLY_DELIVERED = {
  callback = function(task)
    if not task:has_recipients(2) then return false end
    local to = task:get_recipients(2)
    local rcvds = task:get_header_full('Received')
    if not rcvds then return false end
    for _, rcvd in ipairs(rcvds) do
      local _,_,addr = rcvd['decoded']:lower():find("%sfor%s<(.-)>")
      if addr then
        for _, toa in ipairs(to) do
          if toa and toa.addr:lower() == addr then
            return true, addr
          end
        end
        return false
      end
    end
  end,
  description = 'Message either to a list or was forwarded',
  score = 0.0
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
      for _,u in ipairs(urls) do
        local h = u:get_host()

        if h then
          local non_latin,total = util.count_non_ascii(h)

          if non_latin ~= total and non_latin > 0 then
            return true, 1.0, h
          end
        end
      end
    end

    return false
  end,
  score = 5.0,
  description = 'Url contains both latin and non-latin characters'
}
