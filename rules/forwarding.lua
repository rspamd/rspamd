--[[
Copyright (c) 2011-2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Rules to detect forwarding

local rspamd_util = require "rspamd_util"

rspamd_config.FWD_GOOGLE = {
  callback = function (task)
    if not (task:has_from(1) and task:has_recipients(1)) then
      return false
    end
    local envfrom = task:get_from{'smtp', 'orig'}
    local envrcpts = task:get_recipients(1)
    -- Forwarding will only be to a single recipient
    if #envrcpts > 1 then return false end
    -- Get recipient and compute VERP address
    local rcpt = envrcpts[1].addr:lower()
    local verp = rcpt:gsub('@','=')
    -- Get the user portion of the envfrom
    local ef_user = envfrom[1].user:lower()
    -- Check for a match
    if ef_user:find('+caf_=' .. verp, 1, true) then
      local _,_,user = ef_user:find('^(.+)+caf_=')
      if user then
        user = user .. '@' .. envfrom[1].domain
        return true, user
      end
    end
    return false
  end,
  score = 0.0,
  description = "Message was forwarded by Google",
  group = "forwarding"
}

rspamd_config.FWD_YANDEX = {
  callback = function (task)
    if not (task:has_from(1) and task:has_recipients(1)) then
      return false
    end
    local hostname = task:get_hostname()
    if hostname and hostname:lower():find('%.yandex%.[a-z]+$') then
      return task:has_header('X-Yandex-Forward')
    end
    return false
  end,
  score = 0.0,
  description = "Message was forwarded by Yandex",
  group = "forwarding"
}

rspamd_config.FWD_MAILRU = {
  callback = function (task)
    if not (task:has_from(1) and task:has_recipients(1)) then
      return false
    end
    local hostname = task:get_hostname()
    if hostname and hostname:lower():find('%.mail%.ru$') then
      return task:has_header('X-MailRu-Forward')
    end
    return false
  end,
  score = 0.0,
  description = "Message was forwarded by Mail.ru",
  group = "forwarding"
}

rspamd_config.FWD_SRS = {
  callback = function (task)
    if not (task:has_from(1) and task:has_recipients(1)) then
      return false
    end
    local envfrom = task:get_from(1)
    local envrcpts = task:get_recipients(1)
    -- Forwarding is only to a single recipient
    if #envrcpts > 1 then return false end
    -- Get recipient and compute rewritten SRS address
    local srs = '=' .. envrcpts[1].domain:lower() ..
        '=' .. envrcpts[1].user:lower()
    if envfrom[1].user:lower():find('^srs[01]=') and
        envfrom[1].user:lower():find(srs, 1, false)
    then
      return true
    end
    return false
  end,
  score = 0.0,
  description = "Message was forwarded using Sender Rewriting Scheme (SRS)",
  group = "forwarding"
}

rspamd_config.FORWARDED = {
  callback = function (task)
    local function normalize_addr(addr)
      addr = string.match(addr, '^<?([^>]*)>?$') or addr
      local cap, _,domain = string.match(addr, '^([^%+][^%+]*)(%+[^@]*)@(.*)$')
      if cap then
        addr = string.format('%s@%s', cap, domain)
      end

      return addr
    end

    if not task:has_recipients(1) or not task:has_recipients(2) then return false end
    local envrcpts = task:get_recipients(1)
    -- Forwarding will only be for single recipient messages
    if #envrcpts > 1 then return false end
    -- Get any other headers we might need
    local has_list_unsub = task:has_header('List-Unsubscribe')
    local to = task:get_recipients(2)
    local matches = 0
    -- Retrieve and loop through all Received headers
    local rcvds = task:get_received_headers()

    if rcvds then
      for _, rcvd in ipairs(rcvds) do
        local addr = rcvd['for']
        if addr then
          addr = normalize_addr(addr)
          matches = matches + 1
          -- Check that it doesn't match the envrcpt
          if not rspamd_util.strequal_caseless(addr, envrcpts[1].addr) then
            -- Check for mailing-lists as they will have the same signature
            if matches < 2 and has_list_unsub and to and rspamd_util.strequal_caseless(to[1].addr, addr) then
              return false
            else
              return true, 1.0, addr
            end
          end
          -- Prevent any other iterations as we only want
          -- process the first matching Received header
          return false
        end
      end
    end
    return false
  end,
  score = 0.0,
  description = "Message was forwarded",
  group = "forwarding"
}

