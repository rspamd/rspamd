--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2016, Steve Freegard <steve@freegard.name>

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
local rspamd_util = require "rspamd_util"
local function mid_check_func(task)
  local mid = task:get_header('Message-ID')
  if not mid then return false end
  -- Check for 'bare' IP addresses in RHS
  if mid:find("@%d+%.%d+%.%d+%.%d+>$") then
    task:insert_result('MID_BARE_IP', 1.0)
  end
  -- Check for non-FQDN RHS
  if mid:find("@[^%.]+>?$") then
    task:insert_result('MID_RHS_NOT_FQDN', 1.0)
  end
  -- Check for missing <>'s
  if not mid:find('^<[^>]+>$') then
    task:insert_result('MID_MISSING_BRACKETS', 1.0)
  end
  -- Check for IP literal in RHS
  if mid:find("@%[%d+%.%d+%.%d+%.%d+%]") then
    task:insert_result('MID_RHS_IP_LITERAL', 1.0)
  end
  -- Check From address attributes against MID
  local from = task:get_from(2)
  local fd
  if (from and from[1] and from[1].domain and from[1].domain ~= '') then
    fd = from[1].domain:lower()
    local _,_,md = mid:find("@([^>]+)>?$")
    -- See if all or part of the From address
    -- can be found in the Message-ID
    -- extract tld
    local fdtld = nil
    local mdtld = nil
    if md then
      fdtld = rspamd_util.get_tld(fd)
      mdtld = rspamd_util.get_tld(md)
    end
    if (mid:lower():find(from[1].addr:lower(),1,true)) then
      task:insert_result('MID_CONTAINS_FROM', 1.0)
    elseif (md and fd == md:lower()) then
      task:insert_result('MID_RHS_MATCH_FROM', 1.0)
    elseif (mdtld ~= nil and fdtld ~= nil and mdtld:lower() == fdtld) then
      task:insert_result('MID_RHS_MATCH_FROMTLD', 1.0)
    end
  end
  -- Check To address attributes against MID
  local to = task:get_recipients(2)
  if (to and to[1] and to[1].domain and to[1].domain ~= '') then
    local td = to[1].domain:lower()
    local _,_,md = mid:find("@([^>]+)>?$")
    -- Skip if from domain == to domain
    if ((fd and fd ~= td) or not fd) then
      -- See if all or part of the To address
      -- can be found in the Message-ID
      if (mid:lower():find(to[1].addr:lower(),1,true)) then
        task:insert_result('MID_CONTAINS_TO', 1.0)
      elseif (md and td == md:lower()) then
        task:insert_result('MID_RHS_MATCH_TO', 1.0)
      end
    end
  end
end

-- MID checks from Steve Freegard
local check_mid_id = rspamd_config:register_symbol({
  name = 'CHECK_MID',
  score = 0.0,
  group = 'mid',
  type = 'callback,mime',
  callback = mid_check_func
})
rspamd_config:register_virtual_symbol('MID_BARE_IP', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_BARE_IP', 2.0, 'Message-ID RHS is a bare IP address', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_RHS_NOT_FQDN', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_NOT_FQDN', 0.5,
    'Message-ID RHS is not a fully-qualified domain name', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_MISSING_BRACKETS', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_MISSING_BRACKETS', 0.5, 'Message-ID is missing <>\'s', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_RHS_IP_LITERAL', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_IP_LITERAL', 0.5, 'Message-ID RHS is an IP-literal', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_CONTAINS_FROM', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_CONTAINS_FROM', 1.0, 'Message-ID contains From address', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_RHS_MATCH_FROM', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_MATCH_FROM', 0.0,
    'Message-ID RHS matches From domain', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_RHS_MATCH_FROMTLD', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_MATCH_FROMTLD', 0.0,
    'Message-ID RHS matches From domain tld', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_CONTAINS_TO', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_CONTAINS_TO', 1.0, 'Message-ID contains To address', 'default', 'Message ID')
rspamd_config:register_virtual_symbol('MID_RHS_MATCH_TO', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_MATCH_TO', 1.0, 'Message-ID RHS matches To domain', 'default', 'Message ID')

