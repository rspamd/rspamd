--[[
Copyright (c) 2016, Alexander Moisseev <moiseev@mezonplus.ru>

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

--[[
MID plugin - suppress INVALID_MSGID and MISSING_MID for messages originating
from listed valid DKIM domains with missed or known proprietary Message-IDs
]]--

local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"

local settings = {
  url = '',
  symbol_known_mid = 'KNOWN_MID',
  symbol_known_no_mid = 'KNOWN_NO_MID',
  symbol_invalid_msgid = 'INVALID_MSGID',
  symbol_missing_mid = 'MISSING_MID',
  symbol_dkim_allow = 'R_DKIM_ALLOW',
  csymbol_invalid_msgid_allowed = 'INVALID_MSGID_ALLOWED',
  csymbol_missing_mid_allowed = 'MISSING_MID_ALLOWED',
}

local map = {}

local function known_mid_cb(task)
  local re = {}
  local header = task:get_header('Message-Id')
  local das = task:get_symbol(settings['symbol_dkim_allow'])
  if das and das[1] and das[1]['options'] then
    for _,dkim_domain in ipairs(das[1]['options']) do
      local v = map:get_key(dkim_domain)
      if v then
        if v == '' then
          if not header then
            task:insert_result(settings['symbol_known_no_mid'], 1, dkim_domain)
            return
          end
        else
          re[dkim_domain] = rspamd_regexp.create_cached(v)
          if header and re[dkim_domain] and re[dkim_domain]:match(header) then
              task:insert_result(settings['symbol_known_mid'], 1, dkim_domain)
              return
          end
        end
      end
    end
  end
end

local check_mid_id = rspamd_config:register_callback_symbol('CHECK_MID', 1.0,
  function (task)
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
    -- Check From address atrributes against MID
    local from = task:get_from(2)
    if (from and from[1] and from[1].domain) then
      local fd = from[1].domain:lower()
      local _,_,md = mid:find("@([^>]+)>?$")
      -- See if all or part of the From address
      -- can be found in the Message-ID
      if (mid:lower():find(from[1].addr:lower(),1,true)) then
        task:insert_result('MID_CONTAINS_FROM', 1.0)
      elseif (md and fd == md:lower()) then
        task:insert_result('MID_RHS_MATCH_FROM', 1.0)
      end
    end
  end
)

rspamd_config:register_virtual_symbol('MID_BARE_IP', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_BARE_IP', 2.0, 'Message-ID RHS is a bare IP address')
rspamd_config:register_virtual_symbol('MID_RHS_NOT_FQDN', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_NOT_FQDN', 0.5, 'Message-ID RHS is not a fully-qualified domain name')
rspamd_config:register_virtual_symbol('MID_MISSING_BRACKETS', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_MISSING_BRACKETS', 0.5, 'Message-ID is missing <>\'s')
rspamd_config:register_virtual_symbol('MID_RHS_IP_LITERAL', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_IP_LITERAL', 0.5, 'Message-ID RHS is an IP-literal')
rspamd_config:register_virtual_symbol('MID_CONTAINS_FROM', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_CONTAINS_FROM', 1.0, 'Message-ID contains From address')
rspamd_config:register_virtual_symbol('MID_RHS_MATCH_FROM', 1.0, check_mid_id)
rspamd_config:set_metric_symbol('MID_RHS_MATCH_FROM', 1.0, 'Message-ID RHS matches From domain')

local opts =  rspamd_config:get_all_opt('mid')
if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end

  if settings['url'] and #settings['url'] > 0 then
    map = rspamd_config:add_map ({
      url = settings['url'],
      type = 'map',
      description = 'Message-IDs map'
    })

    local id = rspamd_config:register_symbol({
      name = 'KNOWN_MID_CALLBACK',
      type = 'callback',
      callback = known_mid_cb
    })
    rspamd_config:register_symbol({
      name = settings['symbol_known_mid'],
      parent = id,
      type = 'virtual'
    })
    rspamd_config:register_symbol({
      name = settings['symbol_known_no_mid'],
      parent = id,
      type = 'virtual'
    })
    rspamd_config:add_composite(settings['csymbol_invalid_msgid_allowed'],
      settings['symbol_known_mid'] .. ' & ' .. settings['symbol_invalid_msgid'])
    rspamd_config:add_composite(settings['csymbol_missing_mid_allowed'],
      settings['symbol_known_no_mid'] .. ' & ' .. settings['symbol_missing_mid'])

    rspamd_config:register_dependency(id, settings['symbol_dkim_allow'])
  else
    rspamd_logger.infox(rspamd_config, 'url is not specified, disabling module')
  end
end
