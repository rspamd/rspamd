--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
require "fun" ()

local options = {
  dmarc_allow_symbol = 'DMARC_POLICY_ALLOW',
  spf_allow_symbol = 'R_SPF_ALLOW',
  dkim_allow_symbol = 'R_DKIM_ALLOW',

  rules = {}
}

local function whitelist_cb(symbol, rule, task)
  local from = task:get_from(1)
  if from and from[1] and from[1]['domain'] then
    local domain = from[1]['domain']
    local found = false
    local mult = 1.0

    if rule['map'] then
      local val = rule['map']:get_key(domain)
      if val then
        found = true

        if #val > 0 then
          mult = tonumber(val)
        end
      end
    else
      mult = rule['domains'][domain]
      if mult then
        found = true
      end
    end

    if found then
      if rule['valid_spf'] then
        -- Check for spf symbol
        if not task:get_symbol(options['spf_allow_symbol']) then
          found = false
          rspamd_logger.debugx(task, "domain %s has been found in whitelist %s" ..
            "but it doesn't have valid SPF record", domain, symbol)
        end
      end
      if rule['valid_dkim'] then
        if not task:get_symbol(options['dkim_allow_symbol']) then
          found = false
          rspamd_logger.debugx(task, "domain %s has been found in whitelist %s" ..
              "but it doesn't have valid DKIM", domain, symbol)
        end
      end
      if rule['valid_dmarc'] then
        if not task:get_symbol(options['dmarc_allow_symbol']) then
          found = false
          rspamd_logger.debugx(task, "domain %s has been found in whitelist %s" ..
              "but it doesn't have valid DMARC", domain, symbol)
        end
      end
    end

    if found then
      task:insert_result(symbol, mult, domain)
    end
  end

end

local function gen_whitelist_cb(symbol, rule)
  return function(task)
    whitelist_cb(symbol, rule, task)
  end
end

local function process_whitelist_map(input)
  local parser = ucl.parser()
  local res,err = parser:parse_string(string)
  if not res then
    rspamd_logger.warnx(rspamd_config, 'cannot parse settings map: ' .. err)
  else
    local obj = parser:get_object()

    options['rules'] = obj
  end
end

local configure_whitelist_module = function()
  local opts =  rspamd_config:get_all_opt('whitelist')
  if opts then
    for k,v in pairs(opts) do
      options[k] = v
    end
  end

  if options['rules'] then
    each(function(symbol, rule)
      if rule['domains'] then
        if type(rule['domains']) == 'string' then
          rule['map'] = rspamd_config:add_kv_map(rule['domains'])
        elseif type(rule['domains']) == 'table' then
          -- Transform ['domain1', 'domain2' ...] to indexes:
          -- {'domain1' = 1, 'domain2' = 1 ...]
          rule['domains'] = tomap(map(function(d)
            local name = d
            local value = 1

            if type(d) == 'table' then
              name = d[1]
              value = tonumber(d[2])
            end

            return name,value
          end, rule['domains']))
        else
          rspamd_logger.errx(rspamd_config, 'whitelist %s has bad "domains" value',
            symbol)
          return
        end

        local id = rspamd_config:register_symbol(symbol, -1.0,
          gen_whitelist_cb(symbol, rule))

        if rule['valid_spf'] then
          rspamd_config:register_dependency(id, options['spf_allow_symbol'])
        end
        if rule['valid_dkim'] then
          rspamd_config:register_dependency(id, options['dkim_allow_symbol'])
        end
        if rule['valid_dmarc'] then
          rspamd_config:register_dependency(id, options['dmarc_allow_symbol'])
        end

        if rule['score'] then
          if not rule['group'] then
            rule['group'] = 'whitelist'
          end
          rule['name'] = symbol
          rspamd_config:set_metric_symbol(rule)
        end
      end
    end, options['rules'])
  end
end

configure_whitelist_module()