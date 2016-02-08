--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
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
    domain = rspamd_util.get_tld(domain)
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
        if not task:has_symbol(options['spf_allow_symbol']) then
          found = false
          rspamd_logger.debugx(task, "domain %s has been found in whitelist %s" ..
            " but it doesn't have valid SPF record", domain, symbol)
        end
      end
      if rule['valid_dkim'] then
        local sym = task:get_symbol(options['dkim_allow_symbol'])
        if not sym then
          found = false
          rspamd_logger.debugx(task, "domain %s has been found in whitelist %s" ..
              " but it doesn't have valid DKIM", domain, symbol)
        else
          -- Check dkim signatures as they might be for different domains
          found = false
          local dkim_opts = sym[1]['options']

          if dkim_opts then
            for i,d in ipairs(dkim_opts) do
              if d == domain then
                found = true
              end
            end
          end
          if not found then
            rspamd_logger.debugx(task, "domain %s has been found in whitelist %s" ..
                " but it doesn't have matching DKIM signature", domain, symbol)
          end
        end
      end
      if rule['valid_dmarc'] then
        if not task:has_symbol(options['dmarc_allow_symbol']) then
          found = false
          rspamd_logger.debugx(task, "domain %s has been found in whitelist %s" ..
              " but it doesn't have valid DMARC", domain, symbol)
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
          rule['map'] = rspamd_config:add_kv_map(rule['domains'],
            "Whitelist map for " .. symbol)
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
