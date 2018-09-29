--[[
Copyright (c) 2015-2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

if confighelp then
  return
end

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local fun = require "fun"
local lua_util = require "lua_util"

local N = "whitelist"

local options = {
  dmarc_allow_symbol = 'DMARC_POLICY_ALLOW',
  spf_allow_symbol = 'R_SPF_ALLOW',
  dkim_allow_symbol = 'R_DKIM_ALLOW',

  rules = {}
}

local E = {}

local function whitelist_cb(symbol, rule, task)

  local domains = {}

  local function find_domain(dom)
    local mult
    local how = 'wl'
    if rule.blacklist then how = 'bl' end

    local function parse_val(val)
      if val then
        if val == '' then
          return how,1.0
        elseif val:match('^bl:') then
          return 'bl',(tonumber(val:sub(4)) or 1.0)
        elseif val:match('^wl:') then
          return 'wl',(tonumber(val:sub(4)) or 1.0)
        elseif val:match('^both:') then
          return 'both',(tonumber(val:sub(6)) or 1.0)
        else
          return how,(tonumber(val) or 1.0)
        end
      end

      return how,1.0
    end

    if rule['map'] then
      local val = rule['map']:get_key(dom)
      if val then
        how,mult = parse_val(val)
        table.insert(domains, dom)
        return true,mult,how
      end
    elseif rule['maps'] then
      for _,v in pairs(rule['maps']) do
        local map = v.map
        if map then
          local val = map:get_key(dom)
          if val then
            how,mult = parse_val(val)
            table.insert(domains, dom)
            return true,mult,how
          end
        end
      end
    else
      mult = rule['domains'][dom]
      if mult then
        table.insert(domains, dom)
        return true, mult,how
      end
    end

    return false,0.0,how
  end

  local found = false
  local mult
  local how = 'wl' -- whitelist only
  local spf_violated = false
  local dkim_violated = false
  local dmarc_violated = false

  if rule['valid_spf'] then
    if not task:has_symbol(options['spf_allow_symbol']) then
      -- Not whitelisted
      if not rule['blacklist'] and not rule['strict'] then
        return
      end

      spf_violated = true
    end

    -- Now we can check from domain or helo
    local from = task:get_from(1)

    if ((from or E)[1] or E).domain then
      local tld = rspamd_util.get_tld(from[1]['domain'])

      if tld then
        found, mult, how = find_domain(tld)
      end
    else
      local helo = task:get_helo()

      if helo then
        local tld = rspamd_util.get_tld(helo)

        if tld then
          found, mult, how = find_domain(tld)
        end
      end
    end
  end

  if rule['valid_dkim'] then
    local sym = task:get_symbol(options['dkim_allow_symbol'])
    if not sym then
      if not rule['blacklist'] and not rule['strict'] then
        return
      end

      dkim_violated = true
    else
      found = false
      local dkim_opts = sym[1]['options']
      if dkim_opts then
        fun.each(function(val)
          if not found then
            local tld = rspamd_util.get_tld(val)

            if tld then
              found, mult, how = find_domain(tld)
              if not found then
                found, mult, how = find_domain(val)
              end
            end
          end
        end, dkim_opts)
      end
    end
  end

  if rule['valid_dmarc'] then
    if not task:has_symbol(options['dmarc_allow_symbol']) then
      if not rule['blacklist'] and not rule['strict'] then
        return
      end

      dmarc_violated = true
    end

    local from = task:get_from(2)

    if ((from or E)[1] or E).domain then
      local tld = rspamd_util.get_tld(from[1]['domain'])

      if tld then
        found, mult, how = find_domain(tld)
        if not found then
          found, mult, how = find_domain(from[1]['domain'])
        end
      end
    end
  end

  if found then
    local function add_symbol(violated)
      local sym = symbol

      if violated then
        if rule.inverse_symbol then
          sym = rule.inverse_symbol
        else
          -- Inverse multiplier
          if not rule.blacklist then
            mult = -mult
          end
        end

        if rule.strict or how == 'bl' or how == 'both' then
          -- Insert violation rule
          task:insert_result(sym, mult, domains)
        end
      else
        if how == 'wl' or how == 'both' then
          task:insert_result(sym, mult, domains)
        end
      end
    end

    add_symbol(dmarc_violated or dkim_violated or spf_violated)
  end

end

local function gen_whitelist_cb(symbol, rule)
  return function(task)
    whitelist_cb(symbol, rule, task)
  end
end

local configure_whitelist_module = function()
  local opts =  rspamd_config:get_all_opt('whitelist')
  if opts then
    for k,v in pairs(opts) do
      options[k] = v
    end
  else
    rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
    return
  end

  if options['rules'] then
    fun.each(function(symbol, rule)
      if rule['domains'] then
        if type(rule['domains']) == 'string' then
          rule['map'] = rspamd_config:add_map{
            url = rule['domains'],
            description = "Whitelist map for " .. symbol,
            type = 'map'
          }
        elseif type(rule['domains']) == 'table' then
          -- Transform ['domain1', 'domain2' ...] to indexes:
          -- {'domain1' = 1, 'domain2' = 1 ...]
          local is_domains_list = fun.all(function(v)
            if type(v) == 'table' then
              return true
            elseif type(v) == 'string' and not (string.match(v, '^https?://') or
              string.match(v, '^ftp://') or string.match(v, '^[./]')) then
              return true
            end

            return false
          end, rule.domains)

          if is_domains_list then
            rule['domains'] = fun.tomap(fun.map(function(d)
              if type(d) == 'table' then
                return d[1],d[2]
              end

              return d,1.0
            end, rule['domains']))
          else
            rule['map'] = rspamd_config:add_map{
              url = rule['domains'],
              description = "Whitelist map for " .. symbol,
              type = 'map'
            }
          end
        else
          rspamd_logger.errx(rspamd_config, 'whitelist %s has bad "domains" value',
            symbol)
          return
        end

        local flags = 'nice,empty'
        if rule['blacklist'] then
          flags = 'empty'
        end

        local id = rspamd_config:register_symbol({
          name = symbol,
          flags = flags,
          callback = gen_whitelist_cb(symbol, rule)
        })

        if rule.inverse_symbol then
          rspamd_config:register_symbol({
            name = rule.inverse_symbol,
            type = 'virtual',
            parent = id
          })
        end

        local spf_dep = false
        local dkim_dep = false
        if rule['valid_spf'] then
          rspamd_config:register_dependency(symbol, options['spf_allow_symbol'])
          spf_dep = true
        end
        if rule['valid_dkim'] then
          rspamd_config:register_dependency(symbol, options['dkim_allow_symbol'])
          dkim_dep = true
        end
        if rule['valid_dmarc'] then
          if not spf_dep then
            rspamd_config:register_dependency(symbol, options['spf_allow_symbol'])
          end
          if not dkim_dep then
            rspamd_config:register_dependency(symbol, options['dkim_allow_symbol'])
          end
          rspamd_config:register_dependency(symbol, 'DMARC_CALLBACK')
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
  else
    lua_util.disable_module(N, "config")
  end
end

configure_whitelist_module()
