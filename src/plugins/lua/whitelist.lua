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
  check_local = false,
  check_authed = false,
  rules = {}
}

local E = {}

local function whitelist_cb(symbol, rule, task)

  local domains = {}

  local function find_domain(dom, check)
    local mult
    local how = 'wl'

    -- Can be overriden
    if rule.blacklist then how = 'bl' end

    local function parse_val(val)
      local how_override
      -- Strict is 'special'
      if rule.strict then how_override = 'both' end
      if val then
        lua_util.debugm(N, task, "found whitelist key: %s=%s", dom, val)
        if val == '' then
          return (how_override or how),1.0
        elseif val:match('^bl:') then
          return (how_override or 'bl'),(tonumber(val:sub(4)) or 1.0)
        elseif val:match('^wl:') then
          return (how_override or 'wl'),(tonumber(val:sub(4)) or 1.0)
        elseif val:match('^both:') then
          return (how_override or 'both'),(tonumber(val:sub(6)) or 1.0)
        else
          return (how_override or how),(tonumber(val) or 1.0)
        end
      end

      return (how_override or how),1.0
    end

    if rule['map'] then
      local val = rule['map']:get_key(dom)
      if val then
        how,mult = parse_val(val)

        if not domains[check] then
          domains[check] = {}
        end

        domains[check] = {
          [dom] = {how, mult}
        }

        lua_util.debugm(N, task, "final result: %s: %s->%s",
            dom, how, mult)
        return true,mult,how
      end
    elseif rule['maps'] then
      for _,v in pairs(rule['maps']) do
        local map = v.map
        if map then
          local val = map:get_key(dom)
          if val then
            how,mult = parse_val(val)

            if not domains[check] then
              domains[check] = {}
            end

            domains[check] = {
              [dom] = {how, mult}
            }

            lua_util.debugm(N, task, "final result: %s: %s->%s",
                dom, how, mult)
            return true,mult,how
          end
        end
      end
    else
      mult = rule['domains'][dom]
      if mult then
        if not domains[check] then
          domains[check] = {}
        end

        domains[check] = {
          [dom] = {how, mult}
        }

        return true, mult,how
      end
    end

    return false,0.0,how
  end

  local spf_violated = false
  local dmarc_violated = false
  local dkim_violated = false
  local ip_addr = task:get_ip()

  if rule.valid_spf then
    if not task:has_symbol(options['spf_allow_symbol']) then
      -- Not whitelisted
      spf_violated = true
    end
    -- Now we can check from domain or helo
    local from = task:get_from(1)

    if ((from or E)[1] or E).domain then
      local tld = rspamd_util.get_tld(from[1]['domain'])

      if tld then
        find_domain(tld, 'spf')
      end
    else
      local helo = task:get_helo()

      if helo then
        local tld = rspamd_util.get_tld(helo)

        if tld then
          find_domain(tld, 'spf')
        end
      end
    end
  end

  if rule.valid_dkim then
    if task:has_symbol('DKIM_TRACE') then
      local sym = task:get_symbol('DKIM_TRACE')
      local dkim_opts = sym[1]['options']
      if dkim_opts then
        fun.each(function(val)
            if val[2] == '+' then
              local tld = rspamd_util.get_tld(val[1])
              find_domain(tld, 'dkim_success')
            elseif val[2] == '-' then
              local tld = rspamd_util.get_tld(val[1])
              find_domain(tld, 'dkim_fail')
            end
          end,
            fun.map(function(s)
              return lua_util.rspamd_str_split(s, ':')
            end, dkim_opts))
      end
    end
  end

  if rule.valid_dmarc then
    if not task:has_symbol(options.dmarc_allow_symbol) then
      dmarc_violated = true
    end

    local from = task:get_from(2)

    if ((from or E)[1] or E).domain then
      local tld = rspamd_util.get_tld(from[1]['domain'])

      if tld then
        local found = find_domain(tld, 'dmarc')
        if not found then
          find_domain(from[1]['domain'], 'dmarc')
        end
      end
    end
  end


  local final_mult = 1.0
  local found_wl, found_bl = false, false
  local opts = {}

  if rule.valid_dkim then
    dkim_violated = true

    for dom,val in pairs(domains.dkim_success or E) do
      if val[1] == 'wl' or val[1] == 'both' then
        -- We have valid and whitelisted signature
        table.insert(opts, dom .. ':d:+')
        found_wl = true
        dkim_violated = false

        if not found_bl then
          final_mult = val[2]
        end
      end
    end

    -- Blacklist counterpart
    for dom,val in pairs(domains.dkim_fail or E) do
      if val[1] == 'bl' or val[1] == 'both' then
        -- We have valid and whitelisted signature
        table.insert(opts, dom .. ':d:-')
        found_bl = true
        final_mult = val[2]
      else
        -- Even in the case of whitelisting we need to indicate dkim failure
        dkim_violated = true
      end
    end
  end

  local function check_domain_violation(what, dom, val, violated)
    if violated then
      if val[1] == 'both' or val[1] == 'bl' then
        found_bl = true
        final_mult = val[2]
        table.insert(opts, string.format("%s:%s:-", dom, what))
      end
    else
      if val[1] == 'both' or val[1] == 'wl' then
        found_wl = true
        table.insert(opts, string.format("%s:%s:+", dom, what))
        if not found_bl then
          final_mult = val[2]
        end
      end
    end
  end

  if rule.valid_dmarc then

    found_wl = false

    for dom,val in pairs(domains.dmarc or E) do
      check_domain_violation('D', dom, val,
          (dmarc_violated or dkim_violated))
    end
  end

  if rule.valid_spf then
    found_wl = false

    for dom,val in pairs(domains.spf or E) do
      check_domain_violation('s', dom, val,
          (spf_violated or dkim_violated))
    end
  end

  lua_util.debugm(N, task, "final mult: %s", final_mult)

  local function add_symbol(violated, mult)
    local sym = symbol

    if violated then
      if rule.inverse_symbol then
        sym = rule.inverse_symbol
      elseif not rule.blacklist then
        mult = -mult
      end

      if rule.inverse_multiplier then
        mult = mult * rule.inverse_multiplier
      end

      task:insert_result(sym, mult, opts)
    else
      task:insert_result(sym, mult, opts)
    end
  end

  if found_bl then
    if not ((not options.check_authed and task:get_user()) or
        (not options.check_local and ip_addr and ip_addr:is_local())) then
      add_symbol(true, final_mult)
    else
      if rule.valid_spf or rule.valid_dmarc then
        rspamd_logger.infox(task, "skip DMARC/SPF blacklists for local networks and/or authorized users")
      else
        add_symbol(true, final_mult)
      end
    end
  elseif found_wl then
    add_symbol(false, final_mult)
  end

end

local function gen_whitelist_cb(symbol, rule)
  return function(task)
    whitelist_cb(symbol, rule, task)
  end
end

local configure_whitelist_module = function()
  local opts = rspamd_config:get_all_opt('whitelist')
  if opts then
    for k,v in pairs(opts) do
      options[k] = v
    end

    local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
        false, false)
    options.check_local = auth_and_local_conf[1]
    options.check_authed = auth_and_local_conf[2]
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
          callback = gen_whitelist_cb(symbol, rule),
          score = rule.score or 0,
        })

        if rule.inverse_symbol then
          rspamd_config:register_symbol({
            name = rule.inverse_symbol,
            type = 'virtual',
            parent = id,
            score = rule.score and -(rule.score) or 0,
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

          if rule.inverse_symbol then
            local inv_rule = lua_util.shallowcopy(rule)
            inv_rule.name = rule.inverse_symbol
            inv_rule.score = -rule.score
            rspamd_config:set_metric_symbol(inv_rule)
          end
        end
      end
    end, options['rules'])
  else
    lua_util.disable_module(N, "config")
  end
end

configure_whitelist_module()
