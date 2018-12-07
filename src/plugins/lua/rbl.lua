--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2013-2015, Andrew Lewis <nerf@judo.za.org>

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

local hash = require 'rspamd_cryptobox_hash'
local rspamd_logger = require 'rspamd_logger'
local rspamd_util = require 'rspamd_util'
local fun = require 'fun'
local lua_util = require 'lua_util'

-- This plugin implements various types of RBL checks
-- Documentation can be found here:
-- https://rspamd.com/doc/modules/rbl.html

local E = {}
local N = 'rbl'

local rbls = {}
local local_exclusions = nil

local default_monitored = '1.0.0.127'

local function validate_dns(lstr)
  if lstr:match('%.%.') then
    return false
  end
  for v in lstr:gmatch('[^%.]+') do
    if not v:match('^[%w-]+$') or v:len() > 63
      or v:match('^-') or v:match('-$') then
      return false
    end
  end
  return true
end

local hash_alg = {
  sha1 = true,
  md5 = true,
  sha256 = true,
  sha384 = true,
  sha512 = true,
}

local function make_hash(data, specific)
  local h
  if not hash_alg[specific] then
    h = hash.create(data)
  else
    h = hash.create_specific(specific, data)
  end
  return h:hex()
end

local function is_excluded_ip(rip)
  if local_exclusions and local_exclusions:get_key(rip) then
    return true
  end
  return false
end

local function ip_to_rbl(ip, rbl)
  return table.concat(ip:inversed_str_octets(), '.') .. '.' .. rbl
end

local function gen_check_rcvd_conditions(rbl, received_total)
  local min_pos = tonumber(rbl['received_min_pos'])
  local max_pos = tonumber(rbl['received_max_pos'])
  local match_flags = rbl['received_flags']
  local nmatch_flags = rbl['received_nflags']
  local function basic_received_check(rh)
    if not (rh['real_ip'] and rh['real_ip']:is_valid()) then return false end
    if ((rh['real_ip']:get_version() == 6 and rbl['ipv6']) or
      (rh['real_ip']:get_version() == 4 and rbl['ipv4'])) and
      ((rbl['exclude_private_ips'] and not rh['real_ip']:is_local()) or
      not rbl['exclude_private_ips']) and ((rbl['exclude_local_ips'] and
      not is_excluded_ip(rh['real_ip'])) or not rbl['exclude_local_ips']) then
        return true
    else
      return false
    end
  end
  if not (max_pos or min_pos or match_flags or nmatch_flags) then
    return basic_received_check
  end
  return function(rh, pos)
    if not basic_received_check() then return false end
    local got_flags = rh['flags'] or E
    if min_pos then
      if min_pos < 0 then
        if min_pos == -1 then
          if (pos ~= received_total) then
            return false
          end
        else
          if pos <= (received_total - (min_pos*-1)) then
            return false
          end
        end
      elseif pos < min_pos then
        return false
      end
    end
    if max_pos then
      if max_pos < -1 then
        if (received_total - (max_pos*-1)) >= pos then
          return false
        end
      elseif max_pos > 0 then
        if pos > max_pos then
          return false
        end
      end
    end
    if match_flags then
      for _, flag in ipairs(match_flags) do
        if not got_flags[flag] then
          return false
        end
      end
    end
    if nmatch_flags then
      for _, flag in ipairs(nmatch_flags) do
        if got_flags[flag] then
          return false
        end
      end
    end
    return true
  end
end

local function rbl_cb (task)
  local function gen_rbl_callback(rule)
    return function (_, to_resolve, results, err)
      if err and (err ~= 'requested record is not found' and err ~= 'no records with this name') then
        rspamd_logger.errx(task, 'error looking up %s: %s', to_resolve, err)
      end
      if not results then
        lua_util.debugm(N, task, 'DNS RESPONSE: label=%1 results=%2 error=%3 rbl=%4', to_resolve, false, err, rule['rbls'][1]['symbol'])
        return
      else
        lua_util.debugm(N, task, 'DNS RESPONSE: label=%1 results=%2 error=%3 rbl=%4', to_resolve, true, err, rule['rbls'][1]['symbol'])
      end

      for _,rbl in ipairs(rule.rbls) do
        if rbl['returncodes'] == nil and rbl['symbol'] ~= nil then
          task:insert_result(rbl['symbol'], 1, to_resolve)
          return
        end
        for _,result in pairs(results) do
          local ipstr = result:to_string()
          local foundrc
          lua_util.debugm(N, task, '%s DNS result %s', to_resolve, ipstr)
          for s,i in pairs(rbl['returncodes']) do
            if type(i) == 'string' then
              if string.find(ipstr, '^' .. i .. '$') then
                foundrc = i
                task:insert_result(s, 1, to_resolve .. ' : ' .. ipstr)
                break
              end
            elseif type(i) == 'table' then
              for _,v in pairs(i) do
                if string.find(ipstr, '^' .. v .. '$') then
                  foundrc = v
                  task:insert_result(s, 1, to_resolve .. ' : ' .. ipstr)
                  break
                end
              end
            end
          end
          if not foundrc then
            if rbl['unknown'] and rbl['symbol'] then
              task:insert_result(rbl['symbol'], 1, to_resolve)
            else
              rspamd_logger.errx(task, 'RBL %1 returned unknown result: %2',
                rbl['rbl'], ipstr)
            end
          end
        end
      end
    end
  end

  local params = {} -- indexed by rbl name

  local function gen_rbl_rule(to_resolve, rbl)
    lua_util.debugm(N, task, 'DNS REQUEST: label=%1 rbl=%2', to_resolve, rbl['symbol'])
    if not params[to_resolve] then
      local nrule = {
        to_resolve = to_resolve,
        rbls = {rbl},
        forced = true,
      }
      nrule.callback = gen_rbl_callback(nrule)
      params[to_resolve] = nrule
    else
      table.insert(params[to_resolve].rbls, rbl)
    end

    return params[to_resolve]
  end

  local havegot = {
    emails = {},
    received = {},
    dkim = {},
  }

  local notgot = {}

  local alive_rbls = fun.filter(function(_, rbl)
    if rbl.monitored then
      if not rbl.monitored:alive() then
        return false
      end
    end

    return true
  end, rbls)

  -- Now exclude rbls, that are disabled by configuration
  local enabled_rbls = fun.filter(function(_, rbl)
    if rbl['exclude_users'] then
      if not havegot['user'] and not notgot['user'] then
        havegot['user'] = task:get_user()
        if havegot['user'] == nil then
          notgot['user'] = true
        end
      end
      if havegot['user'] ~= nil then
        return false
      end
    end

    if (rbl['exclude_local'] or rbl['exclude_private_ips']) and not notgot['from'] then
      if not havegot['from'] then
        havegot['from'] = task:get_from_ip()
        if not havegot['from']:is_valid() then
          notgot['from'] = true
        end
      end
      if havegot['from'] and not notgot['from'] and ((rbl['exclude_local'] and
        is_excluded_ip(havegot['from'])) or (rbl['exclude_private_ips'] and
        havegot['from']:is_local())) then
        return false
      end
    end

    -- Helo checks
    if rbl['helo'] then
      if notgot['helo'] then
        return false
      end
      if not havegot['helo'] then
        if rbl['hash'] then
          havegot['helo'] = task:get_helo()
          if havegot['helo'] then
            havegot['helo'] = make_hash(havegot['helo'], rbl['hash'])
          else
            notgot['helo'] = true
            return false
          end
        else
          havegot['helo'] = task:get_helo()
          if havegot['helo'] == nil or not validate_dns(havegot['helo']) then
            havegot['helo'] = nil
            notgot['helo'] = true
            return false
          end
        end
      end
    elseif rbl['dkim'] then
      -- DKIM checks
      if notgot['dkim'] then
        return false
      end
      if not havegot['dkim'] then
        local das = task:get_symbol('DKIM_TRACE')
        if ((das or E)[1] or E).options then
          havegot['dkim'] = das[1]['options']
        else
          notgot['dkim'] = true
          return false
        end
      end
    elseif rbl['emails'] then
      -- Emails checks
      if notgot['emails'] then
        return false
      end
      if #havegot['emails'] == 0 then
        havegot['emails'] = task:get_emails()
        if havegot['emails'] == nil then
          notgot['emails'] = true
          havegot['emails'] = {}
          return false
        end
      end
    elseif rbl['from'] then
      if notgot['from'] then
        return false
      end
      if not havegot['from'] then
        havegot['from'] = task:get_from_ip()
        if not havegot['from']:is_valid() then
          notgot['from'] = true
          return false
        end
      end
    elseif rbl['received'] then
      if notgot['received'] then
        return false
      end
      if #havegot['received'] == 0 then
        havegot['received'] = task:get_received_headers()
        if next(havegot['received']) == nil then
          notgot['received'] = true
          havegot['received'] = {}
          return false
        end
      end
    elseif rbl['rdns'] then
      if notgot['rdns'] then
        return false
      end
      if not havegot['rdns'] then
        havegot['rdns'] = task:get_hostname()
        if havegot['rdns'] == nil or havegot['rdns'] == 'unknown' then
          notgot['rdns'] = true
          return false
        end
      end
    end

    return true
  end, alive_rbls)

  -- Now we iterate over enabled rbls and fill params
  -- Helo RBLs
  fun.each(function(_, rbl)
    local to_resolve = havegot['helo'] .. '.' .. rbl['rbl']
    gen_rbl_rule(to_resolve, rbl)
  end,
  fun.filter(function(_, rbl)
    if rbl['helo'] then return true end
    return false
  end, enabled_rbls))

  -- DKIM RBLs
  fun.each(function(_, rbl)
    local mime_from_domain
    if rbl['dkim_match_from'] then
      -- We check merely mime from
      mime_from_domain = ((task:get_from('mime') or E)[1] or E).domain
      if mime_from_domain then
        mime_from_domain = rspamd_util.get_tld(mime_from_domain)
      end
    end

    for _, d in ipairs(havegot['dkim']) do
      local domain,result = d:match('^([^%:]*):([%+%-%~])$')

      -- We must ignore bad signatures, omg
      if domain and result and result == '+' then

        local to_resolve = domain .. '.' .. rbl['rbl']

        if rbl['dkim_match_from'] then
          -- We check merely mime from
          local domain_tld = domain
          if not rbl['dkim_domainonly'] then
            -- Adjust
            domain_tld = rspamd_util.get_tld(domain)
          end

          if mime_from_domain and mime_from_domain == domain_tld then
            gen_rbl_rule(to_resolve, rbl)
          end
        else
          gen_rbl_rule(to_resolve, rbl)
        end
      end
    end
  end,
  fun.filter(function(_, rbl)
    if rbl['dkim'] then return true end
    return false
  end, enabled_rbls))

  -- Emails RBLs
  fun.each(function(_, rbl)
    if rbl['emails'] == 'domain_only' then
      local cleanList = {}
      for _, email in ipairs(havegot['emails']) do
        cleanList[email:get_host()] = true
      end
      for k in pairs(cleanList) do
        local to_resolve
        if rbl['hash'] then
          to_resolve = make_hash(tostring(k), rbl['hash']) .. '.' .. rbl['rbl']
        else
          to_resolve = k .. '.' .. rbl['rbl']
        end
        gen_rbl_rule(to_resolve, rbl)
      end
    else
      for _, email in ipairs(havegot['emails']) do
        local to_resolve
        if rbl['hash'] then
          to_resolve = make_hash(email:get_user() .. '@' .. email:get_host(), rbl['hash']) .. '.' .. rbl['rbl']
        else
          local upart = email:get_user()
          if validate_dns(upart) then
            to_resolve = upart .. '.' .. email:get_host() .. '.' .. rbl['rbl']
          end
        end
        if to_resolve then
          gen_rbl_rule(to_resolve, rbl)
        end
      end
    end
  end,
  fun.filter(function(_, rbl)
    if rbl['emails'] then return true end
    return false
  end, enabled_rbls))

  -- RDNS lists
  fun.each(function(_, rbl)
    local to_resolve = havegot['rdns'] .. '.' .. rbl['rbl']
    gen_rbl_rule(to_resolve, rbl)
  end,
  fun.filter(function(_, rbl)
    if rbl['rdns'] then return true end
    return false
  end, enabled_rbls))

  -- From lists
  fun.each(function(_, rbl)
    if (havegot['from']:get_version() == 6 and rbl['ipv6']) or
      (havegot['from']:get_version() == 4 and rbl['ipv4']) then
      local to_resolve = ip_to_rbl(havegot['from'], rbl['rbl'])
      gen_rbl_rule(to_resolve, rbl)
    end
  end,
  fun.filter(function(_, rbl)
    if rbl['from'] then return true end
    return false
  end, enabled_rbls))

  havegot['received'] = fun.filter(function(h)
    return not h['flags']['artificial']
  end, havegot['received']):totable()

  local received_total = #havegot['received']
  -- Received lists
  fun.each(function(_, rbl)
    local check_conditions = gen_check_rcvd_conditions(rbl, received_total)
    for pos,rh in ipairs(havegot['received']) do
      if check_conditions(rh, pos) then
        local to_resolve = ip_to_rbl(rh['real_ip'], rbl['rbl'])
        local rule = gen_rbl_rule(to_resolve, rbl)
        -- Disable forced for received resolving, as we have no control on
        -- those headers count
        rule.forced = false
      end
    end
  end,
  fun.filter(function(_, rbl)
    if rbl['received'] then return true end
    return false
  end, enabled_rbls))

  local r = task:get_resolver()
  for _,p in pairs(params) do
    r:resolve_a({
      task = task,
      name = p.to_resolve,
      callback = p.callback,
      forced = p.forced
    })
  end
end

-- Configuration
local opts = rspamd_config:get_all_opt(N)
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  lua_util.disable_module(N, "config")
  return
end

-- Plugin defaults should not be changed - override these in config
-- New defaults should not alter behaviour
local default_defaults = {
  ['default_enabled'] = true,
  ['default_ipv4'] = true,
  ['default_ipv6'] = true,
  ['default_received'] = false,
  ['default_from'] = false,
  ['default_unknown'] = false,
  ['default_rdns'] = false,
  ['default_helo'] = false,
  ['default_dkim'] = false,
  ['default_dkim_domainonly'] = true,
  ['default_emails'] = false,
  ['default_exclude_private_ips'] = true,
  ['default_exclude_users'] = false,
  ['default_exclude_local'] = true,
  ['default_is_whitelist'] = false,
  ['default_ignore_whitelist'] = false,
}
for default, default_v in pairs(default_defaults) do
  if opts[default] == nil then
    opts[default] = default_v
  end
end

if(opts['local_exclude_ip_map'] ~= nil) then
  local_exclusions = rspamd_map_add(N, 'local_exclude_ip_map', 'radix',
    'RBL exclusions map')
end

local white_symbols = {}
local black_symbols = {}
local need_dkim = false

local id = rspamd_config:register_symbol({
  type = 'callback',
  callback = rbl_cb,
  name = 'RBL_CALLBACK',
  flags = 'empty,nice'
})

local is_monitored = {}
local rbls_count = 0
for key,rbl in pairs(opts['rbls']) do
  (function()
    if type(rbl) ~= 'table' or rbl['disabled'] then
      rspamd_logger.infox(rspamd_config, 'disable rbl "%s"', key)
      return
    end

    for default,_ in pairs(default_defaults) do
      local rbl_opt = default:gsub('^default_', '')
      if rbl[rbl_opt] == nil then
        rbl[rbl_opt] = opts[default]
      end
    end

    if not rbl['enabled'] then return end

    if type(rbl['returncodes']) == 'table' then
      for s,_ in pairs(rbl['returncodes']) do
        if type(rspamd_config.get_api_version) ~= 'nil' then
          rspamd_config:register_symbol({
            name = s,
            parent = id,
            type = 'virtual'
          })

          if rbl['dkim'] then
            need_dkim = true
          end
          if(rbl['is_whitelist']) then
            if type(rbl['whitelist_exception']) == 'string' then
              if (rbl['whitelist_exception'] ~= s) then
                table.insert(white_symbols, s)
              end
            elseif type(rbl['whitelist_exception']) == 'table' then
              local foundException = false
              for _, e in pairs(rbl['whitelist_exception']) do
                if e == s then
                  foundException = true
                  break
                end
              end
              if not foundException then
                table.insert(white_symbols, s)
              end
            else
                table.insert(white_symbols, s)
            end
          else
            if rbl['ignore_whitelists'] == false then
              table.insert(black_symbols, s)
            end
          end
        end
      end
    end
    if not rbl['symbol'] and
      ((rbl['returncodes'] and rbl['unknown']) or
      (not rbl['returncodes'])) then
        rbl['symbol'] = key
    end
    if rbl['symbol'] then
      rspamd_config:register_symbol({
        name = rbl['symbol'],
        parent = id,
        type = 'virtual'
      })
      rbls_count = rbls_count + 1

      if rbl['dkim'] then
        need_dkim = true
      end
      if (rbl['is_whitelist']) then
            if type(rbl['whitelist_exception']) == 'string' then
              if (rbl['whitelist_exception'] ~= rbl['symbol']) then
                table.insert(white_symbols, rbl['symbol'])
              end
            elseif type(rbl['whitelist_exception']) == 'table' then
              local foundException = false
              for _, e in pairs(rbl['whitelist_exception']) do
                if e == rbl['symbol'] then
                  foundException = true
                  break
                end
              end
              if not foundException then
                table.insert(white_symbols, rbl['symbol'])
              end
            else
              table.insert(white_symbols, rbl['symbol'])
            end
      else
        if rbl['ignore_whitelists'] == false then
          table.insert(black_symbols, rbl['symbol'])
        end
      end
    end
    if rbl['rbl'] then
      if not rbl['disable_monitoring'] and not rbl['is_whitelist'] and
          not is_monitored[rbl['rbl']] then
        is_monitored[rbl['rbl']] = true
        rbl.monitored = rspamd_config:register_monitored(rbl['rbl'], 'dns',
          {
            rcode = 'nxdomain',
            prefix = rbl['monitored_address'] or default_monitored
          })
      end

      rbls[key] = rbl
    end
  end)()
end

if rbls_count == 0 then
  lua_util.disable_module(N, "config")
end

for _, w in pairs(white_symbols) do
  for _, b in pairs(black_symbols) do
    local csymbol = 'RBL_COMPOSITE_' .. w .. '_' .. b
    rspamd_config:set_metric_symbol(csymbol, 0, 'Autogenerated composite')
    rspamd_config:add_composite(csymbol, w .. ' & ' .. b)
  end
end
if need_dkim then
  rspamd_config:register_dependency('RBL_CALLBACK', 'DKIM_CHECK')
end
