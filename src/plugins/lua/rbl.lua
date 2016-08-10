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

-- This plugin implements various types of RBL checks
-- Documentation can be found here:
-- https://rspamd.com/doc/modules/rbl.html

local rbls = {}
local local_exclusions = nil

local rspamd_logger = require 'rspamd_logger'
local rspamd_ip = require 'rspamd_ip'
local rspamd_util = require 'rspamd_util'

local symbols = {
  dkim_allow_symbol = 'R_DKIM_ALLOW',
}

local dkim_config = rspamd_config:get_all_opt("dkim")
if dkim_config['symbol_allow'] then
  symbols['dkim_allow_symbol'] = dkim_config['symbol_allow']
end

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

local function is_excluded_ip(rip)
  if local_exclusions and local_exclusions:get_key(rip) then
    return true
  end
  return false
end

local function ip_to_rbl(ip, rbl)
  return table.concat(ip:inversed_str_octets(), '.') .. '.' .. rbl
end

local function rbl_cb (task)
  local function rbl_dns_cb(resolver, to_resolve, results, err, key)
    if not results then return end
    if not rbls[key] then return end
    if rbls[key]['returncodes'] == nil and rbls[key]['symbol'] ~= nil then
      task:insert_result(rbls[key]['symbol'], 1)
      return
    end
    for _,result in pairs(results) do
      local ipstr = result:to_string()
      local foundrc = false
      for s,i in pairs(rbls[key]['returncodes']) do
        if type(i) == 'string' then
          if string.find(ipstr, '^' .. i .. '$') then
            foundrc = true
            task:insert_result(s, 1)
            break
          end
        elseif type(i) == 'table' then
          for _,v in pairs(i) do
            if string.find(ipstr, '^' .. v .. '$') then
              foundrc = true
              task:insert_result(s, 1)
              break
            end
          end
        end
      end
      if not foundrc then
        if rbls[key]['unknown'] and rbls[key]['symbol'] then
          task:insert_result(rbls[key]['symbol'], 1)
        else
          rspamd_logger.errx(task, 'RBL %1 returned unknown result: %2',
            rbls[key]['rbl'], ipstr)
        end
      end
    end
    task:inc_dns_req()
  end

  local havegot = {}
  local notgot = {}

  for k,rbl in pairs(rbls) do

    (function()
      if rbl['exclude_users'] then
        if not havegot['user'] and not notgot['user'] then
	  havegot['user'] = task:get_user()
	  if havegot['user'] == nil then
	    notgot['user'] = true
	  end
        end
        if havegot['user'] ~= nil then
	  return
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
          return
        end
      end

      if rbl['helo'] then
	(function()
	  if notgot['helo'] then
	    return
	  end
	  if not havegot['helo'] then
	    havegot['helo'] = task:get_helo()
	    if havegot['helo'] == nil or
              not validate_dns(havegot['helo']) then
	      notgot['helo'] = true
	      return
	    end
	  end
	  task:get_resolver():resolve_a({task = task,
	    name = havegot['helo'] .. '.' .. rbl['rbl'],
	    callback = rbl_dns_cb,
	    option = k,
	    forced = true})
	end)()
      end

      if rbl['dkim'] then
        (function()
          if notgot['dkim'] then
            return
          end
          if not havegot['dkim'] then
            local das = task:get_symbol(symbols['dkim_allow_symbol'])
            if das and das[1] and das[1]['options'] then
              havegot['dkim'] = das[1]['options']
            else
              notgot['dkim'] = true
              return
            end
          end
          for _, d in ipairs(havegot['dkim']) do
            if rbl['dkim_domainonly'] then
              d = rspamd_util.get_tld(d)
            end

            task:get_resolver():resolve_a({task = task,
              name = d .. '.' .. rbl['rbl'],
              callback = rbl_dns_cb,
              option = k,
              forced = true})
          end
        end)()
      end

      if rbl['emails'] then
        (function()
          if notgot['emails'] then
            return
          end
          if not havegot['emails'] then
            havegot['emails'] = task:get_emails()
            if havegot['emails'] == nil then
              notgot['emails'] = true
              return
            end
            local cleanList = {}
            for _, e in pairs(havegot['emails']) do
              local localpart = e:get_user()
              local domainpart = e:get_host()
              if rbl['emails'] == 'domain_only' then
                if not cleanList[domainpart] and validate_dns(domainpart) then
                  cleanList[domainpart] = true
                end
              else
                if validate_dns(localpart) and validate_dns(domainpart) then
                  table.insert(cleanList, localpart .. '.' .. domainpart)
                end
              end
            end
            havegot['emails'] = cleanList
            if not next(havegot['emails']) then
              notgot['emails'] = true
              return
            end
          end
          if rbl['emails'] == 'domain_only' then
            for domain, _ in pairs(havegot['emails']) do
              task:get_resolver():resolve_a({task = task,
                name = domain .. '.' .. rbl['rbl'],
                callback = rbl_dns_cb,
                option = k,
                forced = true})
            end
          else
            for _, email in pairs(havegot['emails']) do
              task:get_resolver():resolve_a({task = task,
                name = email .. '.' .. rbl['rbl'],
                callback = rbl_dns_cb,
                option = k,
                forced = true})
            end
          end
        end)()
      end

      if rbl['rdns'] then
	(function()
	  if notgot['rdns'] then
	    return
	  end
	  if not havegot['rdns'] then
	    havegot['rdns'] = task:get_hostname()
	    if havegot['rdns'] == nil or havegot['rdns'] == 'unknown' then
	      notgot['rdns'] = true
	      return
	    end
	  end
	  task:get_resolver():resolve_a({task = task,
	    name = havegot['rdns'] .. '.' .. rbl['rbl'],
	    callback = rbl_dns_cb,
	    option = k,
	    forced = true})
	end)()
      end

      if rbl['from'] then
	(function()
	  if notgot['from'] then
	    return
	  end
	  if not havegot['from'] then
	    havegot['from'] = task:get_from_ip()
	    if not havegot['from']:is_valid() then
	      notgot['from'] = true
	      return
	    end
	  end
	  if (havegot['from']:get_version() == 6 and rbl['ipv6']) or
	    (havegot['from']:get_version() == 4 and rbl['ipv4']) then
	    task:get_resolver():resolve_a({task = task,
	      name = ip_to_rbl(havegot['from'], rbl['rbl']),
	      callback = rbl_dns_cb,
	      option = k,
	      forced = true})
	  end
	end)()
      end

      if rbl['received'] then
	(function()
	  if notgot['received'] then
	    return
	  end
	  if not havegot['received'] then
	    havegot['received'] = task:get_received_headers()
	    if next(havegot['received']) == nil then
	      notgot['received'] = true
	      return
	    end
	  end
	  for _,rh in ipairs(havegot['received']) do
	    if rh['real_ip'] and rh['real_ip']:is_valid() then
              if ((rh['real_ip']:get_version() == 6 and rbl['ipv6']) or
                (rh['real_ip']:get_version() == 4 and rbl['ipv4'])) and
                ((rbl['exclude_private_ips'] and not rh['real_ip']:is_local()) or
                not rbl['exclude_private_ips']) and ((rbl['exclude_local_ips'] and
                not is_excluded_ip(rh['real_ip'])) or not rbl['exclude_local_ips']) then
                  -- Disable forced for received resolving, as we have no control on
                  -- those headers count
                  task:get_resolver():resolve_a({task = task,
                    name = ip_to_rbl(rh['real_ip'], rbl['rbl']),
                    callback = rbl_dns_cb,
                    option = k,
                    forced = false})
              end
	    end
	  end
	end)()
      end
    end)()
  end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
  if rspamd_config:get_api_version() >= 1 then
    rspamd_config:register_module_option('rbl', 'rbls', 'map')
    rspamd_config:register_module_option('rbl', 'default_ipv4', 'string')
    rspamd_config:register_module_option('rbl', 'default_ipv6', 'string')
    rspamd_config:register_module_option('rbl', 'default_received', 'string')
    rspamd_config:register_module_option('rbl', 'default_from', 'string')
    rspamd_config:register_module_option('rbl', 'default_rdns', 'string')
    rspamd_config:register_module_option('rbl', 'default_helo', 'string')
    rspamd_config:register_module_option('rbl', 'default_dkim', 'string')
    rspamd_config:register_module_option('rbl', 'default_dkim_domainonly', 'string')
    rspamd_config:register_module_option('rbl', 'default_unknown', 'string')
    rspamd_config:register_module_option('rbl', 'default_exclude_users', 'string')
    rspamd_config:register_module_option('rbl', 'default_exclude_private_ips', 'string')
    rspamd_config:register_module_option('rbl', 'local_exclude_ip_map', 'string')
    rspamd_config:register_module_option('rbl', 'default_exclude_local', 'string')
    rspamd_config:register_module_option('rbl', 'default_emails', 'string')
    rspamd_config:register_module_option('rbl', 'default_is_whitelist', 'string')
    rspamd_config:register_module_option('rbl', 'default_ignore_whitelists', 'string')
  end
end

-- Configuration
local opts = rspamd_config:get_all_opt('rbl')
if not opts or type(opts) ~= 'table' then
  return
end

-- Plugin defaults should not be changed - override these in config
-- New defaults should not alter behaviour
default_defaults = {
  ['default_ipv4'] = {[1] = true, [2] = 'ipv4'},
  ['default_ipv6'] = {[1] = false, [2] = 'ipv6'},
  ['default_received'] = {[1] = true, [2] = 'received'},
  ['default_from'] = {[1] = false, [2] = 'from'},
  ['default_unknown'] = {[1] = false, [2] = 'unknown'},
  ['default_rdns'] = {[1] = false, [2] = 'rdns'},
  ['default_helo'] = {[1] = false, [2] = 'helo'},
  ['default_dkim'] = {[1] = false, [2] = 'dkim'},
  ['default_dkim_domainonly'] = {[1] = true, [2] = 'dkim_domainonly'},
  ['default_emails'] = {[1] = false, [2] = 'emails'},
  ['default_exclude_users'] = {[1] = false, [2] = 'exclude_users'},
  ['default_exclude_private_ips'] = {[1] = true, [2] = 'exclude_private_ips'},
  ['default_exclude_users'] = {[1] = false, [2] = 'exclude_users'},
  ['default_exclude_local'] = {[1] = true, [2] = 'exclude_local'},
  ['default_is_whitelist'] = {[1] = false, [2] = 'is_whitelist'},
  ['default_ignore_whitelist'] = {[1] = false, [2] = 'ignore_whitelists'},
}
for default, default_v in pairs(default_defaults) do
  if opts[default] == nil then
    opts[default] = default_v[1]
  end
end

if(opts['local_exclude_ip_map'] ~= nil) then
  local_exclusions = rspamd_config:add_radix_map(opts['local_exclude_ip_map'])
end

local white_symbols = {}
local black_symbols = {}
local need_dkim = false

local id = rspamd_config:register_symbol({
  type = 'callback',
  callback = rbl_cb,
  flags = 'empty,nice'
})

for key,rbl in pairs(opts['rbls']) do
  (function()
    if rbl['disabled'] then return end
    for default, default_v in pairs(default_defaults) do
      if(rbl[default_v[2]] == nil) then
        rbl[default_v[2]] = opts[default]
      end
    end
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
    if type(rspamd_config.get_api_version) ~= 'nil' and rbl['symbol'] then
      rspamd_config:register_symbol({
        name = rbl['symbol'],
        parent = id,
        type = 'virtual'
      })

      if rbl['dkim'] then
        need_dkim = true
      end
      if(rbl['is_whitelist']) then
            if type(rbl['whitelist_exception']) == 'string' then
              if (rbl['whitelist_exception'] ~= rbl['symbol']) then
                table.insert(white_symbols, rbl['symbol'])
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
    rbls[key] = rbl
  end)()
end
for _, w in pairs(white_symbols) do
  for _, b in pairs(black_symbols) do
    csymbol = 'RBL_COMPOSITE_' .. w .. '_' .. b
    rspamd_config:set_metric_symbol(csymbol, 0, 'Autogenerated composite')
    rspamd_config:add_composite(csymbol, w .. ' & ' .. b)
  end
end
if need_dkim then
  rspamd_config:register_dependency(id, symbols['dkim_allow_symbol'])
end
