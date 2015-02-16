--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2013-2015, Andrew Lewis <nerf@judo.za.org>
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

-- This plugin implements various types of RBL checks
-- Documentation can be found here:
-- https://rspamd.com/doc/modules/rbl.html

local rbls = {}
local local_exclusions = nil
local private_ips = nil

local rspamd_logger = require "rspamd_logger"
local rspamd_ip = require "rspamd_ip"

local function validate_dns(lstr, rstr)
  if (lstr:len() + rstr:len()) > 252 then
    return false
  end
  for v in lstr:gmatch("[^%.]+") do
    if not v:match("^[%w-]+$") or v:len() > 63
      or v:match("^-") or v:match("-$") then
      return false
    end
  end
  return true
end

local function is_private_ip(rip)
  if private_ips and private_ips:get_key(rip) then
    return true
  end
  return false
end

local function is_excluded_ip(rip)
  if local_exclusions and local_exclusions:get_key(rip) then
    return true
  end
  return false
end

local function ip_to_rbl(ip, rbl)
  return table.concat(ip:inversed_str_octets(), ".") .. '.' .. rbl
end

local function rbl_cb (task)
  local function rbl_dns_cb(resolver, to_resolve, results, err, key)
    if results then
      local thisrbl = nil
      for k,r in pairs(rbls) do
        if k == key then
          thisrbl = r
          break
        end
      end
      if thisrbl ~= nil then
        if thisrbl['returncodes'] == nil then
          if thisrbl['symbol'] ~= nil then
            task:insert_result(thisrbl['symbol'], 1)
          end
        else
          for _,result in pairs(results) do 
            local ipstr = result:to_string()
            local foundrc = false
            for s,i in pairs(thisrbl['returncodes']) do
              if type(i) == 'string' then
                if string.find(ipstr, "^" .. i .. "$") then
                  foundrc = true
                  task:insert_result(s, 1)
                  break
                end
              elseif type(i) == 'table' then
                for _,v in pairs(i) do
                  if string.find(ipstr, "^" .. v .. "$") then
                    foundrc = true
                    task:insert_result(s, 1)
                    break
                  end
                end
              end
            end
            if not foundrc then
              if thisrbl['unknown'] and thisrbl['symbol'] then
                task:insert_result(thisrbl['symbol'], 1)
              else
                rspamd_logger.err('RBL ' .. thisrbl['rbl'] ..
                  ' returned unknown result ' .. ipstr)
              end
            end
          end
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

      if rbl['helo'] then
	(function()
	  if notgot['helo'] then
	    return
	  end
	  if not havegot['helo'] then
	    havegot['helo'] = task:get_helo()
	    if havegot['helo'] == nil or
              not validate_dns(havegot['helo'], rbl['rbl']) then
	      notgot['helo'] = true
	      return
	    end
	  end
	  task:get_resolver():resolve_a(task:get_session(), task:get_mempool(),
	    havegot['helo'] .. '.' .. rbl['rbl'], rbl_dns_cb, k)
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
	  task:get_resolver():resolve_a(task:get_session(), task:get_mempool(),
	    havegot['rdns'] .. '.' .. rbl['rbl'], rbl_dns_cb, k)
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
          if (rbl['exclude_private_ips'] and is_private_ip(havegot['from']))
            or (is_excluded_ip(havegot['from']) and rbl['exclude_local']) then
            return
          end
	  if (havegot['from']:get_version() == 6 and rbl['ipv6']) or
	    (havegot['from']:get_version() == 4 and rbl['ipv4']) then
	    task:get_resolver():resolve_a(task:get_session(), task:get_mempool(),
	      ip_to_rbl(havegot['from'], rbl['rbl']), rbl_dns_cb, k)
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
                ((rbl['exclude_private_ips'] and not is_private_ip(rh['real_ip'])) or
                not rbl['exclude_private_ips']) and ((rbl['exclude_local_ips'] and
                not is_excluded_ip(rh['real_ip'])) or not rbl['exclude_local_ips']) then
                  task:get_resolver():resolve_a(task:get_session(), task:get_mempool(),
                    ip_to_rbl(rh['real_ip'], rbl['rbl']), rbl_dns_cb, k)
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
    rspamd_config:register_module_option('rbl', 'default_unknown', 'string')
    rspamd_config:register_module_option('rbl', 'default_exclude_users', 'string')
    rspamd_config:register_module_option('rbl', 'default_exclude_private_ips', 'string')
    rspamd_config:register_module_option('rbl', 'local_exclude_ip_map', 'string')
    rspamd_config:register_module_option('rbl', 'default_exclude_local', 'string')
    rspamd_config:register_module_option('rbl', 'private_ips', 'string')
  end
end

-- Configuration
local opts = rspamd_config:get_all_opt('rbl')
if not opts or type(opts) ~= 'table' then
  return
end
if(opts['default_ipv4'] == nil) then
  opts['default_ipv4'] = true
end
if(opts['default_ipv6'] == nil) then
  opts['default_ipv6'] = false
end
if(opts['default_received'] == nil) then
  opts['default_received'] = true
end
if(opts['default_from'] == nil) then
  opts['default_from'] = false
end
if(opts['default_unknown'] == nil) then
  opts['default_unknown'] = false
end
if(opts['default_rdns'] == nil) then
  opts['default_rdns'] = false
end
if(opts['default_helo'] == nil) then
  opts['default_helo'] = false
end
if(opts['default_exclude_users'] == nil) then
  opts['default_exclude_users'] = false
end
if(opts['default_exclude_private_ips'] == nil) then
  opts['default_exclude_private_ips'] = false
end
if(opts['default_exclude_local'] == nil) then
  opts['default_exclude_local'] = true
end
if(opts['local_exclude_ip_map'] ~= nil) then
  local_exclusions = rspamd_config:add_radix_map(opts['local_exclude_ip_map'])
end
if(opts['private_ips'] ~= nil) then
  private_ips = rspamd_config:radix_from_config('rbl', 'private_ips')
end

for key,rbl in pairs(opts['rbls']) do
  local o = {
    "ipv4", "ipv6", "from", "received", "unknown", "rdns", "helo", "exclude_users",
    "exclude_private_ips", "exclude_local"
  }
  for i=1,table.maxn(o) do
    if(rbl[o[i]] == nil) then
      rbl[o[i]] = opts['default_' .. o[i]]
    end
  end
  if type(rbl['returncodes']) == 'table' then
    for s,_ in pairs(rbl['returncodes']) do
      if type(rspamd_config.get_api_version) ~= 'nil' then
        rspamd_config:register_virtual_symbol(s, 1)
      end
    end
  end
  if not rbl['symbol'] and type(rbl['returncodes']) ~= 'nil' and not rbl['unknown'] then
    rbl['symbol'] = key
  end
  if type(rspamd_config.get_api_version) ~= 'nil' and rbl['symbol'] then
    rspamd_config:register_virtual_symbol(rbl['symbol'], 1)
  end
  rbls[key] = rbl
end
rspamd_config:register_callback_symbol_priority('RBL', 1.0, 0, rbl_cb)
