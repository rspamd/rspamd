--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
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

-- This plugin implements user dynamic settings
-- Settings documentation can be found here:
-- https://rspamd.com/doc/configuration/settings.html

local set_section = rspamd_config:get_all_opt("settings")
local settings = {}
local settings_initialized = false
local max_pri = 0
local rspamd_logger = require "rspamd_logger"
local rspamd_ip = require "rspamd_ip"
local rspamd_regexp = require "rspamd_regexp"

-- Functional utilities
local function filter(func, tbl)
  local newtbl= {}
  for i,v in pairs(tbl) do
    if func(v) then
      newtbl[i]=v
    end
  end
  return newtbl
end

-- Check limit for a task
local function check_settings(task)
  local function check_addr_setting(rule, addr)
    local function check_specific_addr(elt)
      if rule['name'] then
        if elt['addr'] == rule['name'] then
          return true
        end
      end
      if rule['user'] then
        if rule['user'] == elt['user'] then
          return true
        end
      end
      if rule['domain'] then
        if rule['domain'] == elt['domain'] then
          return true
        end
      end
      if rule['regexp'] then
        if rule['regexp']:match(elt['addr']) then
          return true
        end
      end
      return false
    end

    for _, e in ipairs(addr) do
      if check_specific_addr(e) then
        return true
      end
    end

    return false
  end

  local function check_ip_setting(rule, ip)
    if rule[2] ~= 0 then
      local nip = ip:apply_mask(rule[2])
      if nip and nip == rule[1] then
        return true
      end
    elseif ip == rule[1] then
      return true
    end

    return false
  end

  local function check_specific_setting(name, rule, ip, from, rcpt, user)
    local res = false

    if rule['ip'] then
      if not ip then
        return nil
      end
      for _, i in ipairs(rule['ip']) do
        res = check_ip_setting(i, ip)
        if res then
          break
        end
      end
      if not res then
        return nil
      end
    end

    if rule['from'] then
      if not from then
        return nil
      end
      for _, i in ipairs(rule['from']) do
        res = check_addr_setting(i, from)
        if res then
          break
        end
      end
      if not res then
        return nil
      end
    end

    if rule['rcpt'] then
      if not rcpt then
        return nil
      end
      for _, i in ipairs(rule['rcpt']) do
        res = check_addr_setting(i, rcpt)
        if res then
          break
        end
      end
      if not res then
        return nil
      end
    end

    if rule['user'] then
      if not user then
        return nil
      end
      for _, i in ipairs(rule['user']) do
        res = check_addr_setting(i, user)
        if res then
          break
        end
      end
      if not res then
        return nil
      end
    end

    if res then
      if rule['whitelist'] then
        return {whitelist = true}
      else
        return rule['apply']
      end
    end

    return nil
  end

  -- Do not waste resources
  if not settings_initialized then
    return
  end

  rspamd_logger.info("check for settings")
  local ip = task:get_from_ip()
  local from = task:get_from()
  local rcpt = task:get_recipients()
  local uname = task:get_user()
  local user = {}
  if uname then
    user[1] = {}
    for localpart, domainpart in string.gmatch(uname, "(.+)@(.+)") do
      user[1]["user"] = localpart
      user[1]["domain"] = domainpart
      user[1]["addr"] = uname
      break
    end
    if not user[1]["addr"] then
      user[1]["user"] = uname
      user[1]["addr"] = uname
    end
  end
  -- Match rules according their order
  for pri = max_pri,1,-1 do
    if settings[pri] then
      for name, rule in pairs(settings[pri]) do
        local rule = check_specific_setting(name, rule, ip, from, rcpt, user)
        if rule then
          rspamd_logger.info(string.format("<%s> apply settings according to rule %s",
            task:get_message_id(), name))
          task:set_settings(rule)
        end
      end
    end
  end

end

-- Process settings based on their priority
local function process_settings_table(tbl)
  local get_priority = function(elt)
    local pri_tonum = function(p)
      if p then
        if type(p) == "number" then
          return tonumber(p)
        elseif type(p) == "string" then
          if p == "high" then
            return 3
          elseif p == "medium" then
            return 2
          end

        end

      end

      return 1
    end

    return pri_tonum(elt['priority'])
  end

  -- Check the setting element internal data
  local process_setting_elt = function(name, elt)
    -- Process IP address
    local function process_ip(ip)
      local out = {}

      if type(ip) == "table" then
        for i,v in ipairs(ip) do
          table.insert(out, process_ip(v))
        end
      elseif type(ip) == "string" then
        local slash = string.find(ip, '/')

        if not slash then
          -- Just a plain IP address
          local res = rspamd_ip.from_string(ip)

          if res:is_valid() then
            out[1] = res
            out[2] = 0
          else
            rspamd_logger.err("bad IP address: " .. ip)
            return nil
          end
        else
          local res = rspamd_ip.from_string(string.sub(ip, 1, slash - 1))
          local mask = tonumber(string.sub(ip, slash + 1))

          if res:is_valid() then
            out[1] = res
            out[2] = mask
          else
            rspamd_logger.err("bad IP address: " .. ip)
            return nil
          end
        end
      else
        return nil
      end

      return out
    end

    local function process_addr(addr)
      local out = {}

      if type(addr) == "table" then
        for i,v in ipairs(addr) do
          table.insert(out, process_addr(v))
        end
      elseif type(addr) == "string" then
        local start = string.sub(addr, 1, 1)
        if start == '/' then
          -- It is a regexp
          local re = rspamd_regexp.create(addr)
          if re then
            out['regexp'] = re
          else
            rspamd_logger.err("bad regexp: " .. addr)
            return nil
          end

        elseif start == '@' then
          -- It is a domain if form @domain
          out['domain'] = string.sub(addr, 2)
        else
          -- Check user@domain parts
          local at = string.find(addr, '@')
          if at then
            -- It is full address
            out['name'] = addr
          else
            -- It is a user
            out['user'] = addr
          end
        end
      else
        return nil
      end

      return out
    end

    local check_table = function(elt, out)
      if type(elt) == 'string' then
        return {out}
      end
      
      return out
    end

    local out = {}

    if elt['ip'] then
      local ip = process_ip(elt['ip'])

      if ip then
        out['ip'] = check_table(elt['ip'], ip)
      end
    end
    if elt['from'] then
      local from = process_addr(elt['from'])

      if from then
        out['from'] = check_table(elt['from'], from)
      end
    end
    if elt['rcpt'] then
      local rcpt = process_addr(elt['rcpt'])
      if rcpt then
        out['rcpt'] = check_table(elt['rcpt'], rcpt)
      end
    end
    if elt['user'] then
      local user = process_addr(elt['user'])
      if user then
        out['user'] = check_table(elt['user'], user)
      end
    end

    -- Now we must process actions
    if elt['apply'] then
      -- Just insert all metric results to the action key
      out['apply'] = elt['apply']
    elseif elt['whitelist'] or elt['want_spam'] then
      out['whitelist'] = true
    else
      rspamd_logger.err("no actions in settings: " .. name)
      return nil
    end

    return out
  end

  settings_initialized = false
  -- filter trash in the input
  local ft = filter(
    function(elt)
      if type(elt) == "table" then
        return true
      end
      return false
    end, tbl)
  -- clear all settings

  max_pri = 0
  for k,v in pairs(settings) do settings[k]=nil end
  -- fill new settings by priority
  for k,v in pairs(ft) do
    local pri = get_priority(v)
    if pri > max_pri then max_pri = pri end
    if not settings[pri] then
      settings[pri] = {}
    end
    local s = process_setting_elt(k, v)
    if s then
      settings[pri][k] = s
    end
  end

  settings_initialized = true
  --local dumper = require 'pl.pretty'.dump
  --dumper(settings)

  return true
end

-- Parse settings map from the ucl line
local function process_settings_map(string)
  local ucl = require "ucl"
  local parser = ucl.parser()
  local res,err = parser:parse_string(string)
  if not res then
    rspamd_logger.warn('cannot parse settings map: ' .. err)
  else
    local obj = parser:get_object()
    if obj['settings'] then
      process_settings_table(obj['settings'])
    else
      process_settings_table(obj)
    end
  end
end

if type(set_section) == "string" then
  -- Just a map of ucl
  if rspamd_config:add_map(set_section, "settings map", process_settings_map) then
    rspamd_config:register_pre_filter(check_settings)
  end
elseif type(set_section) == "table" then
  if process_settings_table(set_section) then
    rspamd_config:register_pre_filter(check_settings)
  end
end
