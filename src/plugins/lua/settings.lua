-- This plugin implements user dynamic settings
-- Settings documentation can be found here:
-- https://rspamd.com/doc/configuration/settings.html

local set_section = rspamd_config:get_key("settings")
local settings = {}
local settings_initialized = false

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
    if rule[1] ~= nil then
      local nip = ip:apply_mask(rule[1])
      if nip and nip == rule[0] then
        return true
      end
    elseif ip == rule[0] then
      return true
    end
    
    return false
  end
  
  local function check_specific_setting(name, rule, ip, from, rcpt)
    local res = false
    
    if rule['ip'] and ip then
      for _, i in ipairs(rule['ip']) do
        res = check_ip_setting(i, ip)
        if res then
          break
        end
      end
    end
    
    if not res and rule['from'] and from then
      for _, i in ipairs(rule['from']) do
        res = check_addr_setting(i, from)
        if res then
          break
        end
      end
    end
    
    if not res and rule['rcpt'] and rcpt then
      for _, i in ipairs(rule['rcpt']) do
        res = check_addr_setting(i, rcpt)
        if res then
          break
        end
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
  
  -- Match rules according their order
  for i,v in ipairs(settings) do
    for name, rule in pairs(v) do
      local rule = check_specific_setting(name, rule, ip, from, rcpt)
      if rule then
        task:set_settings(rule)
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
            table.insert(out, {res, 0})
          else
            rspamd_logger.err("bad IP address: " .. ip)
            return nil
          end
        else
          local res = rspamd_ip.from_string(string.sub(ip, 1, slash - 1))
          local mask = tonumber(string.sub(ip, slash + 1))
          
          if res:is_valid() then
            table.insert(out, {res, mask})
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
          local re = regexp.create(string.sub(addr, 2))
          if re then
            out['regexp'] = re
            setmetatable(out, {
              __gc = function(t) t['regexp']:destroy() end 
            })
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
    
    
    local out = {}
    
    if elt['ip'] then
      local ip = process_ip(elt['ip'])
      
      if ip then
        if not out['ip'] then 
          out['ip'] = {ip} 
        else
          table.insert(out['ip'], ip)
        end
      end
    end
    if elt['from'] then
      local from = process_addr(elt['from'])
      
      if from then
       if not out['from'] then 
          out['from'] = {from} 
        else
          table.insert(out['from'], from)
        end
      end
    end
    if elt['rcpt'] then
      local rcpt = process_addr(elt['rcpt'])
      
      if rcpt then
        if not out['rcpt'] then 
          out['rcpt'] = {rcpt} 
        else
          table.insert(out['rcpt'], rcpt)
        end
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
  
  for k,v in pairs(settings) do settings[k]=nil end
  -- fill new settings by priority
  for k,v in pairs(ft) do
    local pri = get_priority(v)
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
  local ucl_parser = require "ucl.parser"
  local res,err = ucl_parser:parse_string(string)
  if not res then
    rspamd_log.warn('cannot parse settings map: ' .. err)
  else
    process_settings_table(res)
  end
end

if type(set_section) == "string" then
  -- Just a map of ucl
  if rspamd_config:add_map(set_section, process_settings_map) then
    rspamd_config:register_pre_filter(check_settings)
  end
elseif type(set_section) == "table" then
  if process_settings_table(set_section) then
    rspamd_config:register_pre_filter(check_settings)
  end
end