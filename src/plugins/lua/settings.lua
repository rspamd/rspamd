-- This plugin implements user dynamic settings
-- Settings documentation can be found here:
-- https://rspamd.com/doc/configuration/settings.html

local set_section = rspamd_config:get_key("settings")
local settings = {}

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
  local process_setting_elt = function(elt)
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
          local res = rspamd_ip.from_string(string.sub(ip, 1, slash))
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
    
    local process_addr = function(addr)
      local out = {
        name = {},
        user = {},
        domain = {},
        regexp = {}
      }
      if type(addr) == "table" then
        for i,v in ipairs(addr) do 
          table.insert(out, process_addr(v))
        end
      elseif type(addr) == "string" then
        if addr[1] == '/' then
          -- It is a regexp
          local re = rspamd_regexp.create(string.sub(addr, 2))
          if re then
            out['regexp'] = re
            setmetatable(out, {
              __gc = function(t) t['regexp']:destroy() end 
            })
          else
            rspamd_logger.err("bad regexp: " .. addr)
          end
          
        elseif addr[1] == '@' then
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
    
    
    local out = {
      ip = {},
      rcpt = {},
      from = {}
    }
    if elt['ip'] then
      local ip = process_ip(elt['ip'])
      
      if ip then
        table.insert(out['ip'], ip)
      end
    end
    if elt['from'] then
      local from = process_addr(elt['from'])
      
      if from then
        table.insert(out['from'], from)
      end
    end
    if elt['rcpt'] then
      local rcpt = process_addr(elt['rcpt'])
      
      if rcpt then
        table.insert(out['rcpt'], rcpt)
      end
    end
    
    return out
  end
  
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
    local s = process_setting_elt(v)
    if s then
      settings[pri][k] = s
    end
  end
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