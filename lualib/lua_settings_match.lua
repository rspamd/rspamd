--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>
Licensed under the Apache License, Version 2.0.
]]--

-- Matching primitives shared by ordinary settings and DATA policy scopes.
local rspamd_logger = require 'rspamd_logger'
local rspamd_regexp = require 'rspamd_regexp'
local rspamd_ip = require 'rspamd_ip'
local lua_maps = require 'lua_maps'

local function check_addr_setting(expected, addr)
  local function check_specific_addr(elt)
    if expected.name then
      if lua_maps.rspamd_maybe_check_map(expected.name, elt.addr) then
        return true
      end
    end

    if expected.user then
      if lua_maps.rspamd_maybe_check_map(expected.user, elt.user) then
        return true
      end
    end

    if expected.domain and elt.domain then
      if lua_maps.rspamd_maybe_check_map(expected.domain, elt.domain) then
        return true
      end
    end

    if expected.regexp then
      if expected.regexp:match(elt.addr) then
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

local function check_string_setting(expected, str)
  if expected.regexp then
    if expected.regexp:match(str) then
      return true
    end
  elseif expected.check then
    if lua_maps.rspamd_maybe_check_map(expected.check, str) then
      return true
    end
  end

  return false
end

local function check_ip_setting(expected, ip)
  if type(expected) == "string" then
    if lua_maps.rspamd_maybe_check_map(expected, ip:to_string()) then
      return true
    end
  else
    local nip = ip:apply_mask(expected[2])
    if nip and nip:to_string() == expected[1] then
      return true
    end
  end

  return false
end

-- Process IP address: converted to a table {ip, mask}
local function process_ip_condition(cfg, ip, out)
  if type(ip) == "table" then
    for _, v in ipairs(ip) do
      process_ip_condition(cfg, v, out)
    end

    return
  end

  if type(ip) == "string" then
    if string.sub(ip, 1, 4) == "map:" then
      -- It is a map, don't apply any extra logic
      table.insert(out, ip)
      return
    end

    local mask
    local slash = string.find(ip, '/')

    if slash then
      mask = string.sub(ip, slash + 1)
      ip = string.sub(ip, 1, slash - 1)
    end

    local res = rspamd_ip.from_string(ip)

    if res:is_valid() then
      if mask then
        local mask_num = tonumber(mask)

        if mask_num then
          -- normalize IP
          res = res:apply_mask(mask_num)

          if res:is_valid() then
            table.insert(out, { res:to_string(), mask_num })
            return
          end
        end

        rspamd_logger.errx(cfg, "bad IP mask: %s/%s", ip, mask)
        return
      end

      -- Just a plain IP address
      table.insert(out, res:to_string())
      return
    end
  end

  rspamd_logger.errx(cfg, "bad IP address: " .. ip)
end

-- Process email like condition, converted to a table with fields:
-- name - full email (surprise!)
-- user - user part
-- domain - domain part
-- regexp - full email regexp (yes, it sucks)
local function process_email_condition(cfg, addr)
  local out = {}

  if type(addr) == "table" then
    for _, v in ipairs(addr) do
      table.insert(out, process_email_condition(cfg, v))
    end
  elseif type(addr) == "string" then
    if string.sub(addr, 1, 4) == "map:" then
      -- It is map, don't apply any extra logic
      out['name'] = addr
    else
      local start = string.sub(addr, 1, 1)

      if start == '/' then
        -- It is a regexp
        local re = rspamd_regexp.create(addr)

        if re then
          out['regexp'] = re
        else
          rspamd_logger.errx(cfg, "bad regexp: " .. addr)
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
    end
  else
    return nil
  end

  return out
end

-- Convert a plain string condition to a table:
-- check - string to match
-- regexp - regexp to match
local function process_string_condition(cfg, addr)
  local out = {}

  if type(addr) == "table" then
    for _, v in ipairs(addr) do
      table.insert(out, process_string_condition(cfg, v))
    end
  elseif type(addr) == "string" then
    if string.sub(addr, 1, 4) == "map:" then
      -- It is map, don't apply any extra logic
      out['check'] = addr
    else
      local start = string.sub(addr, 1, 1)

      if start == '/' then
        -- It is a regexp
        local re = rspamd_regexp.create(addr)

        if re then
          out['regexp'] = re
        else
          rspamd_logger.errx(cfg, "bad regexp: " .. addr)
          return nil
        end

      else
        out['check'] = addr
      end
    end
  else
    return nil
  end

  return out
end

return {
  check_addr_setting = check_addr_setting,
  check_string_setting = check_string_setting,
  check_ip_setting = check_ip_setting,
  process_ip_condition = process_ip_condition,
  process_email_condition = process_email_condition,
  process_string_condition = process_string_condition,
}
