--[[
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

--[[[
-- @module lua_util
-- This module contains utility functions for working with Lua and/or Rspamd
--]]

local exports = {}
local lpeg = require 'lpeg'

local split_grammar = {}
local function rspamd_str_split(s, sep)
  local gr = split_grammar[sep]

  if not gr then
    local _sep = lpeg.P(sep)
    local elem = lpeg.C((1 - _sep)^0)
    local p = lpeg.Ct(elem * (_sep * elem)^0)
    gr = p
    split_grammar[sep] = gr
  end

  return gr:match(s)
end

--[[[
-- @function lua_util.str_split(text, deliminator)
-- Splits text into a numeric table by deliminator
-- @param {string} text deliminated text
-- @param {string} deliminator the deliminator
-- @return {table} numeric table containing string parts
--]]

exports.rspamd_str_split = rspamd_str_split
exports.str_split = rspamd_str_split

local space = lpeg.S' \t\n\v\f\r'
local nospace = 1 - space
local ptrim = space^0 * lpeg.C((space^0 * nospace^1)^0)
local match = lpeg.match
exports.rspamd_str_trim = function(s)
  return match(ptrim, s)
end

--[[[
-- @function lua_util.round(number, decimalPlaces)
-- Round number to fixed number of decimal points
-- @param {number} number number to round
-- @param {number} decimalPlaces number of decimal points
-- @return {number} rounded number
--]]

-- Robert Jay Gould http://lua-users.org/wiki/SimpleRound
exports.round = function(num, numDecimalPlaces)
  local mult = 10^(numDecimalPlaces or 0)
  return math.floor(num * mult) / mult
end

--[[[
-- @function lua_util.template(text, replacements)
-- Replaces values in a text template
-- Variable names can contain letters, numbers and underscores, are prefixed with `$` and may or not use curly braces.
-- @param {string} text text containing variables
-- @param {table} replacements key/value pairs for replacements
-- @return {string} string containing replaced values
-- @example
-- local goop = lua_util.template("HELLO $FOO ${BAR}!", {['FOO'] = 'LUA', ['BAR'] = 'WORLD'})
-- -- goop contains "HELLO LUA WORLD!"
--]]

exports.template = function(tmpl, keys)
  local var_lit = lpeg.P { lpeg.R("az") + lpeg.R("AZ") + lpeg.R("09") + "_" }
  local var = lpeg.P { (lpeg.P("$") / "") * ((var_lit^1) / keys) }
  local var_braced = lpeg.P { (lpeg.P("${") / "") * ((var_lit^1) / keys) * (lpeg.P("}") / "") }

  local template_grammar = lpeg.Cs((var + var_braced + 1)^0)

  return lpeg.match(template_grammar, tmpl)
end

exports.remove_email_aliases = function(email_addr)
  local function check_gmail_user(addr)
    -- Remove all points
    local no_dots_user = string.gsub(addr.user, '%.', '')
    local cap, pluses = string.match(no_dots_user, '^([^%+][^%+]*)(%+.*)$')
    if cap then
      return cap, rspamd_str_split(pluses, '+'), nil
    elseif no_dots_user ~= addr.user then
      return no_dots_user,{},nil
    end

    return nil
  end

  local function check_address(addr)
    if addr.user then
      local cap, pluses = string.match(addr.user, '^([^%+][^%+]*)(%+.*)$')
      if cap then
        return cap, rspamd_str_split(pluses, '+'), nil
      end
    end

    return nil
  end

  local function set_addr(addr, new_user, new_domain)
    if new_user then
      addr.user = new_user
    end
    if new_domain then
      addr.domain = new_domain
    end

    if addr.domain then
      addr.addr = string.format('%s@%s', addr.user, addr.domain)
    else
      addr.addr = string.format('%s@', addr.user)
    end

    if addr.name and #addr.name > 0 then
      addr.raw = string.format('"%s" <%s>', addr.name, addr.addr)
    else
      addr.raw = string.format('<%s>', addr.addr)
    end
  end

  local function check_gmail(addr)
    local nu, tags, nd = check_gmail_user(addr)

    if nu then
      return nu, tags, nd
    end

    return nil
  end

  local function check_googlemail(addr)
    local nd = 'gmail.com'
    local nu, tags = check_gmail_user(addr)

    if nu then
      return nu, tags, nd
    end

    return nil, nil, nd
  end

  local specific_domains = {
    ['gmail.com'] = check_gmail,
    ['googlemail.com'] = check_googlemail,
  }

  if email_addr then
    if email_addr.domain and specific_domains[email_addr.domain] then
      local nu, tags, nd = specific_domains[email_addr.domain](email_addr)
      if nu or nd then
        set_addr(email_addr, nu, nd)

        return nu, tags
      end
    else
      local nu, tags, nd = check_address(email_addr)
      if nu or nd then
        set_addr(email_addr, nu, nd)

        return nu, tags
      end
    end

    return nil
  end
end

exports.is_rspamc_or_controller = function(task)
  local ua = task:get_request_header('User-Agent') or ''
  local pwd = task:get_request_header('Password')
  local is_rspamc = false
  if tostring(ua) == 'rspamc' or pwd then is_rspamc = true end

  return is_rspamc
end

--[[[
-- @function lua_util.unpack(table)
-- Converts numeric table to varargs
-- This is `unpack` on Lua 5.1/5.2/LuaJIT and `table.unpack` on Lua 5.3
-- @param {table} table numerically indexed table to unpack
-- @return {varargs} unpacked table elements
--]]

local unpack_function = table.unpack or unpack
exports.unpack = function(t)
  return unpack_function(t)
end

--[[[
-- @function lua_util.spairs(table)
-- Like `pairs` but keys are sorted lexicographically
-- @param {table} table table containing key/value pairs
-- @return {function} generator function returning key/value pairs
--]]

-- Sorted iteration:
-- for k,v in spairs(t) do ... end
--
-- or with custom comparison:
-- for k, v in spairs(t, function(t, a, b) return t[a] < t[b] end)
--
-- optional limit is also available (e.g. return top X elements)
local function spairs(t, order, lim)
  -- collect the keys
  local keys = {}
  for k in pairs(t) do keys[#keys+1] = k end

  -- if order function given, sort by it by passing the table and keys a, b,
  -- otherwise just sort the keys
  if order then
    table.sort(keys, function(a,b) return order(t, a, b) end)
  else
    table.sort(keys)
  end

  -- return the iterator function
  local i = 0
  return function()
    i = i + 1
    if not lim or i <= lim then
      if keys[i] then
        return keys[i], t[keys[i]]
      end
    end
  end
end

exports.spairs = spairs

--[[[
-- @function lua_util.disable_module(modname, how)
-- Disables a plugin or disables redis for a plugin.
-- @param {string} modname name of plugin to disable
-- @param {string} how 'redis' to disable redis, 'config' to disable startup
--]]

local function disable_module(modname, how)
  if rspamd_plugins_state.enabled[modname] then
    rspamd_plugins_state.enabled[modname] = nil
  end

  if how == 'redis' then
    rspamd_plugins_state.disabled_redis[modname] = {}
  elseif how == 'config' then
    rspamd_plugins_state.disabled_unconfigured[modname] = {}
  else
    rspamd_plugins_state.disabled_failed[modname] = {}
  end
end

exports.disable_module = disable_module

return exports
