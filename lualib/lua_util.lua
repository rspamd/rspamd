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
-- Disables a plugin
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
  elseif how == 'experimental' then
    rspamd_plugins_state.disabled_experimental[modname] = {}
  else
    rspamd_plugins_state.disabled_failed[modname] = {}
  end
end

exports.disable_module = disable_module

--[[[
-- @function lua_util.disable_module(modname)
-- Checks experimental plugins state and disable if needed
-- @param {string} modname name of plugin to check
-- @return {boolean} true if plugin should be enabled, false otherwise
--]]
local function check_experimental(modname)
  if rspamd_config:experimental_enabled() then
    return true
  else
    disable_module(modname, 'experimental')
  end

  return false
end

exports.check_experimental = check_experimental

--[[[
-- @function lua_util.list_to_hash(list)
-- Converts numerically-indexed table to table indexed by values
-- @param {table} list numerically-indexed table or string, which is treated as a one-element list
-- @return {table} table indexed by values
-- @example
-- local h = lua_util.list_to_hash({"a", "b"})
-- -- h contains {a = true, b = true}
--]]
local function list_to_hash(list)
  if type(list) == 'table' then
    if list[1] then
      local h = {}
      for _, e in ipairs(list) do
        h[e] = true
      end
      return h
    else
      return list
    end
  elseif type(list) == 'string' then
    local h = {}
    h[list] = true
    return h
  end
end

exports.list_to_hash = list_to_hash

--[[[
-- @function lua_util.parse_time_interval(str)
-- Parses human readable time interval
-- Accepts 's' for seconds, 'm' for minutes, 'h' for hours, 'd' for days,
-- 'w' for weeks, 'y' for years
-- @param {string} str input string
-- @return {number|nil} parsed interval as seconds (might be fractional)
--]]
local function parse_time_interval(str)
  local function parse_time_suffix(s)
    if s == 's' then
      return 1
    elseif s == 'm' then
      return 60
    elseif s == 'h' then
      return 3600
    elseif s == 'd' then
      return 86400
    elseif s == 'w' then
      return 86400 * 7
    elseif s == 'y' then
      return 365 * 86400;
    end
  end

  local digit = lpeg.R("09")
  local parser = {}
  parser.integer =
  (lpeg.S("+-") ^ -1) *
      (digit   ^  1)
  parser.fractional =
  (lpeg.P(".")   ) *
      (digit ^ 1)
  parser.number =
  (parser.integer *
      (parser.fractional ^ -1)) +
      (lpeg.S("+-") * parser.fractional)
  parser.time = lpeg.Cf(lpeg.Cc(1) *
      (parser.number / tonumber) *
      ((lpeg.S("smhdwy") / parse_time_suffix) ^ -1),
    function (acc, val) return acc * val end)

  local t = lpeg.match(parser.time, str)

  return t
end

exports.parse_time_interval = parse_time_interval

--[[[
-- @function lua_util.table_cmp(t1, t2)
-- Compare two tables deeply
--]]
local function table_cmp(table1, table2)
  local avoid_loops = {}
  local function recurse(t1, t2)
    if type(t1) ~= type(t2) then return false end
    if type(t1) ~= "table" then return t1 == t2 end

    if avoid_loops[t1] then return avoid_loops[t1] == t2 end
    avoid_loops[t1] = t2
    -- Copy keys from t2
    local t2keys = {}
    local t2tablekeys = {}
    for k, _ in pairs(t2) do
      if type(k) == "table" then table.insert(t2tablekeys, k) end
      t2keys[k] = true
    end
    -- Let's iterate keys from t1
    for k1, v1 in pairs(t1) do
      local v2 = t2[k1]
      if type(k1) == "table" then
        -- if key is a table, we need to find an equivalent one.
        local ok = false
        for i, tk in ipairs(t2tablekeys) do
          if table_cmp(k1, tk) and recurse(v1, t2[tk]) then
            table.remove(t2tablekeys, i)
            t2keys[tk] = nil
            ok = true
            break
          end
        end
        if not ok then return false end
      else
        -- t1 has a key which t2 doesn't have, fail.
        if v2 == nil then return false end
        t2keys[k1] = nil
        if not recurse(v1, v2) then return false end
      end
    end
    -- if t2 has a key which t1 doesn't have, fail.
    if next(t2keys) then return false end
    return true
  end
  return recurse(table1, table2)
end

exports.table_cmp = table_cmp

return exports
