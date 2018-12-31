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
local rspamd_util = require "rspamd_util"
local fun = require "fun"

local split_grammar = {}
local spaces_split_grammar
local space = lpeg.S' \t\n\v\f\r'
local nospace = 1 - space
local ptrim = space^0 * lpeg.C((space^0 * nospace^1)^0)
local match = lpeg.match

local function rspamd_str_split(s, sep)
  local gr
  if not sep then
    if not spaces_split_grammar then
      local _sep = space
      local elem = lpeg.C((1 - _sep)^0)
      local p = lpeg.Ct(elem * (_sep * elem)^0)
      spaces_split_grammar = p
    end

    gr = spaces_split_grammar
  else
    gr = split_grammar[sep]

    if not gr then
      local _sep
      if type(sep) == 'string' then
        _sep = lpeg.S(sep) -- Assume set
      else
        _sep = sep -- Assume lpeg object
      end
      local elem = lpeg.C((1 - _sep)^0)
      local p = lpeg.Ct(elem * (_sep * elem)^0)
      gr = p
      split_grammar[sep] = gr
    end
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
-- @function lua_util.dehumanize_number(str)
-- Parses human readable number
-- Accepts 'k' for thousands, 'm' for millions, 'g' for billions, 'b' suffix for 1024 multiplier,
-- e.g. `10mb` equal to `10 * 1024 * 1024`
-- @param {string} str input string
-- @return {number|nil} parsed number
--]]
local function dehumanize_number(str)
  local function parse_suffix(s)
    if s == 'k' then
      return 1000
    elseif s == 'm' then
      return 1000000
    elseif s == 'g' then
      return 1e9
    elseif s == 'kb' then
      return 1024
    elseif s == 'mb' then
      return 1024 * 1024
    elseif s == 'gb' then
      return 1024 * 1024;
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
  parser.humanized_number = lpeg.Cf(lpeg.Cc(1) *
      (parser.number / tonumber) *
      (((lpeg.S("kmg") * (lpeg.P("b") ^ -1)) / parse_suffix) ^ -1),
      function (acc, val) return acc * val end)

  local t = lpeg.match(parser.humanized_number, str)

  return t
end

exports.dehumanize_number = dehumanize_number

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

--[[[
-- @function lua_util.table_cmp(task, name, value, stop_chars)
-- Performs header folding
--]]
exports.fold_header = function(task, name, value, stop_chars)

  local how

  if task:has_flag("milter") then
    how = "lf"
  else
    how = task:get_newlines_type()
  end

  return rspamd_util.fold_header(name, value, how, stop_chars)
end

--[[[
-- @function lua_util.override_defaults(defaults, override)
-- Overrides values from defaults with override
--]]
local function override_defaults(def, override)
  -- Corner cases
  if not override or type(override) ~= 'table' then
    return def
  end
  if not def or type(def) ~= 'table' then
    return override
  end

  local res = {}

  for k,v in pairs(override) do
    if type(v) == 'table' then
      if def[k] and type(def[k]) == 'table' then
        -- Recursively override elements
        res[k] = override_defaults(def[k], v)
      else
        res[k] = v
      end
    else
      res[k] = v
    end
  end

  for k,v in pairs(def) do
    if type(res[k]) == 'nil' then
      res[k] = v
    end
  end

  return res
end

exports.override_defaults = override_defaults

--[[[
-- @function lua_util.extract_specific_urls(params)
-- params: {
- - task
- - limit <int> (default = 9999)
- - esld_limit <int> (default = 9999) n domains per eSLD (effective second level domain)
                                      works only if number of unique eSLD less than `limit`
- - need_emails <bool> (default = false)
- - filter <callback> (default = nil)
- - prefix <string> cache prefix (default = nil)
-- }
-- Apply heuristic in extracting of urls from task, this function
-- tries its best to extract specific number of urls from a task based on
-- their characteristics
--]]
-- exports.extract_specific_urls = function(params_or_task, limit, need_emails, filter, prefix)
exports.extract_specific_urls = function(params_or_task, lim, need_emails, filter, prefix)
  local default_params = {
    limit = 9999,
    esld_limit = 9999,
    need_emails = false,
    filter = nil,
    prefix = nil
  }

  local params
  if type(params_or_task) == 'table' and type(lim) == 'nil' then
    params = params_or_task
  else
    -- Deprecated call
    params = {
      task = params_or_task,
      limit = lim,
      need_emails = need_emails,
      filter = filter,
      prefix = prefix
    }
  end
  for k,v in pairs(default_params) do
    if not params[k] then params[k] = v end
  end


  local cache_key

  if params.prefix then
    cache_key = params.prefix
  else
    cache_key = string.format('sp_urls_%d%s', params.limit, params.need_emails)
  end


  local cached = params.task:cache_get(cache_key)

  if cached then
    return cached
  end

  local urls = params.task:get_urls(params.need_emails)

  if not urls then return {} end

  if params.filter then urls = fun.totable(fun.filter(params.filter, urls)) end

  if #urls <= params.limit and #urls <= params.esld_limit then
    params.task:cache_set(cache_key, urls)
    return urls
  end

  -- Filter by tld:
  local tlds = {}
  local eslds = {}
  local ntlds, neslds = 0, 0

  local res = {}

  for _,u in ipairs(urls) do
    local esld = u:get_tld()

    if esld then
      if not eslds[esld] then
        eslds[esld] = {u}
        neslds = neslds + 1
      else
        if #eslds[esld] < params.esld_limit then
          table.insert(eslds[esld], u)
        end
      end

      local parts = rspamd_str_split(esld, '.')
      local tld = table.concat(fun.totable(fun.tail(parts)), '.')

      if not tlds[tld] then
        tlds[tld] = {u}
        ntlds = ntlds + 1
      else
        table.insert(tlds[tld], u)
      end

      -- Extract priority urls that are proven to be malicious
      if not u:is_html_displayed() then
        if u:is_obscured() then
          table.insert(res, u)
        else
          if u:get_user() then
            table.insert(res, u)
          elseif u:is_subject() or u:is_phished() then
            table.insert(res, u)
          end
        end
      end
    end
  end

  local limit = params.limit
  limit = limit - #res
  if limit <= 0 then limit = 1 end

  if neslds <= limit then
    -- We can get urls based on their eslds
    repeat
      local item_found = false

      for _,lurls in pairs(eslds) do
        if #lurls > 0 then
          table.insert(res, table.remove(lurls))
          limit = limit - 1
          item_found = true
        end
      end

    until limit <= 0 or not item_found

    params.task:cache_set(cache_key, urls)
    return res
  end

  if ntlds <= limit then
    while limit > 0 do
      for _,lurls in pairs(tlds) do
        if #lurls > 0 then
          table.insert(res, table.remove(lurls))
          limit = limit - 1
        end
      end
    end

    params.task:cache_set(cache_key, urls)
    return res
  end

  -- We need to sort tlds table first
  local tlds_keys = {}
  for k,_ in pairs(tlds) do table.insert(tlds_keys, k) end
  table.sort(tlds_keys, function (t1, t2)
    return #tlds[t1] < #tlds[t2]
  end)

  ntlds = #tlds_keys
  for i=1,ntlds / 2 do
    local tld1 = tlds[tlds_keys[i]]
    local tld2 = tlds[tlds_keys[ntlds - i]]
    if #tld1 > 0 then
      table.insert(res, table.remove(tld1))
      limit = limit - 1
    end
    if #tld2 > 0 then
      table.insert(res, table.remove(tld2))
      limit = limit - 1
    end

    if limit <= 0 then
      break
    end
  end

  params.task:cache_set(cache_key, urls)
  return res
end

--[[[
-- @function lua_util.deepcopy(table)
-- params: {
- - table
-- }
-- Performs deep copy of the table. Including metatables
--]]
local function deepcopy(orig)
  local orig_type = type(orig)
  local copy
  if orig_type == 'table' then
    copy = {}
    for orig_key, orig_value in next, orig, nil do
      copy[deepcopy(orig_key)] = deepcopy(orig_value)
    end
    setmetatable(copy, deepcopy(getmetatable(orig)))
  else -- number, string, boolean, etc
    copy = orig
  end
  return copy
end

exports.deepcopy = deepcopy

--[[[
-- @function lua_util.shallowcopy(tbl)
-- Performs shallow (and fast) copy of a table or another Lua type
--]]
exports.shallowcopy = function(orig)
  local orig_type = type(orig)
  local copy
  if orig_type == 'table' then
    copy = {}
    for orig_key, orig_value in pairs(orig) do
      copy[orig_key] = orig_value
    end
  else
    copy = orig
  end
  return copy
end

-- Debugging support
local unconditional_debug = false
local debug_modules = {}
local debug_aliases = {}
local log_level = 384 -- debug + forced (1 << 7 | 1 << 8)

if type(rspamd_config) == 'userdata' then
  local logger = require "rspamd_logger"
  -- Fill debug modules from the config
  local logging = rspamd_config:get_all_opt('logging')
  if logging then
    local log_level_str = logging.level
    if log_level_str then
      if log_level_str == 'debug' then
        unconditional_debug = true
      end
    end

    if not unconditional_debug then
      if logging.debug_modules then
        for _,m in ipairs(logging.debug_modules) do
          debug_modules[m] = true
          logger.infox(rspamd_config, 'enable debug for Lua module %s', m)
        end
      end

      if #debug_aliases > 0 then
        for alias,mod in pairs(debug_aliases) do
          if debug_modules[mod] then
            debug_modules[alias] = true
            logger.infox(rspamd_config, 'enable debug for Lua module %s (%s aliased)',
                alias, mod)
          end
        end
      end
    end
  end
end

--[[[
-- @function lua_util.debugm(module, [log_object], format, ...)
-- Performs fast debug log for a specific module
--]]
exports.debugm = function(mod, obj_or_fmt, fmt_or_something, ...)
  local logger = require "rspamd_logger"
  if unconditional_debug or debug_modules[mod] then
    if type(obj_or_fmt) == 'string' then
      logger.logx(log_level, mod, '', 2, obj_or_fmt, fmt_or_something, ...)
    else
      logger.logx(log_level, mod, obj_or_fmt, 2, fmt_or_something, ...)
    end
  end
end

--[[[
-- @function lua_util.add_debug_alias(mod, alias)
-- Add debugging alias so logging to `alias` will be treated as logging to `mod`
--]]
exports.add_debug_alias = function(mod, alias)
  local logger = require "rspamd_logger"
  debug_aliases[alias] = mod

  if debug_modules[mod] then
    debug_modules[alias] = true
    logger.infox(rspamd_config, 'enable debug for Lua module %s (%s aliased)',
        alias, mod)
  end
end
---[[[
-- @function lua_util.get_task_verdict(task)
-- Returns verdict for a task, must be called from idempotent filters only
-- Returns string:
-- * `spam`: if message have over reject threshold and has more than one positive rule
-- * `junk`: if a message has between score between [add_header/rewrite subject] to reject thresholds and has more than two positive rules
-- * `passthrough`: if a message has been passed through some short-circuit rule
-- * `ham`: if a message has overall score below junk level **and** more than three negative rule, or negative total score
-- * `uncertain`: all other cases
--]]
exports.get_task_verdict = function(task)
  local result = task:get_metric_result()

  if result then

    if result.passthrough then
      return 'passthrough'
    end

    local action = result.action

    if action == 'reject' and result.npositive > 1 then
      return 'spam'
    elseif action == 'no action' then
      if result.score < 0 or result.nnegative > 3 then
        return 'ham'
      end
    else
      -- All colors of junk
      if action == 'add header' or action == 'rewrite subject' then
        if result.npositive > 2 then
          return 'junk'
        end
      end
    end
  end

  return 'uncertain'
end


return exports
