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
local lupa = require "lupa"

local split_grammar = {}
local spaces_split_grammar
local space = lpeg.S' \t\n\v\f\r'
local nospace = 1 - space
local ptrim = space^0 * lpeg.C((space^0 * nospace^1)^0)
local match = lpeg.match

lupa.configure('{%', '%}', '{=', '=}', '{#', '#}', {
  keep_trailing_newline = true,
  autoescape = false,
})

lupa.filters.pbkdf = function(s)
  local cr = require "rspamd_cryptobox"
  return cr.pbkdf(s)
end

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

local function rspamd_str_trim(s)
  return match(ptrim, s)
end
exports.rspamd_str_trim = rspamd_str_trim
--[[[
-- @function lua_util.str_trim(text)
-- Returns a string with no trailing and leading spaces
-- @param {string} text input text
-- @return {string} string with no trailing and leading spaces
--]]
exports.str_trim = rspamd_str_trim

--[[[
-- @function lua_util.str_startswith(text, prefix)
-- @param {string} text
-- @param {string} prefix
-- @return {boolean} true if text starts with the specified prefix, false otherwise
--]]
exports.str_startswith = function(s, prefix)
  return s:sub(1, prefix:len()) == prefix
end

--[[[
-- @function lua_util.str_endswith(text, suffix)
-- @param {string} text
-- @param {string} suffix
-- @return {boolean} true if text ends with the specified suffix, false otherwise
--]]
exports.str_endswith = function(s, suffix)
  return s:sub(-suffix:len()) == suffix
end

--[[[
-- @function lua_util.round(number, decimalPlaces)
-- Round number to fixed number of decimal points
-- @param {number} number number to round
-- @param {number} decimalPlaces number of decimal points
-- @return {number} rounded number
--]]

-- modified version from Robert Jay Gould http://lua-users.org/wiki/SimpleRound
exports.round = function(num, numDecimalPlaces)
  local mult = 10^(numDecimalPlaces or 0)
  if num >= 0 then
    return math.floor(num * mult + 0.5) / mult
  else
    return math.ceil(num * mult - 0.5) / mult
  end
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

local function enrich_template_with_globals(env)
  local newenv = exports.shallowcopy(env)
  newenv.paths = rspamd_paths
  newenv.env = rspamd_env

  return newenv
end
--[[[
-- @function lua_util.jinja_template(text, env[, skip_global_env])
-- Replaces values in a text template according to jinja2 syntax
-- @param {string} text text containing variables
-- @param {table} replacements key/value pairs for replacements
-- @param {boolean} skip_global_env don't export Rspamd superglobals
-- @return {string} string containing replaced values
-- @example
-- lua_util.jinja_template("HELLO {{FOO}} {{BAR}}!", {['FOO'] = 'LUA', ['BAR'] = 'WORLD'})
-- "HELLO LUA WORLD!"
--]]
exports.jinja_template = function(text, env, skip_global_env)
  if not skip_global_env then
    env = enrich_template_with_globals(env)
  end

  return lupa.expand(text, env)
end

--[[[
-- @function lua_util.jinja_file(filename, env[, skip_global_env])
-- Replaces values in a text template according to jinja2 syntax
-- @param {string} filename name of file to expand
-- @param {table} replacements key/value pairs for replacements
-- @param {boolean} skip_global_env don't export Rspamd superglobals
-- @return {string} string containing replaced values
-- @example
-- lua_util.jinja_template("HELLO {{FOO}} {{BAR}}!", {['FOO'] = 'LUA', ['BAR'] = 'WORLD'})
-- "HELLO LUA WORLD!"
--]]
exports.jinja_template_file = function(filename, env, skip_global_env)
  if not skip_global_env then
    env = enrich_template_with_globals(env)
  end

  return lupa.expand_file(filename, env)
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
-- @function lua_util.flatten(table)
-- Flatten underlying tables in a single table
-- @param {table} table table of tables
-- @return {table} flattened table
--]]
exports.flatten = function(t)
  local res = {}
  for _,e in fun.iter(t) do
    for _,v in fun.iter(e) do
      res[#res + 1] = v
    end
  end

  return res
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
-- @function lua_util.nkeys(table|gen, param, state)
-- Returns number of keys in a table (i.e. from both the array and hash parts combined)
-- @param {table} list numerically-indexed table or string, which is treated as a one-element list
-- @return {number} number of keys
-- @example
-- print(lua_util.nkeys({}))  -- 0
-- print(lua_util.nkeys({ "a", nil, "b" }))  -- 2
-- print(lua_util.nkeys({ dog = 3, cat = 4, bird = nil }))  -- 2
-- print(lua_util.nkeys({ "a", dog = 3, cat = 4 }))  -- 3
--
--]]
local function nkeys(gen, param, state)
  local n = 0
  if not param then
    for _,_ in pairs(gen) do n = n + 1 end
  else
    for _,_ in fun.iter(gen, param, state) do n = n + 1 end
  end
  return n
end

exports.nkeys = nkeys

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
-- @function lua_util.filter_specific_urls(urls, params)
-- params: {
- - task - if needed to save in the cache
- - limit <int> (default = 9999)
- - esld_limit <int> (default = 9999) n domains per eSLD (effective second level domain)
                                      works only if number of unique eSLD less than `limit`
- - need_emails <bool> (default = false)
- - filter <callback> (default = nil)
- - prefix <string> cache prefix (default = nil)
-- }
-- Apply heuristic in extracting of urls from `urls` table, this function
-- tries its best to extract specific number of urls from a task based on
-- their characteristics
--]]
exports.filter_specific_urls = function (urls, params)
  local cache_key

  if params.task and not params.no_cache then
    if params.prefix then
      cache_key = params.prefix
    else
      cache_key = string.format('sp_urls_%d%s%s%s', params.limit,
          tostring(params.need_emails or false),
          tostring(params.need_images or false),
          tostring(params.need_content or false))
    end
    local cached = params.task:cache_get(cache_key)

    if cached then
      return cached
    end
  end

  if not urls then return {} end

  if params.filter then urls = fun.totable(fun.filter(params.filter, urls)) end

  -- Filter by tld:
  local tlds = {}
  local eslds = {}
  local ntlds, neslds = 0, 0

  local res = {}
  local nres = 0

  local function insert_url(str, u)
    if not res[str] then
      res[str] = u
      nres = nres + 1

      return true
    end

    return false
  end

  local function process_single_url(u, default_priority)
    local priority = default_priority or 1 -- Normal priority
    local flags = u:get_flags()
    if params.ignore_ip and flags.numeric then
      return
    end

    if flags.redirected then
      local redir = u:get_redirected() -- get the real url

      if params.ignore_redirected then
        -- Replace `u` with redir
        u = redir
        priority = 2
      else
        -- Process both redirected url and the original one
        process_single_url(redir, 2)
      end
    end

    if flags.image then
      if not params.need_images then
        -- Ignore url
        return
      else
        -- Penalise images in urls
        priority = 0
      end
    end

    local esld = u:get_tld()
    local str_hash = tostring(u)

    if esld then
      -- Special cases
      if (u:get_protocol() ~= 'mailto') and (not flags.html_displayed) then
        if flags.obscured then
          priority = 3
        else
          if (flags.has_user or flags.has_port) then
            priority = 2
          elseif (flags.subject or flags.phished) then
            priority = 2
          end
        end
      elseif flags.html_displayed then
        priority = 0
      end

      if not eslds[esld] then
        eslds[esld] = {{str_hash, u, priority}}
        neslds = neslds + 1
      else
        if #eslds[esld] < params.esld_limit then
          table.insert(eslds[esld], {str_hash, u, priority})
        end
      end


      -- eSLD - 1 part => tld
      local parts = rspamd_str_split(esld, '.')
      local tld = table.concat(fun.totable(fun.tail(parts)), '.')

      if not tlds[tld] then
        tlds[tld] = {{str_hash, u, priority}}
        ntlds = ntlds + 1
      else
        table.insert(tlds[tld], {str_hash, u, priority})
      end
    end
  end

  for _,u in ipairs(urls) do
    process_single_url(u)
  end

  local limit = params.limit
  limit = limit - nres
  if limit < 0 then limit = 0 end

  if limit == 0 then
    res = exports.values(res)
    if params.task and not params.no_cache then
      params.task:cache_set(cache_key, res)
    end
    return res
  end

  -- Sort eSLDs and tlds
  local function sort_stuff(tbl)
    -- Sort according to max priority
    table.sort(tbl, function(e1, e2)
      -- Sort by priority so max priority is at the end
      table.sort(e1, function(tr1, tr2)
        return tr1[3] < tr2[3]
      end)
      table.sort(e2, function(tr1, tr2)
        return tr1[3] < tr2[3]
      end)

      if e1[#e1][3] ~= e2[#e2][3] then
        -- Sort by priority so max priority is at the beginning
        return e1[#e1][3] > e2[#e2][3]
      else
        -- Prefer less urls to more urls per esld
        return #e1 < #e2
      end

    end)

    return tbl
  end

  eslds = sort_stuff(exports.values(eslds))
  neslds = #eslds

  if neslds <= limit then
    -- Number of eslds < limit
    repeat
      local item_found = false

      for _,lurls in ipairs(eslds) do
        if #lurls > 0 then
          local last = table.remove(lurls)
          insert_url(last[1], last[2])
          limit = limit - 1
          item_found = true
        end
      end

    until limit <= 0 or not item_found

    res = exports.values(res)
    if params.task and not params.no_cache then
      params.task:cache_set(cache_key, res)
    end
    return res
  end

  tlds = sort_stuff(exports.values(tlds))
  ntlds = #tlds

  -- Number of tlds < limit
  while limit > 0 do
    for _,lurls in ipairs(tlds) do
      if #lurls > 0 then
        local last = table.remove(lurls)
        insert_url(last[1], last[2])
        limit = limit - 1
      end
      if limit == 0 then break end
    end
  end

  res = exports.values(res)
  if params.task and not params.no_cache then
    params.task:cache_set(cache_key, res)
  end
  return res
end

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
- - ignore_redirected <bool> (default = false)
- - need_images <bool> (default = false)
- - need_content <bool> (default = false)
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
    need_images = false,
    need_content = false,
    filter = nil,
    prefix = nil,
    ignore_ip = false,
    ignore_redirected = false,
    no_cache = false,
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
    if type(params[k]) == 'nil' and v ~= nil then params[k] = v end
  end
  local url_params = {
    emails = params.need_emails,
    images = params.need_images,
    content = params.need_content,
    flags = params.flags, -- maybe nil
    flags_mode = params.flags_mode, -- maybe nil
  }

  -- Shortcut for cached stuff
  if params.task and not params.no_cache then
    local cache_key
    if params.prefix then
      cache_key = params.prefix
    else
      local cache_key_suffix
      if params.flags then
        cache_key_suffix = table.concat(params.flags) .. (params.flags_mode or '')
      else
        cache_key_suffix = string.format('%s%s%s',
          tostring(params.need_emails or false),
          tostring(params.need_images or false),
          tostring(params.need_content or false))
      end
      cache_key = string.format('sp_urls_%d%s', params.limit, cache_key_suffix)
    end
    local cached = params.task:cache_get(cache_key)

    if cached then
      return cached
    end
  end

  -- No cache version
  local urls = params.task:get_urls(url_params)

  return exports.filter_specific_urls(urls, params)
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
    if getmetatable(orig) then
      setmetatable(copy, deepcopy(getmetatable(orig)))
    end
  else -- number, string, boolean, etc
    copy = orig
  end
  return copy
end

exports.deepcopy = deepcopy

--[[[
-- @function lua_util.deepsort(table)
-- params: {
- - table
-- }
-- Performs recursive in-place sort of a table
--]]
local function default_sort_cmp(e1, e2)
  if type(e1) == type(e2) then
    return e1 < e2
  else
    return type(e1) < type(e2)
  end
end

local function deepsort(tbl, sort_func)
  local orig_type = type(tbl)
  if orig_type == 'table' then
    table.sort(tbl, sort_func or default_sort_cmp)
    for _, orig_value in next, tbl, nil do
      deepsort(orig_value)
    end
  end
end

exports.deepsort = deepsort

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
local logger = require "rspamd_logger"
local unconditional_debug = logger.log_level() == 'debug'
local debug_modules = {}
local debug_aliases = {}
local log_level = 384 -- debug + forced (1 << 7 | 1 << 8)


exports.init_debug_logging = function(config)
  -- Fill debug modules from the config
  if not unconditional_debug then
    local log_config = config:get_all_opt('logging')
    if log_config then
      local log_level_str = log_config.level
      if log_level_str then
        if log_level_str == 'debug' then
          unconditional_debug = true
        end
      end
      if log_config.debug_modules then
        for _,m in ipairs(log_config.debug_modules) do
          debug_modules[m] = true
          logger.infox(config, 'enable debug for Lua module %s', m)
        end
      end

      if #debug_aliases > 0 then
        for alias,mod in pairs(debug_aliases) do
          if debug_modules[mod] then
            debug_modules[alias] = true
            logger.infox(config, 'enable debug for Lua module %s (%s aliased)',
                alias, mod)
          end
        end
      end
    end
  end
end

exports.enable_debug_logging = function()
  unconditional_debug = true
end

exports.enable_debug_modules = function(...)
  for _,m in ipairs({...}) do
    debug_modules[m] = true
  end
end

exports.disable_debug_logging = function()
  unconditional_debug = false
end

--[[[
-- @function lua_util.debugm(module, [log_object], format, ...)
-- Performs fast debug log for a specific module
--]]
exports.debugm = function(mod, obj_or_fmt, fmt_or_something, ...)
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
  debug_aliases[alias] = mod

  if debug_modules[mod] then
    debug_modules[alias] = true
    logger.infox(rspamd_config, 'enable debug for Lua module %s (%s aliased)',
        alias, mod)
  end
end
---[[[
-- @function lua_util.get_task_verdict(task)
-- Returns verdict for a task + score if certain, must be called from idempotent filters only
-- Returns string:
-- * `spam`: if message have over reject threshold and has more than one positive rule
-- * `junk`: if a message has between score between [add_header/rewrite subject] to reject thresholds and has more than two positive rules
-- * `passthrough`: if a message has been passed through some short-circuit rule
-- * `ham`: if a message has overall score below junk level **and** more than three negative rule, or negative total score
-- * `uncertain`: all other cases
--]]
exports.get_task_verdict = function(task)
  local lua_verdict = require "lua_verdict"

  return lua_verdict.get_default_verdict(task)
end

---[[[
-- @function lua_util.maybe_obfuscate_string(subject, settings, prefix)
-- Obfuscate string if enabled in settings. Also checks utf8 validity - if
-- string is not valid utf8 then '???' is returned. Empty string returned as is.
-- Supported settings:
-- * <prefix>_privacy = false - subject privacy is off
-- * <prefix>_privacy_alg = 'blake2' - default hash-algorithm to obfuscate subject
-- * <prefix>_privacy_prefix = 'obf' - prefix to show it's obfuscated
-- * <prefix>_privacy_length = 16 - cut the length of the hash; if 0 or fasle full hash is returned
-- @return obfuscated or validated subject
--]]

exports.maybe_obfuscate_string = function(subject, settings, prefix)
  local hash = require 'rspamd_cryptobox_hash'
  if not subject or subject == '' then
    return subject
  elseif not rspamd_util.is_valid_utf8(subject) then
    subject = '???'
  elseif settings[prefix .. '_privacy'] then
    local hash_alg = settings[prefix .. '_privacy_alg'] or 'blake2'
    local subject_hash = hash.create_specific(hash_alg, subject)

    local strip_len = settings[prefix .. '_privacy_length']
    if strip_len and strip_len > 0 then
      subject = subject_hash:hex():sub(1, strip_len)
    else
      subject = subject_hash:hex()
    end

    local privacy_prefix = settings[prefix .. '_privacy_prefix']
    if privacy_prefix and #privacy_prefix > 0 then
      subject = privacy_prefix .. ':' .. subject
    end
  end

  return subject
end

---[[[
-- @function lua_util.callback_from_string(str)
-- Converts a string like `return function(...) end` to lua function and return true and this function
-- or returns false + error message
-- @return status code and function object or an error message
--]]]
exports.callback_from_string = function(s)
  local loadstring = loadstring or load

  if not s or #s == 0 then
    return false,'invalid or empty string'
  end

  s = exports.rspamd_str_trim(s)
  local inp

  if s:match('^return%s*function') then
    -- 'return function', can be evaluated directly
    inp = s
  elseif s:match('^function%s*%(') then
    inp = 'return ' .. s
  else
    -- Just a plain sequence
    inp = 'return function(...)\n' .. s .. '; end'
  end

  local ret, res_or_err = pcall(loadstring(inp))

  if not ret or type(res_or_err) ~= 'function' then
    return false,res_or_err
  end

  return ret,res_or_err
end

---[[[
-- @function lua_util.keys(t)
-- Returns all keys from a specific table
-- @param {table} t input table (or iterator triplet)
-- @return array of keys
--]]]
exports.keys = function(gen, param, state)
  local keys = {}
  local i = 1

  if param then
    for k,_ in fun.iter(gen, param, state) do
      rawset(keys, i, k)
      i = i + 1
    end
  else
    for k,_ in pairs(gen) do
      rawset(keys, i, k)
      i = i + 1
    end
  end

  return keys
end

---[[[
-- @function lua_util.values(t)
-- Returns all values from a specific table
-- @param {table} t input table
-- @return array of values
--]]]
exports.values = function(gen, param, state)
  local values = {}
  local i = 1

  if param then
    for _,v in fun.iter(gen, param, state) do
      rawset(values, i, v)
      i = i + 1
    end
  else
    for _,v in pairs(gen) do
      rawset(values, i, v)
      i = i + 1
    end
  end

  return values
end

---[[[
-- @function lua_util.distance_sorted(t1, t2)
-- Returns distance between two sorted tables t1 and t2
-- @param {table} t1 input table
-- @param {table} t2 input table
-- @return distance between `t1` and `t2`
--]]]
exports.distance_sorted = function(t1, t2)
  local ncomp = #t1
  local ndiff = 0
  local i,j = 1,1

  if ncomp < #t2 then
    ncomp = #t2
  end

  for _=1,ncomp do
    if j > #t2 then
      ndiff = ndiff + ncomp - #t2
      if i > j then
        ndiff = ndiff - (i - j)
      end
      break
    elseif i > #t1 then
      ndiff = ndiff + ncomp - #t1
      if j > i then
        ndiff = ndiff - (j - i)
      end
      break
    end

    if t1[i] == t2[j] then
      i = i + 1
      j = j + 1
    elseif t1[i] < t2[j] then
      i = i + 1
      ndiff = ndiff + 1
    else
      j = j + 1
      ndiff = ndiff + 1
    end
  end

  return ndiff
end

---[[[
-- @function lua_util.table_digest(t)
-- Returns hash of all values if t[1] is string or all keys/values otherwise
-- @param {table} t input array or map
-- @return {string} base32 representation of blake2b hash of all strings
--]]]
local function table_digest(t)
  local cr = require "rspamd_cryptobox_hash"
  local h = cr.create()

  if t[1] then
    for _,e in ipairs(t) do
      if type(e) == 'table' then
        h:update(table_digest(e))
      else
        h:update(tostring(e))
      end
    end
  else
    for k,v in pairs(t) do
      h:update(tostring(k))

      if type(v) == 'string' then
        h:update(v)
      elseif type(v) == 'table' then
        h:update(table_digest(v))
      end
    end
  end
 return h:base32()
end

exports.table_digest = table_digest

---[[[
-- @function lua_util.toboolean(v)
-- Converts a string or a number to boolean
-- @param {string|number} v
-- @return {boolean} v converted to boolean
--]]]
exports.toboolean = function(v)
  local true_t = {
    ['1'] = true,
    ['true'] = true,
    ['TRUE'] = true,
    ['True'] = true,
  };
  local false_t = {
    ['0'] = false,
    ['false'] = false,
    ['FALSE'] = false,
    ['False'] = false,
  };

  if type(v) == 'string' then
    if true_t[v] == true then
      return true;
    elseif false_t[v] == false then
      return false;
    else
      return false, string.format( 'cannot convert %q to boolean', v);
    end
  elseif type(v) == 'number' then
    return (not (v == 0))
  else
    return false, string.format( 'cannot convert %q to boolean', v);
  end
end

---[[[
-- @function lua_util.config_check_local_or_authed(config, modname)
-- Reads check_local and check_authed from the config as this is used in many modules
-- @param {rspamd_config} config `rspamd_config` global
-- @param {name} module name
-- @return {boolean} v converted to boolean
--]]]
exports.config_check_local_or_authed = function(rspamd_config, modname, def_local, def_authed)
  local check_local = def_local or false
  local check_authed = def_authed or false

  local function try_section(where)
    local ret = false
    local opts = rspamd_config:get_all_opt(where)
    if type(opts) == 'table' then
      if type(opts['check_local']) == 'boolean' then
        check_local = opts['check_local']
        ret = true
      end
      if type(opts['check_authed']) == 'boolean' then
        check_authed = opts['check_authed']
        ret = true
      end
    end

    return ret
  end

  if not try_section(modname) then
    try_section('options')
  end

  return {check_local, check_authed}
end

---[[[
-- @function lua_util.is_skip_local_or_authed(task, conf[, ip])
-- Returns `true` if local or authenticated task should be skipped for this module
-- @param {rspamd_task} task
-- @param {table} conf table returned from `config_check_local_or_authed`
-- @param {rspamd_ip} ip optional ip address (can be obtained from a task)
-- @return {boolean} true if check should be skipped
--]]]
exports.is_skip_local_or_authed = function(task, conf, ip)
  if not ip then
    ip = task:get_from_ip()
  end
  if not conf then
    conf = {false, false}
  end
  if ((not conf[2] and task:get_user()) or
      (not conf[1] and type(ip) == 'userdata' and ip:is_local())) then
    return true
  end

  return false
end

---[[[
-- @function lua_util.maybe_smtp_quote_value(str)
-- Checks string for the forbidden elements (tspecials in RFC and quote string if needed)
-- @param {string} str input string
-- @return {string} original or quoted string
--]]]
local tspecial = lpeg.S"()<>,;:\\\"/[]?= \t\v"
local special_match = lpeg.P((1 - tspecial)^0 * tspecial^1)
exports.maybe_smtp_quote_value = function(str)
  if special_match:match(str) then
    return string.format('"%s"', str:gsub('"', '\\"'))
  end

  return str
end

---[[[
-- @function lua_util.shuffle(table)
-- Performs in-place shuffling of a table
-- @param {table} tbl table to shuffle
-- @return {table} same table
--]]]
exports.shuffle = function(tbl)
  local size = #tbl
  for i = size, 1, -1 do
    local rand = math.random(size)
    tbl[i], tbl[rand] = tbl[rand], tbl[i]
  end
  return tbl
end

return exports
