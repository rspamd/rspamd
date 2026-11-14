--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

--[[[
-- @module lua_dynconf
-- Dynamic configuration registry.
--
-- A module registers its defaults, static configuration, an optional schema and the list of option
-- paths that are allowed to be overridden at runtime ("dynamic" paths). The registry owns one settings
-- table per module and mutates it in place when an external source (for example Redis) delivers an
-- override, so reading `settings.option` stays a plain table access: no metamethods, no C calls, no
-- yields. Table identity (of the root and of intermediate tables) never changes.
--
-- Without a `dynconf` section in the configuration the registry is a passive store: `register` and
-- `dump` work, but there is no timer, no network traffic and no per-task work.
--
-- Lua code here must run on LuaJIT and on PUC Lua 5.3+, so no `goto`, no bit operators and no
-- integer division are used.
--]]

local exports = {}

local lua_util = require "lua_util"
local logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"

local N = "dynconf"

local deepcopy = lua_util.deepcopy
local table_cmp = lua_util.table_cmp
local override_defaults = lua_util.override_defaults

-- Redacted marker used in dumps
local REDACTED = '***'
-- Do not wait longer than this for a backend check before allowing another one
local INFLIGHT_TIMEOUT = 30.0
local MAX_DEPTH = 32
local POLICIES = { interval = true, on_access = true, both = true, manual = true }

-- Words that mark a value as secret when the last path segment is that word or ends with `_<word>`
-- (case-insensitive, `-` counts as `_`); `key` alone is matched exactly
local SECRET_WORDS = {
  'password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'privkey',
  'private_key', 'secret_key', 'fuzzy_key', 'shingles_key',
}

local modules = {}       -- name -> module descriptor
local backends = {}      -- name -> backend implementation
local source_order = {}  -- override sources in registration order (later wins)
local generation = 0

-- Framework state (top-level `dynconf` section)
local fw = {
  configured = false,
  enabled = false,
  backend_name = nil,
  policy = 'interval',
  interval = 10.0,
  jitter = 0.2,
  ttl = 10.0,
  section = nil,
  ev_base = nil,
  worker = nil,
  started = false,
  inflight = false,
  inflight_since = 0,
  token = 0,
  last_check = nil,
  last_update = nil,
  last_error = nil,
  applied_count = 0,
  on_load_registered = false,
}

-- Note: indexing `rspamd_config` with an unknown name does not return nil (it returns a symbol proxy
-- userdata), so the presence of a method has to be checked by type
local function cfg_method(name)
  local f = rspamd_config and rspamd_config[name]
  if type(f) == 'function' then
    return f
  end
  return nil
end

local function get_time()
  return rspamd_util.get_time()
end

local function dbg(fmt, ...)
  lua_util.debugm(N, rspamd_config, fmt, ...)
end

-- Helpers for paths ------------------------------------------------------------------------------

local function path_str(path)
  local t = {}
  for i = 1, #path do
    t[i] = tostring(path[i])
  end
  return table.concat(t, '.')
end

local function split_path(str)
  local t = {}
  for seg in string.gmatch(str, '[^%.]+') do
    t[#t + 1] = seg
  end
  return t
end

local function copy_path(path)
  local t = {}
  for i = 1, #path do
    t[i] = path[i]
  end
  return t
end

local function path_matches(pattern, path)
  if #pattern ~= #path then
    return false
  end
  for i = 1, #pattern do
    if pattern[i] ~= '*' and pattern[i] ~= tostring(path[i]) then
      return false
    end
  end
  return true
end

-- True if `path` is a strict prefix of `pattern`
local function path_is_prefix(pattern, path)
  if #pattern <= #path then
    return false
  end
  for i = 1, #path do
    if pattern[i] ~= '*' and pattern[i] ~= tostring(path[i]) then
      return false
    end
  end
  return true
end

local function matches_any(patterns, path)
  for _, p in ipairs(patterns) do
    if path_matches(p, path) then
      return true
    end
  end
  return false
end

local function is_prefix_of_any(patterns, path)
  for _, p in ipairs(patterns) do
    if path_is_prefix(p, path) then
      return true
    end
  end
  return false
end

local function get_path(root, path)
  local cur = root
  for i = 1, #path do
    if type(cur) ~= 'table' then
      return nil
    end
    cur = cur[path[i]]
  end
  return cur
end

-- Copies `src` into `dst` keeping the identity of `dst` and of every nested table that exists on both
-- sides
local function sync_into(dst, src)
  for k in pairs(dst) do
    if src[k] == nil then
      dst[k] = nil
    end
  end
  for k, v in pairs(src) do
    if type(v) == 'table' and type(dst[k]) == 'table' then
      sync_into(dst[k], v)
    else
      dst[k] = deepcopy(v)
    end
  end
end

-- Sets a value by path in place, creating intermediate tables; a nil value never creates anything
local function set_path(root, path, value)
  local cur = root
  for i = 1, #path - 1 do
    local nxt = cur[path[i]]
    if type(nxt) ~= 'table' then
      if value == nil then
        return
      end
      nxt = {}
      cur[path[i]] = nxt
    end
    cur = nxt
  end

  local last = path[#path]
  local old = cur[last]
  if type(value) == 'table' and type(old) == 'table' then
    sync_into(old, value)
  else
    cur[last] = deepcopy(value)
  end
end

local function sorted_keys(t)
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys, function(a, b)
    local ta, tb = type(a), type(b)
    if ta == tb and (ta == 'number' or ta == 'string') then
      return a < b
    end
    return ta .. tostring(a) < tb .. tostring(b)
  end)
  return keys
end

-- Removes the empty tables that a removed override leaves on `path`; a table that exists in `ref` (the
-- pipeline result) is kept. Stops at the first table that is not empty.
local function prune_empty(root, path, ref)
  for i = #path - 1, 1, -1 do
    local prefix = {}
    for j = 1, i do
      prefix[j] = path[j]
    end
    local tbl = get_path(root, prefix)
    if type(tbl) == 'table' and next(tbl) == nil and get_path(ref, prefix) == nil then
      local parent = root
      if i > 1 then
        local pp = {}
        for j = 1, i - 1 do
          pp[j] = path[j]
        end
        parent = get_path(root, pp)
      end
      parent[path[i]] = nil
    else
      return
    end
  end
end

-- A JSON object has string keys even for array indices: use the number if the base table has it
local function normalize_key(parent, k)
  if type(k) == 'string' and type(parent) == 'table' and parent[k] == nil then
    local n = tonumber(k)
    if n and n == math.floor(n) and parent[n] ~= nil then
      return n
    end
  end
  return k
end

-- Returns an error string if `value` contains something that must never be an override
local function check_clean(value, path, depth, seen)
  local tv = type(value)
  if tv == 'function' or tv == 'userdata' or tv == 'thread' then
    return string.format('%s: values of type %s are not allowed', path_str(path), tv)
  end
  if tv ~= 'table' then
    return nil
  end
  if depth > MAX_DEPTH or seen[value] then
    return string.format('%s: value is too deeply nested or has loops', path_str(path))
  end
  seen[value] = true
  for k, v in pairs(value) do
    local tk = type(k)
    if tk ~= 'string' and tk ~= 'number' then
      seen[value] = nil
      return string.format('%s: keys of type %s are not allowed', path_str(path), tk)
    end
    path[#path + 1] = k
    local err = check_clean(v, path, depth + 1, seen)
    path[#path] = nil
    if err then
      seen[value] = nil
      return err
    end
  end
  seen[value] = nil
  return nil
end

-- True if a pattern that matches or starts with `path` names its last segment literally (and not by `*`)
local function literal_segment(mod, path)
  local n = #path
  for _, p in ipairs(mod.patterns) do
    if #p >= n and p[n] ~= '*' and p[n] == tostring(path[n]) then
      local ok = true
      for i = 1, n - 1 do
        if p[i] ~= '*' and p[i] ~= tostring(path[i]) then
          ok = false
          break
        end
      end
      if ok then
        return true
      end
    end
  end
  return false
end

-- Walks an override table. Every leaf (a path matching a declared dynamic pattern) must be clean and, if
-- there is no schema, of the same type as the base value. Calls `cb(path, value)` for every leaf; numeric
-- strings are turned into array indices where the base table has them. An entry that a `*` segment
-- selects must exist in the base configuration: overrides never create entries.
local function walk_overrides(mod, tbl, path, cb)
  for k in pairs(tbl) do
    local tk = type(k)
    if tk ~= 'string' and tk ~= 'number' then
      return false, string.format('%s: keys of type %s are not allowed', path_str(path), tk)
    end
  end

  local base_parent = get_path(mod.raw_base, path)

  for _, k in ipairs(sorted_keys(tbl)) do
    local v = tbl[k]
    path[#path + 1] = normalize_key(base_parent, k)
    local ok, err = true, nil
    local tv = type(v)
    local is_leaf = matches_any(mod.patterns, path)
    local is_prefix = not is_leaf and tv == 'table' and is_prefix_of_any(mod.patterns, path)

    if tv == 'function' or tv == 'userdata' or tv == 'thread' then
      ok, err = false, string.format('%s: values of type %s are not allowed', path_str(path), tv)
    elseif (is_leaf or is_prefix) and not literal_segment(mod, path) and
        (type(base_parent) ~= 'table' or base_parent[path[#path]] == nil) then
      ok, err = false, string.format('%s: there is no such entry in the configuration', path_str(path))
    elseif is_leaf then
      err = check_clean(v, path, 1, {})
      if err then
        ok = false
      elseif not mod.schema then
        local base = get_path(mod.raw_base, path)
        if base ~= nil and type(base) ~= tv then
          ok, err = false, string.format('%s: type mismatch, expected %s, got %s',
              path_str(path), type(base), tv)
        end
      end
      if ok and cb then
        cb(copy_path(path), v)
      end
    elseif is_prefix then
      ok, err = walk_overrides(mod, v, path, cb)
    else
      ok, err = false, string.format('%s: option is not dynamic', path_str(path))
    end

    path[#path] = nil
    if not ok then
      return false, err
    end
  end

  return true
end

-- Source ordering --------------------------------------------------------------------------------

local function source_known(name)
  for _, s in ipairs(source_order) do
    if s == name then
      return true
    end
  end
  return false
end

local function add_source(name)
  if not source_known(name) then
    source_order[#source_order + 1] = name
  end
end

-- Merges the overrides of all sources leaf by leaf: the value of a leaf from a later source replaces the
-- whole value of the earlier one. `extra` (optional) is merged last.
local function merge_sources(mod, overrides, extra)
  local merged = {}
  local function add(values)
    walk_overrides(mod, values, {}, function(path, v)
      set_path(merged, path, v)
    end)
  end
  for _, src in ipairs(source_order) do
    local entry = overrides[src]
    if entry and entry.values then
      add(entry.values)
    end
  end
  if extra then
    add(extra)
  end
  return merged
end

-- Pipeline ---------------------------------------------------------------------------------------

local function format_schema_error(err)
  local ok, T = pcall(require, "lua_shape.core")
  if ok and type(err) == 'table' then
    return T.format_error(err)
  end
  return tostring(err)
end

-- raw_base + merged overrides -> schema -> transform; returns a fresh table or nil, err
local function run_pipeline(mod, merged)
  local res = deepcopy(mod.raw_base)
  -- The whole value of a leaf replaces the base one (a list can be emptied, a map can lose keys)
  walk_overrides(mod, merged, {}, function(path, v)
    set_path(res, path, v)
  end)

  if mod.schema then
    local ok, v, err = pcall(mod.schema.transform, mod.schema, res)
    if not ok then
      return nil, tostring(v)
    end
    if v == nil then
      return nil, format_schema_error(err)
    end
    res = v
  end

  if mod.transform then
    local ok, v, err = pcall(mod.transform, res)
    if not ok then
      return nil, tostring(v)
    end
    if v == nil then
      return nil, tostring(err or 'transform function returned nil')
    end
    res = v
  end

  return deepcopy(res)
end

-- Collects leaf paths of an override table into `out` (keyed by dotted path)
local function collect_leaves(mod, overrides, out)
  if not overrides then
    return
  end
  walk_overrides(mod, overrides, {}, function(path)
    local key = path_str(path)
    if not out[key] then
      out[key] = path
    end
  end)
end

-- Effective values of dynamic paths only, as a nested table (used for C subscribers)
local function snapshot_dynamic(mod, values)
  local out = {}

  local function expand(tbl, pattern, idx, path)
    if type(tbl) ~= 'table' then
      return
    end
    local seg = pattern[idx]
    if idx == #pattern then
      if seg == '*' then
        for k, v in pairs(tbl) do
          path[idx] = k
          set_path(out, path, v)
        end
        path[idx] = nil
      elseif tbl[seg] ~= nil then
        path[idx] = seg
        set_path(out, path, tbl[seg])
        path[idx] = nil
      else
        -- Also try a numeric key for array-like tables
        local n = tonumber(seg)
        if n and tbl[n] ~= nil then
          path[idx] = n
          set_path(out, path, tbl[n])
          path[idx] = nil
        end
      end
      return
    end
    if seg == '*' then
      for k, v in pairs(tbl) do
        path[idx] = k
        expand(v, pattern, idx + 1, path)
      end
      path[idx] = nil
    else
      local sub = tbl[seg]
      if sub == nil then
        local n = tonumber(seg)
        if n then
          sub = tbl[n]
          seg = n
        end
      end
      path[idx] = seg
      expand(sub, pattern, idx + 1, path)
      path[idx] = nil
    end
  end

  for _, pattern in ipairs(mod.patterns) do
    expand(values, pattern, 1, {})
  end

  return out
end

local function bump_generation()
  generation = generation + 1
  local bump = cfg_method('dynconf_bump_generation')
  if bump then
    local ok, err = pcall(bump, rspamd_config)
    if not ok then
      logger.warnx(rspamd_config, 'dynconf_bump_generation failed: %s', err)
    end
  end
end

-- Tells the C subscriber about the new effective values `values` (the result of the pipeline). Returns
-- true if there is nothing to tell or the subscriber has accepted the update, `false, error` otherwise
local function notify_c(mod, values)
  if not mod.c_subscriber then
    return true
  end
  local notify = cfg_method('dynconf_notify')
  if not notify then
    dbg('no C notification hook is available for %s', mod.name)
    return true
  end
  local ok, res, err = pcall(notify, rspamd_config, mod.name, snapshot_dynamic(mod, values))
  if not ok then
    logger.warnx(rspamd_config, 'cannot notify C module %s about the new configuration: %s', mod.name, res)
    return false, string.format('cannot notify C module %s: %s', mod.name, tostring(res))
  elseif res == false then
    logger.warnx(rspamd_config, 'C module %s rejected the new configuration: %s', mod.name, err)
    return false, string.format('C module %s rejected the configuration: %s', mod.name, tostring(err))
  end
  return true
end

local function run_hooks(mod, changed)
  for _, hook in ipairs(mod.hooks) do
    local ok, err = pcall(hook, mod.settings, changed)
    if not ok then
      logger.errx(rspamd_config, 'dynconf on_change hook for %s failed: %s', mod.name, err)
    end
  end
end

-- Registration -----------------------------------------------------------------------------------

local function parse_patterns(list, what)
  local res = {}
  if list == nil then
    return res
  end
  if type(list) ~= 'table' then
    return nil, string.format('%s must be an array of paths', what)
  end
  for _, p in ipairs(list) do
    if type(p) ~= 'string' or p == '' then
      return nil, string.format('%s must contain non-empty strings only', what)
    end
    local segs = split_path(p)
    if #segs == 0 then
      return nil, string.format('%s: invalid path "%s"', what, p)
    end
    res[#res + 1] = segs
  end
  return res
end

local function static_opts(name, opts)
  if opts == false then
    return {}
  end
  local get_all_opt = cfg_method('get_all_opt')
  if opts == nil and get_all_opt then
    local ok, res = pcall(get_all_opt, rspamd_config, name)
    if ok then
      opts = res
    end
  end
  if type(opts) ~= 'table' then
    return {}
  end
  return opts
end

local ensure_framework

--[[[
-- @function lua_dynconf.register(module, params)
-- Registers a module's settings and returns the live settings table.
-- @param {string} module module name
-- @param {table} params:
--   * `defaults` (table): defaults, required (may be empty)
--   * `opts` (table|false|nil): static configuration; `nil` means "read `rspamd_config:get_all_opt(module)`",
--      `false` means "no static configuration"
--   * `schema` (lua_shape schema, optional), `schema_id` (string, optional: schema is registered under it)
--   * `dynamic` (array of dotted paths, `*` matches one segment): options that may be overridden
--   * `secret` (array of dotted paths): additional paths redacted in dumps
--   * `transform` (function(tbl) -> tbl | nil, err): pure idempotent normaliser
--   * `on_change` (function(settings, changed_paths)): called after each accepted update
-- @return {table} the live settings table, or `nil, error` on failure
-- @example
-- local settings, err = dynconf.register(N, { defaults = settings, opts = opts, dynamic = { 'threshold' } })
--]]
local function register(name, params)
  if type(name) ~= 'string' or name == '' then
    return nil, 'module name must be a non-empty string'
  end
  params = params or {}

  local existing = modules[name]
  if existing and not existing.static_only then
    dbg('module %s is already registered, returning the existing settings', name)
    return existing.settings
  end

  ensure_framework()

  local defaults = params.defaults
  if defaults == nil then
    defaults = {}
  elseif type(defaults) ~= 'table' then
    return nil, 'defaults must be a table'
  end

  local patterns, perr = parse_patterns(params.dynamic, 'dynamic')
  if not patterns then
    return nil, perr
  end
  local secrets
  secrets, perr = parse_patterns(params.secret, 'secret')
  if not secrets then
    return nil, perr
  end

  local opts = static_opts(name, params.opts)
  local mod = {
    name = name,
    defaults = deepcopy(defaults),
    static = deepcopy(opts),
    raw_base = deepcopy(override_defaults(deepcopy(defaults), opts)),
    patterns = patterns,
    secrets = secrets,
    transform = params.transform,
    schema_id = params.schema_id,
    hooks = {},
    overrides = {},
    merged = {},
    version = 0,
    static_only = false,
    c_subscriber = false,
  }

  if params.on_change then
    mod.hooks[1] = params.on_change
  end

  if params.schema then
    local resolved = params.schema
    if params.schema_id then
      local ok, res = pcall(function()
        return require("lua_shape.plugin_schema").register(params.schema_id, params.schema)
      end)
      if not ok then
        return nil, tostring(res)
      end
      resolved = res or params.schema
    else
      local ok, res = pcall(function()
        return require("lua_shape.registry").global():resolve_schema(params.schema)
      end)
      if ok and res then
        resolved = res
      end
    end
    mod.schema = resolved
  end

  local settings, err = run_pipeline(mod, {})
  if not settings then
    return nil, err
  end
  mod.settings = settings
  modules[name] = mod

  return settings
end
exports.register = register

--[[[
-- @function lua_dynconf.register_static(module, opts)
-- Records the raw static configuration of a module for dump visibility only (no dynamic paths)
--]]
function exports.register_static(name, opts)
  if type(name) ~= 'string' or modules[name] then
    return
  end
  ensure_framework()
  local static = static_opts(name, opts)
  modules[name] = {
    name = name,
    defaults = {},
    static = deepcopy(static),
    raw_base = deepcopy(static),
    patterns = {},
    secrets = {},
    hooks = {},
    overrides = {},
    merged = {},
    version = 0,
    static_only = true,
    c_subscriber = false,
    settings = nil,
  }
end

--[[[
-- @function lua_dynconf.register_c(module, paths)
-- Registers a C module: its static configuration is the `module` section, `paths` is an array of
-- dynamic path patterns. After every accepted update the C side is notified with the effective values
-- of the dynamic paths.
-- @return {boolean} true on success, or `false, error`
--]]
function exports.register_c(name, paths)
  local settings, err = register(name, { defaults = {}, dynamic = paths })
  if not settings then
    return false, err
  end
  modules[name].c_subscriber = true
  return true
end

--[[[
-- @function lua_dynconf.on_change(module, fn)
-- Adds a change hook `fn(settings, changed_paths)` to a registered module
--]]
function exports.on_change(name, fn)
  local mod = modules[name]
  if not mod or type(fn) ~= 'function' then
    return false
  end
  table.insert(mod.hooks, fn)
  return true
end

--[[[
-- @function lua_dynconf.get(module)
-- Returns the live settings table of a module or nil
--]]
function exports.get(name)
  local mod = modules[name]
  return mod and mod.settings or nil
end

--[[[
-- @function lua_dynconf.is_dynamic(module, path)
-- Returns true if the dotted path (or an array of segments) is declared dynamic for the module
--]]
function exports.is_dynamic(name, path)
  local mod = modules[name]
  if not mod then
    return false
  end
  if type(path) == 'string' then
    path = split_path(path)
  end
  if type(path) ~= 'table' or #path == 0 then
    return false
  end
  return matches_any(mod.patterns, path)
end

--[[[
-- @function lua_dynconf.modules()
-- Returns a sorted array of registered module names
--]]
function exports.modules()
  return sorted_keys(modules)
end

--[[[
-- @function lua_dynconf.generation()
-- Returns the global generation counter: it grows on every applied change
--]]
function exports.generation()
  return generation
end

-- Applying overrides -----------------------------------------------------------------------------

local function check_overrides(mod, values)
  if type(values) ~= 'table' then
    return false, string.format('overrides for %s must be a table', mod.name)
  end
  return walk_overrides(mod, values, {}, nil)
end

--[[[
-- @function lua_dynconf.validate(module, values, [source])
-- Checks an override table the same way `apply` does but changes nothing. `source` names the override
-- source that `values` would replace (other sources are still taken into account).
-- @return {boolean} ok or `false, error`
--]]
function exports.validate(name, values, source)
  local mod = modules[name]
  if not mod then
    return false, string.format('unknown module %s', tostring(name))
  end
  if mod.static_only then
    return false, string.format('module %s has no dynamic options', name)
  end

  local candidate = {}
  for k, v in pairs(mod.overrides) do
    candidate[k] = v
  end
  local extra
  if values then
    local ok, err = check_overrides(mod, values)
    if not ok then
      return false, err
    end
    if source and source_known(source) then
      candidate[source] = { values = values }
    else
      extra = values
    end
  elseif source then
    candidate[source] = nil
  end

  local merged = merge_sources(mod, candidate, extra)
  local res, err = run_pipeline(mod, merged)
  if not res then
    return false, err
  end
  return true
end

--[[[
-- @function lua_dynconf.apply(source, module, overrides, version)
-- Applies (or removes, when `overrides` is nil/false) the override table of `source` for a module.
-- On any error the previous state is kept untouched.
-- @return {boolean} ok, or `false, error`; on success the third value is an array of changed paths
--]]
function exports.apply(source, name, overrides, version)
  local mod = modules[name]
  if not mod then
    return false, string.format('unknown module %s', tostring(name))
  end
  if mod.static_only then
    return false, string.format('module %s has no dynamic options', name)
  end
  if type(source) ~= 'string' or source == '' then
    return false, 'override source must be a non-empty string'
  end

  if overrides then
    local ok, err = check_overrides(mod, overrides)
    if not ok then
      return false, err
    end
  end

  add_source(source)
  local candidate = {}
  for k, v in pairs(mod.overrides) do
    candidate[k] = v
  end
  if overrides then
    candidate[source] = { version = version, updated = get_time(), values = deepcopy(overrides) }
  else
    candidate[source] = nil
  end

  local merged = merge_sources(mod, candidate)
  local result, err = run_pipeline(mod, merged)
  if not result then
    return false, err
  end

  -- Every leaf of the old and the new overrides has to be refreshed from the pipeline result
  local leaves = {}
  collect_leaves(mod, mod.merged, leaves)
  collect_leaves(mod, merged, leaves)

  local changed = {}
  local changes = {}
  for key, path in pairs(leaves) do
    local new_value = get_path(result, path)
    local old_value = get_path(mod.settings, path)
    local same
    if type(new_value) == 'table' and type(old_value) == 'table' then
      same = table_cmp(new_value, old_value)
    else
      same = new_value == old_value
    end
    if not same then
      changes[#changes + 1] = { path = path, value = new_value }
      changed[#changed + 1] = key
    end
  end
  table.sort(changed)

  -- The C subscriber decides first: if it rejects the update nothing has been changed
  if #changed > 0 then
    local nok, nerr = notify_c(mod, result)
    if not nok then
      return false, nerr
    end
  end

  for _, change in ipairs(changes) do
    set_path(mod.settings, change.path, change.value)
    if change.value == nil then
      prune_empty(mod.settings, change.path, result)
    end
  end

  mod.overrides = candidate
  mod.merged = merged

  if #changed > 0 then
    mod.version = mod.version + 1
    bump_generation()
    run_hooks(mod, changed)
  end

  return true, nil, changed
end

-- Dump -------------------------------------------------------------------------------------------

local function is_secret_key(key)
  local k = tostring(key):lower():gsub('%-', '_')
  if k == 'key' then
    return true
  end
  for _, w in ipairs(SECRET_WORDS) do
    -- The whole name or its last words: `password`, `redis_password`
    if k == w or (#k > #w and k:sub(-#w - 1) == '_' .. w) then
      return true
    end
  end
  return false
end

local function dump_value(mod, value, path, redact, depth)
  local tv = type(value)
  if tv == 'function' then
    return '<function>'
  elseif tv == 'userdata' then
    return '<userdata>'
  elseif tv ~= 'table' then
    return value
  end
  if depth > MAX_DEPTH then
    return '<too deep>'
  end

  local res = {}
  for k, v in pairs(value) do
    path[#path + 1] = k
    local secret = false
    if redact and v ~= nil then
      secret = is_secret_key(k) or matches_any(mod.secrets, path)
    end
    if secret then
      -- A secret subtree is hidden entirely
      res[k] = REDACTED
    else
      res[k] = dump_value(mod, v, path, redact, depth + 1)
    end
    path[#path] = nil
  end
  return res
end

--[[[
-- @function lua_dynconf.dump(opts)
-- Returns a plain table describing the registry: framework state, backends, and for every module its
-- defaults, static configuration, overrides per source, effective values and dynamic paths.
-- @param {table} opts `module` limits the dump to one module, `redact = false` disables redaction of
-- secrets (keys like password, token, api_key and the module's `secret` paths)
--]]
function exports.dump(opts)
  opts = opts or {}
  local redact = opts.redact ~= false
  local res = {
    enabled = fw.enabled,
    generation = generation,
    policy = fw.policy,
    backends = {},
    modules = {},
  }

  if fw.enabled and fw.backend_name then
    local state = {
      version = fw.applied_count,
      last_check = fw.last_check,
      last_update = fw.last_update,
      last_error = fw.last_error,
    }
    local impl = backends[fw.backend_name]
    if impl and type(impl.version) == 'function' then
      local ok, v = pcall(impl.version)
      if ok and v ~= nil then
        state.version = v
      end
    end
    res.backends[fw.backend_name] = state
  end

  for _, name in ipairs(sorted_keys(modules)) do
    if not opts.module or opts.module == name then
      local mod = modules[name]
      local dyn = {}
      for _, p in ipairs(mod.patterns) do
        dyn[#dyn + 1] = table.concat(p, '.')
      end
      local overrides = {}
      for src, entry in pairs(mod.overrides) do
        overrides[src] = {
          version = entry.version,
          updated = entry.updated,
          values = dump_value(mod, entry.values, {}, redact, 1),
        }
      end
      res.modules[name] = {
        schema_id = mod.schema_id,
        static_only = mod.static_only,
        version = mod.version,
        dynamic = dyn,
        defaults = dump_value(mod, mod.defaults, {}, redact, 1),
        static = dump_value(mod, mod.static, {}, redact, 1),
        overrides = overrides,
        effective = dump_value(mod, mod.settings or mod.static, {}, redact, 1),
      }
    end
  end

  return res
end

--[[[
-- @function lua_dynconf.dump_json(opts)
-- Same as `dump` but returns a compact JSON string
--]]
function exports.dump_json(opts)
  local ucl = require "ucl"
  return ucl.to_format(exports.dump(opts), 'json-compact')
end

-- Backends and the framework ---------------------------------------------------------------------

--[[[
-- @function lua_dynconf.register_backend(name, impl)
-- Registers an override source. `impl` has `configure(section) -> ok, err`, `start(cfg, ev_base, worker)`,
-- `check(ev_base, cb)` where `cb(err, updates, commit)` and `updates` is `nil` (nothing changed) or
-- `{ [module] = { version = n, values = tbl } | false }`; the optional `commit` function is called when the
-- registry accepts the result (not when it is stale), so that a backend can record what it has delivered.
-- An optional `set(ctx, module, values, cb)` writes an override
--]]
function exports.register_backend(name, impl)
  if type(name) ~= 'string' or type(impl) ~= 'table' or type(impl.check) ~= 'function' then
    return false, 'invalid backend'
  end
  backends[name] = impl
  add_source(name)
  return true
end

local function parse_number(v)
  if type(v) == 'string' then
    return lua_util.parse_time_interval(v)
  end
  return tonumber(v)
end

local function disarm_c()
  local arm = cfg_method('dynconf_arm')
  if arm then
    pcall(arm, rspamd_config, 0)
  end
end

local function finish_check(token, cb, err, updates, commit)
  if token ~= fw.token then
    -- A timed out check completed late: its result is stale
    dbg('ignoring a stale dynconf check result')
    return
  end
  fw.inflight = false
  fw.last_check = get_time()

  if err then
    fw.last_error = tostring(err)
    logger.warnx(rspamd_config, 'dynconf check failed: %s', err)
    if cb then
      cb(err)
    end
    return
  end

  -- The backend records what it has delivered only for a result that is not stale
  if type(commit) == 'function' then
    local cok, cerr = pcall(commit)
    if not cok then
      logger.warnx(rspamd_config, 'dynconf: backend commit failed: %s', cerr)
    end
  end

  local applied = {}
  local errors = {}
  if type(updates) == 'table' then
    for _, name in ipairs(sorted_keys(updates)) do
      local upd = updates[name]
      if not modules[name] then
        dbg('ignoring an update for an unknown module %s', name)
      else
        local ok, aerr
        if upd == false then
          ok, aerr = exports.apply(fw.backend_name, name, nil)
        elseif type(upd) == 'table' then
          ok, aerr = exports.apply(fw.backend_name, name, upd.values or {}, upd.version)
        else
          ok, aerr = false, 'invalid update'
        end
        if ok then
          applied[#applied + 1] = name
        else
          errors[#errors + 1] = string.format('%s: %s', name, aerr)
          logger.warnx(rspamd_config, 'dynconf: cannot apply update for %s: %s', name, aerr)
        end
      end
    end
  end

  if #applied > 0 then
    fw.last_update = fw.last_check
    fw.applied_count = fw.applied_count + 1
  end
  if #errors > 0 then
    fw.last_error = table.concat(errors, '; ')
  else
    fw.last_error = nil
  end

  if cb then
    cb(#errors > 0 and fw.last_error or nil, applied)
  end
end

--[[[
-- @function lua_dynconf.check_now(ev_base, cb)
-- Asks the backend for updates right now and applies them. Only one check runs at a time: if one is
-- in flight (and has not timed out) returns `false` and calls `cb('check in progress')`.
-- `cb(err, applied_modules)` is optional.
-- @return {boolean} true if a check was started
--]]
function exports.check_now(ev_base, cb)
  local backend = fw.backend_name and backends[fw.backend_name]
  if not fw.enabled or not backend then
    if cb then
      cb('dynconf is not enabled')
    end
    return false
  end

  local now = get_time()
  if fw.inflight then
    if now - fw.inflight_since < INFLIGHT_TIMEOUT then
      if cb then
        cb('check in progress')
      end
      return false
    end
    logger.warnx(rspamd_config, 'dynconf: previous check has timed out, starting a new one')
  end

  fw.token = fw.token + 1
  local token = fw.token
  fw.inflight = true
  fw.inflight_since = now

  local done = false
  local ok, err = pcall(backend.check, ev_base or fw.ev_base, function(cerr, updates, commit)
    if done then
      return
    end
    done = true
    finish_check(token, cb, cerr, updates, commit)
  end)

  if not ok and not done then
    done = true
    finish_check(token, cb, err)
  end

  return true
end

--[[[
-- @function lua_dynconf.set(module, values, ctx, cb)
-- Applies an override locally (`values == nil` removes it) and writes it through the backend; if the write
-- fails the local change is rolled back.
-- `ctx` is `{ task = t }` or `{ ev_base = e }`; `cb(err)` is called when done.
--]]
function exports.set(name, values, ctx, cb)
  local backend = fw.backend_name and backends[fw.backend_name]
  if not fw.enabled or not backend then
    return false, 'dynconf is not enabled'
  end
  if type(backend.set) ~= 'function' then
    return false, 'backend does not support writes'
  end
  local source = fw.backend_name
  local ok, err = exports.validate(name, values or nil, source)
  if not ok then
    return false, err
  end

  -- Apply locally first: the C subscribers can still reject the values, and then nothing is written
  local mod = modules[name]
  local prev = mod.overrides[source]
  local prev_values = prev and prev.values and deepcopy(prev.values) or nil
  local prev_version = prev and prev.version
  local aok, aerr = exports.apply(source, name, values or nil, nil)
  if not aok then
    return false, aerr
  end
  local mine = mod.overrides[source]

  ctx = ctx or { ev_base = fw.ev_base }
  backend.set(ctx, name, values or nil, function(serr, version)
    -- Nothing must be rolled back if a check has replaced the entry in the meantime
    local still_mine = mod.overrides[source] == mine
    if serr then
      if still_mine then
        local rok, rerr = exports.apply(source, name, prev_values, prev_version)
        if not rok then
          logger.warnx(rspamd_config, 'dynconf: cannot roll back the override of %s: %s', name, rerr)
        end
      end
      if cb then
        cb(serr)
      end
      return
    end
    if still_mine and mine then
      mine.version = version
    end
    if cb then
      cb(nil)
    end
  end)
  return true
end

local function arm_on_access(ev_base)
  local arm = cfg_method('dynconf_arm')
  if not arm then
    dbg('on-access policy requested but the C hook is not available')
    return
  end

  local function trigger(_, loop)
    -- Re-arm first so that a slow backend never causes repeated triggers
    pcall(arm, rspamd_config, get_time() + fw.ttl, trigger)
    exports.check_now(type(loop) == 'userdata' and loop or ev_base)
  end

  pcall(arm, rspamd_config, get_time(), trigger)
end

--[[[
-- @function lua_dynconf.start(cfg, ev_base, worker)
-- Starts the configured backend in a worker and arms the update policy. Called from `on_load`.
--]]
function exports.start(cfg, ev_base, worker)
  if not fw.enabled or fw.started then
    return false
  end
  local backend = backends[fw.backend_name]
  if not backend then
    return false
  end

  fw.started = true
  fw.ev_base = ev_base
  fw.worker = worker

  if type(backend.start) == 'function' then
    local ok, err = pcall(backend.start, cfg, ev_base, worker)
    if not ok then
      logger.errx(rspamd_config, 'dynconf: cannot start backend %s: %s', fw.backend_name, err)
      fw.last_error = tostring(err)
      return false
    end
  end

  local policy = fw.policy
  if policy == 'interval' or policy == 'both' then
    -- math.random has the same state in every worker (it is seeded before fork), so workers would probe
    -- in lockstep: use a private generator (Park-Miller) seeded after fork
    local seed = (tonumber(rspamd_util.random_hex(8), 16) or 1) % 2147483646 + 1
    local function rnd()
      seed = (seed * 16807) % 2147483647
      return seed / 2147483647
    end
    local function delay()
      local j = fw.jitter
      return fw.interval * (1.0 + j * (rnd() * 2.0 - 1.0))
    end
    local function tick()
      exports.check_now(ev_base)
      return delay()
    end
    rspamd_config:add_periodic(ev_base, 0.1 + rnd() * fw.jitter * fw.interval, tick, false)
  end
  if policy == 'on_access' or policy == 'both' then
    arm_on_access(ev_base)
  end

  return true
end

--[[[
-- @function lua_dynconf.configure(section)
-- Configures the framework from the (already parsed) `dynconf` section. Normally called automatically
-- on the first `register`; calling it explicitly is useful for tests.
-- @return {boolean} ok, or `false, error` (the framework stays disabled)
--]]
function exports.configure(section)
  fw.configured = true
  fw.enabled = false
  fw.section = section

  if type(section) ~= 'table' or not section.enabled then
    return true
  end

  local policy = section.policy or 'interval'
  if not POLICIES[policy] then
    return false, string.format('invalid dynconf policy "%s"', tostring(policy))
  end

  local interval = section.interval and parse_number(section.interval) or 10.0
  local ttl = section.ttl and parse_number(section.ttl) or 10.0
  local jitter = tonumber(section.jitter) or 0.2
  if not interval or interval <= 0 or not ttl or ttl <= 0 then
    return false, 'invalid dynconf interval or ttl'
  end
  if jitter < 0 or jitter > 1 then
    return false, 'dynconf jitter must be between 0 and 1'
  end

  local backend_name = section.backend or 'redis'
  if not backends[backend_name] and backend_name == 'redis' then
    local ok, impl = pcall(require, "lua_dynconf.redis")
    if not ok then
      return false, string.format('cannot load the redis backend: %s', impl)
    end
    exports.register_backend('redis', impl)
  end
  local backend = backends[backend_name]
  if not backend then
    return false, string.format('unknown dynconf backend "%s"', tostring(backend_name))
  end

  if type(backend.configure) == 'function' then
    local ok, bok, berr = pcall(backend.configure, section)
    if not ok then
      return false, string.format('cannot configure backend %s: %s', backend_name, bok)
    end
    if not bok then
      return false, string.format('cannot configure backend %s: %s', backend_name, berr)
    end
  end

  fw.backend_name = backend_name
  fw.policy = policy
  fw.interval = interval
  fw.ttl = ttl
  fw.jitter = jitter
  fw.enabled = true
  add_source(backend_name)

  local add_on_load = cfg_method('add_on_load')
  if not fw.on_load_registered and add_on_load and not _G.confighelp then
    fw.on_load_registered = true
    add_on_load(rspamd_config, function(cfg, ev_base, worker)
      exports.start(cfg, ev_base, worker)
    end)
  end

  return true
end

ensure_framework = function()
  if fw.configured then
    return
  end
  fw.configured = true

  local get_all_opt = cfg_method('get_all_opt')
  if _G.confighelp or not get_all_opt then
    return
  end

  local ok, section = pcall(get_all_opt, rspamd_config, 'dynconf')
  if not ok or type(section) ~= 'table' then
    return
  end

  local cok, cerr = exports.configure(section)
  if not cok then
    logger.errx(rspamd_config, 'dynconf is disabled: %s', cerr)
    fw.enabled = false
    disarm_c()
  end
end

return exports
