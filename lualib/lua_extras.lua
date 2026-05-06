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
-- @module lua_extras
-- Helpers and a directory loader for shipping custom selectors, maps and
-- regexp rules from $LOCAL_CONFDIR/lua.local.d/{maps,selectors,regexps}/*.lua
-- without touching rspamd.local.lua.
--
-- Loading is two-phase: phase 1 collects every entry from every file into
-- staging buffers; phase 2 resolves and registers them in dependency order
-- (maps -> selectors -> regexps). Entries that need to inspect siblings
-- registered earlier in the same pass (typical example: a selector that
-- captures `rspamd_maps[name]` or compiles an `rspamd_regexp` from map data)
-- can wrap their definition in `lua_extras.deferred(factory_fn)` so the
-- factory runs after all earlier-kind entries are registered.
--
-- Errors in any single file or entry are logged and skipped; they never
-- abort startup.
--]]

local exports = {}

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_selectors = require "lua_selectors"

local DEFERRED_MARKER = '__lua_extras_deferred'

--[[[
-- @function lua_extras.deferred(factory)
-- Wraps a factory function so the loader calls it during phase 2, after all
-- earlier-kind entries have been registered, and uses the returned table as
-- the concrete definition. The factory receives `(cfg)`.
--]]
exports.deferred = function(factory)
  if type(factory) ~= 'function' then
    error('lua_extras.deferred: expected a function, got ' .. type(factory))
  end
  return { [DEFERRED_MARKER] = true, factory = factory }
end

local function is_deferred(v)
  return type(v) == 'table' and v[DEFERRED_MARKER] == true
end

--[[[
-- @function lua_extras.register_selector(cfg, name, def)
-- Registers a selector extractor.
-- `def` may be:
--   * a function - treated as `get_value`;
--   * a full selector table - `{ get_value = fn, description = ..., type = ... }`.
--
-- An optional `re_selector` field opts the selector into the regexp DSL by
-- calling `cfg:register_re_selector(name, selector_str, delimiter)` after the
-- extractor is registered. It accepts either:
--   * `true` - bind alias `name` to the selector pipeline `name` with delimiter ' ';
--   * `{ selector = '<pipeline>', delimiter = ' ' }` - explicit binding.
--
-- Returns true on success, false on error.
--]]
exports.register_selector = function(cfg, name, def)
  if type(def) == 'function' then
    def = { get_value = def }
  end

  if type(def) ~= 'table' or type(def.get_value) ~= 'function' then
    rspamd_logger.errx(cfg, 'lua_extras: bad selector %s: expected function or table with get_value',
        name)
    return false
  end

  local re_sel = def.re_selector
  -- lua_selectors does not need this field
  def.re_selector = nil

  if not lua_selectors.register_extractor(cfg, name, def) then
    return false
  end

  if re_sel then
    local pipeline, delimiter
    if re_sel == true then
      pipeline, delimiter = name, ' '
    elseif type(re_sel) == 'table' then
      pipeline = re_sel.selector or name
      delimiter = re_sel.delimiter or ' '
    else
      rspamd_logger.errx(cfg,
          'lua_extras: bad re_selector for selector %s: expected true or table', name)
      return true
    end
    local ok, err = pcall(function()
      cfg:register_re_selector(name, pipeline, delimiter)
    end)
    if not ok then
      rspamd_logger.errx(cfg,
          'lua_extras: register_re_selector failed for %s: %s', name, err)
    end
  end

  return true
end

--[[[
-- @function lua_extras.register_map(cfg, name, args)
-- Registers a map. `args` is the table accepted by rspamd_config:add_map().
-- The created map object is stored as rspamd_maps[name] so it can be looked
-- up by other lua code.
-- Returns the map object on success, nil on error.
--]]
exports.register_map = function(cfg, name, args)
  if type(args) ~= 'table' then
    rspamd_logger.errx(cfg, 'lua_extras: bad map %s: expected table of add_map arguments', name)
    return nil
  end

  rspamd_maps = rspamd_maps or {}

  local ok, map_or_err = pcall(function()
    return cfg:add_map(args)
  end)

  if not ok or not map_or_err then
    rspamd_logger.errx(cfg, 'lua_extras: cannot add map %s: %s', name, map_or_err)
    return nil
  end

  rspamd_maps[name] = map_or_err
  return map_or_err
end

--[[[
-- @function lua_extras.register_regexp(cfg, symbol, def)
-- Registers a regexp rule by assigning it into config['regexp'][symbol],
-- matching the rspamd.local.lua / *.lua pattern documented in
-- conf/lua.local.d/module.lua.example.
-- Returns true on success, false on error.
--]]
exports.register_regexp = function(cfg, symbol, def)
  if type(def) ~= 'table' or type(def.re) ~= 'string' then
    rspamd_logger.errx(cfg, 'lua_extras: bad regexp %s: expected table with `re` string', symbol)
    return false
  end

  config = config or {}
  config['regexp'] = config['regexp'] or {}

  if config['regexp'][symbol] then
    rspamd_logger.warnx(cfg, 'lua_extras: redefining regexp symbol %s', symbol)
  end

  config['regexp'][symbol] = def
  return true
end

local kind_handlers = {
  maps = exports.register_map,
  selectors = exports.register_selector,
  regexps = exports.register_regexp,
}

-- Resolution order for cross-kind dependencies:
--   maps     - register first (no deps)
--   selectors - may consume maps (rspamd_maps[name]) at definition or task time
--   regexps  - may reference selectors via the {name} expansion syntax
local KIND_ORDER = { 'maps', 'selectors', 'regexps' }

local function preload_one_dir(cfg, dir, kind, sink)
  local files = rspamd_util.glob(dir .. '/*.lua') or {}
  -- Stable ordering across platforms
  table.sort(files)

  for _, path in ipairs(files) do
    local ok, chunk = pcall(loadfile, path)
    if not ok or not chunk then
      rspamd_logger.errx(cfg, 'lua_extras: cannot load %s: %s', path, chunk)
    else
      local run_ok, ret = pcall(chunk)
      if not run_ok then
        rspamd_logger.errx(cfg, 'lua_extras: error executing %s: %s', path, ret)
      elseif type(ret) ~= 'table' then
        rspamd_logger.warnx(cfg,
            'lua_extras: %s did not return a table (kind=%s), skipped', path, kind)
      else
        for name, def in pairs(ret) do
          if type(name) ~= 'string' then
            rspamd_logger.errx(cfg,
                'lua_extras: %s contains non-string key (kind=%s), skipped entry', path, kind)
          else
            table.insert(sink, { name = name, def = def, path = path })
          end
        end
      end
    end
  end
end

local function resolve_entry(cfg, entry, kind)
  local def = entry.def
  if is_deferred(def) then
    local ok, ret = pcall(def.factory, cfg)
    if not ok then
      rspamd_logger.errx(cfg,
          'lua_extras: deferred factory for %s/%s in %s failed: %s',
          kind, entry.name, entry.path, ret)
      return nil
    end
    return ret
  end
  return def
end

--[[[
-- @function lua_extras.load_extras(cfg, base_dir)
-- Two-phase loader: globs `base_dir/{maps,selectors,regexps}/*.lua`,
-- collects every returned entry, then registers them in dependency order
-- (maps -> selectors -> regexps). Deferred entries (see lua_extras.deferred)
-- are evaluated during phase 2 so they can see entries from earlier kinds.
--]]
exports.load_extras = function(cfg, base_dir)
  local staged = {}
  for _, kind in ipairs(KIND_ORDER) do
    staged[kind] = {}
    preload_one_dir(cfg, base_dir .. '/' .. kind, kind, staged[kind])
  end

  for _, kind in ipairs(KIND_ORDER) do
    local handler = kind_handlers[kind]
    for _, entry in ipairs(staged[kind]) do
      local resolved = resolve_entry(cfg, entry, kind)
      if resolved ~= nil then
        handler(cfg, entry.name, resolved)
      end
    end
  end
end

--[[[
-- @function lua_extras.load_dir(cfg, dir, kind)
-- Single-kind loader. Useful when a closed plugin or other code wants to
-- ingest a structured directory of one specific kind. For the standard
-- $LOCAL_CONFDIR/lua.local.d tree, prefer lua_extras.load_extras() which
-- handles cross-kind ordering.
--]]
exports.load_dir = function(cfg, dir, kind)
  local handler = kind_handlers[kind]
  if not handler then
    rspamd_logger.errx(cfg, 'lua_extras: unknown kind %s for dir %s', kind, dir)
    return
  end

  local sink = {}
  preload_one_dir(cfg, dir, kind, sink)
  for _, entry in ipairs(sink) do
    local resolved = resolve_entry(cfg, entry, kind)
    if resolved ~= nil then
      handler(cfg, entry.name, resolved)
    end
  end
end

return exports
