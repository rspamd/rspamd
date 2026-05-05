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
-- regexp rules from $LOCAL_CONFDIR/lua.local.d/{selectors,maps,regexps}/*.lua
-- without touching rspamd.local.lua.
--
-- Each structured file is expected to `return` a table whose entries are
-- registered with the matching helper. Errors in any single file are logged
-- and do not abort startup.
--]]

local exports = {}

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_selectors = require "lua_selectors"

--[[[
-- @function lua_extras.register_selector(cfg, name, def)
-- Registers a selector extractor.
-- `def` may be a function (treated as `get_value`) or a full selector table
-- (`{ get_value = fn, description = '...', type = '...' }`).
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

  return lua_selectors.register_extractor(cfg, name, def)
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
  selectors = exports.register_selector,
  maps = exports.register_map,
  regexps = exports.register_regexp,
}

--[[[
-- @function lua_extras.load_dir(cfg, dir, kind)
-- Loads every *.lua file in `dir`, expecting each to return a table of
-- { name = def } pairs. Each pair is dispatched to the helper for `kind`
-- (one of 'selectors', 'maps', 'regexps'). Errors are logged and skipped.
--]]
exports.load_dir = function(cfg, dir, kind)
  local handler = kind_handlers[kind]
  if not handler then
    rspamd_logger.errx(cfg, 'lua_extras: unknown kind %s for dir %s', kind, dir)
    return
  end

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
            handler(cfg, name, def)
          end
        end
      end
    end
  end
end

return exports
