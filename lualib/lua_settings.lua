--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
-- @module lua_settings
-- This module contains internal helpers for the settings infrastructure in Rspamd
-- More details at https://rspamd.com/doc/configuration/settings.html
--]]

local exports = {}
local known_ids = {}
local post_init_added = false
local post_init_performed = false
local all_symbols
local default_symbols

local fun = require "fun"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"

local function register_settings_cb(from_postload)
  if not post_init_performed then
    all_symbols = rspamd_config:get_symbols()

    default_symbols = fun.totable(fun.filter(function(_, v)
      return not v.allowed_ids or #v.allowed_ids == 0 or v.flags.explicit_disable
    end,all_symbols))

    local explicit_symbols = lua_util.keys(fun.filter(function(k, v)
      return v.flags.explicit_disable
    end, all_symbols))

    local symnames = lua_util.list_to_hash(lua_util.keys(all_symbols))

    for _,set in pairs(known_ids) do
      local s = set.settings.apply or {}
      set.symbols = lua_util.shallowcopy(symnames)
      local enabled_symbols = {}
      local seen_enabled = false
      local disabled_symbols = {}
      local seen_disabled = false

      -- Enabled map
      if s.symbols_enabled then
        -- Remove all symbols from set.symbols aside of explicit_disable symbols
        set.symbols = lua_util.list_to_hash(explicit_symbols)
        seen_enabled = true
        for _,sym in ipairs(s.symbols_enabled) do
          enabled_symbols[sym] = true
          set.symbols[sym] = true
        end
      end
      if s.groups_enabled then
        seen_enabled = true
        for _,gr in ipairs(s.groups_enabled) do
          local syms = rspamd_config:get_group_symbols(gr)

          if syms then
            for _,sym in ipairs(syms) do
              enabled_symbols[sym] = true
              set.symbols[sym] = true
            end
          end
        end
      end

      -- Disabled map
      if s.symbols_disabled then
        seen_disabled = true
        for _,sym in ipairs(s.symbols_disabled) do
          disabled_symbols[sym] = true
          set.symbols[sym] = false
        end
      end
      if s.groups_disabled then
        seen_disabled = true
        for _,gr in ipairs(s.groups_disabled) do
          local syms = rspamd_config:get_group_symbols(gr)

          if syms then
            for _,sym in ipairs(syms) do
              disabled_symbols[sym] = true
              set.symbols[sym] = false
            end
          end
        end
      end

      -- Deal with complexity to avoid mess in C
      if not seen_enabled then enabled_symbols = nil end
      if not seen_disabled then disabled_symbols = nil end

      if enabled_symbols or disabled_symbols then
        -- Specify what symbols are really enabled for this settings id
        set.has_specific_symbols = true
      end

      rspamd_config:register_settings_id(set.name, enabled_symbols, disabled_symbols)

      -- Remove to avoid clash
      s.symbols_disabled = nil
      s.symbols_enabled = nil
      s.groups_enabled = nil
      s.groups_disabled = nil
    end

    -- We now iterate over all symbols and check for allowed_ids/forbidden_ids
    for k,v in pairs(all_symbols) do
      if v.allowed_ids and not v.flags.explicit_disable then
        for _,id in ipairs(v.allowed_ids) do
          if known_ids[id] then
            local set = known_ids[id]
            if not set.has_specific_symbols then
              set.has_specific_symbols = true
            end
            set.symbols[k] = true
          else
            rspamd_logger.errx(rspamd_config, 'symbol %s is allowed at unknown settings id %s',
                k, id)
          end
        end
      end
      if v.forbidden_ids then
        for _,id in ipairs(v.forbidden_ids) do
          if known_ids[id] then
            local set = known_ids[id]
            if not set.has_specific_symbols then
              set.has_specific_symbols = true
            end
            set.symbols[k] = false
          else
            rspamd_logger.errx(rspamd_config, 'symbol %s is denied at unknown settings id %s',
                k, id)
          end
        end
      end
    end

    -- Now we create lists of symbols for each settings and digest
    for _,set in pairs(known_ids) do
      set.symbols = lua_util.keys(fun.filter(function(_, v) return v end, set.symbols))
      table.sort(set.symbols)
      set.digest = lua_util.table_digest(set.symbols)
    end

    post_init_performed = true
  end
end

-- Returns numeric representation of the settings id
local function numeric_settings_id(str)
  local cr = require "rspamd_cryptobox_hash"
  local util = require "rspamd_util"
  local ret = util.unpack("I4",
      cr.create_specific('xxh64'):update(str):bin())

  return ret
end

exports.numeric_settings_id = numeric_settings_id

-- Used to do the following:
-- If there is a group of symbols_allowed, it checks if that is an array
-- If that is a hash table then we transform it to a normal list, probably adding symbols to adjust scores
local function transform_settings_maybe(settings, name)
  if settings.apply then
    local apply = settings.apply

    if apply.symbols_enabled then
      local senabled = apply.symbols_enabled

      if not senabled[1] then
        -- Transform map to a list
        local nlist = {}
        if not apply.scores then
          apply.scores = {}
        end
        for k,v in pairs(senabled) do
          if tonumber(v) then
            -- Move to symbols as well
            apply.scores[k] = tonumber(v)
            lua_util.debugm('settings', rspamd_config,
                'set symbol %s -> %s for settings %s', k, v, name)
          end
          nlist[#nlist + 1] = k
        end
        -- Convert
        apply.symbols_enabled = nlist
      end

      local symhash = lua_util.list_to_hash(apply.symbols_enabled)

      if apply.symbols then
        -- Check if added symbols are enabled
        for k,v in pairs(apply.symbols) do
          local s
          -- Check if we have ["sym1", "sym2" ...] or {"sym1": xx, "sym2": yy}
          if type(k) == 'string' then
            s = k
          else
            s = v
          end
          if not symhash[s] then
            lua_util.debugm('settings', rspamd_config,
                'added symbol %s to symbols_enabled for %s', s, name)
            apply.symbols_enabled[#apply.symbols_enabled + 1] = s
          end
        end
      end
    end
  end

  return settings
end

local function register_settings_id(str, settings, from_postload)
  local numeric_id = numeric_settings_id(str)

  if known_ids[numeric_id] then
    -- Might be either rewrite or a collision
    if known_ids[numeric_id].name ~= str then
      local logger = require "rspamd_logger"

      logger.errx(rspamd_config, 'settings ID clash! id %s maps to %s and conflicts with %s',
          numeric_id, known_ids[numeric_id].name, str)

      return nil
    end
  else
    known_ids[numeric_id] = {
      name = str,
      id = numeric_id,
      settings = transform_settings_maybe(settings, str),
      symbols = {}
    }
  end

  if not from_postload and not post_init_added then
    -- Use high priority to ensure that settings are initialised early but not before all
    -- plugins are loaded
    rspamd_config:add_post_init(function () register_settings_cb(true) end, 150)
    rspamd_config:add_config_unload(function()
      if post_init_added then
        known_ids = {}
        post_init_added = false
      end
      post_init_performed = false
    end)

    post_init_added = true
  end

  return numeric_id
end

exports.register_settings_id = register_settings_id


local function settings_by_id(id)
  if not post_init_performed then
    register_settings_cb(false)
  end
  return known_ids[id]
end


exports.settings_by_id = settings_by_id
exports.all_settings = function()
  if not post_init_performed then
    register_settings_cb(false)
  end
  return known_ids
end
exports.all_symbols = function()
  if not post_init_performed then
    register_settings_cb(false)
  end
  return all_symbols
end
-- What is enabled when no settings are there
exports.default_symbols = function()
  if not post_init_performed then
    register_settings_cb(false)
  end
  return default_symbols
end

exports.load_all_settings = register_settings_cb

return exports