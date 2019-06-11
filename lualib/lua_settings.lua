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

-- Returns numeric representation of the settings id
local function numeric_settings_id(str)
  local cr = require "rspamd_cryptobox_hash"
  local util = require "rspamd_util"
  local ret = util.unpack("I4",
      cr.create_specific('xxh64'):update(str):bin())

  return ret
end

local function register_settings_id(str, settings)
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
      settings = settings
    }
  end

  return numeric_id
end

exports.register_settings_id = register_settings_id

local function reset_ids()
  known_ids = {}
end

exports.reset_ids = reset_ids

local function settings_by_id(id)
  return known_ids[id]
end

exports.settings_by_id = settings_by_id

return exports