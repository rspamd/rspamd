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

local logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local meta_functions = require "lua_meta"
local maps = require "lua_maps"

local exports = {}

exports.rspamd_parse_redis_server = lua_redis.rspamd_parse_redis_server
exports.parse_redis_server = lua_redis.rspamd_parse_redis_server
exports.rspamd_redis_make_request = lua_redis.rspamd_redis_make_request
exports.redis_make_request = lua_redis.rspamd_redis_make_request

exports.rspamd_gen_metatokens = meta_functions.rspamd_gen_metatokens
exports.rspamd_count_metatokens = meta_functions.rspamd_count_metatokens

exports.rspamd_map_add = maps.rspamd_map_add

exports.rspamd_str_split = lua_util.rspamd_str_split

-- a special syntax sugar to export all functions to the global table
setmetatable(exports, {
  __call = function(t, override)
    for k, v in pairs(t) do
      if _G[k] ~= nil then
        local msg = 'function ' .. k .. ' already exists in global scope.'
        if override then
          _G[k] = v
          logger.errx('WARNING: ' .. msg .. ' Overwritten.')
        else
          logger.errx('NOTICE: ' .. msg .. ' Skipped.')
        end
      else
        _G[k] = v
      end
    end
  end,
})

return exports
