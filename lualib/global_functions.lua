local logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local meta_functions = require "meta_functions"
local maps = require "maps"

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
