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
]]

-- Lua module for fuzzy Redis backend update path (following the Bayes pattern)

local exports = {}
local lua_redis = require "lua_redis"
local logger = require "rspamd_logger"

local N = "fuzzy_redis"

local function gen_update_functor(redis_params, update_script_id)
  -- Returns function(ev_base, prefix, updates, src, expire, callback)
  -- updates is an array of tables: {op, digest, flag, value, is_weak, shingle_keys}
  -- callback(success_boolean) is called when all operations complete
  return function(ev_base, prefix, updates, src, expire, callback)
    local n_ops = 0
    local n_completed = 0
    local has_error = false
    local count_key = prefix .. "_count"

    -- Count actual operations (skip "dup")
    for _, upd in ipairs(updates) do
      if upd.op ~= "dup" then
        n_ops = n_ops + 1
      end
    end

    -- Final step: INCR version key and invoke callback
    local function do_version_incr()
      local version_key = prefix .. src

      local function version_cb(err, _)
        if err then
          logger.errx(rspamd_config, '%s: version INCR failed for %s: %s',
              N, version_key, err)
        end
        callback(not has_error)
      end

      if not lua_redis.redis_make_request_taskless(ev_base, rspamd_config,
          redis_params, version_key, true, version_cb, 'INCR', { version_key }) then
        logger.errx(rspamd_config, '%s: cannot make version INCR request', N)
        callback(false)
      end
    end

    -- Called when one exec_redis_script completes
    local function on_op_complete()
      n_completed = n_completed + 1
      if n_completed >= n_ops then
        do_version_incr()
      end
    end

    -- If no actual operations, just do version INCR
    if n_ops == 0 then
      do_version_incr()
      return
    end

    for _, upd in ipairs(updates) do
      if upd.op ~= "dup" then
        local hash_key = prefix .. upd.digest

        -- Build KEYS array for the Redis script
        local keys = {
          hash_key,
          upd.op,
          tostring(upd.flag),
          tostring(upd.value),
          tostring(expire),
          tostring(upd.timestamp),
          tostring(upd.is_weak),
          count_key,
          upd.digest,
        }

        -- Append shingle keys if present
        if upd.shingle_keys then
          for _, sk in ipairs(upd.shingle_keys) do
            keys[#keys + 1] = sk
          end
        end

        local function update_cb(err, _)
          if err then
            logger.errx(rspamd_config, '%s: update script failed: %s', N, err)
            has_error = true
          end
          on_op_complete()
        end

        lua_redis.exec_redis_script(update_script_id,
            { ev_base = ev_base, is_write = true, key = hash_key },
            update_cb, keys)
      end
    end
  end
end

-- Initialize fuzzy Redis update module
-- @param redis_params table returned by lua_redis.try_load_redis_servers
-- @return update functor or nil on error
exports.lua_fuzzy_redis_init = function(redis_params)
  if not redis_params then
    logger.errx(rspamd_config, '%s: no redis params provided', N)
    return nil
  end

  local update_script_id, err = lua_redis.load_redis_script_from_file(
      "fuzzy_update.lua", redis_params)
  if not update_script_id then
    logger.errx(rspamd_config, '%s: cannot load fuzzy_update.lua: %s', N,
        err or "unknown error")
    return nil
  end

  return gen_update_functor(redis_params, update_script_id)
end

return exports
