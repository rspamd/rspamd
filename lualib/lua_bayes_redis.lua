--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- This file contains functions to support Bayes statistics in Redis

local exports = {}
local lua_redis = require "lua_redis"
local logger = require "rspamd_logger"
local lua_util = require "lua_util"

local N = "bayes"

local function gen_classify_functor(redis_params, classify_script_id)
  return function(task, expanded_key, id, is_spam, stat_tokens, callback)

    local function classify_redis_cb(err, data)
      lua_util.debugm(N, task, 'classify redis cb: %s, %s', err, data)
      if err then
        callback(task, false, err)
      else
        callback(task, true, data[1], data[2], data[3], data[4])
      end
    end

    lua_redis.exec_redis_script(classify_script_id,
        { task = task, is_write = false, key = expanded_key },
        classify_redis_cb, { expanded_key, stat_tokens })
  end
end

local function gen_learn_functor(redis_params, learn_script_id)
  return function(task, expanded_key, id, is_spam, symbol, is_unlearn, stat_tokens, callback)
    local function learn_redis_cb(err, data)
      lua_util.debugm(N, task, 'learn redis cb: %s, %s', err, data)
      if err then
        callback(task, false, err)
      else
        callback(task, true)
      end
    end

    lua_redis.exec_redis_script(learn_script_id,
        { task = task, is_write = false, key = expanded_key },
        learn_redis_cb, { expanded_key, tostring(is_spam), symbol, tostring(is_unlearn), stat_tokens })
  end
end

---
--- Init bayes classifier
--- @param classifier_ucl ucl of the classifier config
--- @param statfile_ucl ucl of the statfile config
--- @return a pair of (classify_functor, learn_functor) or `nil` in case of error
exports.lua_bayes_init_classifier = function(classifier_ucl, statfile_ucl, symbol, stat_periodic_cb)
  local redis_params

  if classifier_ucl.backend then
    redis_params = lua_redis.try_load_redis_servers(classifier_ucl.backend, rspamd_config, true)
  end

  -- Try load from statfile options
  if not redis_params then
    if statfile_ucl then
      redis_params = lua_redis.try_load_redis_servers(statfile_ucl, rspamd_config, true)
    end
  end

  -- Load directly from classifier config
  if not redis_params then
    redis_params = lua_redis.try_load_redis_servers(classifier_ucl, rspamd_config, false, "statistics")
  end

  if not redis_params then
    logger.err(rspamd_config, "cannot load Redis parameters for the classifier")
    return nil
  end

  local classify_script_id = lua_redis.load_redis_script_from_file("bayes_classify.lua", redis_params)
  local learn_script_id = lua_redis.load_redis_script_from_file("bayes_learn.lua", redis_params)
  local stat_script_id = lua_redis.load_redis_script_from_file("bayes_stat.lua", redis_params)
  local max_users = classifier_ucl.max_users or 1000

  rspamd_config:add_on_load(function(_, ev_base, _)

    rspamd_config:add_periodic(ev_base, 0.0, function(cfg, _)

      local function stat_redis_cb(err, data)
        -- TODO: write this function

      end

      lua_redis.exec_redis_script(stat_script_id,
          { ev_base = ev_base, cfg = cfg, is_write = false },
          stat_redis_cb, { symbol, max_users })
      return 30.0 -- TODO: make configurable
    end)
  end)

  return gen_classify_functor(redis_params, classify_script_id), gen_learn_functor(redis_params, learn_script_id)
end

return exports