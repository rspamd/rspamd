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

local N = "stat_redis"

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
  return function(task, expanded_key, id, is_spam, stat_tokens, callback)
    -- TODO: write this function
  end
end

---
--- Init bayes classifier
--- @param classifier_ucl ucl of the classifier config
--- @param statfile_ucl ucl of the statfile config
--- @return a pair of (classify_functor, learn_functor) or `nil` in case of error
exports.lua_bayes_init_classifier = function(classifier_ucl, statfile_ucl)
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

  return gen_classify_functor(redis_params, classify_script_id), gen_learn_functor(redis_params, learn_script_id)
end

return exports