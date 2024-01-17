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
local ucl = require "ucl"

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
  return function(task, expanded_key, id, is_spam, symbol, is_unlearn, stat_tokens, callback, maybe_text_tokens)
    local function learn_redis_cb(err, data)
      lua_util.debugm(N, task, 'learn redis cb: %s, %s', err, data)
      if err then
        callback(task, false, err)
      else
        callback(task, true)
      end
    end

    if maybe_text_tokens then
      lua_redis.exec_redis_script(learn_script_id,
          { task = task, is_write = true, key = expanded_key },
          learn_redis_cb,
          { expanded_key, tostring(is_spam), symbol, tostring(is_unlearn), stat_tokens, maybe_text_tokens })
    else
      lua_redis.exec_redis_script(learn_script_id,
          { task = task, is_write = true, key = expanded_key },
          learn_redis_cb, { expanded_key, tostring(is_spam), symbol, tostring(is_unlearn), stat_tokens })
    end

  end
end

local function load_redis_params(classifier_ucl, statfile_ucl)
  local redis_params

  -- Try load from statfile options
  if statfile_ucl.redis then
    redis_params = lua_redis.try_load_redis_servers(statfile_ucl.redis, rspamd_config, true)
  end

  if not redis_params then
    if statfile_ucl then
      redis_params = lua_redis.try_load_redis_servers(statfile_ucl, rspamd_config, true)
    end
  end

  -- Try load from classifier config
  if not redis_params and classifier_ucl.backend then
    redis_params = lua_redis.try_load_redis_servers(classifier_ucl.backend, rspamd_config, true)
  end

  if not redis_params and classifier_ucl.redis then
    redis_params = lua_redis.try_load_redis_servers(classifier_ucl.redis, rspamd_config, true)
  end

  if not redis_params then
    redis_params = lua_redis.try_load_redis_servers(classifier_ucl, rspamd_config, true)
  end

  -- Try load global options
  if not redis_params then
    redis_params = lua_redis.try_load_redis_servers(rspamd_config:get_all_opt('redis'), rspamd_config, true)
  end

  if not redis_params then
    logger.err(rspamd_config, "cannot load Redis parameters for the classifier")
    return nil
  end

  return redis_params
end

---
--- Init bayes classifier
--- @param classifier_ucl ucl of the classifier config
--- @param statfile_ucl ucl of the statfile config
--- @return a pair of (classify_functor, learn_functor) or `nil` in case of error
exports.lua_bayes_init_statfile = function(classifier_ucl, statfile_ucl, symbol, is_spam, ev_base, stat_periodic_cb)

  local redis_params = load_redis_params(classifier_ucl, statfile_ucl)

  if not redis_params then
    return nil
  end

  local classify_script_id = lua_redis.load_redis_script_from_file("bayes_classify.lua", redis_params)
  local learn_script_id = lua_redis.load_redis_script_from_file("bayes_learn.lua", redis_params)
  local stat_script_id = lua_redis.load_redis_script_from_file("bayes_stat.lua", redis_params)
  local max_users = classifier_ucl.max_users or 1000

  local current_data = {
    users = 0,
    revision = 0,
  }
  local final_data = {
    users = 0,
    revision = 0, -- number of learns
  }
  local cursor = 0
  rspamd_config:add_periodic(ev_base, 0.0, function(cfg, _)

    local function stat_redis_cb(err, data)
      lua_util.debugm(N, cfg, 'stat redis cb: %s, %s', err, data)

      if err then
        logger.warn(cfg, 'cannot get bayes statistics for %s: %s', symbol, err)
      else
        local new_cursor = data[1]
        current_data.users = current_data.users + data[2]
        current_data.revision = current_data.revision + data[3]
        if new_cursor == 0 then
          -- Done iteration
          final_data = lua_util.shallowcopy(current_data)
          current_data = {
            users = 0,
            revision = 0,
          }
          lua_util.debugm(N, cfg, 'final data: %s', final_data)
          stat_periodic_cb(cfg, final_data)
        end

        cursor = new_cursor
      end
    end

    lua_redis.exec_redis_script(stat_script_id,
        { ev_base = ev_base, cfg = cfg, is_write = false },
        stat_redis_cb, { tostring(cursor),
                         symbol,
                         is_spam and "learns_spam" or "learns_ham",
                         tostring(max_users) })
    return statfile_ucl.monitor_timeout or classifier_ucl.monitor_timeout or 30.0
  end)

  return gen_classify_functor(redis_params, classify_script_id), gen_learn_functor(redis_params, learn_script_id)
end

local function gen_cache_check_functor(redis_params, check_script_id, conf)
  local packed_conf = ucl.to_format(conf, 'msgpack')
  return function(task, cache_id, callback)

    local function classify_redis_cb(err, data)
      lua_util.debugm(N, task, 'check cache redis cb: %s, %s (%s)', err, data, type(data))
      if err then
        callback(task, false, err)
      else
        if type(data) == 'number' then
          callback(task, true, data)
        else
          callback(task, false, 'not found')
        end
      end
    end

    lua_util.debugm(N, task, 'checking cache: %s', cache_id)
    lua_redis.exec_redis_script(check_script_id,
        { task = task, is_write = false, key = cache_id },
        classify_redis_cb, { cache_id, packed_conf })
  end
end

local function gen_cache_learn_functor(redis_params, learn_script_id, conf)
  local packed_conf = ucl.to_format(conf, 'msgpack')
  return function(task, cache_id, is_spam)
    local function learn_redis_cb(err, data)
      lua_util.debugm(N, task, 'learn_cache redis cb: %s, %s', err, data)
    end

    lua_util.debugm(N, task, 'try to learn cache: %s', cache_id)
    lua_redis.exec_redis_script(learn_script_id,
        { task = task, is_write = true, key = cache_id },
        learn_redis_cb,
        { cache_id, is_spam and "1" or "0", packed_conf })

  end
end

exports.lua_bayes_init_cache = function(classifier_ucl, statfile_ucl)
  local redis_params = load_redis_params(classifier_ucl, statfile_ucl)

  if not redis_params then
    return nil
  end

  local default_conf = {
    cache_prefix = "learned_ids",
    cache_max_elt = 10000, -- Maximum number of elements in the cache key
    cache_max_keys = 5, -- Maximum number of keys in the cache
    cache_per_user_mult = 0.1, -- Multiplier for per user cache size
    cache_elt_len = 32, -- Length of the element in the cache (will trim id to that value)
  }

  local conf = lua_util.override_defaults(default_conf, classifier_ucl)
  -- Clean all not known configurations
  for k, _ in pairs(conf) do
    if default_conf[k] == nil then
      conf[k] = nil
    end
  end

  local check_script_id = lua_redis.load_redis_script_from_file("bayes_cache_check.lua", redis_params)
  local learn_script_id = lua_redis.load_redis_script_from_file("bayes_cache_learn.lua", redis_params)

  return gen_cache_check_functor(redis_params, check_script_id, conf), gen_cache_learn_functor(redis_params,
      learn_script_id, conf)
end

return exports
