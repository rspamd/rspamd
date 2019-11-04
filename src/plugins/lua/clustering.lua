--[[
Copyright (c) 2018, Vsevolod Stakhov

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

if confighelp then
  return
end

-- Plugin for finding patterns in email flows

local N = 'clustering'

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_verdict = require "lua_verdict"
local lua_redis = require "lua_redis"
local lua_selectors = require "lua_selectors"
local ts = require("tableshape").types

local redis_params

local rules = {} -- Rules placement

local default_rule = {
  max_elts = 100, -- Maximum elements in a cluster
  expire = 3600, -- Expire for a bucket when limit is not reached
  expire_overflow = 36000, -- Expire for a bucket when limit is reached
  spam_mult = 1.0, -- Increase on spam hit
  junk_mult = 0.5, -- Increase on junk
  ham_mult = -0.1, -- Increase on ham
  size_mult = 0.01, -- Reaches 1.0 on `max_elts`
  score_mult = 0.1,
}

local rule_schema = ts.shape{
  max_elts = ts.number + ts.string / tonumber,
  expire = ts.number + ts.string / lua_util.parse_time_interval,
  expire_overflow = ts.number + ts.string / lua_util.parse_time_interval,
  spam_mult = ts.number,
  junk_mult = ts.number,
  ham_mult = ts.number,
  size_mult = ts.number,
  score_mult = ts.number,
  source_selector = ts.string,
  cluster_selector = ts.string,
  symbol = ts.string:is_optional(),
  prefix = ts.string:is_optional(),
}

-- Redis scripts

-- Queries for a cluster's data
-- Arguments:
-- 1. Source selector (string)
-- 2. Cluster selector (string)
-- Returns: {cur_elts, total_score, element_score}
local query_cluster_script = [[
local sz = redis.call('HLEN', KEYS[1])

if not sz or not tonumber(sz) then
  -- New bucket, will update on idempotent phase
  return {0, '0', '0'}
end

local total_score = redis.call('HGET', KEYS[1], '__s')
total_score = tonumber(total_score) or 0
local score = redis.call('HGET', KEYS[1], KEYS[2])
if not score or not tonumber(score) then
  return {sz, tostring(total_score), '0'}
end
return {sz, tostring(total_score), tostring(score)}
]]
local query_cluster_id

-- Updates cluster's data
-- Arguments:
-- 1. Source selector (string)
-- 2. Cluster selector (string)
-- 3. Score (number)
-- 4. Max buckets (number)
-- 5. Expire (number)
-- 6. Expire overflow (number)
-- Returns: nothing
local update_cluster_script = [[
local sz = redis.call('HLEN', KEYS[1])

if not sz or not tonumber(sz) then
  -- Create bucket
  redis.call('HSET', KEYS[1], KEYS[2], math.abs(KEYS[3]))
  redis.call('HSET', KEYS[1], '__s', KEYS[3])
  redis.call('EXPIRE', KEYS[1], KEYS[5])

  return
end

sz = tonumber(sz)
local lim = tonumber(KEYS[4])

if sz > lim then

  if k then
    -- Existing key
    redis.call('HINCRBYFLOAT', KEYS[1], KEYS[2], math.abs(KEYS[3]))
  end
else
  redis.call('HINCRBYFLOAT', KEYS[1], KEYS[2], math.abs(KEYS[3]))
  redis.call('EXPIRE', KEYS[1], KEYS[6])
end

redis.call('HINCRBYFLOAT', KEYS[1], '__s', KEYS[3])
redis.call('EXPIRE', KEYS[1], KEYS[5])
]]
local update_cluster_id

-- Callbacks and logic

local function clusterting_filter_cb(task, rule)
  local source_selector = rule.source_selector(task)
  local cluster_selector

  if source_selector then
    cluster_selector = rule.cluster_selector(task)
  end

  if not cluster_selector or not source_selector then
    rspamd_logger.debugm(N, task, 'skip rule %s, selectors: source="%s", cluster="%s"',
        rule.name, source_selector, cluster_selector)
    return
  end

  local function combine_scores(cur_elts, total_score, element_score)
    local final_score

    local size_score = cur_elts * rule.size_mult
    local cluster_score = total_score * rule.score_mult

    if element_score > 0 then
      -- We have seen this element mostly in junk/spam
      final_score = math.min(1.0, size_score + cluster_score)
    else
      -- We have seen this element in ham mostly, so subtract average it from the size score
      final_score = math.min(1.0, size_score - cluster_score / cur_elts)
    end
    rspamd_logger.debugm(N, task,
        'processed rule %s, selectors: source="%s", cluster="%s"; data: %s elts, %s score, %s elt score',
        rule.name, source_selector, cluster_selector, cur_elts, total_score, element_score)
    if final_score > 0.1 then
      task:insert_result(rule.symbol, final_score, {source_selector,
                                                    tostring(size_score),
                                                    tostring(cluster_score)})
    end
  end

  local function redis_get_cb(err, data)
    if data then
      if type(data) == 'table' then
        combine_scores(tonumber(data[1]), tonumber(data[2]), tonumber(data[3]))
      else
        rspamd_logger.errx(task, 'invalid type while getting clustering keys %s: %s',
            source_selector, type(data))
      end

    elseif err then
      rspamd_logger.errx(task, 'got error while getting clustering keys %s: %s',
          source_selector, err)
    else
      rspamd_logger.errx(task, 'got error while getting clustering keys %s: %s',
          source_selector, "unknown error")
    end
  end

  lua_redis.exec_redis_script(query_cluster_id,
      {task = task, is_write = false, key = source_selector},
      redis_get_cb,
      {source_selector, cluster_selector})
end

local function clusterting_idempotent_cb(task, rule)
  if task:has_flag('skip') then return end
  if not rule.allow_local and lua_util.is_rspamc_or_controller(task) then return end

  local verdict = lua_verdict.get_specific_verdict(N, task)
  local score

  if verdict == 'ham' then
    score = rule.ham_mult
  elseif verdict == 'spam' then
    score = rule.spam_mult
  elseif verdict == 'junk' then
    score = rule.junk_mult
  else
    rspamd_logger.debugm(N, task, 'skip rule %s, verdict=%s',
        rule.name, verdict)
    return
  end

  local source_selector = rule.source_selector(task)
  local cluster_selector

  if source_selector then
    cluster_selector = rule.cluster_selector(task)
  end

  if not cluster_selector or not source_selector then
    rspamd_logger.debugm(N, task, 'skip rule %s, selectors: source="%s", cluster="%s"',
        rule.name, source_selector, cluster_selector)
    return
  end

  local function redis_set_cb(err, data)
    if err then
      rspamd_logger.errx(task, 'got error while getting clustering keys %s: %s',
          source_selector, err)
    else
      rspamd_logger.debugm(N, task, 'set clustering key for %s: %s{%s} = %s',
          source_selector, "unknown error")
    end
  end

  lua_redis.exec_redis_script(update_cluster_id,
      {task = task, is_write = true, key = source_selector},
      redis_set_cb,
      {
        source_selector,
        cluster_selector,
        tostring(score),
        tostring(rule.max_elts),
        tostring(rule.expire),
        tostring(rule.expire_overflow)
      }
  )
end
-- Init part
redis_params = lua_redis.parse_redis_server('clustering')
local opts = rspamd_config:get_all_opt("clustering")

-- Initialization part
if not (opts and type(opts) == 'table') then
  lua_util.disable_module(N, "config")
  return
end

if not redis_params then
  lua_util.disable_module(N, "redis")
  return
end

if opts['rules'] then
  for k,v in pairs(opts['rules']) do
    local raw_rule = lua_util.override_defaults(default_rule, v)

    local rule,err = rule_schema:transform(raw_rule)

    if not rule then
      rspamd_logger.errx(rspamd_config, 'invalid clustering rule %s: %s',
          k, err)
    else

      if not rule.symbol then rule.symbol = k end
      if not rule.prefix then rule.prefix = k .. "_" end

      rule.source_selector = lua_selectors.create_selector_closure(rspamd_config,
          rule.source_selector, '')
      rule.cluster_selector =  lua_selectors.create_selector_closure(rspamd_config,
          rule.cluster_selector, '')
      if rule.source_selector and rule.cluster_selector then
        rule.name = k
        table.insert(rules, rule)
      end
    end
  end

  if #rules > 0 then

    query_cluster_id = lua_redis.add_redis_script(query_cluster_script, redis_params)
    update_cluster_id = lua_redis.add_redis_script(update_cluster_script, redis_params)
    local function callback_gen(f, rule)
      return function(task) return f(task, rule) end
    end

    for _,rule in ipairs(rules) do
      rspamd_config:register_symbol{
        name = rule.symbol,
        type = 'normal',
        callback = callback_gen(clusterting_filter_cb, rule),
      }
      rspamd_config:register_symbol{
        name = rule.symbol .. '_STORE',
        type = 'idempotent',
        callback = callback_gen(clusterting_idempotent_cb, rule),
      }
    end
  else
    lua_util.disable_module(N, "config")
  end
else
  lua_util.disable_module(N, "config")
end
