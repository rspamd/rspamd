--[[
Copyright (c) 2017, Andrew Lewis <nerf@judo.za.org>
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
]] --

if confighelp then
  return
end

local N = 'bayes_expiry'
local E = {}
local logger = require "rspamd_logger"
local lutil = require "lua_util"
local lredis = require "lua_redis"

local settings = {
  interval = 60, -- one iteration step per minute
  count = 1000, -- check up to 1000 keys on each iteration
  threshold = 10, -- require at least 10 occurrences to increase expire
  epsilon_common = 0.01, -- eliminate common if spam to ham rate is equal to this epsilon
  common_ttl_divisor = 100, -- how should we discriminate common elements
  significant_factor = 3.0 / 4.0, -- which tokens should we update
  classifiers = {},
}

local template = {

}

local function check_redis_classifier(cls, cfg)
  -- Skip old classifiers
  if cls.new_schema then
    local symbol_spam, symbol_ham
    local expiry = (cls.expiry or cls.expire)
    -- Load symbols from statfiles
    local statfiles = cls.statfile
    for _,stf in ipairs(statfiles) do
      local symbol = stf.symbol or 'undefined'

      local spam
      if stf.spam then
        spam = stf.spam
      else
        if string.match(symbol:upper(), 'SPAM') then
          spam = true
        else
          spam = false
        end
      end

      if spam then
        symbol_spam = symbol
      else
        symbol_ham = symbol
      end
    end

    if not symbol_spam or not symbol_ham or not expiry then
      return
    end
    -- Now try to load redis_params if needed

    local redis_params = {}
    if not lredis.try_load_redis_servers(cls, rspamd_config, redis_params) then
      if not lredis.try_load_redis_servers(cfg[N] or E, rspamd_config, redis_params) then
        if not lredis.try_load_redis_servers(cfg['redis'] or E, rspamd_config, redis_params) then
          return false
        end
      end
    end

    table.insert(settings.classifiers, {
      symbol_spam = symbol_spam,
      symbol_ham = symbol_ham,
      redis_params = redis_params,
      expiry = expiry
    })
  end
end

-- Check classifiers and try find the appropriate ones
local obj = rspamd_config:get_ucl()

local classifier = obj.classifier

if classifier then
  if classifier[1] then
    for _,cls in ipairs(classifier) do
      if cls.bayes then cls = cls.bayes end
      if cls.backend and cls.backend == 'redis' then
        check_redis_classifier(cls, obj)
      end
    end
  else
    if classifier.bayes then

      classifier = classifier.bayes
      if classifier[1] then
        for _,cls in ipairs(classifier) do
          if cls.backend and cls.backend == 'redis' then
            check_redis_classifier(cls, obj)
          end
        end
      else
        if classifier.backend and classifier.backend == 'redis' then
          check_redis_classifier(classifier, obj)
        end
      end
    end
  end
end


local opts = rspamd_config:get_all_opt(N)

if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end
end

-- Fill template
template.count = settings.count
template.threshold = settings.threshold
template.common_ttl_divisor = settings.common_ttl_divisor
template.epsilon_common = settings.epsilon_common
template.significant_factor = settings.significant_factor

for k,v in pairs(template) do
  template[k] = tostring(v)
end

-- Arguments:
-- [1] = symbol pattern
-- [2] = expire value
-- [3] = cursor
-- returns new cursor
local expiry_script = [[
  local ret = redis.call('SCAN', KEYS[3], 'MATCH', KEYS[1], 'COUNT', '${count}')
  local next = ret[1]
  local keys = ret[2]
  local nelts = 0
  local extended = 0
  local discriminated = 0

  for _,key in ipairs(keys) do
    local values = redis.call('HMGET', key, 'H', 'S')
    local ham = tonumber(values[1]) or 0
    local spam = tonumber(values[2]) or 0

    if ham > ${threshold} or spam > ${threshold} then
      local total = ham + spam

      if total > 0 then
        if ham / total > ${significant_factor} or spam / total > ${significant_factor} then
          redis.replicate_commands()
          redis.call('EXPIRE', key, KEYS[2])
          extended = extended + 1
        elseif math.abs(ham - spam) <= total * ${epsilon_common} then
          local ttl = redis.call('TTL', key)
          redis.replicate_commands()
          redis.call('EXPIRE', key, tonumber(ttl) / ${common_ttl_divisor})
          discriminated = discriminated + 1
        end
      end
    end
    nelts = nelts + 1
  end

  return {next, nelts, extended, discriminated}
]]

local cur = 0

local function expire_step(cls, ev_base, worker)

  local function redis_step_cb(err, data)
    if err then
      logger.errx(rspamd_config, 'cannot perform expiry step: %s', err)
    elseif type(data) == 'table' then
      local next,nelts,extended,discriminated = tonumber(data[1]), tonumber(data[2]),
        tonumber(data[3]),tonumber(data[4])

      if next ~= 0 then
        logger.infox(rspamd_config, 'executed expiry step for bayes: %s items checked, %s extended, %s discriminated',
            nelts, extended, discriminated)
      else
        logger.infox(rspamd_config, 'executed final expiry step for bayes: %s items checked, %s extended, %s discriminated',
            nelts, extended, discriminated)
      end

      cur = next
    end
  end
  lredis.exec_redis_script(cls.script,
      {ev_base = ev_base, is_write = true},
      redis_step_cb,
      {'RS*_*', cls.expiry, cur}
  )
end

rspamd_config:add_on_load(function (_, ev_base, worker)
  -- Exit unless we're the first 'controller' worker
  if not (worker:get_name() == 'controller' and worker:get_index() == 0) then return end

  local unique_redis_params = {}
  -- Push redis script to all unique redis servers
  for _,cls in ipairs(settings.classifiers) do
    local seen = false
    for _,rp in ipairs(unique_redis_params) do
      if lutil.table_cmp(rp, cls.redis_params) then
        seen = true
      end
    end

    if not seen then
      table.insert(unique_redis_params, cls.redis_params)
    end
  end

  for _,rp in ipairs(unique_redis_params) do
    local script_id = lredis.add_redis_script(lutil.template(expiry_script,
        template), rp)

    for _,cls in ipairs(settings.classifiers) do
      if lutil.table_cmp(rp, cls.redis_params) then
        cls.script = script_id
      end
    end
  end

  -- Expire tokens at regular intervals
  for _,cls in ipairs(settings.classifiers) do
    rspamd_config:add_periodic(ev_base, settings['interval'], function ()
      expire_step(cls, ev_base, worker)
      return true
    end)
  end
end)
