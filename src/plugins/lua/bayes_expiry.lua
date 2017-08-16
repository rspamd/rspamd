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
local logger = require "rspamd_logger"
local mempool = require "rspamd_mempool"
local util = require "rspamd_util"
local lutil = require "lua_util"
local lredis = require "lua_redis"

local pool = mempool.create()
local settings = {
  interval = 604800,
  statefile = string.format('%s/%s', rspamd_paths['DBDIR'], 'bayes_expired'),
  variables = {
    ot_bayes_ttl = 31536000, -- one year
    ot_min_age = 7776000, -- 90 days
    ot_min_count = 5,
  },
  symbols = {},
  timeout = 60,
}

local VAR_NAME = 'bayes_expired'
local EXPIRE_SCRIPT_TMPL = [[local result = {}
local OT_BAYES_TTL = ${ot_bayes_ttl}
local OT_MIN_AGE = ${ot_min_age}
local OT_MIN_COUNT = ${ot_min_count}
local symbol = ARGV[1]
local prefixes = redis.call('SMEMBERS', symbol .. '_keys')
for _, pfx in ipairs(prefixes) do
  local res = redis.call('SCAN', '0', 'MATCH', pfx .. '_*')
  local cursor, data = res[1], res[2]
  while data do
    local key_name = table.remove(data)
    if key_name then
      local h, s = redis.call('HMGET', key_name, 'H', 'S')
      if (h or s) then
        if not s then s = 0 else s = tonumber(s) end
        if not h then h = 0 else h = tonumber(h) end
        if s < OT_MIN_COUNT and h < OT_MIN_COUNT then
          local ttl = redis.call('TTL', key_name)
          if ttl > 0 then
            local age = OT_BAYES_TTL - ttl
            if age > OT_MIN_AGE then
              table.insert(result, key_name)
            end
          end
        end
      end
    else
      if cursor == "0" then
        data = nil
      else
        local res = redis.call('SCAN', tostring(cursor), 'MATCH', pfx .. '_*')
        cursor, data = res[1], res[2]
      end
    end
  end
end
return table.concat(result, string.char(31))]]

local function configure_bayes_expiry()
  local opts = rspamd_config:get_all_opt(N)
  if not type(opts) == 'table' then return false end
  for k, v in pairs(opts) do
    settings[k] = v
  end
  if not settings.symbols[1] then
    logger.warn('No symbols configured, not enabling expiry')
    return false
  end
  return true
end

if not configure_bayes_expiry() then return end

local function get_redis_params(ev_base, symbol)
  local redis_params
  local copts = rspamd_config:get_all_opt('classifier')
  if not type(copts) == 'table' then
    logger.errx(ev_base, "Couldn't get classifier configuration")
    return
  end
  if type(copts.backend) == 'table' then
    redis_params = lredis.rspamd_parse_redis_server(nil, copts.backend, true)
  end
  if redis_params then return redis_params end
  if type(copts.statfile) == 'table' then
    for _, stf in ipairs(copts.statfile) do
      if stf.name == symbol then
        redis_params = lredis.rspamd_parse_redis_server(nil, copts.backend, true)
      end
    end
  end
  if redis_params then return redis_params end
  redis_params = lredis.rspamd_parse_redis_server(nil, copts, false)
  redis_params.timeout = settings.timeout
  return redis_params
end

rspamd_config:add_on_load(function (_, ev_base, worker)
  local processed_symbols, expire_script_sha
  -- Exit unless we're the first 'normal' worker
  if not (worker:get_name() == 'normal' and worker:get_index() == 0) then return end
  -- Persist mempool variable to statefile on shutdown
  rspamd_config:register_finish_script(function ()
    local stamp = pool:get_variable(VAR_NAME, 'double')
    if not stamp then
      logger.warnx(ev_base, 'No last bayes expiry to persist to disk')
      return
    end
    local f, err = io.open(settings['statefile'], 'w')
    if err then
      logger.errx(ev_base, 'Unable to write statefile to disk: %s', err)
      return
    end
    if f then
      f:write(pool:get_variable(VAR_NAME, 'double'))
      f:close()
    end
  end)
  local expire_symbol
  local function load_scripts(redis_params, cont, p1, p2)
    local function load_script_cb(err, data)
      if err then
        logger.errx(ev_base, 'Error loading script: %s', err)
      else
        if type(data) == 'string' then
          expire_script_sha = data
          logger.debugm(N, ev_base, 'expire_script_sha: %s', expire_script_sha)
          if type(cont) == 'function' then
            cont(p1, p2)
          end
        end
      end
    end
    local scripttxt = lutil.template(EXPIRE_SCRIPT_TMPL, settings.variables)
    local ret = lredis.redis_make_request_taskless(ev_base,
      rspamd_config,
      redis_params,
      nil,
      true, -- is write
      load_script_cb, --callback
      'SCRIPT', -- command
      {'LOAD', scripttxt}
    )
    if not ret then
      logger.errx(ev_base, 'Error loading script')
    end
  end
  local function continue_expire()
    for _, symbol in ipairs(settings.symbols) do
      if not processed_symbols[symbol] then
        local redis_params = get_redis_params(ev_base, symbol)
        if not redis_params then
          processed_symbols[symbol] = true
          logger.errx(ev_base, "Couldn't get redis params")
        else
          load_scripts(redis_params, expire_symbol, redis_params, symbol)
          break
        end
      end
    end
  end
  expire_symbol = function(redis_params, symbol)
    local function del_keys_cb(err, data)
      if err then
        logger.errx(ev_base, 'Redis request failed: %s', err)
      end
      processed_symbols[symbol] = true
      continue_expire()
    end
    local function get_keys_cb(err, data)
      if err then
        logger.errx(ev_base, 'Redis request failed: %s', err)
        processed_symbols[symbol] = true
        continue_expire()
      else
        if type(data) == 'string' then
          if data == "" then
            data = {}
          else
            data = lutil.rspamd_str_split(data, string.char(31))
          end
        end
        if type(data) == 'table' then
          if not data[1] then
            logger.warnx(ev_base, 'No keys to delete: %s', symbol)
            processed_symbols[symbol] = true
            continue_expire()
          else
            local ret = lredis.redis_make_request_taskless(ev_base,
              rspamd_config,
              redis_params,
              nil,
              true, -- is write
              del_keys_cb, --callback
              'DEL', -- command
              data
            )
            if not ret then
              logger.errx(ev_base, 'Redis request failed')
              processed_symbols[symbol] = true
              continue_expire()
            end
          end
        else
          logger.warnx(ev_base, 'No keys to delete: %s', symbol)
          processed_symbols[symbol] = true
          continue_expire()
        end
      end
    end
    local ret = lredis.redis_make_request_taskless(ev_base,
      rspamd_config,
      redis_params,
      nil,
      false, -- is write
      get_keys_cb, --callback
      'EVALSHA', -- command
      {expire_script_sha, 0, symbol}
    )
    if not ret then
      logger.errx(ev_base, 'Redis request failed')
      processed_symbols[symbol] = true
      continue_expire()
    end
  end
  local function begin_expire(time)
    local stamp = time or util.get_time()
    pool:set_variable(VAR_NAME, stamp)
    processed_symbols = {}
    continue_expire()
  end
  -- Expire tokens at regular intervals
  local function schedule_regular_expiry()
    rspamd_config:add_periodic(ev_base, settings['interval'], function ()
      begin_expire()
      return true
    end)
  end
  -- Expire tokens and reschedule expiry
  local function schedule_intermediate_expiry(when)
    rspamd_config:add_periodic(ev_base, when, function ()
      begin_expire()
      schedule_regular_expiry()
      return false
    end)
  end
  -- Try read statefile on startup
  local stamp
  local f, err = io.open(settings['statefile'], 'r')
  if err then
    logger.warnx(ev_base, 'Failed to open statefile: %s', err)
  end
  if f then
    io.input(f)
    stamp = tonumber(io.read())
    pool:set_variable(VAR_NAME, stamp)
  end
  local time = util.get_time()
  if not stamp then
    logger.debugm(N, ev_base, 'No state found - expiring stats immediately')
    begin_expire(time)
    schedule_regular_expiry()
    return
  end
  local delta = stamp - time + settings['interval']
  if delta <= 0 then
    logger.debugm(N, ev_base, 'Last expiry is too old - expiring stats immediately')
    begin_expire(time)
    schedule_regular_expiry()
    return
  end
  logger.debugm(N, ev_base, 'Scheduling next expiry in %s seconds', delta)
  schedule_intermediate_expiry(delta)
end)
