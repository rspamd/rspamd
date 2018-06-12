--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local rspamd_logger = require "rspamd_logger"
local redis_params
local ucl = require "ucl"
local fun = require "fun"
local lua_util = require "lua_util"
local rspamd_redis = require "lua_redis"
local N = "dynamic_conf"

if confighelp then
  return
end

local settings = {
  redis_key = "dynamic_conf",
  redis_watch_interval = 10.0,
  priority = 10
}

local cur_settings = {
  version = 0,
  updates = {
    symbols = {},
    actions = {},
    has_updates = false
  }
}

local function alpha_cmp(v1, v2)
  local math = math
  if math.abs(v1 - v2) < 0.001 then
    return true
  end

  return false
end

local function apply_dynamic_actions(_, acts)
  fun.each(function(k, v)
     if type(v) == 'table' then
      v['name'] = k
      if not v['priority'] then
        v['priority'] = settings.priority
      end
      rspamd_config:set_metric_action(v)
    else
      rspamd_config:set_metric_symbol({
        name = k,
        score = v,
        priority = settings.priority
      })
    end
  end, fun.filter(function(k, v)
    local act = rspamd_config:get_metric_action(k)
    if (act and alpha_cmp(act, v)) or cur_settings.updates.actions[k] then
      return false
    end

    return true
  end, acts))
end

local function apply_dynamic_scores(_, sc)
  fun.each(function(k, v)
    if type(v) == 'table' then
      v['name'] = k
      if not v['priority'] then
        v['priority'] = settings.priority
      end
      rspamd_config:set_metric_symbol(v)
    else
      rspamd_config:set_metric_symbol({
        name = k,
        score = v,
        priority = settings.priority
      })
    end
  end, fun.filter(function(k, v)
    -- Select elts with scores that are different from local ones
    local sym = rspamd_config:get_metric_symbol(k)
    if (sym and alpha_cmp(sym.score, v)) or cur_settings.updates.symbols[k] then
      return false
    end

    return true
  end, sc))
end

local function apply_dynamic_conf(cfg, data)
  if data['scores'] then
    -- Apply scores changes
    apply_dynamic_scores(cfg, data['scores'])
  end

  if data['actions'] then
    apply_dynamic_actions(cfg, data['actions'])
  end

  if data['symbols_enabled'] then
    fun.each(function(_, v)
      cfg:enable_symbol(v)
    end, data['symbols_enabled'])
  end

  if data['symbols_disabled'] then
    fun.each(function(_, v)
      cfg:disable_symbol(v)
    end, data['symbols_disabled'])
  end
end

local function update_dynamic_conf(cfg, ev_base, recv)
  local function redis_version_set_cb(err, data)
    if err then
      rspamd_logger.errx(cfg, "cannot save dynamic conf version to redis: %s", err)
    else
      rspamd_logger.infox(cfg, "saved dynamic conf version: %s", data)
      cur_settings.updates.has_updates = false
      cur_settings.updates.symbols = {}
      cur_settings.updates.actions = {}
    end
  end
  local function redis_data_set_cb(err)
    if err then
      rspamd_logger.errx(cfg, "cannot save dynamic conf to redis: %s", err)
    else
      rspamd_redis.redis_make_request_taskless(ev_base,
          cfg,
          redis_params,
          settings.redis_key,
          true,
          redis_version_set_cb,
          'HINCRBY', {settings.redis_key, 'v', '1'})
    end
  end

  if recv then
    -- We need to merge two configs
    if recv['scores'] then
      if not cur_settings.data.scores then
        cur_settings.data.scores = {}
      end
      fun.each(function(k, v)
        cur_settings.data.scores[k] = v
      end,
      fun.filter(function(k)
        if cur_settings.updates.symbols[k] then
          return false
        end
        return true
      end, recv['scores']))
    end
    if recv['actions'] then
      if not cur_settings.data.actions then
        cur_settings.data.actions = {}
      end
      fun.each(function(k, v)
        cur_settings.data.actions[k] = v
      end,
      fun.filter(function(k)
        if cur_settings.updates.actions[k] then
          return false
        end
        return true
      end, recv['actions']))
    end
  end
  local newdata = ucl.to_format(cur_settings.data, 'json-compact')
  rspamd_redis.redis_make_request_taskless(ev_base, cfg, redis_params,
      settings.redis_key, true,
      redis_data_set_cb, 'HSET', {settings.redis_key, 'd', newdata})
end

local function check_dynamic_conf(cfg, ev_base)
  local function redis_load_cb(redis_err, data)
    if redis_err then
      rspamd_logger.errx(cfg, "cannot read dynamic conf from redis: %s", redis_err)
    elseif data and type(data) == 'string' then
      local parser = ucl.parser()
      local _,err = parser:parse_string(data)

      if err then
        rspamd_logger.errx(cfg, "cannot load dynamic conf from redis: %s", err)
      else
        local d = parser:get_object()
        apply_dynamic_conf(cfg, d)
        if cur_settings.updates.has_updates then
          -- Need to send our updates to Redis
          update_dynamic_conf(cfg, ev_base, d)
        else
          cur_settings.data = d
        end
      end
    end
  end
  local function redis_check_cb(err, data)
    if not err and type(data) == 'string' then
      local rver = tonumber(data)

      if not cur_settings.version or (rver and rver > cur_settings.version) then
        rspamd_logger.infox(cfg, "need to load fresh dynamic settings with version %s, local version is %s",
          rver, cur_settings.version)
        cur_settings.version = rver
        rspamd_redis.redis_make_request_taskless(ev_base, cfg, redis_params,
            settings.redis_key, false,
            redis_load_cb, 'HGET', {settings.redis_key, 'd'})
      elseif cur_settings.updates.has_updates then
        -- Need to send our updates to Redis
        update_dynamic_conf(cfg, ev_base)
      end
    elseif cur_settings.updates.has_updates then
      -- Need to send our updates to Redis
      update_dynamic_conf(cfg, ev_base)
    end
  end

  rspamd_redis.redis_make_request_taskless(ev_base, cfg, redis_params,
      settings.redis_key, false,
      redis_check_cb, 'HGET', {settings.redis_key, 'v'})
end

local section = rspamd_config:get_all_opt("dynamic_conf")
if section then
  redis_params = rspamd_redis.parse_redis_server('dynamic_conf')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    return
  end

  for k,v in pairs(section) do
    settings[k] = v
  end

  rspamd_config:add_on_load(function(_, ev_base, worker)
    if worker:is_scanner() then
      rspamd_config:add_periodic(ev_base, 0.0,
          function(cfg, _ev_base)
            check_dynamic_conf(cfg, _ev_base)
            return settings.redis_watch_interval
          end, true)
    end
  end)
end

-- Updates part
local function add_dynamic_symbol(_, sym, score)
  local add = false
  if not cur_settings.data then
    cur_settings.data = {}
  end

  if not cur_settings.data.scores then
    cur_settings.data.scores = {}
    cur_settings.data.scores[sym] = score
    add = true
  else
    if cur_settings.data.scores[sym] then
      if cur_settings.data.scores[sym] ~= score then
        add = true
      end
    else
      cur_settings.data.scores[sym] = score
      add = true
    end
  end

  if add then
    cur_settings.data.scores[sym] = score
    table.insert(cur_settings.updates.symbols, sym)
    cur_settings.updates.has_updates = true
  end

  return add
end

local function add_dynamic_action(_, act, score)
  local add = false
  if not cur_settings.data then
    cur_settings.data = {}
    cur_settings.version = 0
  end

  if not cur_settings.data.actions then
    cur_settings.data.actions = {}
    cur_settings.data.actions[act] = score
    add = true
  else
    if cur_settings.data.actions[act] then
      if cur_settings.data.actions[act] ~= score then
        add = true
      end
    else
      cur_settings.data.actions[act] = score
      add = true
    end
  end

  if add then
    cur_settings.data.actions[act] = score
    table.insert(cur_settings.updates.actions, act)
    cur_settings.updates.has_updates = true
  end

  return add
end

if section then
  if redis_params then
    rspamd_plugins["dynamic_conf"] = {
      add_symbol = add_dynamic_symbol,
      add_action = add_dynamic_action,
    }
  else
    lua_util.disable_module(N, "redis")
  end
else
  lua_util.disable_module(N, "config")
end