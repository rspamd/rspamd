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
local rspamd_redis = require 'rspamd_redis'
local redis_params
local ucl = require "ucl"
require "fun" ()

local settings = {
  redis_key = "dynamic_conf",
  redis_watch_interval = 10.0,
  priority = 10
}

local cur_settings = {
  version = 0
}

local function redis_make_request(ev_base, cfg, key, is_write, callback, command, args)
  if not ev_base or not redis_params or not callback or not command then
    return false,nil,nil
  end

  local addr
  local rspamd_redis = require "rspamd_redis"

  if key then
    if is_write then
      addr = redis_params['write_servers']:get_upstream_by_hash(key)
    else
      addr = redis_params['read_servers']:get_upstream_by_hash(key)
    end
  else
    if is_write then
      addr = redis_params['write_servers']:get_upstream_master_slave(key)
    else
      addr = redis_params['read_servers']:get_upstream_round_robin(key)
    end
  end

  if not addr then
    logger.errx(task, 'cannot select server to make redis request')
  end

  local options = {
    ev_base = ev_base,
    config = cfg,
    callback = callback,
    host = addr:get_addr(),
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }

  if redis_params['password'] then
    options['password'] = redis_params['password']
  end

  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end

  local ret,conn = rspamd_redis.make_request(options)
  return ret,conn,addr
end

local function apply_dynamic_actions(cfg, acts)
  each(function(k, v)
     if type[v] == 'table' then
      v['action'] = k
      if not v['priority'] then
        v['priority'] = settings.priority
      end
      rspamd_config:set_metric_action(v)
    else
      rspamd_config:set_metric_symbol({
        action = k,
        score = v,
        priority = settings.priority
      })
    end
  end, filter(function(k, v)
    local act = rspamd_config:get_metric_action(k)
    if act and act == v then
      return false
    end

    return true
  end, acts))
end

local function apply_dynamic_scores(cfg, sc)
  each(function(k, v)
    if type[v] == 'table' then
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
  end, filter(function(k, v)
    -- Select elts with scores that are different from local ones
    local sym = rspamd_config:get_metric_symbol(k)
    if sym and sym.score == v then
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
    each(function(i, v)
      cfg:enable_symbol(v)
    end, data['symbols_enabled'])
  end

  if data['symbols_disabled'] then
    each(function(i, v)
      cfg:disable_symbol(v)
    end, data['symbols_disabled'])
  end
end

local function check_dynamic_conf(cfg, ev_base)
  local function redis_load_cb(err, data)
    if data and type(data) == 'string' then
      local parser = ucl.parser()
      local res,err = parser:parse_string(data)

      if err then
        rspamd_logger.errx(cfg, "cannot parse dynamic conf from redis: %s", err)
      else
        apply_dynamic_conf(cfg, res)
        cur_settings.version = rversion
        cur_settings.data = res
      end
    end
  end
  local function redis_check_cb(err, data)
    if not err and type(data) == 'string' then
      local rver = tonumber(data)

      if rver and rver > cur_settings.version then
        rspamd_logger.infox(cfg, "need to load fresh dynamic settings with version %s, local version is %s",
          rver, cur_settings.version)
        redis_make_request(ev_base, cfg, settings.redis_key, false,
          redis_load_cb, 'HGET', {settings.redis_key, 'd'})
      end
    end
  end

  redis_make_request(ev_base, cfg, settings.redis_key, false,
    redis_check_cb, 'HGET', {settings.redis_key, 'v'})
end

local section = rspamd_config:get_all_opt("dynamic_conf")
if section then
  redis_params = rspamd_parse_redis_server('dynamic_conf')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    return
  end

  for k,v in pairs(section) do
    settings[k] = v
  end

  rspamd_config:add_on_load(function(cfg, ev_base)
    rspamd_config:add_periodic(ev_base, settings.redis_watch_interval,
    function(cfg, ev_base)
      check_dynamic_conf(cfg, ev_base)
      return true
    end, true)
  end)
end
