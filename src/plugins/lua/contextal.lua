--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local E = {}
local N = 'contextal'

if confighelp then
  return
end

local opts = rspamd_config:get_all_opt(N)
if not opts then
  return
end

local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"

local redis_params

local contextal_actions = {
  'ALERT',
  'ALLOW',
  'BLOCK',
  'QUARANTINE',
  'SPAM',
}

local settings = {
  action_symbol_prefix = 'CONTEXTAL_ACTION',
  base_url = 'http://localhost:8080',
  cache_ttl = 3600,
  custom_actions = {},
  http_timeout = 2,
  key_prefix = 'CXAL',
  request_ttl = 4,
  submission_symbol = 'CONTEXTAL_SUBMIT',
}

local static_boundary = rspamd_util.random_hex(32)

local function cache_key(task)
  return string.format('%s_%s', settings.key_prefix, task:get_digest())
end

local function process_actions(task, obj, is_cached)
  for _, match in ipairs((obj[1] or E).actions) do
    local act = match.action
    local scenario = match.scenario
    if not (act and scenario) then
      rspamd_logger.err(task, 'bad result: %s', match)
    elseif contextal_actions[act] then
      task:insert_result(settings.action_symbol_prefix .. '_' .. act, 1.0, scenario)
    else
      rspamd_logger.err(task, 'unknown action: %s', act)
    end
  end

  if not redis_params or is_cached then return end

  local cache_obj
  if (obj[1] or E).actions then
    cache_obj = {[1] = {["actions"] = obj[1].actions}}
  elseif (obj[1] or E).work_id then
    cache_obj = {[1] = {["work_id"] = obj[1].work_id}}
  else
    rspamd_logger.err(task, 'bad result: %s', obj)
    return
  end

  local function redis_set_cb(err)
    if err then
      rspamd_logger.err(task, 'error setting cache: %s', err)
    end
  end

  local key = cache_key(task)
  local ret = lua_redis.redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'SET', -- command
      { key, ucl.to_format(cache_obj, 'json-compact') } -- arguments
  )

  if not ret then
    rspamd_logger.err(task, 'cannot make redis request to cache result')
    return
  end
end

local function process_cached(task, txt)
  local parser = ucl.parser()
  local _, err = parser:parse_string(txt)
  if err then
    rspamd_logger.err(task, 'cannot parse JSON (cached): %s', err)
    return
  end
  local obj = parser:get_object()
  if (obj[1] or E).actions then
    task:disable_symbol(settings.action_symbol_prefix)
    return process_actions(task, obj, true)
  elseif (obj[1] or E).work_id then
    task:get_mempool():set_variable('contextal_work_id', obj.work_id)
  else
    rspamd_logger.err(task, 'bad result (cached): %s', obj)
  end
end

local function submit(task)

  local function http_callback(err, code, body, hdrs)
    if err then
      rspamd_logger.err(task, 'http error: %s', err)
      return
    end
    if code ~= 201 then
      rspamd_logger.err(task, 'bad http code: %s', code)
      return
    end
    local parser = ucl.parser()
    local _, parse_err = parser:parse_string(body)
    if parse_err then
      rspamd_logger.err(task, 'cannot parse JSON: %s', err)
      return
    end
    local obj = parser:get_object()
    local work_id = obj.work_id
    if work_id then
      task:get_mempool():set_variable('contextal_work_id', work_id)
    end
    task:insert_result(settings.submission_symbol, 1.0,
        string.format('work_id=%s', work_id or 'nil'))
  end

  local req = {
    object_data = {['data'] = task:get_content()},
  }
  if settings.request_ttl then
    req.ttl = {['data'] = tostring(settings.request_ttl)}
  end
  if settings.max_recursion then
    req.maxrec = {['data'] = tostring(settings.max_recursion)}
  end
  rspamd_http.request({
      task = task,
      url = settings.submit_url,
      body = lua_util.table_to_multipart_body(req, static_boundary),
      callback = http_callback,
      headers = {
        ['Content-Type'] = string.format('multipart/form-data; boundary="%s"', static_boundary)
      },
      timeout = settings.http_timeout,
      gzip = settings.gzip,
      keepalive = settings.keepalive,
      no_ssl_verify = settings.no_ssl_verify,
  })
end

local function submit_cb(task)
  if redis_params then

    local function redis_get_cb(err, data)
      if err then
        rspamd_logger.err(task, 'error querying redis: %s', err)
        return
      end
      if type(data) == 'userdata' then
        return submit(task)
      end
      process_cached(task, data)
    end

    local key = cache_key(task)
    local ret = lua_redis.redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_get_cb, --callback
        'GET', -- command
        { key } -- arguments
    )

    if not ret then
      rspamd_logger.err(task, 'cannot make redis request to check results')
      return
    end

  else
    return submit(task)
  end
end

local function action_cb(task)
  local work_id = task:get_mempool():get_variable('contextal_work_id', 'string')
  if not work_id then
    rspamd_logger.err(task, 'no work id found in mempool')
    return
  end

  local function http_callback(err, code, body, hdrs)
    if err then
      rspamd_logger.err(task, 'http error: %s', err)
      return
    end
    if code ~= 200 then
      rspamd_logger.err(task, 'bad http code: %s', code)
      return
    end
    local parser = ucl.parser()
    local _, parse_err = parser:parse_string(body)
    if parse_err then
      rspamd_logger.err(task, 'cannot parse JSON: %s', err)
      return
    end
    local obj = parser:get_object()
    if (obj[1] or E).actions then
      return process_actions(task, obj, false)
    end
  end

  rspamd_http.request({
      task = task,
      url = settings.actions_url .. work_id,
      callback = http_callback,
      timeout = settings.http_timeout,
      gzip = settings.gzip,
      keepalive = settings.keepalive,
      no_ssl_verify = settings.no_ssl_verify,
  })
end

local function set_url_path(base, path)
  local ts = base:sub(#base) == '/' and '' or '/'
  return base .. ts .. path
end

settings = lua_util.override_defaults(settings, opts)

contextal_actions = lua_util.list_to_hash(contextal_actions)
for _, k in ipairs(settings.custom_actions) do
  contextal_actions[k] = true
end

if not settings.base_url then
  if not (settings.submit_url and settings.actions_url) then
    rspamd_logger.err(rspamd_config, 'no URL configured for contextal')
    lua_util.disable_module(N, 'config')
    return
  end
else
  if not settings.submit_url then
    settings.submit_url = set_url_path(settings.base_url, 'api/v1/submit')
  end
  if not settings.actions_url then
    settings.actions_url = set_url_path(settings.base_url, 'api/v1/actions/')
  end
end

redis_params = lua_redis.parse_redis_server(N)
if redis_params then
  lua_redis.register_prefix(settings.key_prefix .. '_*', N,
      'Cache for contextal plugin')
end

rspamd_config:register_symbol({
  name = settings.submission_symbol,
  priority = lua_util.symbols_priorities.top,
  type = 'prefilter',
  group = N,
  callback = submit_cb
})

local id = rspamd_config:register_symbol({
  name = settings.action_symbol_prefix,
  type = 'postfilter',
  priority = lua_util.symbols_priorities.high - 1,
  group = N,
  callback = action_cb
})

for k in pairs(contextal_actions) do
  rspamd_config:register_symbol({
    name = settings.action_symbol_prefix .. '_' .. k,
    parent = id,
    type = 'virtual',
    group = N,
  })
end
