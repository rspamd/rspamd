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
local redis_cache = require "lua_cache"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local ts = require("tableshape").types
local ucl = require "ucl"

local cache_context, redis_params

local contextal_actions = {
  ['ALERT'] = true,
  ['ALLOW'] = true,
  ['BLOCK'] = true,
  ['QUARANTINE'] = true,
  ['SPAM'] = true,
}

local config_schema = lua_redis.enrich_schema {
  action_symbol_prefix = ts.string:is_optional(),
  base_url = ts.string:is_optional(),
  cache_prefix = ts.string:is_optional(),
  cache_timeout = ts.number:is_optional(),
  cache_ttl = ts.number:is_optional(),
  custom_actions = ts.array_of(ts.string):is_optional(),
  defer_if_no_result = ts.boolean:is_optional(),
  defer_message = ts.string:is_optional(),
  enabled = ts.boolean:is_optional(),
  http_timeout = ts.number:is_optional(),
  request_ttl = ts.number:is_optional(),
  submission_symbol = ts.string:is_optional(),
}

local settings = {
  action_symbol_prefix = 'CONTEXTAL_ACTION',
  base_url = 'http://localhost:8080',
  cache_prefix = 'CXAL',
  cache_timeout = 5,
  cache_ttl = 3600,
  custom_actions = {},
  defer_if_no_result = false,
  defer_message = 'Awaiting deep scan - try again later',
  http_timeout = 2,
  request_ttl = 4,
  submission_symbol = 'CONTEXTAL_SUBMIT',
}

local static_boundary = rspamd_util.random_hex(32)
local use_request_ttl = true

local function maybe_defer(task, obj)
  if settings.defer_if_no_result and not ((obj or E)[1] or E).actions then
    task:set_pre_result('soft reject', settings.defer_message)
  end
end

local function process_actions(task, obj, is_cached)
  for _, match in ipairs((obj[1] or E).actions or E) do
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

  if not cache_context or is_cached then
    maybe_defer(task, obj)
    return
  end

  local cache_obj
  if (obj[1] or E).actions then
    cache_obj = {[1] = {["actions"] = obj[1].actions}}
  else
    local work_id = task:get_mempool():get_variable('contextal_work_id', 'string')
    if work_id then
      cache_obj = {[1] = {["work_id"] = work_id}}
    else
      rspamd_logger.err(task, 'no work id found in mempool')
      return
    end
  end

  redis_cache.cache_set(task,
      task:get_digest(),
      cache_obj,
      cache_context)

  maybe_defer(task, obj)
end

local function process_cached(task, obj)
  if (obj[1] or E).actions then
    task:disable_symbol(settings.action_symbol_prefix)
    return process_actions(task, obj, true)
  elseif (obj[1] or E).work_id then
    task:get_mempool():set_variable('contextal_work_id', obj[1].work_id)
  else
    rspamd_logger.err(task, 'bad result (cached): %s', obj)
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
      maybe_defer(task)
      return
    end
    if code ~= 200 then
      rspamd_logger.err(task, 'bad http code: %s', code)
      maybe_defer(task)
      return
    end
    local parser = ucl.parser()
    local _, parse_err = parser:parse_string(body)
    if parse_err then
      rspamd_logger.err(task, 'cannot parse JSON: %s', err)
      maybe_defer(task)
      return
    end
    local obj = parser:get_object()
    return process_actions(task, obj, false)
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

local function submit(task)

  local function http_callback(err, code, body, hdrs)
    if err then
      rspamd_logger.err(task, 'http error: %s', err)
      maybe_defer(task)
      return
    end
    if code ~= 201 then
      rspamd_logger.err(task, 'bad http code: %s', code)
      maybe_defer(task)
      return
    end
    local parser = ucl.parser()
    local _, parse_err = parser:parse_string(body)
    if parse_err then
      rspamd_logger.err(task, 'cannot parse JSON: %s', err)
      maybe_defer(task)
      return
    end
    local obj = parser:get_object()
    local work_id = obj.work_id
    if work_id then
      task:get_mempool():set_variable('contextal_work_id', work_id)
    end
    task:insert_result(settings.submission_symbol, 1.0,
        string.format('work_id=%s', work_id or 'nil'))
    task:add_timer(settings.request_ttl, action_cb)
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

local function cache_hit(task, err, data)
  if err then
    rspamd_logger.err(task, 'error getting cache: %s', err)
  else
    process_cached(task, data)
  end
end

local function submit_cb(task)
  if cache_context then
    redis_cache.cache_get(task,
        task:get_digest(),
        cache_context,
        settings.cache_timeout,
        submit,
        cache_hit
    )
  else
    submit(task)
  end
end

local function set_url_path(base, path)
  local slash = base:sub(#base) == '/' and '' or '/'
  return base .. slash .. path
end

settings = lua_util.override_defaults(settings, opts)

local res, err = config_schema:transform(settings)
if not res then
  rspamd_logger.warnx(rspamd_config, 'plugin %s is misconfigured: %s', N, err)
  local err_msg = string.format("schema error: %s", res)
  lua_util.config_utils.push_config_error(N, err_msg)
  lua_util.disable_module(N, "failed", err_msg)
  return
end

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
  cache_context = redis_cache.create_cache_context(redis_params, {
      cache_prefix = settings.cache_prefix,
      cache_ttl = settings.cache_ttl,
      cache_format = 'json',
      cache_use_hashing = false
  })
end

local submission_id = rspamd_config:register_symbol({
  name = settings.submission_symbol,
  type = 'normal',
  group = N,
  callback = submit_cb
})

local top_options = rspamd_config:get_all_opt('options')
if settings.request_ttl and settings.request_ttl >= (top_options.task_timeout * 0.8) then
  rspamd_logger.warn(rspamd_config, [[request ttl is >= 80% of task timeout, won't wait on processing]])
  use_request_ttl = false
elseif not settings.request_ttl then
  use_request_ttl = false
end

local parent_id
if use_request_ttl then
  parent_id = submission_id
else
  parent_id = rspamd_config:register_symbol({
    name = settings.action_symbol_prefix,
    type = 'postfilter',
    priority = lua_util.symbols_priorities.high - 1,
    group = N,
    callback = action_cb
  })
end

for k in pairs(contextal_actions) do
  rspamd_config:register_symbol({
    name = settings.action_symbol_prefix .. '_' .. k,
    parent = parent_id,
    type = 'virtual',
    group = N,
  })
end
