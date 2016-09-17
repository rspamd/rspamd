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

-- MX check plugin
local rspamd_logger = require "rspamd_logger"
local rspamd_tcp = require "rspamd_tcp"
local rspamd_redis = require "rspamd_redis"
local rspamd_util = require "rspamd_util"
require "fun" ()

local settings = {
  timeout = 1.0, -- connect timeout
  symbol_bad_mx = 'MX_INVALID',
  symbol_no_mx = 'MX_MISSING',
  symbol_good_mx = 'MX_GOOD',
  expire = 86400, -- 1 day by default
  key_prefix = 'rmx'
}
local redis_params

local function mx_check(task)
  local from = task:get_from('smtp')
  local mx_domain

  if from and from[1] and from[1]['domain'] and not from[2] then
    mx_domain = rspamd_util.get_tld(from[1]['domain'])
  end

  if not mx_domain then
    return
  end

  local valid = false

  local function check_results(mxes)
    if all(function(k, elt) return elt.checked end, mxes) then
      -- Save cache
      local key = settings.key_prefix .. mx_domain
      local function redis_cache_cb(task, err, data)
        if err ~= nil then
          rspamd_logger.errx(task, 'redis_cache_cb received error: %1', err)
          return
        end
      end
      if not valid then
        task:insert_result(settings.symbol_bad_mx, 1.0)
        local ret,_,_ = rspamd_redis_make_request(task,
          redis_params, -- connect params
          key, -- hash key
          false, -- is write
          redis_cache_cb, --callback
          'SETEX', -- command
          {key, tostring(settings.expire / 10.0), '0'} -- arguments
        )
      else
        local valid_mx = {}
        each(function(k, mx)
          table.insert(valid_mx, k)
        end, filter(function (k, elt) return elt.working end, mxes))
        task:insert_result(settings.symbol_good_mx, 1.0, valid_mx)
        local ret,_,_ = rspamd_redis_make_request(task,
          redis_params, -- connect params
          key, -- hash key
          false, -- is write
          redis_cache_cb, --callback
          'SETEX', -- command
          {key, tostring(settings.expire), table.concat(valid_mx, ';')} -- arguments
        )
      end
    end
  end

  local function gen_mx_a_callback(name, mxes)
    return function(resolver, to_resolve, results, err, _, authenticated)
      mxes[name].ips = results

      local function io_cb(err, data, conn)
        if err then
          mxes[name].checked = true
        else
          mxes[name].checked = true
          mxes[name].working = true
          valid = true
        end
        check_results(mxes)
      end
      local function on_connect_cb(conn)
        if err then
          mxes[name].checked = true
        else
          mxes[name].checked = true
          valid = true
          mxes[name].working = true
        end
        conn:close()
        check_results(mxes)
      end

      if err or not results then
        mxes[name].checked = true
      else
        -- Try to open TCP connection to port 25
        for _,res in ipairs(results) do
          local ret = rspamd_tcp.new({
            task = task,
            host = res:to_string(),
            callback = io_cb,
            on_connect = on_connect_cb,
            timeout = settings.timeout,
            port = 25
          })

          if not ret then
            mxes[name].checked = true
          end
        end
      end
      check_results(mxes)
    end
  end

  local function mx_callback(resolver, to_resolve, results, err, _, authenticated)
    if err or not results then
      task:insert_result(settings.symbol_no_mx, 1.0)
    else
      local mxes = {}
      table.sort(results, function(r1, r2)
        return r1['priority'] < r2['priority']
      end)
      for _,mx in ipairs(results) do
        -- Not checked
        mxes[mx['name']] = {checked = false, working = false, ips = {}}
      end

      for _,mx in ipairs(results) do
        local r = task:get_resolver()
        -- XXX: maybe add ipv6?
        r:resolve('a', {
          name = mx['name'],
          callback = gen_mx_a_callback(mx['name'], mxes),
          task = task,
          forced = true
        })
      end
      check_results(mxes)
    end
  end

  if not redis_params then
    local r = task:get_resolver()
    r:resolve('mx', {
      name = mx_domain,
      callback = mx_callback,
      task = task,
      forced = true
    })
  else
    local function redis_cache_get_cb(task, err, data)
      if err or type(data) ~= 'string' then
        local r = task:get_resolver()
        r:resolve('mx', {
          name = mx_domain,
          callback = mx_callback,
          task = task,
          forced = true
        })
      else
        if data == '0' then
          task:insert_result(settings.symbol_bad_mx, 1.0, 'cached')
        else
          task:insert_result(settings.symbol_good_mx, 1.0, {'cached', data})
        end
      end
    end

    local key = settings.key_prefix .. mx_domain
    local ret,_,_ = rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_cache_get_cb, --callback
      'GET', -- command
      {key} -- arguments
    )

    if not ret then
      local r = task:get_resolver()
      r:resolve('mx', {
        name = mx_domain,
        callback = mx_callback,
        task = task,
        forced = true
      })
    end
  end
end

-- Module setup
local opts = rspamd_config:get_all_opt('mx_check')
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'module is unconfigured')
  return
end
if opts then
  redis_params = rspamd_parse_redis_server('mx_check')
  for k,v in pairs(opts) do
    settings[k] = v
  end

  local id = rspamd_config:register_symbol({
    name = settings.symbol_bad_mx,
    type = 'normal',
    callback = mx_check,
  })
  rspamd_config:register_symbol({
    name = settings.symbol_no_mx,
    type = 'virtual',
    parent = id
  })
  rspamd_config:register_symbol({
    name = settings.symbol_good_mx,
    type = 'virtual',
    parent = id
  })

  rspamd_config:set_metric_symbol({
    name = settings.symbol_bad_mx,
    score = 4.0,
    description = 'Domain has no working MX',
    group = 'MX'
  })
  rspamd_config:set_metric_symbol({
    name = settings.symbol_good_mx,
    score = -0.1,
    description = 'Domain has working MX',
    group = 'MX'
  })
  rspamd_config:set_metric_symbol({
    name = settings.symbol_no_mx,
    score = 1.5,
    description = 'Domain has no working MX',
    group = 'MX'
  })
end
