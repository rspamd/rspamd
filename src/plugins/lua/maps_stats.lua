--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
  rspamd_config:add_example(nil, 'maps_stats',
      "Stores maps statistics in Redis", [[
maps_stats {
  # one iteration step per 2 minutes
  interval = 2m;
  # how many elements to store in Redis
  count = 1k;
  # common prefix for elements
  prefix = 'rm_';
}
]])
end

local redis_params
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local lua_redis = require "lua_redis"
local N = "maps_stats"

local settings = {
  interval = 120, -- one iteration step per 2 minutes
  count = 1000, -- how many elements to store in Redis
  prefix = 'rm_', -- common prefix for elements
}

local function process_map(map, ev_base, _)
  if map:get_nelts() > 0 and map:get_uri() ~= 'static' then
    local key = settings.prefix .. map:get_uri()

    local function redis_zrange_cb(err, data)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot delete extra elements in %s: %s',
            key, err)
      elseif data then
        rspamd_logger.infox(rspamd_config, 'cleared %s elements from %s',
            data, key)
      end
    end
    local function redis_card_cb(err, data)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot get number of elements in %s: %s',
            key, err)
      elseif data then
        if settings.count > 0 and tonumber(data) > settings.count then
          lua_redis.rspamd_redis_make_request_taskless(ev_base,
              rspamd_config,
              redis_params, -- connect params
              key, -- hash key
              true, -- is write
              redis_zrange_cb, --callback
              'ZREMRANGEBYRANK', -- command
              {key, '0', tostring(-(settings.count) - 1)} -- arguments
          )
        end
      end
    end
    local ret, conn, _ = lua_redis.rspamd_redis_make_request_taskless(ev_base,
        rspamd_config,
        redis_params, -- connect params
        key, -- hash key
        true, -- is write
        redis_card_cb, --callback
        'ZCARD', -- command
        {key} -- arguments
    )

    if ret and conn then
      local stats = map:get_stats(true)
      for k,s in pairs(stats) do
        if s > 0 then
          conn:add_cmd('ZINCRBY', {key, tostring(s), k})
        end
      end
    end
  end
end

if not lua_util.check_experimental(N) then
  return
end

local opts = rspamd_config:get_all_opt(N)

if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end
end

redis_params = lua_redis.parse_redis_server(N, opts)
-- XXX, this is a poor approach as not all maps are defined here...
local tmaps = rspamd_config:get_maps()
for _,m in ipairs(tmaps) do
  if m:get_uri() ~= 'static' then
    lua_redis.register_prefix(settings.prefix .. m:get_uri(), N,
        'Maps stats data', {
          type = 'zlist',
          persistent = true,
        })
  end
end

if redis_params then
  rspamd_config:add_on_load(function (_, ev_base, worker)
    local maps = rspamd_config:get_maps()

    for _,m in ipairs(maps) do
      rspamd_config:add_periodic(ev_base,
          settings['interval'],
          function ()
            process_map(m, ev_base, worker)
            return true
          end, true)
    end
  end)
end