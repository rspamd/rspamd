--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2019, Denis Paavilainen <denpa@denpa.pro>

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

-- Detect remote OS via passive fingerprinting

local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local rspamd_logger = require "rspamd_logger"
local p0f = require("lua_scanners").filter('p0f').p0f

local N = 'p0f'

if confighelp then
  rspamd_config:add_example(nil, N,
    'Detect remote OS via passive fingerprinting',
    [[
p0f {
  # Enable module
  enabled = true

  # Path to the unix socket that p0f listens on
  socket = '/var/run/p0f.sock';

  # Connection timeout
  timeout = 5s;

  # If defined, insert symbol with lookup results
  symbol = 'P0F';

  # Patterns to match against results returned by p0f
  # Symbol will be yielded on OS string, link type or distance matches
  patterns = {
    WINDOWS = '^Windows.*';
    #DSL = '^DSL$';
    #DISTANCE10 = '^distance:10$';
  }

  # Cache lifetime in seconds (default - 2 hours)
  expire = 7200;

  # Cache key prefix
  prefix = 'p0f';
}
]])
  return
end

local rule

local function check_p0f(task)
  local ip = task:get_from_ip()

  if not (ip and ip:is_valid()) or ip:is_local() then
    return
  end

  p0f.check(task, ip, rule)
end

local opts = rspamd_config:get_all_opt(N)

rule = p0f.configure(opts)

if rule then
  rule.redis_params = lua_redis.parse_redis_server(N)

  lua_redis.register_prefix(rule.prefix .. '*', N,
      'P0f check cache', {
        type = 'string',
      })

  local id = rspamd_config:register_symbol({
    name = 'P0F_CHECK',
    type = 'prefilter',
    callback = check_p0f,
    priority = 8,
    flags = 'empty,nostat',
    group = N
  })

  if rule.symbol then
    rspamd_config:register_symbol({
      name = rule.symbol,
      parent = id,
      type = 'virtual',
      flags = 'empty',
      group = N
    })
  end

  for sym in pairs(rule.patterns) do
    rspamd_logger.debugm(N, rspamd_config, 'registering: %1', {
      type = 'virtual',
      name = sym,
      parent = id,
      group = N
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = sym,
      parent = id,
      group = N
    })
  end
else
  lua_util.disable_module(N, 'config')
  rspamd_logger.infox('p0f module not configured');
end
