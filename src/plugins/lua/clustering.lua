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

local E = {}
local N = 'clustering'

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local fun = require "fun"
local lua_selectors = require "lua_selectors"
local ts = require("tableshape").types

local redis_params = nil

local rules = {} -- Rules placement

local default_rule = {
  max_elts = 100, -- Maximum elements in a cluster
  expire = 3600, -- Expire for a bucket when limit is not reached
  expire_overflow = 36000, -- Expire for a bucket when limit is reached
  spam_mult = 1.0, -- Increase on spam hit
  junk_mult = 0.5, -- Increase on junk
  ham_mult = 0.1, -- Increase on ham
  size_mult = 0.01, -- Reaches 1.0 on `max_elts`
  rate_mult = 0.1,
}

local rule_schema = ts.shape{
  max_elts = ts.number + ts.string / tonumber,
  expire = ts.number + ts.string / lua_util.parse_time_interval,
  expire_overflow = ts.number + ts.string / lua_util.parse_time_interval,
  spam_mult = ts.number,
  junk_mult = ts.number,
  ham_mult = ts.number,
  size_mult = ts.number,
  rate_mult = ts.number,
  source_selector = ts.string,
  cluster_selector = ts.string,
  symbol = ts.string:is_optional(),
  prefix = ts.string:is_optional(),
}

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
        table.insert(rules, rule)
      end
    end
  end

  if #rules > 0 then
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
        name = rule.symbol + '_STORE',
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