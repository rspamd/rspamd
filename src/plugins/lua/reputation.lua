--[[
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
]]--

if confighelp then
  return
end

-- A generic plugin for reputation handling

local E = {}
local N = 'reputation'

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_lua_utils = require "lua_util"
local fun = require "fun"
local redis_params = nil
local default_expiry = 864000 -- 10 day by default

-- IP Selector functions


-- Selectors are used to extract reputation tokens
local ip_selector = {
  config = {
    actions = { -- how each action is treated in scoring
      ['reject'] = 1.0,
      ['add header'] = 0.25,
      ['rewrite subject'] = 0.25,
      ['no action'] = 1.0
    },
    scores = { -- how each component is evaluated
      ['asn'] = 0.4,
      ['country'] = 0.01,
      ['ipnet'] = 0.5,
      ['ip'] = 1.0
    },
    symbol = 'IP_SCORE', -- symbol to be inserted
    hash = 'ip_score', -- hash table in redis used for storing scores
    asn_suffix = 'a:', -- prefix for ASN hashes
    country_suffix = 'c:', -- prefix for country hashes
    ipnet_suffix = 'n:', -- prefix for ipnet hashes
    lower_bound = 10, -- minimum number of messages to be scored
    min_score = nil,
    max_score = nil,
    score_divisor = 1,
  },
  --dependencies = {"ASN"}, -- ASN is a prefilter now...
}

local selectors = {
  ip = ip_selector,
}

local function reputation_dns_init(rule)
  if not rule.backend.config.list then
    rspamd_logger.errx(rspamd_config, "rule %s with DNS backend has no `list` parameter defined",
      rule.symbol)
    return false
  end

  return true
end

local function reputation_dns_get_token(task, token)
end

local function reputation_redis_get_token(task, token)
end

local function reputation_redis_set_token(task, token, value)
end

-- Backends are responsible for getting reputation tokens
local backends = {
  redis = {
    config = {
      expiry = default_expiry
    },
    get_token = reputation_redis_get_token,
    set_token = reputation_redis_set_token,
  },
  dns = {
    config = {
    },
    get_token = reputation_dns_get_token,
    -- No set token for DNS
    init = reputation_dns_init,
  }
}

local function reputation_filter_cb(task, rule)
  rule.selector.filter(task, rule, rule.backend)
end

local function reputation_postfilter_cb(task, rule)
  rule.selector.postfilter(task, rule, rule.backend)
end

local function reputation_idempotent_cb(task, rule)
  rule.selector.idempotent(task, rule, rule.backend)
end

local function deepcopy(orig)
  local orig_type = type(orig)
  local copy
  if orig_type == 'table' then
    copy = {}
    for orig_key, orig_value in next, orig, nil do
      copy[deepcopy(orig_key)] = deepcopy(orig_value)
    end
    setmetatable(copy, deepcopy(getmetatable(orig)))
  else -- number, string, boolean, etc
    copy = orig
  end
  return copy
end
local function override_defaults(def, override)
  for k,v in pairs(override) do
    if def[k] then
      if type(v) == 'table' then
        override_defaults(def[k], v)
      else
        def[k] = v
      end
    else
      def[k] = v
    end
  end
end

local rules = {}

local function callback_gen(cb, rule)
  return function(task)
    cb(task, rule)
  end
end

local function parse_rule(name, tbl)
  local selector = selectors[tbl.selector['type']]

  if not selector then
    rspamd_logger.errx(rspamd_config, "unknown selector defined for rule %s: %s", name,
      tbl.selector.type)
    return
  end

  local backend = tbl.backend
  if not backend or not backend.type then
    rspamd_logger.errx(rspamd_config, "no backend defined for rule %s", name)
    return
  end

  backend = backends[backend.type]
  if not backend then
    rspamd_logger.errx(rspamd_config, "unknown backend defined for rule %s: %s", name,
      tbl.backend.type)
    return
  end
  -- Allow config override
  local rule = {
    selector = deepcopy(selector),
    backend = deepcopy(backend)
  }

  -- Override default config params
  override_defaults(rule.backend.config, tbl.backend)
  override_defaults(rule.selector.config, tbl.selector)

  local symbol = name
  if tbl.symbol then
    symbol = name
  end

  rule.symbol = symbol

  -- Perform additional initialization if needed
  if rule.selector.init then
    if not rule.selector.init(rule) then
      return
    end
  end
  if rule.backend.init then
    if not rule.backend.init(rule) then
      return
    end
  end

  -- We now generate symbol for checking
  local id = rspamd_config:register_symbol{
    name = symbol,
    type = 'normal',
    callback = callback_gen(reputation_filter_cb, rule),
  }

  if rule.selector.dependencies then
    fun.each(function(d)
      rspamd_config:register_dependency(id, d)
    end, rule.selector.dependencies)
  end

  if rule.selector.postfilter then
    -- Also register a postfilter
    rspamd_config:register_symbol{
      name = symbol .. '_POST',
      type = 'postfilter,nostat',
      callback = callback_gen(reputation_postfilter_cb, rule),
    }
  end

  if rule.selector.idempotent then
    -- Has also idempotent component (e.g. saving data to the backend)
    rspamd_config:register_symbol{
      name = symbol .. '_IDEMPOTENT',
      type = 'idempotent',
      callback = callback_gen(reputation_idempotent_cb, rule),
    }
  end

  rules.symbol = rule
end

redis_params = rspamd_parse_redis_server('reputation')
local opts = rspamd_config:get_all_opt("fann_redis")

-- Initialization part
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  return
end

if opts['rules'] then
  for k,v in opts['rules'] do
    if not v.selector or not v.selector.type then
      rspamd_logger.errx(rspamd_config, "no selector defined for rule %s", k)
    else
      parse_rule(k, v)
    end
  end
end
