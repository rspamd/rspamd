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
  return
end

-- IP score is a module that set ip score of specific ip, asn, country
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"

-- Default settings
local redis_params = nil
local whitelist = nil
local asn_cc_whitelist = nil
local check_authed = false
local check_local = false
local M = "ip_score"
local N = M

local options = {
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
  asn_prefix = 'a:', -- prefix for ASN hashes
  country_prefix = 'c:', -- prefix for country hashes
  ipnet_prefix = 'n:', -- prefix for ipnet hashes
  servers = '', -- list of servers
  lower_bound = 10, -- minimum number of messages to be scored
  metric = 'default',
  old_shard = false,
  min_score = nil,
  max_score = nil,
  score_divisor = 1,
}

local function ip_score_hash_key(asn, country, ipnet, ip)
  if options.old_shard then
    if country then
      return country
    elseif asn then
      return asn
    elseif ipnet then
      return ipnet
    else
      return ip:to_string()
    end
  end

  -- Better sharding
  return string.format('%s:%s:%s:%s', asn, country, ipnet,
      ip:to_string())
end

local function ip_score_get_task_vars(task)
  local pool = task:get_mempool()
  local asn, country, ipnet
  if pool:get_variable("asn") then
    asn = pool:get_variable("asn")
  end
  if pool:get_variable("country") then
    country = pool:get_variable("country")
  end
  if pool:get_variable("ipnet") then
    ipnet = pool:get_variable("ipnet")
  end

  return asn, country, ipnet
end

local function normalize_score(sc, total, mult)
  if total < options['lower_bound'] then
    return 0
  end
  return mult * rspamd_util.tanh(2.718281 * sc / total)
end

-- Set score based on metric's action
local ip_score_set = function(task)
  if lua_util.is_rspamc_or_controller(task) then return end
  local function new_score_set(score, old_score, old_total)
    local new_total
    if old_total == -1 or old_total ~= old_total then
      new_total = 1
    else
      new_total = old_total + 1
    end

    if score ~= score then
      score = 0
    end

    return old_score + score, new_total
  end

  local score_set_cb = function(err)
    if err then
      rspamd_logger.infox(task, 'got error while IP score changing: %1', err)
    end
  end

  local ip = task:get_from_ip()
  if not check_authed and task:get_user() then
    return
  end
  local action = task:get_metric_action(options['metric'])
  if not ip or not ip:is_valid() then
    return
  end
  if not check_local and ip:is_local() then
    return
  end

  local pool = task:get_mempool()
  local asn, country, ipnet = ip_score_get_task_vars(task)

  if not pool:has_variable('ip_score') or not asn or not country or not ipnet then
    return
  end

  local asn_score,total_asn,
        country_score,total_country,
        ipnet_score,total_ipnet,
        ip_score, total_ip = pool:get_variable('ip_score',
        'double,double,double,double,double,double,double,double')
  lua_util.debugm(M, task,
      'raw scores: asn: %s, total_asn: %s, country: %s, ' ..
          'total_country: %s, ipnet: %s, total_ipnet: %s, ip:%s, total_ip: %s',
      asn_score, total_asn,
      country_score, total_country,
      ipnet_score, total_ipnet,
      ip_score, total_ip)

  local score_mult = 0
  if options['actions'][action] then
    score_mult = options['actions'][action]
  end
  local score = task:get_metric_score(options['metric'])[1]
  if action == 'no action' and score > 0 then
    score_mult = 0
  end

  score = score_mult * rspamd_util.tanh (2.718281 * (score/options['score_divisor']))

  local hkey = ip_score_hash_key(asn, country, ipnet, ip)

  asn_score,total_asn = new_score_set(score, asn_score, total_asn)
  country_score,total_country = new_score_set(score, country_score, total_country)
  ipnet_score,total_ipnet = new_score_set(score, ipnet_score, total_ipnet)
  ip_score,total_ip = new_score_set(score, ip_score, total_ip)
  lua_util.debugm(M, task,
      'processed scores: asn: %s, total_asn: %s, country: %s, total_country: %s,' ..
          ' ipnet: %s, total_ipnet: %s, ip:%s, total_ip: %s',
    asn_score,total_asn,
    country_score,total_country,
    ipnet_score,total_ipnet,
    ip_score, total_ip)
  local redis_args = {options['hash'],
    options['asn_prefix'] .. asn, string.format('%f|%d', asn_score, total_asn),
    options['country_prefix'] .. country, string.format('%f|%d', country_score, total_country),
    options['ipnet_prefix'] .. ipnet, string.format('%f|%d', ipnet_score, total_ipnet),
    ip:to_string(), string.format('%f|%d', ip_score, total_ip)}

  local ret = rspamd_redis_make_request(task,
    redis_params, -- connect params
    hkey, -- hash key
    true, -- is write
    score_set_cb, --callback
    'HMSET', -- command
    redis_args -- arguments
  )
  if not ret then
    rspamd_logger.errx(task, 'error connecting to redis')
    return
  end

  -- Now insert final result
  asn_score = normalize_score(asn_score, total_asn, options['scores']['asn'])
  country_score = normalize_score(country_score, total_country,
      options['scores']['country'])
  ipnet_score = normalize_score(ipnet_score, total_ipnet,
       options['scores']['ipnet'])
  ip_score = normalize_score(ip_score, total_ip, options['scores']['ip'])

  local total_score = 0.0
  local description_t = {}

  if ip_score ~= 0 then
    total_score = total_score + ip_score
    table.insert(description_t,
        'ip: ' .. '(' .. string.format('%.2f', ip_score * 10) .. ')')
  end
  if ipnet_score ~= 0 then
    total_score = total_score + ipnet_score
    table.insert(description_t,
        'ipnet: ' .. ipnet .. '(' .. string.format('%.2f', ipnet_score * 10) .. ')')
  end
  if asn_score ~= 0 then
    total_score = total_score + asn_score
    table.insert(description_t,
        'asn: ' .. asn .. '(' .. string.format('%.2f', asn_score * 10) .. ')')
  end
  if country_score ~= 0 then
    total_score = total_score + country_score
    table.insert(description_t,
        'country: ' .. country .. '(' .. string.format('%.2f', country_score * 10) .. ')')
  end

  if options['max_score'] and (total_score*10) > options['max_score'] then
    total_score = options['max_score']/10
  end
  if options['min_score'] and (total_score*10) < options['min_score'] then
    total_score = options['min_score']/10
  end

  if total_score ~= 0 then
    task:insert_result(options['symbol'], total_score, table.concat(description_t, ', '))
  end
end

-- Check score for ip in keystorage
local ip_score_check = function(task)
  local asn, country, ipnet = ip_score_get_task_vars(task)
  local ip = task:get_from_ip()

  local ip_score_redis_cb = function(err, data)
    if err then
      rspamd_logger.errx(task, 'Redis error: %s', err)
      -- XXX: upstreams
    end
    local function calculate_score(score)
      local parts = lua_util.rspamd_str_split(score, '|')
      local rep = tonumber(parts[1])
      local total = tonumber(parts[2])

      if rep ~= rep then rep = 0 end
      if total ~= total then total = 0 end

      return rep, total
    end

    if err then
      -- Key is not found or error occurred
      return
    elseif data then
      -- Scores and total number of messages per bucket
      local asn_score,total_asn,
        country_score,total_country,
        ipnet_score,total_ipnet,
        ip_score, total_ip = 0, -1, 0, -1, 0, -1, 0, -1
      if data[1] and type(data[1]) ~= 'userdata' then
        asn_score,total_asn = calculate_score(data[1])
      end
      if data[2] and type(data[2]) ~= 'userdata' then
        country_score,total_country = calculate_score(data[2])
      end
      if data[3] and type(data[3]) ~= 'userdata' then
        ipnet_score,total_ipnet = calculate_score(data[3])
      end
      if data[4] and type(data[4]) ~= 'userdata' then
        ip_score,total_ip = calculate_score(data[4])
      end
      -- Save everything for the post filter
      task:get_mempool():set_variable('ip_score', asn_score,total_asn,
        country_score,total_country,
        ipnet_score,total_ipnet,
        ip_score, total_ip)
    end
  end

  local function create_get_command()
    local cmd = 'HMGET'

    local args = {options['hash']}

    if asn then
      table.insert(args, options['asn_prefix'] .. asn)
    else
      -- fake arg
      table.insert(args, options['asn_prefix'])
    end
    if country then
      table.insert(args, options['country_prefix'] .. country)
    else
      -- fake arg
      table.insert(args, options['country_prefix'])
    end
    if ipnet then
      table.insert(args, options['ipnet_prefix'] .. ipnet)
    else
      -- fake arg
      table.insert(args, options['ipnet_prefix'])
    end

    table.insert(args, ip:to_string())

    return cmd, args
  end

  if task:get_user() and not check_authed then
    rspamd_logger.infox(task, "skip IP Score for authorized users")
    return
  end
  if ip and ip:is_local() and not check_local then
    rspamd_logger.infox(task, "skip IP Score for local networks")
    return
  end
  if ip:is_valid() then
    -- Check IP whitelist
    if whitelist then
      if whitelist:get_key(task:get_from_ip()) then
        -- Address is whitelisted
        return
      end
    end
    -- Check ASN & country whitelist
    if asn_cc_whitelist then
      if asn_cc_whitelist:get_key(country) then
        return
      end
      if asn_cc_whitelist:get_key(asn) then
        return
      end
    end

    local cmd, args = create_get_command()

    local ret = rspamd_redis_make_request(task,
      redis_params, -- connect params
      ip_score_hash_key(asn, country, ipnet, ip), -- hash key
      false, -- is write
      ip_score_redis_cb, --callback
      cmd, -- command
      args -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, 'error connecting to redis')
    end
  end
end

local function try_opts(where)
  local ret = false
  local opts = rspamd_config:get_all_opt(where)
  if type(opts) == 'table' then
    if type(opts['check_local']) == 'boolean' then
      check_local = opts['check_local']
      ret = true
    end
    if type(opts['check_authed']) == 'boolean' then
      check_authed = opts['check_authed']
      ret = true
    end
  end

  return ret
end

if not try_opts(N) then try_opts('options') end

-- Configuration options
local configure_ip_score_module = function()
  local opts = rspamd_config:get_all_opt(N)

  if not opts then return end
  for k,v in pairs(opts) do
    options[k] = v
  end
  redis_params = rspamd_parse_redis_server('ip_score')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified')
    return
  end
  asn_cc_whitelist = rspamd_map_add('ip_score', 'asn_cc_whitelist', 'map',
    'IP score whitelisted ASNs/countries')
  whitelist = rspamd_map_add('ip_score', 'whitelist', 'radix',
    'IP score whitelisted ips')
  return true
end


if not configure_ip_score_module() then return end
if redis_params then
  -- Register ip_score module
  rspamd_config:register_symbol({
    name = 'IPSCORE_SAVE',
    type = 'postfilter,nostat',
    priority = 5,
    callback = ip_score_set,
    flags = 'empty',
  })
  rspamd_config:register_symbol({
    name = options['symbol'],
    callback = ip_score_check,
    group = 'reputation',
    score = 2.0,
    flags = 'empty',
  })
else
  lua_util.disable_module(N, "redis")
end
