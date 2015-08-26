--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

-- IP score is a module that set ip score of specific ip, asn, country
local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_util = require "rspamd_util"
local _ = require "fun"

-- Default settings
local default_port = 6379
local upstreams = nil
local whitelist = nil

local options = {
  asn_provider = 'origin.asn.cymru.com', -- provider for ASN data
  actions = { -- how each action is treated in scoring
    ['reject'] = 1.0,
    ['add header'] = 0.25,
    ['rewrite subject'] = 0.25,
    ['no action'] = 1.0
  },
  scores = { -- how each component is evaluated
    ['asn'] = 0.5,
    ['country'] = 0.1,
    ['ipnet'] = 0.8,
    ['ip'] = 1.0
  },
  symbol = 'IP_SCORE', -- symbol to be inserted
  hash = 'ip_score', -- hash table in redis used for storing scores
  asn_prefix = 'a:', -- prefix for ASN hashes
  country_prefix = 'c:', -- prefix for country hashes
  ipnet_prefix = 'n:', -- prefix for ipnet hashes
  servers = '', -- list of servers
  lower_bound = 10, -- minimum number of messages to be scored
  metric = 'default'
}

local asn_re = rspamd_regexp.create_cached("[\\|\\s]")

local function asn_check(task)
  local ip = task:get_from_ip()
  
  local function asn_dns_cb(resolver, to_resolve, results, err, key)
    if results and results[1] then
      local parts = asn_re:split(results[1])
      -- "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
      if parts[1] then
        task:get_mempool():set_variable("asn", parts[1])
      end
      if parts[2] then
        task:get_mempool():set_variable("ipnet", parts[2])
      end
      if parts[3] then
        task:get_mempool():set_variable("country", parts[3])
      end
    end
  end
  
  if ip and ip:is_valid() then
    local req_name = rspamd_logger.slog("%1.%2",
      table.concat(ip:inversed_str_octets(), '.'), options['asn_provider'])
    
    task:get_resolver():resolve_txt(task:get_session(), task:get_mempool(),
        req_name, asn_dns_cb)
  end
end

local function ip_score_hash_key(asn, country, ipnet, ip)
  -- We use the most common attribute as hashing key
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

-- Set score based on metric's action
local ip_score_set = function(task)
  local function new_score_set(score, old_score, old_total)
    local new_total
    if old_total == -1 then
      new_total = 1
    else
      new_total = old_total + 1
    end
    
    return old_score + score, new_total
  end

  local score_set_cb = function(task, err, data)
    if err then
      rspamd_logger.infox('got error while IP score changing: %1', err)
    end
  end

  local action = task:get_metric_action(options['metric'])
  local ip = task:get_from_ip()
  if not ip or not ip:is_valid() then
    return
  end
  
  -- Check whitelist
  if whitelist then
    if whitelist:get_key(ip) then
      -- Address is whitelisted
      return
    end
  end
  
  local pool = task:get_mempool()
  local asn, country, ipnet = ip_score_get_task_vars(task)
  
  if not pool:has_variable('ip_score') then
    return
  end
  
  local asn_score,total_asn,
        country_score,total_country,
        ipnet_score,total_ipnet,
        ip_score, total_ip = pool:get_variable('ip_score', 
        'double,double,double,double,double,double,double,double')

  local score_mult = 0
  if options['actions'][action] then
    score_mult = options['actions'][action]
  end
  local score = task:get_metric_score(options['metric'])[1]
  if action == 'no action' and score > 0 then
    score_mult = 0
  end

  score = score_mult * rspamd_util.tanh (2.718 * score)

  if score ~= 0 then
    local hkey = ip_score_hash_key(asn, country, ipnet, ip)
    local upstream = upstreams:get_upstream_by_hash(hkey)
    local addr = upstream:get_addr()
    
    asn_score,total_asn = new_score_set(score, asn_score, total_asn)
    country_score,total_country = new_score_set(score, country_score, total_country)
    ipnet_score,total_ipnet = new_score_set(score, ipnet_score, total_ipnet)
    ip_score,total_ip = new_score_set(score, ip_score, total_ip)
    
    rspamd_redis.make_request(task, addr, score_set_cb, 
      'HMSET', {options['hash'], 
      options['asn_prefix'] .. asn, string.format('%f|%d', asn_score, total_asn),
      options['country_prefix'] .. country, string.format('%f|%d', country_score, total_country),
      options['ipnet_prefix'] .. ipnet, string.format('%f|%d', ipnet_score, total_ipnet),
      ip:to_string(), string.format('%f|%d', ip_score, total_ip)})
  end
end

-- Check score for ip in keystorage
local ip_score_check = function(task)
  local asn, country, ipnet = ip_score_get_task_vars(task)

  local ip_score_redis_cb = function(task, err, data)
    local function calculate_score(score)
      local parts = asn_re:split(score)
      local rep = tonumber(parts[1])
      local total = tonumber(parts[2])
      
      return rep, total
    end
    
    local function normalize_score(sc, total, mult)
      if total < options['lower_bound'] then
        return 0
      end
      
      -- -mult to mult
      return mult * rspamd_util.tanh(2.718 * sc / total)
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
        table.insert(description_t, 'ip: ' .. '(' .. math.floor(ip_score * 1000) / 100 .. ')')
      end
      if ipnet_score ~= 0 then
        total_score = total_score + ipnet_score
        table.insert(description_t, 'ipnet: ' .. ipnet .. '(' .. math.floor(ipnet_score * 1000) / 100 .. ')')
      end
      if asn_score ~= 0 then
        total_score = total_score + asn_score
        table.insert(description_t, 'asn: ' .. asn .. '(' .. math.floor(asn_score * 1000) / 100 .. ')')
      end
      if country_score ~= 0 then
        total_score = total_score + country_score
        table.insert(description_t, 'country: ' .. country .. '(' .. math.floor(country_score * 1000) / 100 .. ')')
      end
      
      if total_score ~= 0 then
        task:insert_result(options['symbol'], total_score, table.concat(description_t, ', '))
      end
    end
  end
  
  local function create_get_command(ip, asn, country, ipnet)
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
  
  local ip = task:get_from_ip()
  if ip:is_valid() then
    if whitelist then
      if whitelist:get_key(task:get_from_ip()) then
        -- Address is whitelisted
        return
      end
    end

    local cmd, args = create_get_command(ip, asn, country, ipnet)
    local upstream = upstreams:get_upstream_by_hash(
      ip_score_hash_key(asn, country, ipnet, ip))
    local addr = upstream:get_addr()
    rspamd_redis.make_request(task, addr, ip_score_redis_cb, cmd, args)
  end
end


-- Configuration options
local configure_ip_score_module = function()
  local opts =  rspamd_config:get_all_opt('ip_score')
  if opts then
    for k,v in pairs(opts) do
      options[k] = v
    end
    if options['servers'] and options['servers'] ~= '' then
      upstreams = upstream_list.create(options['servers'], default_port)
      if not upstreams then
        rspamd_logger.err('no servers are specified')
      end
    end
    if options['whitelist'] then
      whitelist = rspamd_config:add_radix_map(opts['whitelist'])
    end
  end
end


configure_ip_score_module()
if upstreams then
  -- Register ip_score module
  if options['asn_provider'] then
    rspamd_config:register_pre_filter(asn_check)
  end
  rspamd_config:register_symbol(options['symbol'], 1.0, ip_score_check)
  rspamd_config:register_post_filter(ip_score_set)
end
