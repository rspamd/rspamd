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
local _ = require "fun"

-- Default settings
local default_port = 6379
local asn_provider = 'origin.asn.cymru.com'
local upstreams = nil
local metric = 'default'
local reject_score = 3
local add_header_score = 1
local no_action_score = -2
local symbol = 'IP_SCORE'
local prefix = 'i:'
local asn_prefix = 'a:'
local country_prefix = 'c:'
local ipnet_prefix = 'n:'
-- This score is used for normalization of scores from keystorage
local normalize_score = 100
local whitelist = nil
local expire = 240
local asn_re = rspamd_regexp.create_cached("/|/")

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
      table.concat(ip:inversed_str_octets(), '.'), asn_provider)
    
    task:get_resolver():resolve_txt(task:get_session(), task:get_mempool(),
        req_name, asn_dns_cb)
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
  -- Callback generator
  local make_key_cb = function(ip)
    local cb = function(task, err, data)
      if err then
        rspamd_logger.info('got error while IP score changing: ' .. err)
      end
    end
    return cb
  end
  
  local function process_action(ip, asn, country, ipnet, score)
    local cmd
    
    if score > 0 then
      cmd = 'INCRBY'
    else
      cmd = 'DECRBY'
      score = -score
    end
    
    local args = {}
    
    if asn then
      table.insert(args, asn_prefix .. asn)
      table.insert(args, score)
    end
    if country then
      table.insert(args, country_prefix .. country)
      table.insert(args, score)
    end
    if ipnet then
      table.insert(args, ipnet_prefix .. ipnet)
      table.insert(args, score)
    end
    
    table.insert(args, prefix .. ip:to_string())
    table.insert(args, score)
    
    return cmd, args
  end

  local action = task:get_metric_action(metric)
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

  local asn, country, ipnet = ip_score_get_task_vars(task)

  local cmd, args
  
  if action then
    local cb = make_key_cb(ip)
    -- Now check action
    if action == 'reject' then
      cmd, args = process_action(ip, asn, country, ipnet, reject_score)
    elseif action == 'add header' then
      cmd, args = process_action(ip, asn, country, ipnet, add_header_score)
    elseif action == 'no action' then
      cmd, args = process_action(ip, asn, country, ipnet, no_action_score)
    end
  end
  
  if cmd then
    local hkey = ip:to_string()
    if country then
      hkey = country
    elseif asn then
      hkey = asn
    elseif ipnet then
      hkey = ipnet
    end
    
    local upstream = upstreams:get_upstream_by_hash(hkey)
    local addr = upstream:get_addr()
    rspamd_redis.make_request(task, addr, make_key_cb(ip), cmd, args)
  end
end

-- Check score for ip in keystorage
local ip_score_check = function(task)
  local asn, country, ipnet = ip_score_get_task_vars(task)

  local ip_score_redis_cb = function(task, err, data)
    local function normalize_score(score)
      -- Normalize
      local nscore
      if score > 0 and score > normalize_score then
        nscore = 1
      elseif score < 0 and score < -normalize_score then
        nscore = -1
      else
        nscore = score / normalize_score
      end
      
      return nscore
    end
    
    if err then
      -- Key is not found or error occurred
      return
    elseif data then
      
      if data[1] and type(data[1]) == 'number' then
        local asn_score = normalize_score(tonumber(data[1]))
        task:insert_result(symbol, asn_score, 'asn: ' .. asn)
      end
      if data[2] and type(data[2]) == 'number' then
        local country_score = normalize_score(tonumber(data[2]))
        task:insert_result(symbol, country_score, 'country: ' .. country)
      end
      if data[3] and type(data[3]) == 'number' then
        local ipnet_score = normalize_score(tonumber(data[3]))
        task:insert_result(symbol, ipnet_score, 'ipnet: ' .. country)
      end
      if data[4] and type(data[4]) == 'number' then
        local ip_score = normalize_score(tonumber(data[4]))
        task:insert_result(symbol, ip_score, 'ip')
      end
    end
  end
  
  local function create_get_command(ip, asn, country, ipnet)
    local cmd = 'MGET'
    
    local args = {}
    
    if asn then
      table.insert(args, asn_prefix .. asn)
    else
      -- fake arg
      table.insert(args, asn_prefix)
    end
    if country then
      table.insert(args, country_prefix .. country)
    else
      -- fake arg
      table.insert(args, country_prefix)
    end
    if ipnet then
      table.insert(args, ipnet_prefix .. ipnet)
    else
      -- fake arg
      table.insert(args, ipnet_prefix)
    end
    
    table.insert(args, prefix .. ip:to_string())
    
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
    local upstream = upstreams:get_upstream_by_hash(ip:to_string())
    local addr = upstream:get_addr()
    rspamd_redis.make_request(task, addr, ip_score_redis_cb, cmd, args)
  end
end


-- Configuration options
local configure_ip_score_module = function()
  local opts =  rspamd_config:get_all_opt('ip_score')
  if opts then
    if opts['metric'] then
      metric = opts['metric']
    end
    if opts['reject_score'] then
      reject_score = opts['reject_score']
    end
    if opts['add_header_score'] then
      add_header_score = opts['add_header_score']
    end
    if opts['no_action_score'] then
      no_action_score = opts['no_action_score']
    end
    if opts['symbol'] then
      symbol = opts['symbol']
    end
    if opts['normalize_score'] then
      normalize_score = opts['normalize_score']
    end
    if opts['threshold'] then
      normalize_score = opts['normalize_score']
    end
    if opts['whitelist'] then
      whitelist = rspamd_config:add_radix_map(opts['whitelist'])
    end
    if opts['expire'] then
      expire = opts['expire']
    end
    if opts['prefix'] then
      prefix = opts['prefix']
    end
    if opts['asn_provider'] then
      asn_provider = opts['asn_provider']
    end
    if opts['servers'] then
      upstreams = upstream_list.create(opts['servers'], default_port)
      if not upstreams then
        rspamd_logger.err('no servers are specified')
      end
    end
  end
end

-- Registration
rspamd_config:register_module_option('ip_score', 'keystorage_host', 'string')
rspamd_config:register_module_option('ip_score', 'keystorage_port', 'uint')
rspamd_config:register_module_option('ip_score', 'metric', 'string')
rspamd_config:register_module_option('ip_score', 'reject_score', 'int')
rspamd_config:register_module_option('ip_score', 'add_header_score', 'int')
rspamd_config:register_module_option('ip_score', 'no_action_score', 'int')
rspamd_config:register_module_option('ip_score', 'symbol', 'string')
rspamd_config:register_module_option('ip_score', 'normalize_score', 'uint')
rspamd_config:register_module_option('ip_score', 'whitelist', 'map')
rspamd_config:register_module_option('ip_score', 'expire', 'uint')

configure_ip_score_module()
if upstreams and normalize_score > 0 then
  -- Register ip_score module
  if asn_provider then
    rspamd_config:register_pre_filter(asn_check)
  end
  rspamd_config:register_symbol(symbol, 1.0, ip_score_check)
  rspamd_config:register_post_filter(ip_score_set)
end
