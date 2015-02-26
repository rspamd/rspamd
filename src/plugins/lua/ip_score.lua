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

-- IP score is a module that set ip score of specific ip and

-- Default settings
local default_port = 6379
local upstreams = nil
local metric = 'default'
local reject_score = 3
local add_header_score = 1
local no_action_score = -2
local symbol = 'IP_SCORE'
local prefix = 'ip_score:'
-- This score is used for normalization of scores from keystorage
local normalize_score = 100
local whitelist = nil
local expire = 240
local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"
local _ = require "fun"

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
  
  local function process_action(ip, score)
    local cmd = 'INCRBY'
    local args = {}
    table.insert(args, prefix .. ip:to_string())
    if score > 0 then
      table.insert(args, score)
    else
      cmd = 'DECRBY'
      table.insert(args, -score)
    end
    
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

  local cmd, args
  if action then
    local cb = make_key_cb(ip)
    -- Now check action
    if action == 'reject' then
      cmd, args = process_action(ip, reject_score)
    elseif action == 'add header' then
      cmd, args = process_action(ip, add_header_score)
    elseif action == 'no action' then
      cmd, args = process_action(ip, no_action_score)
    end
  end
  
  if cmd then
    local upstream = upstreams:get_upstream_by_hash(ip:to_string())
    local addr = upstream:get_addr()
    rspamd_redis.make_request(task, addr, make_key_cb(ip), cmd, args)
  end
end

-- Check score for ip in keystorage
local ip_score_check = function(task)
  local cb = function(task, err, data)
    if err then
      -- Key is not found or error occurred
      return
    elseif data then
      local score = tonumber(data)
      if not score then
        return
      end
      
      -- Normalize
      if score > 0 and score > normalize_score then
        score = 1
      elseif score < 0 and score < -normalize_score then
        score = -1
      else
        score = score / normalize_score
      end
      task:insert_result(symbol, score)
    end
  end
  local ip = task:get_from_ip()
  if ip:is_valid() then
    if whitelist then
      if whitelist:get_key(task:get_from_ip()) then
        -- Address is whitelisted
        return
      end
    end
    local upstream = upstreams:get_upstream_by_hash(ip:to_string())
    local addr = upstream:get_addr()
    rspamd_redis.make_request(task, addr, cb, 'GET', {prefix .. ip:to_string()})
  end
end


-- Configuration options
local configure_ip_score_module = function()
  local opts =  rspamd_config:get_all_opt('ip_score')
  if opts then
    if opts['keystorage_host'] then
      keystorage_host = opts['keystorage_host']
    end
    if opts['keystorage_port'] then
      keystorage_port = opts['keystorage_port']
    end
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
  end
  if opts['servers'] then
    upstreams = upstream_list.create(opts['servers'], default_port)
    if not upstreams then
      rspamd_logger.err('no servers are specified')
    end
  end
end

-- Registration
if rspamd_config:get_api_version() >= 9 then
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
    rspamd_config:register_symbol(symbol, 1.0, ip_score_check)
    rspamd_config:register_post_filter(ip_score_set)
  end
else
  rspamd_logger.err('cannot register module ip_score as it requires at least 9 version of lua API and rspamd >= 0.4.6')
end
