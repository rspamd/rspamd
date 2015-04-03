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

-- Dmarc policy filter

local rspamd_regexp = require "rspamd_regexp"
local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"
local dumper = require 'pl.pretty'.dump

local symbols = {
  spf_allow_symbol = 'R_SPF_ALLOW',
  spf_deny_symbol = 'R_SPF_FAIL',
  spf_softfail_symbol = 'R_SPF_SOFTFAIL',
  spf_neutral_symbol = 'R_SPF_NEUTRAL',

  dkim_allow_symbol = 'R_DKIM_ALLOW',
  dkim_deny_symbol = 'R_DKIM_REJECT',
}
-- Default port for redis upstreams
local default_port = 6379
local upstreams = nil
local dmarc_redis_key_prefix = "dmarc_"

local elts_re = rspamd_regexp.create_cached(";\\s+")

local function dmarc_report(task, spf_ok, dkim_ok)
  local ip = task:get_from_ip()
  if not ip:is_valid() then
    return nil
  end
  local res = string.format('%d:%s:%s:%s', task:get_date(0),
    ip:to_string(), tostring(spf_ok), tostring(dkim_ok))
    
  return res
end

local function dmarc_callback(task)
  local from = task:get_from()
  
  local function dmarc_report_cb(task, err, data)
    if not err then
      rspamd_logger.info(string.format('<%s> dmarc report saved for %s',
        task:get_message_id(), from[1]['domain']))
    else
      rspamd_logger.err(string.format('<%s> dmarc report is not saved for %s: %s',
        task:get_message_id(), from[1]['domain'], err))
    end
  end
  
  local function dmarc_dns_cb(resolver, to_resolve, results, err, key)
    local strict_spf = false
    local strict_dkim = false
    local strict_policy = false
    local rua
    
    if results then
      for _,r in ipairs(results) do
        local elts = elts_re:split(r)

        if elts then
          for _,e in ipairs(elts) do
            dkim_pol = string.match(e, '^adkim=([sr])$')
            if dkim_pol and dkim_pol == 's' then
              strict_dkim = true
            end
            spf_pol = string.match(e, '^aspf=([sr])$')
            if spf_pol and spf_pol == 's' then
              strict_spf = true
            end
            policy = string.match(e, '^p=reject$')
            if policy then
              strict_policy = true
            end
            
            if not rua then
              rua = string.match(e, '^rua=([^%s]+)$')
            end
          end
        end
      end
    end

    if strict_spf then
      -- Handle subdomains
    end
    if strict_dkim then
      -- Handle subdomain
    end
    
    -- Check dkim and spf symbols
    local spf_ok = false
    local dkim_ok = false
    if task:get_symbol(symbols['spf_allow_symbol']) then spf_ok = true end
    if task:get_symbol(symbols['dkim_allow_symbol']) then dkim_ok = true end
    
    if strict_policy and (not spf_ok or not dkim_ok) then
      local res = 0.5
      if not dkim_ok and not spf_ok then res = 1.0 end
      
      task:insert_result('DMARC_STRICT_DENY', res)
      
    elseif strict_policy then
      task:insert_result('DMARC_STRICT_ALLOW', res)
    end
    
    if rua and (not spf_ok or not dkim_ok) and upstreams then
      -- Prepare and send redis report element
      local upstream = upstreams:get_upstream_by_hash(from[1]['domain'])
      local redis_key = dmarc_redis_key_prefix .. from[1]['domain']
      local addr = upstream:get_addr()
      local report_data = dmarc_report(task, spf_ok, dkim_ok)
      
      if report_data then
        rspamd_redis.make_request(task, addr, dmarc_report_cb, 
          'LPUSH', {redis_key, report_data})
      end
    end
    
    -- XXX: handle rua and push data to redis
  end
  
  if from and from[1]['domain'] then
    -- XXX: use tld list here and generate top level domain
    local dmarc_domain = '_dmarc.' .. from[1]['domain']
    task:get_resolver():resolve_txt(task:get_session(), task:get_mempool(),
      dmarc_domain, dmarc_dns_cb)
  end
end

local opts = rspamd_config:get_all_opt('dmarc')
if not opts or type(opts) ~= 'table' then
  return
end

if not opts['servers'] then
  rspamd_logger.err('no servers are specified for dmarc stats')
else
  upstreams = upstream_list.create(opts['servers'], default_port)
  if not upstreams then
    rspamd_logger.err('cannot parse servers parameter')
  end
end

if opts['key_prefix'] then
  dmarc_redis_key_prefix = opts['key_prefix']
end

-- Check spf and dkim sections for changed symbols
local function check_mopt(var, opts, name)
  if opts[name] then
    symbols['var'] = tostring(opts[name])
  end
end

local spf_opts = rspamd_config:get_all_opt('spf')
if spf_opts then
  check_mopt('spf_deny_symbol', spf_opts, 'symbol_fail')
  check_mopt('spf_allow_symbol', spf_opts, 'symbol_allow')
  check_mopt('spf_softfail_symbol', spf_opts, 'symbol_softfail')
  check_mopt('spf_neutral_symbol', spf_opts, 'symbol_neutral')
end

local dkim_opts = rspamd_config:get_all_opt('dkim')
if dkim_opts then
  check_mopt('dkim_deny_symbol', 'symbol_reject')
  check_mopt('dkim_allow_symbol', 'symbol_allow')
end

rspamd_config:register_virtual_symbol('DMARC_POLICY_ALLOW', -1)
rspamd_config:register_virtual_symbol('DMARC_POLICY_REJECT', 1)
rspamd_config:register_post_filter(dmarc_callback)