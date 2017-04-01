--[[
Copyright (c) 2011-2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2015-2016, Andrew Lewis <nerf@judo.za.org>

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

-- Dmarc policy filter

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local check_local = false
local check_authed = false

local symbols = {
  spf_allow_symbol = 'R_SPF_ALLOW',
  spf_deny_symbol = 'R_SPF_FAIL',
  spf_softfail_symbol = 'R_SPF_SOFTFAIL',
  spf_neutral_symbol = 'R_SPF_NEUTRAL',
  spf_tempfail_symbol = 'R_SPF_DNSFAIL',
  spf_na_symbol = 'R_SPF_NA',

  dkim_allow_symbol = 'R_DKIM_ALLOW',
  dkim_deny_symbol = 'R_DKIM_REJECT',
  dkim_tempfail_symbol = 'R_DKIM_TEMPFAIL',
  dkim_na_symbol = 'R_DKIM_NA',
}

local dmarc_symbols = {
  allow = 'DMARC_POLICY_ALLOW',
  badpolicy = 'DMARC_BAD_POLICY',
  dnsfail = 'DMARC_DNSFAIL',
  na = 'DMARC_NA',
  reject = 'DMARC_POLICY_REJECT',
  softfail = 'DMARC_POLICY_SOFTFAIL',
  quarantine = 'DMARC_POLICY_QUARANTINE',
}

-- Default port for redis upstreams
local redis_params = nil
local dmarc_redis_key_prefix = "dmarc_"
-- 2 days
local dmarc_redis_key_expire = 60 * 60 * 24 * 2
local dmarc_reporting = false
local dmarc_actions = {}

local E = {}

local function gen_dmarc_grammar()
  local lpeg = require "lpeg"
  lpeg.locale(lpeg)
  local space = lpeg.space^0
  local name = lpeg.C(lpeg.alpha^1) * space
  local sep = lpeg.S("\\;") * space
  local value = lpeg.C(lpeg.P(lpeg.graph - sep)^1)
  local pair = lpeg.Cg(name * "=" * space * value) * sep^-1
  local list = lpeg.Cf(lpeg.Ct("") * pair^0, rawset)
  local version = lpeg.P("v") * space * lpeg.P("=") * space * lpeg.P("DMARC1")
  local record = version * space * sep * list

  return record
end

local dmarc_grammar = gen_dmarc_grammar()

local function dmarc_report(task, spf_ok, dkim_ok, disposition, sampled_out)
  local ip = task:get_from_ip()
  if not ip:is_valid() then
    return nil
  end
  local res = string.format('%d,%s,%s,%s,%s,%s', task:get_date(0),
    ip:to_string(), tostring(spf_ok), tostring(dkim_ok),
    disposition, (sampled_out and 'sampled_out' or ''))

  return res
end

local function dmarc_callback(task)
  local function maybe_force_action(disposition)
    local force_action = dmarc_actions[disposition]
    if force_action then
      task:set_pre_result(force_action, 'Action set by DMARC')
    end
  end
  local from = task:get_from(2)
  local dmarc_domain
  local ip_addr = task:get_ip()

  if ((not check_authed and task:get_user()) or
      (not check_local and ip_addr and ip_addr:is_local())) then
    rspamd_logger.infox(task, "skip DMARC checks for local networks and authorized users");
    return
  end
  if ((from or E)[1] or E).domain and ((from or E)[1] or E).domain ~= '' and not (from or E)[2] then
    dmarc_domain = rspamd_util.get_tld(from[1]['domain'])
  elseif (from or E)[2] then
    task:insert_result(dmarc_symbols['na'], 1.0, 'Duplicate From header')
    return maybe_force_action('na')
  elseif (from or E)[1] then
    task:insert_result(dmarc_symbols['na'], 1.0, 'No domain in From header')
    return maybe_force_action('na')
  else
    task:insert_result(dmarc_symbols['na'], 1.0, 'No From header')
    return maybe_force_action('na')
  end

  local function dmarc_report_cb(err)
    if not err then
      rspamd_logger.infox(task, '<%1> dmarc report saved for %2',
        task:get_message_id(), from[1]['domain'])
    else
      rspamd_logger.errx(task, '<%1> dmarc report is not saved for %2: %3',
        task:get_message_id(), from[1]['domain'], err)
    end
  end

  local function dmarc_dns_cb(_, to_resolve, results, err)

    task:inc_dns_req()
    local lookup_domain = string.sub(to_resolve, 8)
    if err and (err ~= 'requested record is not found' and err ~= 'no records with this name') then
      task:insert_result(dmarc_symbols['dnsfail'], 1.0, lookup_domain .. ' : ' .. err)
      return maybe_force_action('dnsfail')
    elseif err and (err == 'requested record is not found' or err == 'no records with this name') and
      lookup_domain == dmarc_domain then
      task:insert_result(dmarc_symbols['na'], 1.0, lookup_domain)
      return maybe_force_action('na')
    end

    if not results then
      if lookup_domain ~= dmarc_domain then
        local resolve_name = '_dmarc.' .. dmarc_domain
        task:get_resolver():resolve_txt({
          task=task,
          name = resolve_name,
          callback = dmarc_dns_cb,
          forced = true})
        return
      end

      task:insert_result(dmarc_symbols['na'], 1.0, lookup_domain)
      return maybe_force_action('na')
    end

    local pct
    local reason = {}
    local strict_spf = false
    local strict_dkim = false
    local dmarc_policy = 'none'
    local found_policy = false
    local failed_policy
    local rua

    for _,r in ipairs(results) do
      if failed_policy then break end
      (function()
        local elts = dmarc_grammar:match(r)
        if not elts then
          return
        else
          if found_policy then
            failed_policy = 'Multiple policies defined in DNS'
            return
          else
            found_policy = true
          end
        end

        if elts then
          local dkim_pol = elts['adkim']
          if dkim_pol then
            if dkim_pol == 's' then
              strict_dkim = true
            elseif dkim_pol ~= 'r' then
              failed_policy = 'adkim tag has invalid value: ' .. dkim_pol
              return
            end
          end

          local spf_pol = elts['aspf']
          if spf_pol then
            if spf_pol == 's' then
              strict_spf = true
            elseif spf_pol ~= 'r' then
              failed_policy = 'aspf tag has invalid value: ' .. spf_pol
              return
            end
          end

          local policy = elts['p']
          if policy then
            if (policy == 'reject') then
              dmarc_policy = 'reject'
            elseif (policy == 'quarantine') then
              dmarc_policy = 'quarantine'
            elseif (policy ~= 'none') then
              failed_policy = 'p tag has invalid value: ' .. policy
              return
            end
          end

          local subdomain_policy = elts['sp']
          if subdomain_policy and lookup_domain == dmarc_domain then
            if (subdomain_policy == 'reject') then
              if dmarc_domain ~= from[1]['domain'] then
                dmarc_policy = 'reject'
              end
            elseif (subdomain_policy == 'quarantine') then
              if dmarc_domain ~= from[1]['domain'] then
                dmarc_policy = 'quarantine'
              end
            elseif (subdomain_policy == 'none') then
              if dmarc_domain ~= from[1]['domain'] then
                dmarc_policy = 'none'
              end
            elseif (subdomain_policy ~= 'none') then
              failed_policy = 'sp tag has invalid value: ' .. subdomain_policy
              return
            end
          end

          pct = elts['pct']
          if pct then
            pct = tonumber(pct)
          end

          if not rua then
            rua = elts['rua']
          end
        end
      end)()
    end

    if not found_policy then
      if lookup_domain ~= dmarc_domain then
        local resolve_name = '_dmarc.' .. dmarc_domain
        task:get_resolver():resolve_txt({
          task=task,
          name = resolve_name,
          callback = dmarc_dns_cb,
          forced = true})

        return
      else
        task:insert_result(dmarc_symbols['na'], 1.0, lookup_domain)
        return maybe_force_action('na')
      end
    end

    local res = 0.5
    if failed_policy then
      task:insert_result(dmarc_symbols['badpolicy'], res, lookup_domain .. ' : ' .. failed_policy)
      return maybe_force_action('badpolicy')
    end

    -- Check dkim and spf symbols
    local spf_ok = false
    local dkim_ok = false
    if task:has_symbol(symbols['spf_allow_symbol']) then
      local efrom = task:get_from(1)
      if ((efrom or E)[1] or E).domain then
        if strict_spf and rspamd_util.strequal_caseless(efrom[1]['domain'], from[1]['domain']) then
          spf_ok = true
        elseif strict_spf then
          table.insert(reason, "SPF not aligned (strict)")
        end
        if not strict_spf then
          local spf_tld = rspamd_util.get_tld(efrom[1]['domain'])
          if rspamd_util.strequal_caseless(spf_tld, dmarc_domain) then
            spf_ok = true
          else
            table.insert(reason, "SPF not aligned (relaxed)")
          end
        end
      end
    else
      table.insert(reason, "No valid SPF")
    end
    local das = task:get_symbol(symbols['dkim_allow_symbol'])
    if ((das or E)[1] or E).options then
      for _,dkim_domain in ipairs(das[1]['options']) do
        if strict_dkim and rspamd_util.strequal_caseless(from[1]['domain'], dkim_domain) then
          dkim_ok = true
        elseif strict_dkim then
          table.insert(reason, "DKIM not aligned (strict)")
        end
        if not strict_dkim then
          local dkim_tld = rspamd_util.get_tld(dkim_domain)
          if rspamd_util.strequal_caseless(dkim_tld, dmarc_domain) then
            dkim_ok = true
          else
            table.insert(reason, "DKIM not aligned (relaxed)")
          end
        end
      end
    else
      table.insert(reason, "No valid DKIM")
    end

    local disposition = 'none'
    local sampled_out = false

    if not (spf_ok or dkim_ok) then
      local reason_str = table.concat(reason, ", ")
      res = 1.0
      local spf_tmpfail = task:get_symbol(symbols['spf_tempfail_symbol'])
      local dkim_tmpfail = task:get_symbol(symbols['dkim_tempfail_symbol'])
      if (spf_tmpfail or dkim_tmpfail) then
        task:insert_result(dmarc_symbols['dnsfail'], 1.0, lookup_domain .. ' : ' .. 'SPF/DKIM temp error', dmarc_policy)
        return maybe_force_action('dnsfail')
      end
      if dmarc_policy == 'quarantine' then
        if not pct or pct == 100 or (math.random(100) <= pct) then
          task:insert_result(dmarc_symbols['quarantine'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
          disposition = "quarantine"
        else
          task:insert_result(dmarc_symbols['softfail'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy, "sampled_out")
          sampled_out = true
        end
      elseif dmarc_policy == 'reject' then
        if not pct or pct == 100 or (math.random(100) <= pct) then
          task:insert_result(dmarc_symbols['reject'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
          disposition = "reject"
        else
          task:insert_result(dmarc_symbols['quarantine'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy, "sampled_out")
          disposition = "quarantine"
          sampled_out = true
        end
      else
        task:insert_result(dmarc_symbols['softfail'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
      end
    else
      task:insert_result(dmarc_symbols['allow'], res, lookup_domain, dmarc_policy)
    end

    if rua and redis_params and dmarc_reporting then
      -- Prepare and send redis report element
      local redis_key = dmarc_redis_key_prefix .. from[1]['domain']
      local report_data = dmarc_report(task, spf_ok, dkim_ok, disposition, sampled_out)

      if report_data then
        local ret,conn,_ = rspamd_redis_make_request(task,
          redis_params, -- connect params
          from[1]['domain'], -- hash key
          true, -- is write
          dmarc_report_cb, --callback
          'LPUSH', -- command
          {redis_key, report_data} -- arguments
        )
        if ret and conn then
          conn:add_cmd('EXPIRE', {
            redis_key, tostring(dmarc_redis_key_expire)
          })
        end
      end
    end

    return maybe_force_action(disposition)

  end

  -- Do initial request
  local resolve_name = '_dmarc.' .. from[1]['domain']
  task:get_resolver():resolve_txt({
    task=task,
    name = resolve_name,
    callback = dmarc_dns_cb,
    forced = true})
end

local opts = rspamd_config:get_all_opt('options')
if opts and type(opts) ~= 'table' then
  if type(opts['check_local']) == 'boolean' then
    check_local = opts['check_local']
  end
  if type(opts['check_authed']) == 'boolean' then
    check_authed = opts['check_authed']
  end
end

opts = rspamd_config:get_all_opt('dmarc')
if not opts or type(opts) ~= 'table' then
  return
end

if opts['symbols'] then
  for k,_ in pairs(dmarc_symbols) do
    if opts['symbols'][k] then
      dmarc_symbols[k] = opts['symbols'][k]
    end
  end
end

if opts['reporting'] == true then
  dmarc_reporting = true
end
if type(opts['actions']) == 'table' then
  dmarc_actions = opts['actions']
end

redis_params = rspamd_parse_redis_server('dmarc')
if not redis_params then
  rspamd_logger.infox(rspamd_config, 'cannot parse servers parameter')
end

if opts['key_prefix'] then
  dmarc_redis_key_prefix = opts['key_prefix']
end

if opts['expire'] then
  dmarc_redis_key_expire = opts['expire']
end

if opts['key_expire'] then
  dmarc_redis_key_expire = opts['key_expire']
end

-- Check spf and dkim sections for changed symbols
local function check_mopt(var, m_opts, name)
  if m_opts[name] then
    symbols[var] = tostring(m_opts[name])
  end
end

local spf_opts = rspamd_config:get_all_opt('spf')
if spf_opts then
  check_mopt('spf_deny_symbol', spf_opts, 'symbol_fail')
  check_mopt('spf_allow_symbol', spf_opts, 'symbol_allow')
  check_mopt('spf_softfail_symbol', spf_opts, 'symbol_softfail')
  check_mopt('spf_neutral_symbol', spf_opts, 'symbol_neutral')
  check_mopt('spf_tempfail_symbol', spf_opts, 'symbol_dnsfail')
  check_mopt('spf_na_symbol', spf_opts, 'symbol_na')
end

local dkim_opts = rspamd_config:get_all_opt('dkim')
if dkim_opts then
  check_mopt('dkim_deny_symbol', dkim_opts, 'symbol_reject')
  check_mopt('dkim_allow_symbol', dkim_opts, 'symbol_allow')
  check_mopt('dkim_tempfail_symbol', dkim_opts, 'symbol_tempfail')
  check_mopt('dkim_na_symbol', dkim_opts, 'symbol_na')
end

local id = rspamd_config:register_symbol({
  name = 'DMARC_CALLBACK',
  type = 'callback',
  callback = dmarc_callback
})
rspamd_config:register_symbol({
  name = dmarc_symbols['allow'],
  flags = 'nice',
  parent = id,
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['reject'],
  parent = id,
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['quarantine'],
  parent = id,
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['softfail'],
  parent = id,
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['dnsfail'],
  parent = id,
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['na'],
  parent = id,
  type = 'virtual'
})

rspamd_config:register_dependency(id, symbols['spf_allow_symbol'])
rspamd_config:register_dependency(id, symbols['dkim_allow_symbol'])

