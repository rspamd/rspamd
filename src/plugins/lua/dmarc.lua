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
local rspamd_redis = require "lua_redis"
local lua_util = require "lua_util"

if confighelp then
  return
end

local N = 'dmarc'

local settings = {
  auth_and_local_conf = false,
  symbols = {
    spf_allow_symbol = 'R_SPF_ALLOW',
    spf_deny_symbol = 'R_SPF_FAIL',
    spf_softfail_symbol = 'R_SPF_SOFTFAIL',
    spf_neutral_symbol = 'R_SPF_NEUTRAL',
    spf_tempfail_symbol = 'R_SPF_DNSFAIL',
    spf_permfail_symbol = 'R_SPF_PERMFAIL',
    spf_na_symbol = 'R_SPF_NA',

    dkim_allow_symbol = 'R_DKIM_ALLOW',
    dkim_deny_symbol = 'R_DKIM_REJECT',
    dkim_tempfail_symbol = 'R_DKIM_TEMPFAIL',
    dkim_na_symbol = 'R_DKIM_NA',
    dkim_permfail_symbol = 'R_DKIM_PERMFAIL',

    -- DMARC symbols
    allow = 'DMARC_POLICY_ALLOW',
    badpolicy = 'DMARC_BAD_POLICY',
    dnsfail = 'DMARC_DNSFAIL',
    na = 'DMARC_NA',
    reject = 'DMARC_POLICY_REJECT',
    softfail = 'DMARC_POLICY_SOFTFAIL',
    quarantine = 'DMARC_POLICY_QUARANTINE',
  },
  no_sampling_domains = nil,
  no_reporting_domains = nil,
  reporting = {
    redis_keys = {
      index_prefix = 'dmarc_idx',
      report_prefix = 'dmarc_rpt',
      join_char = ';',
    },
    enabled = false,
    max_entries = 1000,
    keys_expire = 172800,
    only_domains = nil,
  },
  actions = {},
}

local redis_params = nil

local E = {}

-- Keys:
-- 1 = index key (string)
-- 2 = report key (string)
-- 3 = max report elements (number)
-- 4 = expiry time for elements (number)
-- Arguments
-- 1 = dmarc domain
-- 2 = dmarc report
local take_report_id
local take_report_script = [[
local index_key = KEYS[1]
local report_key = KEYS[2]
local max_entries = -(tonumber(KEYS[3]) + 1)
local keys_expiry = tonumber(KEYS[4])
local dmarc_domain = ARGV[1]
local report = ARGV[2]
redis.call('SADD', index_key, report_key)
redis.call('EXPIRE', index_key, 172800)
redis.call('ZINCRBY', report_key, 1, report)
redis.call('ZREMRANGEBYRANK', report_key, 0, max_entries)
redis.call('EXPIRE', report_key, 172800)
]]

local function gen_dmarc_grammar()
  local lpeg = require "lpeg"
  lpeg.locale(lpeg)
  local space = lpeg.space^0
  local name = lpeg.C(lpeg.alpha^1) * space
  local sep = (lpeg.S("\\;") * space) + (lpeg.space^1)
  local value = lpeg.C(lpeg.P(lpeg.graph - sep)^1)
  local pair = lpeg.Cg(name * "=" * space * value) * sep^-1
  local list = lpeg.Cf(lpeg.Ct("") * pair^0, rawset)
  local version = lpeg.P("v") * space * lpeg.P("=") * space * lpeg.P("DMARC1")
  local record = version * sep * list

  return record
end

local dmarc_grammar = gen_dmarc_grammar()

local function dmarc_key_value_case(elts)
  if type(elts) ~= "table" then
    return elts
  end
  local result = {}
  for k, v in pairs(elts) do
    k = k:lower()
    if k ~= "v" then
      v = v:lower()
    end

    result[k] = v
  end

  return result
end


-- Returns a key used to be inserted into dmarc report sample
local function dmarc_report(task, spf_ok, dkim_ok, disposition,
    sampled_out, hfromdom, spfdom, dres, spf_result)
  local ip = task:get_from_ip()
  if ip and not ip:is_valid() then
    return nil
  end
  local rspamd_lua_utils = require "lua_util"
  if rspamd_lua_utils.is_rspamc_or_controller(task) then return end
  local dkim_pass = table.concat(dres.pass or E, '|')
  local dkim_fail = table.concat(dres.fail or E, '|')
  local dkim_temperror = table.concat(dres.temperror or E, '|')
  local dkim_permerror = table.concat(dres.permerror or E, '|')
  local disposition_to_return = (disposition == "softfail") and "none" or disposition
  local res = table.concat({
    ip:to_string(), spf_ok, dkim_ok,
    disposition_to_return, (sampled_out and 'sampled_out' or ''), hfromdom,
    dkim_pass, dkim_fail, dkim_temperror, dkim_permerror, spfdom, spf_result}, ',')

  return res
end

local function maybe_force_action(task, disposition)
  if disposition then
    local force_action = settings.actions[disposition]
    if force_action then
      -- Set least action
      task:set_pre_result(force_action, 'Action set by DMARC', N, nil, nil, 'least')
    end
  end
end

--[[
-- Used to check dmarc record, check elements and produce dmarc policy processed
-- result.
-- Returns:
--     false,false - record is garbadge
--     false,error_message - record is invalid
--     true,policy_table - record is valid and parsed
]]
local function dmarc_check_record(task, record, is_tld)
  local failed_policy
  local result = {
    dmarc_policy = 'none'
  }

  local elts = dmarc_grammar:match(record)
  lua_util.debugm(N, task, "got DMARC record: %s, tld_flag=%s, processed=%s",
      record, is_tld, elts)

  if elts then
    elts = dmarc_key_value_case(elts)

    local dkim_pol = elts['adkim']
    if dkim_pol then
      if dkim_pol == 's' then
        result.strict_dkim = true
      elseif dkim_pol ~= 'r' then
        failed_policy = 'adkim tag has invalid value: ' .. dkim_pol
        return false,failed_policy
      end
    end

    local spf_pol = elts['aspf']
    if spf_pol then
      if spf_pol == 's' then
        result.strict_spf = true
      elseif spf_pol ~= 'r' then
        failed_policy = 'aspf tag has invalid value: ' .. spf_pol
        return false,failed_policy
      end
    end

    local policy = elts['p']
    if policy then
      if (policy == 'reject') then
        result.dmarc_policy = 'reject'
      elseif (policy == 'quarantine') then
        result.dmarc_policy = 'quarantine'
      elseif (policy ~= 'none') then
        failed_policy = 'p tag has invalid value: ' .. policy
        return false,failed_policy
      end
    end

    -- Adjust policy if we are in tld mode
    local subdomain_policy = elts['sp']
    if elts['sp'] and is_tld then
      result.subdomain_policy = elts['sp']

      if (subdomain_policy == 'reject') then
        result.dmarc_policy = 'reject'
      elseif (subdomain_policy == 'quarantine') then
        result.dmarc_policy = 'quarantine'
      elseif (subdomain_policy == 'none') then
        result.dmarc_policy = 'none'
      elseif (subdomain_policy ~= 'none') then
        failed_policy = 'sp tag has invalid value: ' .. subdomain_policy
        return false,failed_policy
      end
    end
    result.pct = elts['pct']
    if result.pct then
      result.pct = tonumber(result.pct)
    end

    if elts.rua then
      result.rua = elts['rua']
    end
  else
    return false,false -- Ignore garbadge
  end

  return true, result
end

local function dmarc_validate_policy(task, policy, hdrfromdom, dmarc_esld)
  local reason = {}

  -- Check dkim and spf symbols
  local spf_ok = false
  local dkim_ok = false
  local spf_tmpfail = false
  local dkim_tmpfail = false

  local spf_domain = ((task:get_from(1) or E)[1] or E).domain

  if not spf_domain or spf_domain == '' then
    spf_domain = task:get_helo() or ''
  end

  if task:has_symbol(settings.symbols['spf_allow_symbol']) then
    if policy.strict_spf then
      if rspamd_util.strequal_caseless(spf_domain, hdrfromdom) then
        spf_ok = true
      else
        table.insert(reason, "SPF not aligned (strict)")
      end
    else
      local spf_tld = rspamd_util.get_tld(spf_domain)
      if rspamd_util.strequal_caseless(spf_tld, dmarc_esld) then
        spf_ok = true
      else
        table.insert(reason, "SPF not aligned (relaxed)")
      end
    end
  else
    if task:has_symbol(settings.symbols['spf_tempfail_symbol']) then
      if policy.strict_spf then
        if rspamd_util.strequal_caseless(spf_domain, hdrfromdom) then
          spf_tmpfail = true
        end
      else
        local spf_tld = rspamd_util.get_tld(spf_domain)
        if rspamd_util.strequal_caseless(spf_tld, dmarc_esld) then
          spf_tmpfail = true
        end
      end
    end

    table.insert(reason, "No valid SPF")
  end


  local opts = ((task:get_symbol('DKIM_TRACE') or E)[1] or E).options
  local dkim_results = {
    pass = {},
    temperror = {},
    permerror = {},
    fail = {},
  }


  if opts then
    dkim_results.pass = {}
    local dkim_violated

    for _,opt in ipairs(opts) do
      local check_res = string.sub(opt, -1)
      local domain = string.sub(opt, 1, -3)

      if check_res == '+' then
        table.insert(dkim_results.pass, domain)

        if policy.strict_dkim then
          if rspamd_util.strequal_caseless(hdrfromdom, domain) then
            dkim_ok = true
          else
            dkim_violated = "DKIM not aligned (strict)"
          end
        else
          local dkim_tld = rspamd_util.get_tld(domain)

          if rspamd_util.strequal_caseless(dkim_tld, dmarc_esld) then
            dkim_ok = true
          else
            dkim_violated = "DKIM not aligned (relaxed)"
          end
        end
      elseif check_res == '?' then
        -- Check for dkim tempfail
        if not dkim_ok then
          if policy.strict_dkim then
            if rspamd_util.strequal_caseless(hdrfromdom, domain) then
              dkim_tmpfail = true
            end
          else
            local dkim_tld = rspamd_util.get_tld(domain)

            if rspamd_util.strequal_caseless(dkim_tld, dmarc_esld) then
              dkim_tmpfail = true
            end
          end
        end
        table.insert(dkim_results.temperror, domain)
      elseif check_res == '-' then
        table.insert(dkim_results.fail, domain)
      else
        table.insert(dkim_results.permerror, domain)
      end
    end

    if not dkim_ok and dkim_violated then
      table.insert(reason, dkim_violated)
    end
  else
    table.insert(reason, "No valid DKIM")
  end

  lua_util.debugm(N, task,
      "validated dmarc policy for %s: %s; dkim_ok=%s, dkim_tempfail=%s, spf_ok=%s, spf_tempfail=%s",
      policy.domain, policy.dmarc_policy,
      dkim_ok, dkim_tmpfail,
      spf_ok, spf_tmpfail)

  local disposition = 'none'
  local sampled_out = false

  local function handle_dmarc_failure(what, reason_str)
    if not policy.pct or policy.pct == 100 then
      task:insert_result(settings.symbols[what], 1.0,
          policy.domain .. ' : ' .. reason_str, policy.dmarc_policy)
      disposition = what
    else
      local coin = math.random(100)
      if (coin > policy.pct) then
        if (not settings.no_sampling_domains or
            not settings.no_sampling_domains:get_key(policy.domain)) then

          if what == 'reject' then
            disposition = 'quarantine'
          else
            disposition = 'softfail'
          end

          task:insert_result(settings.symbols[disposition], 1.0,
              policy.domain .. ' : ' .. reason_str, policy.dmarc_policy, "sampled_out")
          sampled_out = true
          lua_util.debugm(N, task,
              'changed dmarc policy from %s to %s, sampled out: %s < %s',
              what, disposition, coin, policy.pct)
        else
          task:insert_result(settings.symbols[what], 1.0,
              policy.domain .. ' : ' .. reason_str, policy.dmarc_policy, "local_policy")
          disposition = what
        end
      else
        task:insert_result(settings.symbols[what], 1.0,
            policy.domain .. ' : ' .. reason_str, policy.dmarc_policy)
        disposition = what
      end
    end

    maybe_force_action(task, disposition)
  end

  if spf_ok or dkim_ok then
    --[[
    https://tools.ietf.org/html/rfc7489#section-6.6.2
    DMARC evaluation can only yield a "pass" result after one of the
    underlying authentication mechanisms passes for an aligned
    identifier.
    ]]--
    task:insert_result(settings.symbols['allow'], 1.0, policy.domain,
        policy.dmarc_policy)
  else
    --[[
    https://tools.ietf.org/html/rfc7489#section-6.6.2

    If neither passes and one or both of them fail due to a
    temporary error, the Receiver evaluating the message is unable to
    conclude that the DMARC mechanism had a permanent failure; they
    therefore cannot apply the advertised DMARC policy.
    ]]--
    if spf_tmpfail or dkim_tmpfail then
      task:insert_result(settings.symbols['dnsfail'], 1.0, policy.domain..
          ' : ' .. 'SPF/DKIM temp error', policy.dmarc_policy)
    else
      -- We can now check the failed policy and maybe send report data elt
      local reason_str = table.concat(reason, ', ')

      if policy.dmarc_policy == 'quarantine' then
        handle_dmarc_failure('quarantine', reason_str)
      elseif policy.dmarc_policy == 'reject' then
        handle_dmarc_failure('reject', reason_str)
      else
        task:insert_result(settings.symbols['softfail'], 1.0,
            policy.domain .. ' : ' .. reason_str,
            policy.dmarc_policy)
      end
    end
  end

  if policy.rua and redis_params and settings.reporting.enabled then
    if settings.no_reporting_domains then
      if settings.no_reporting_domains:get_key(policy.domain) or
          settings.no_reporting_domains:get_key(rspamd_util.get_tld(policy.domain)) then
        rspamd_logger.infox(task, 'DMARC reporting suppressed for %1', policy.domain)
        return
      end
    end

    local function dmarc_report_cb(err)
      if not err then
        rspamd_logger.infox(task, '<%1> dmarc report saved for %2',
            task:get_message_id(), hdrfromdom)
      else
        rspamd_logger.errx(task, '<%1> dmarc report is not saved for %2: %3',
            task:get_message_id(), hdrfromdom, err)
      end
    end

    local spf_result
    if spf_ok then
      spf_result = 'pass'
    elseif spf_tmpfail then
      spf_result = 'temperror'
    else
      if task:has_symbol(settings.symbols.spf_deny_symbol) then
        spf_result = 'fail'
      elseif task:has_symbol(settings.symbols.spf_softfail_symbol) then
        spf_result = 'softfail'
      elseif task:has_symbol(settings.symbols.spf_neutral_symbol) then
        spf_result = 'neutral'
      elseif task:has_symbol(settings.symbols.spf_permfail_symbol) then
        spf_result = 'permerror'
      else
        spf_result = 'none'
      end
    end

    -- Prepare and send redis report element
    local period = os.date('!%Y%m%d',
        task:get_date({format = 'connect', gmt = true}))
    local dmarc_domain_key = table.concat(
        {settings.reporting.redis_keys.report_prefix, hdrfromdom, period},
        settings.reporting.redis_keys.join_char)
    local report_data = dmarc_report(task,
        spf_ok and 'pass' or 'fail',
        dkim_ok and 'pass' or 'fail',
        disposition,
        sampled_out,
        hdrfromdom,
        spf_domain,
        dkim_results,
        spf_result)

    local idx_key = table.concat({settings.redis_keys.index_prefix, period},
        settings.redis_keys.join_char)

    if report_data then
      rspamd_redis.exec_redis_script(take_report_id,
          {task = task, is_write = true},
          dmarc_report_cb,
          {idx_key, dmarc_domain_key,
           tostring(settings.reporting.max_entries), tostring(settings.reporting.keys_expire)},
          {hdrfromdom, report_data})
    end
  end
end

local function dmarc_callback(task)
  local from = task:get_from(2)
  local hfromdom = ((from or E)[1] or E).domain
  local dmarc_domain
  local ip_addr = task:get_ip()
  local dmarc_checks = task:get_mempool():get_variable('dmarc_checks', 'double') or 0
  local seen_invalid = false

  if dmarc_checks ~= 2 then
    rspamd_logger.infox(task, "skip DMARC checks as either SPF or DKIM were not checked")
    return
  end

  if lua_util.is_skip_local_or_authed(task, settings.auth_and_local_conf, ip_addr) then
    rspamd_logger.infox(task, "skip DMARC checks for local networks and authorized users")
    return
  end

  -- Do some initial sanity checks, detect tld domain if different
  if hfromdom and hfromdom ~= '' and not (from or E)[2] then
    dmarc_domain = rspamd_util.get_tld(hfromdom)
  elseif (from or E)[2] then
    task:insert_result(settings.symbols['na'], 1.0, 'Duplicate From header')
    return maybe_force_action(task, 'na')
  elseif (from or E)[1] then
    task:insert_result(settings.symbols['na'], 1.0, 'No domain in From header')
    return maybe_force_action(task,'na')
  else
    task:insert_result(settings.symbols['na'], 1.0, 'No From header')
    return maybe_force_action(task,'na')
  end


  local dns_checks_inflight = 0
  local dmarc_domain_policy = {}
  local dmarc_tld_policy = {}

  local function process_dmarc_policy(policy, final)
    lua_util.debugm(N, task, "validate DMARC policy (final=%s): %s",
        true, policy)
    if policy.err and policy.symbol then
      -- In case of fatal errors or final check for tld, we give up and
      -- insert result
      if final or policy.fatal then
        task:insert_result(policy.symbol, 1.0, policy.err)
        maybe_force_action(task, policy.disposition)

        return true
      end
    elseif policy.dmarc_policy then
      dmarc_validate_policy(task, policy, hfromdom, dmarc_domain)

      return true -- We have a more specific version, use it
    end

    return false -- Missing record
  end

  local function gen_dmarc_cb(lookup_domain, is_tld)
    local policy_target = dmarc_domain_policy
    if is_tld then
      policy_target = dmarc_tld_policy
    end

    return function (_, _, results, err)
      dns_checks_inflight = dns_checks_inflight - 1

      if not seen_invalid then
        policy_target.domain = lookup_domain

        if err then
          if (err ~= 'requested record is not found' and
              err ~= 'no records with this name') then
            policy_target.err = lookup_domain .. ' : ' .. err
            policy_target.symbol = settings.symbols['dnsfail']
          else
            policy_target.err = lookup_domain
            policy_target.symbol = settings.symbols['na']
          end
        else
          local has_valid_policy = false

          for _,rec in ipairs(results) do
            local ret,results_or_err = dmarc_check_record(task, rec, is_tld)

            if not ret then
              if results_or_err then
                -- We have a fatal parsing error, give up
                policy_target.err = lookup_domain .. ' : ' .. results_or_err
                policy_target.symbol = settings.symbols['badpolicy']
                policy_target.fatal = true
                seen_invalid = true
              end
            else
              if has_valid_policy then
                policy_target.err = lookup_domain .. ' : ' ..
                    'Multiple policies defined in DNS'
                policy_target.symbol = settings.symbols['badpolicy']
                policy_target.fatal = true
                seen_invalid = true
              end
              has_valid_policy = true

              for k,v in pairs(results_or_err) do
                policy_target[k] = v
              end
            end
          end

          if not has_valid_policy and not seen_invalid then
            policy_target.err = lookup_domain .. ':' .. ' no valid DMARC record'
            policy_target.symbol = settings.symbols['na']
          end
        end
      end

      if dns_checks_inflight == 0 then
        lua_util.debugm(N, task, "finished DNS queries, validate policies")
        -- We have checked both tld and real domain (if different)
        if not process_dmarc_policy(dmarc_domain_policy, false) then
          -- Try tld policy as well
          if not process_dmarc_policy(dmarc_tld_policy, true) then
            process_dmarc_policy(dmarc_domain_policy, true)
          end
        end
      end
    end
  end

  local resolve_name = '_dmarc.' .. hfromdom

  task:get_resolver():resolve_txt({
    task=task,
    name = resolve_name,
    callback = gen_dmarc_cb(hfromdom, false),
    forced = true
  })
  dns_checks_inflight = dns_checks_inflight + 1

  if dmarc_domain ~= hfromdom then
    resolve_name = '_dmarc.' .. dmarc_domain

    task:get_resolver():resolve_txt({
      task=task,
      name = resolve_name,
      callback = gen_dmarc_cb(dmarc_domain, true),
      forced = true
    })

    dns_checks_inflight = dns_checks_inflight + 1
  end
end


local opts = rspamd_config:get_all_opt('dmarc')
settings = lua_util.override_defaults(settings, opts)

settings.auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
    false, false)

local lua_maps = require "lua_maps"
lua_maps.fill_config_maps(N, settings, {
  no_sampling_domains = {
    optional = true,
    type = 'map',
    description = 'Domains not to apply DMARC sampling to'
  },
  no_reporting_domains = {
    optional = true,
    type = 'map',
    description = 'Domains not to apply DMARC reporting to'
  },
})


if settings.reporting == true then
  rspamd_logger.errx(rspamd_config, 'old style dmarc reporting is NO LONGER supported, please read the documentation')
elseif settings.reporting.enabled then
  redis_params = rspamd_parse_redis_server('dmarc')
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'cannot parse servers parameter')
  else
    rspamd_logger.infox(rspamd_config, 'dmarc reporting is enabled')
    take_report_id = rspamd_redis.add_redis_script(take_report_script, redis_params)
  end
end

-- Check spf and dkim sections for changed symbols
local function check_mopt(var, m_opts, name)
  if m_opts[name] then
    settings.symbols[var] = tostring(m_opts[name])
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
  name = 'DMARC_CHECK',
  type = 'callback',
  callback = dmarc_callback
})
rspamd_config:register_symbol({
  name = 'DMARC_CALLBACK', -- compatibility symbol
  type = 'virtual,skip',
  parent = id,
})
rspamd_config:register_symbol({
  name = settings.symbols['allow'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = settings.symbols['reject'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = settings.symbols['quarantine'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = settings.symbols['softfail'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = settings.symbols['dnsfail'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = settings.symbols['badpolicy'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = settings.symbols['na'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})

rspamd_config:register_dependency('DMARC_CHECK', settings.symbols['spf_allow_symbol'])
rspamd_config:register_dependency('DMARC_CHECK', settings.symbols['dkim_allow_symbol'])

-- DMARC munging support
if settings.munging then
  local lua_maps_expressions = require "lua_maps_expressions"
  local lua_mime = require "lua_mime"

  local munging_defaults = {
    reply_goes_to_list = false,
    mitigate_allow_only = true, -- perform munging based on DMARC_POLICY_ALLOW only
    mitigate_strict_only = false, -- perform mugning merely for reject/quarantine policies
    munge_from = true, -- replace from with something like <orig name> via <rcpt user>
    list_map = nil, -- map of maillist domains
    munge_map_condition = nil, -- maps expression to enable munging
  }

  local munging_opts = lua_util.override_defaults(munging_defaults, settings.munging)

  if not munging_opts.list_map  then
    rspamd_logger.errx(rspamd_config, 'cannot enable DMARC munging with no list_map parameter')

    return
  end

  munging_opts.list_map = lua_maps.map_add_from_ucl(munging_opts.list_map,
      'set', 'DMARC munging map of the recipients addresses to munge')

  if not munging_opts.list_map  then
    rspamd_logger.errx(rspamd_config, 'cannot enable DMARC munging with invalid list_map (invalid map)')

    return
  end

  if munging_opts.munge_map_condition then
    munging_opts.munge_map_condition = lua_maps_expressions.create(rspamd_config,
            munging_opts.munge_map_condition, N)
  end

  local function dmarc_munge_callback(task)
    if munging_opts.mitigate_allow_only then
      if not task:has_symbol(settings.symbols.allow) then
        lua_util.debugm(N, task, 'skip munging, no %s symbol',
                settings.symbols.allow)
        -- Excepted
        return
      end
    else
      local has_dmarc = task:has_symbol(settings.symbols.allow) or
              task:has_symbol(settings.symbols.quarantine) or
              task:has_symbol(settings.symbols.reject) or
              task:has_symbol(settings.symbols.softfail)

      if not has_dmarc then
        lua_util.debugm(N, task, 'skip munging, no %s symbol',
                settings.symbols.allow)
        -- Excepted
        return
      end
    end
    if munging_opts.mitigate_strict_only then
      local s = task:get_symbol(settings.symbols.allow) or {[1] = {}}
      local sopts = s[1].options or {}

      local seen_strict
      for _,o in ipairs(sopts) do
        if o == 'reject' or o == 'quarantine' then
          seen_strict = true
          break
        end
      end

      if not seen_strict then
        lua_util.debugm(N, task, 'skip munging, no strict policy found in %s',
                settings.symbols.allow)
        -- Excepted
        return
      end
    end
    if munging_opts.munge_map_condition then
      local accepted,trace = munging_opts.munge_map_condition:process(task)
      if not accepted then
        lua_util.debugm(task, 'skip munging, maps condition not satisified: (%s)',
                trace)
        -- Excepted
        return
      end
    end
    -- Now, look for domain for munging
    local mr = task:get_recipients({ 'mime', 'orig'})
    local rcpt_found
    if mr then
      for _,r in ipairs(mr) do
        if r.domain and munging_opts.list_map:get_key(r.addr) then
          rcpt_found = r
          break
        end
      end
    end

    if not rcpt_found then
      lua_util.debugm(task, 'skip munging, recipients are not in list_map')
      -- Excepted
      return
    end

    local from = task:get_from({ 'mime', 'orig'})

    if not from or not from[1] then
      lua_util.debugm(task, 'skip munging, from is bad')
      -- Excepted
      return
    end

    from = from[1]
    local via_user = rcpt_found.user
    local via_addr = rcpt_found.addr
    local via_name

    if from.name then
      via_name = string.format('%s via %s', from.name, via_user)
    else
      via_name = string.format('%s via %s', from.user or 'unknown', via_user)
    end

    local hdr_encoded = rspamd_util.fold_header('From',
            rspamd_util.mime_header_encode(string.format('%s <%s>',
                    via_name, via_addr)))
    local orig_from_encoded = rspamd_util.fold_header('X-Original-From',
            rspamd_util.mime_header_encode(string.format('%s <%s>',
                    from.name or '', from.addr)))
    local add_hdrs = {
      ['From'] = { order = 1, value = hdr_encoded },
    }
    local remove_hdrs = {['From'] = 0}

    local nreply = from.addr
    if munging_opts.reply_goes_to_list then
      -- Reply-to goes to the list
      nreply = via_addr
    end

    if task:has_header('Reply-To') then
      -- If we have reply-to header, then we need to insert an additional
      -- address there
      local orig_reply = task:get_header_full('Reply-To')[1]
      if orig_reply.value then
        nreply = string.format('%s, %s', orig_reply.value, nreply)
      end
      remove_hdrs['Reply-To'] = 1
    end

    add_hdrs['Reply-To'] = {order = 0, value = nreply}

    add_hdrs['X-Original-From'] = { order = 0, value = orig_from_encoded}
    lua_mime.modify_headers(task, {
      remove = remove_hdrs,
      add = add_hdrs
    })
    lua_util.debugm(N, task, 'munged DMARC header for %s: %s -> %s',
            from.domain, hdr_encoded, from.addr)
    rspamd_logger.infox(task, 'munged DMARC header for %s', from.addr)
    task:insert_result('DMARC_MUNGED', 1.0, from.addr)
  end

  rspamd_config:register_symbol({
    name = 'DMARC_MUNGED',
    type = 'normal',
    flags = 'nostat',
    score = 0,
    group = 'policies',
    groups = {'dmarc'},
    callback = dmarc_munge_callback
  })

  rspamd_config:register_dependency('DMARC_MUNGED', 'DMARC_CHECK')
  -- To avoid dkim signing issues
  rspamd_config:register_dependency('DKIM_SIGNED', 'DMARC_MUNGED')
  rspamd_config:register_dependency('ARC_SIGNED', 'DMARC_MUNGED')

  rspamd_logger.infox(rspamd_config, 'enabled DMARC munging')
end
