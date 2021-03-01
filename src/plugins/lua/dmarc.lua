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
local mempool = require "rspamd_mempool"
local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"
local rspamd_redis = require "lua_redis"
local lua_util = require "lua_util"
local auth_and_local_conf

if confighelp then
  return
end

local N = 'dmarc'
local no_sampling_domains
local no_reporting_domains
local statefile = string.format('%s/%s', rspamd_paths['DBDIR'], 'dmarc_reports_last_sent')
local VAR_NAME = 'dmarc_reports_last_sent'
local INTERVAL = 86400
local pool

local report_settings = {
  helo = 'rspamd',
  hscan_count = 1000,
  smtp = '127.0.0.1',
  smtp_port = 25,
  retries = 2,
  from_name = 'Rspamd',
  msgid_from = 'rspamd',
}

local report_template = [[From: "{= from_name =}" <{= from_addr =}>
To: {= rcpt =}
{%+ if is_string(bcc) %}Bcc: {= bcc =}{%- endif %}
Subject: Report Domain: {= reporting_domain =}
	Submitter: {= submitter =}
	Report-ID: {= report_id =}
Date: {= report_date =}
MIME-Version: 1.0
Message-ID: <{= message_id =}>
Content-Type: multipart/mixed;
	boundary="----=_NextPart_000_024E_01CC9B0A.AFE54C00"

This is a multipart message in MIME format.

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

This is an aggregate report from {= submitter =}.

Report domain: {= reporting_domain =}
Submitter: {= submitter =}
Report ID: {= report_id =}

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: application/gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
	filename="{= submitter =}!{= reporting_domain =}!{= report_start =}!{= report_end =}.xml.gz"

]]
local report_footer = [[

------=_NextPart_000_024E_01CC9B0A.AFE54C00--]]

local symbols = {
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

local redis_keys = {
  index_prefix = 'dmarc_idx',
  report_prefix = 'dmarc',
  join_char = ';',
}

local function gen_xml_grammar()
  local lpeg = require 'lpeg'
  local lt = lpeg.P('<') / '&lt;'
  local gt = lpeg.P('>') / '&gt;'
  local amp = lpeg.P('&') / '&amp;'
  local quot = lpeg.P('"') / '&quot;'
  local apos = lpeg.P("'") / '&apos;'
  local special = lt + gt + amp + quot + apos
  local grammar = lpeg.Cs((special + 1)^0)
  return grammar
end

local xml_grammar = gen_xml_grammar()

local function escape_xml(input)
  if type(input) == 'string' or type(input) == 'userdata' then
    return xml_grammar:match(input)
  else
    input = tostring(input)

    if input then
      return xml_grammar:match(input)
    end
  end

  return ''
end

-- Default port for redis upstreams
local redis_params = nil
-- 2 days
local dmarc_reporting = false
local dmarc_actions = {}

local E = {}

local take_report_id
local take_report_script = [[
local index_key = KEYS[1]
local report_key = KEYS[2]
local dmarc_domain = ARGV[1]
local report = ARGV[2]
redis.call('SADD', index_key, report_key)
redis.call('EXPIRE', index_key, 172800)
redis.call('HINCRBY', report_key, report, 1)
redis.call('EXPIRE', report_key, 172800)
]]

-- return the timezone offset in seconds, as it was on the time given by ts
-- Eric Feliksik
local function get_timezone_offset(ts)
  local utcdate   = os.date("!*t", ts)
  local localdate = os.date("*t", ts)
  localdate.isdst = false -- this is the trick
  return os.difftime(os.time(localdate), os.time(utcdate))
end

local tz_offset = get_timezone_offset(os.time())

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
    local force_action = dmarc_actions[disposition]
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

  if task:has_symbol(symbols['spf_allow_symbol']) then
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
    if task:has_symbol(symbols['spf_tempfail_symbol']) then
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
      task:insert_result(dmarc_symbols[what], 1.0,
          policy.domain .. ' : ' .. reason_str, policy.dmarc_policy)
      disposition = what
    else
      local coin = math.random(100)
      if (coin > policy.pct) then
        if (not no_sampling_domains or
            not no_sampling_domains:get_key(policy.domain)) then

          if what == 'reject' then
            disposition = 'quarantine'
          else
            disposition = 'softfail'
          end

          task:insert_result(dmarc_symbols[disposition], 1.0,
              policy.domain .. ' : ' .. reason_str, policy.dmarc_policy, "sampled_out")
          sampled_out = true
          lua_util.debugm(N, task,
              'changed dmarc policy from %s to %s, sampled out: %s < %s',
              what, disposition, coin, policy.pct)
        else
          task:insert_result(dmarc_symbols[what], 1.0,
              policy.domain .. ' : ' .. reason_str, policy.dmarc_policy, "local_policy")
          disposition = what
        end
      else
        task:insert_result(dmarc_symbols[what], 1.0,
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
    task:insert_result(dmarc_symbols['allow'], 1.0, policy.domain,
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
      task:insert_result(dmarc_symbols['dnsfail'], 1.0, policy.domain..
          ' : ' .. 'SPF/DKIM temp error', policy.dmarc_policy)
    else
      -- We can now check the failed policy and maybe send report data elt
      local reason_str = table.concat(reason, ', ')

      if policy.dmarc_policy == 'quarantine' then
        handle_dmarc_failure('quarantine', reason_str)
      elseif policy.dmarc_policy == 'reject' then
        handle_dmarc_failure('reject', reason_str)
      else
        task:insert_result(dmarc_symbols['softfail'], 1.0,
            policy.domain .. ' : ' .. reason_str,
            policy.dmarc_policy)
      end
    end
  end

  if policy.rua and redis_params and dmarc_reporting then
    if no_reporting_domains then
      if no_reporting_domains:get_key(policy.domain) or
          no_reporting_domains:get_key(rspamd_util.get_tld(policy.domain)) then
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
      if task:has_symbol(symbols.spf_deny_symbol) then
        spf_result = 'fail'
      elseif task:has_symbol(symbols.spf_softfail_symbol) then
        spf_result = 'softfail'
      elseif task:has_symbol(symbols.spf_neutral_symbol) then
        spf_result = 'neutral'
      elseif task:has_symbol(symbols.spf_permfail_symbol) then
        spf_result = 'permerror'
      else
        spf_result = 'none'
      end
    end

    -- Prepare and send redis report element
    local period = os.date('!%Y%m%d',
        task:get_date({format = 'connect', gmt = true}))
    local dmarc_domain_key = table.concat(
        {redis_keys.report_prefix, hdrfromdom, period}, redis_keys.join_char)
    local report_data = dmarc_report(task,
        spf_ok and 'pass' or 'fail',
        dkim_ok and 'pass' or 'fail',
        disposition,
        sampled_out,
        hdrfromdom,
        spf_domain,
        dkim_results,
        spf_result)

    local idx_key = table.concat({redis_keys.index_prefix, period},
        redis_keys.join_char)

    if report_data then
      rspamd_redis.exec_redis_script(take_report_id,
          {task = task, is_write = true},
          dmarc_report_cb,
          {idx_key, dmarc_domain_key},
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

  if lua_util.is_skip_local_or_authed(task, auth_and_local_conf, ip_addr) then
    rspamd_logger.infox(task, "skip DMARC checks for local networks and authorized users")
    return
  end

  -- Do some initial sanity checks, detect tld domain if different
  if hfromdom and hfromdom ~= '' and not (from or E)[2] then
    dmarc_domain = rspamd_util.get_tld(hfromdom)
  elseif (from or E)[2] then
    task:insert_result(dmarc_symbols['na'], 1.0, 'Duplicate From header')
    return maybe_force_action(task, 'na')
  elseif (from or E)[1] then
    task:insert_result(dmarc_symbols['na'], 1.0, 'No domain in From header')
    return maybe_force_action(task,'na')
  else
    task:insert_result(dmarc_symbols['na'], 1.0, 'No From header')
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
            policy_target.symbol = dmarc_symbols['dnsfail']
          else
            policy_target.err = lookup_domain
            policy_target.symbol = dmarc_symbols['na']
          end
        else
          local has_valid_policy = false

          for _,rec in ipairs(results) do
            local ret,results_or_err = dmarc_check_record(task, rec, is_tld)

            if not ret then
              if results_or_err then
                -- We have a fatal parsing error, give up
                policy_target.err = lookup_domain .. ' : ' .. results_or_err
                policy_target.symbol = dmarc_symbols['badpolicy']
                policy_target.fatal = true
                seen_invalid = true
              end
            else
              if has_valid_policy then
                policy_target.err = lookup_domain .. ' : ' ..
                    'Multiple policies defined in DNS'
                policy_target.symbol = dmarc_symbols['badpolicy']
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
            policy_target.symbol = dmarc_symbols['na']
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
if not opts or type(opts) ~= 'table' then
  return
end

auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
    false, false)

no_sampling_domains = rspamd_map_add(N, 'no_sampling_domains', 'map', 'Domains not to apply DMARC sampling to')
no_reporting_domains = rspamd_map_add(N, 'no_reporting_domains', 'map', 'Domains not to apply DMARC reporting to')

if opts['symbols'] then
  for k,_ in pairs(dmarc_symbols) do
    if opts['symbols'][k] then
      dmarc_symbols[k] = opts['symbols'][k]
    end
  end
end

-- XXX: rework this shitty code some day please
if opts['reporting'] == true then
  redis_params = rspamd_parse_redis_server('dmarc')
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'cannot parse servers parameter')
  elseif not opts['send_reports'] then
    dmarc_reporting = true
    take_report_id = rspamd_redis.add_redis_script(take_report_script, redis_params)
  else
    dmarc_reporting = true
    if type(opts['report_settings']) == 'table' then
      for k, v in pairs(opts['report_settings']) do
        report_settings[k] = v
      end
    end
    for _, e in ipairs({'email', 'domain', 'org_name'}) do
      if not report_settings[e] then
        rspamd_logger.errx(rspamd_config, 'Missing required setting: report_settings.%s', e)
        return
      end
    end
    take_report_id = rspamd_redis.add_redis_script(take_report_script, redis_params)
    rspamd_config:add_on_load(function(cfg, ev_base, worker)
      if not worker:is_primary_controller() then return end

      pool = mempool.create()

      rspamd_config:register_finish_script(function ()
        local stamp = pool:get_variable(VAR_NAME, 'double')
        if not stamp then
          rspamd_logger.warnx(rspamd_config, 'No last DMARC report information to persist to disk')
          return
        end
        local f, err = io.open(statefile, 'w')
        if err then
          rspamd_logger.errx(rspamd_config, 'Unable to write statefile to disk: %s', err)
          return
        end
        assert(f:write(pool:get_variable(VAR_NAME, 'double')))
        assert(f:close())
        pool:destroy()
      end)

      local get_reporting_domain, reporting_domain, report_start,
            report_end, report_id, want_period, report_key
      local reporting_addrs = {}
      local bcc_addrs = {}
      local domain_policy = {}
      local to_verify = {}
      local cursor = 0
      local function entry_to_xml(data)
        local buf = {
          table.concat({
            '<record><row><source_ip>', data.ip, '</source_ip><count>',
            data.count, '</count><policy_evaluated><disposition>',
            data.disposition, '</disposition><dkim>', data.dkim_disposition,
            '</dkim><spf>', data.spf_disposition, '</spf>'
          }),
        }
        if data.override ~= '' then
          table.insert(buf, string.format('<reason><type>%s</type></reason>', data.override))
        end
        table.insert(buf, table.concat({
          '</policy_evaluated></row><identifiers><header_from>', data.header_from,
          '</header_from></identifiers>',
        }))
        table.insert(buf, '<auth_results>')
        if data.dkim_results[1] then
          for _, d in ipairs(data.dkim_results) do
            table.insert(buf, table.concat({
              '<dkim><domain>', d.domain, '</domain><result>',
              d.result, '</result></dkim>',
            }))
          end
        end
        table.insert(buf, table.concat({
          '<spf><domain>', data.spf_domain, '</domain><result>',
          data.spf_result, '</result></spf></auth_results></record>',
        }))
        return table.concat(buf)
      end
      local function dmarc_report_xml()
        local entries = {}
        report_id = string.format('%s.%d.%d',
            reporting_domain, report_start, report_end)
        lua_util.debugm(N, rspamd_config, 'new report: %s', report_id)
        local actions = {
          push = function(t)
            local data = t[1]
            local split = rspamd_str_split(data, ',')
            local row = {
              ip = split[1],
              spf_disposition = split[2],
              dkim_disposition = split[3],
              disposition = split[4],
              override = split[5],
              header_from = split[6],
              dkim_results = {},
              spf_domain = split[11],
              spf_result = split[12],
              count = t[2],
            }
            if split[7] and split[7] ~= '' then
              local tmp = rspamd_str_split(split[7], '|')
              for _, d in ipairs(tmp) do
                table.insert(row.dkim_results, {domain = d, result = 'pass'})
              end
            end
            if split[8] and split[8] ~= '' then
              local tmp = rspamd_str_split(split[8], '|')
              for _, d in ipairs(tmp) do
                table.insert(row.dkim_results, {domain = d, result = 'fail'})
              end
            end
            if split[9] and split[9] ~= '' then
              local tmp = rspamd_str_split(split[9], '|')
              for _, d in ipairs(tmp) do
                table.insert(row.dkim_results, {domain = d, result = 'temperror'})
              end
            end
            if split[10] and split[10] ~= '' then
              local tmp = lua_util.str_split(split[10], '|')
              for _, d in ipairs(tmp) do
                table.insert(row.dkim_results,
                    {domain = d, result = 'permerror'})
              end
            end
            table.insert(entries, row)
          end,
          -- TODO: please rework this shit
          header = function()
              return table.concat({
                '<?xml version="1.0" encoding="utf-8"?><feedback><report_metadata><org_name>',
                escape_xml(report_settings.org_name), '</org_name><email>',
                escape_xml(report_settings.email), '</email><report_id>',
                report_id, '</report_id><date_range><begin>', report_start,
                '</begin><end>', report_end, '</end></date_range></report_metadata><policy_published><domain>',
                reporting_domain, '</domain><adkim>', escape_xml(domain_policy.adkim), '</adkim><aspf>',
                escape_xml(domain_policy.aspf), '</aspf><p>', escape_xml(domain_policy.p),
                '</p><sp>', escape_xml(domain_policy.sp), '</sp><pct>',
                escape_xml(domain_policy.pct),
                '</pct></policy_published>'
              })
          end,
          footer = function()
            return [[</feedback>]]
          end,
          entries = function()
            local buf = {}
            for _, e in pairs(entries) do
              table.insert(buf, entry_to_xml(e))
            end
            return table.concat(buf, '')
          end,
        }
        return function(action, p)
          local f = actions[action]
          if not f then error('invalid action: ' .. action) end
          return f(p)
        end
      end


      local function send_report_via_email(xmlf, retry)
        if not retry then retry = 0 end

        local function sendmail_cb(ret, err)
          if not ret then
            rspamd_logger.errx(rspamd_config, "Couldn't send mail for %s: %s", err)
            if retry >= report_settings.retries then
              rspamd_logger.errx(rspamd_config, "Couldn't send mail for %s: retries exceeded", reporting_domain)
              return get_reporting_domain()
            else
              send_report_via_email(xmlf, retry + 1)
            end
          else
            get_reporting_domain()
          end
        end

        -- Format message
        local list_rcpt = lua_util.keys(reporting_addrs)

        local encoded = rspamd_util.encode_base64(rspamd_util.gzip_compress(
              table.concat(
                {xmlf('header'),
                 xmlf('entries'),
                 xmlf('footer')})), 73)
        local addr_string = table.concat(list_rcpt, ', ')

        bcc_addrs = lua_util.keys(bcc_addrs)
        local bcc_string
        if #bcc_addrs > 0 then
          bcc_string = table.concat(bcc_addrs, ', ')
        end

        local rhead = lua_util.jinja_template(report_template,
            {
              from_name = report_settings.from_name,
              from_addr = report_settings.email,
              rcpt = addr_string,
              bcc = bcc_string,
              reporting_domain = reporting_domain,
              submitter = report_settings.domain,
              report_id = report_id,
              report_date = rspamd_util.time_to_string(rspamd_util.get_time()),
              message_id = rspamd_util.random_hex(16) .. '@' .. report_settings.msgid_from,
              report_start = report_start,
              report_end = report_end
            }, true)
        local message = {
          (rhead:gsub("\n", "\r\n")),
          encoded,
          (report_footer:gsub("\n", "\r\n"))
        }

        local lua_smtp = require "lua_smtp"
        lua_smtp.sendmail({
          ev_base = ev_base,
          config = rspamd_config,
          host = report_settings.smtp,
          port = report_settings.smtp_port,
          resolver = rspamd_config:get_resolver(),
          from = report_settings.email,
          recipients = list_rcpt,
          helo =  report_settings.helo,
        }, message, sendmail_cb)
      end


      local function make_report()
        if type(report_settings.override_address) == 'string' then
          reporting_addrs = { [report_settings.override_address] = true}
        end
        if type(report_settings.additional_address) == 'string' then
          if report_settings.additional_address_bcc then
            bcc_addrs[report_settings.additional_address] = true
          else
            reporting_addrs[report_settings.additional_address] = true
          end
        end
        rspamd_logger.infox(rspamd_config, 'sending report for %s <%s> (<%s> bcc)',
            reporting_domain, reporting_addrs, bcc_addrs)
        local dmarc_xml = dmarc_report_xml()
        local dmarc_push_cb
        dmarc_push_cb = function(err, data)
          if err then
            rspamd_logger.errx(rspamd_config, 'redis request failed: %s', err)
            -- XXX: data is orphaned; replace key or delete data
            get_reporting_domain()
          elseif type(data) == 'table' then
            cursor = tonumber(data[1])
            for i = 1, #data[2], 2 do
              dmarc_xml('push', {data[2][i], data[2][i+1]})
            end
            if cursor ~= 0 then
              local ret = rspamd_redis.redis_make_request_taskless(ev_base,
                rspamd_config,
                redis_params,
                nil,
                false, -- is write
                dmarc_push_cb, --callback
                'HSCAN', -- command
                {report_key, cursor, 'COUNT', report_settings.hscan_count}
              )
              if not ret then
                rspamd_logger.errx(rspamd_config, 'failed to schedule redis request')
                get_reporting_domain()
              end
            else
              send_report_via_email(dmarc_xml)
            end
          end
        end

        local ret = rspamd_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          redis_params,
          nil,
          false, -- is write
          dmarc_push_cb, --callback
          'HSCAN', -- command
          {report_key, cursor, 'COUNT', report_settings.hscan_count}
        )
        if not ret then
          rspamd_logger.errx(rspamd_config, 'failed to schedule redis request')
          -- XXX: data is orphaned; replace key or delete data
          get_reporting_domain()
        end
      end
      local function delete_reports()
        local function delete_reports_cb(err)
          if err then
            rspamd_logger.errx(rspamd_config, 'error deleting reports: %s', err)
          end
          rspamd_logger.infox(rspamd_config, 'deleted reports for %s', reporting_domain)
          get_reporting_domain()
        end
        local ret = rspamd_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          redis_params,
          nil,
          true, -- is write
          delete_reports_cb, --callback
          'DEL', -- command
          {report_key}
        )
        if not ret then
          rspamd_logger.errx(rspamd_config, 'failed to schedule redis request')
          get_reporting_domain()
        end
      end
      local function verify_reporting_address()
        local function verifier(test_addr, vdom)
          local retry = 0
          local function verify_cb(resolver, to_resolve, results, err, _, authenticated)
            if err then
              if err == 'no records with this name' or err == 'requested record is not found' then
                rspamd_logger.infox(rspamd_config, 'reports to %s for %s not authorised', test_addr, reporting_domain)
                to_verify[test_addr] = nil
              else
                rspamd_logger.errx(rspamd_config, 'lookup error [%s]: %s', to_resolve, err)
                if retry < report_settings.retries then
                  retry = retry + 1
                  rspamd_config:get_resolver():resolve('txt', {
                    ev_base = ev_base,
                    name = string.format('%s._report._dmarc.%s',
                        reporting_domain, vdom),
                    callback = verify_cb,
                  })
                else
                  delete_reports()
                end
              end
            else
              local is_authed = false
              -- XXX: reporting address could be overridden
              for _, r in ipairs(results) do
                if string.match(r, 'v=DMARC1') then
                  is_authed = true
                  break
                end
              end
              if not is_authed then
                to_verify[test_addr] = nil
                rspamd_logger.infox(rspamd_config, 'Reports to %s for %s not authorised', test_addr, reporting_domain)
              else
                to_verify[test_addr] = nil
                reporting_addrs[test_addr] = true
              end
            end
            local t, nvdom = next(to_verify)
            if not t then
              if next(reporting_addrs) then
                make_report()
              else
                rspamd_logger.infox(rspamd_config, 'No valid reporting addresses for %s', reporting_domain)
                delete_reports()
              end
            else
              verifier(t, nvdom)
            end
          end
          rspamd_config:get_resolver():resolve('txt', {
            ev_base = ev_base,
            name = string.format('%s._report._dmarc.%s',
                reporting_domain, vdom),
            callback = verify_cb,
          })
        end
        local t, vdom = next(to_verify)
        verifier(t, vdom)
      end
      local function get_reporting_address()
        local retry = 0
        local esld = rspamd_util.get_tld(reporting_domain)
        local function check_addr_cb(resolver, to_resolve, results, err, _, authenticated)
          if err then
            if err == 'no records with this name' or err == 'requested record is not found' then
              if reporting_domain ~= esld then
                rspamd_config:get_resolver():resolve('txt', {
                  ev_base = ev_base,
                  name = string.format('_dmarc.%s', esld),
                  callback = check_addr_cb,
                })
              else
                rspamd_logger.errx(rspamd_config, 'no DMARC record found for %s', reporting_domain)
                delete_reports()
              end
            else
              rspamd_logger.errx(rspamd_config, 'lookup error [%s]: %s', to_resolve, err)
              if retry < report_settings.retries then
                retry = retry + 1
                rspamd_config:get_resolver():resolve('txt', {
                  ev_base = ev_base,
                  name = to_resolve,
                  callback = check_addr_cb,
                })
              else
                rspamd_logger.errx(rspamd_config, "couldn't get reporting address for %s: retries exceeded",
                    reporting_domain)
                delete_reports()
              end
            end
          else
            local policy
            local found_policy, failed_policy = false, false
            for _, r in ipairs(results) do
              local elts = dmarc_grammar:match(r)
              if elts and found_policy then
                failed_policy = true
              elseif elts then
                found_policy = true
                policy = dmarc_key_value_case(elts)
              end
            end
            if not found_policy then
              rspamd_logger.errx(rspamd_config, 'no policy: %s', to_resolve)
              if reporting_domain ~= esld then
                rspamd_config:get_resolver():resolve('txt', {
                  ev_base = ev_base,
                  name = string.format('_dmarc.%s', esld),
                  callback = check_addr_cb,
                })
              else
                delete_reports()
              end
            elseif failed_policy then
              rspamd_logger.errx(rspamd_config, 'duplicate policies: %s', to_resolve)
              delete_reports()
            elseif not policy['rua'] then
              rspamd_logger.errx(rspamd_config, 'no reporting address: %s', to_resolve)
              delete_reports()
            else
              local upool = mempool.create()
              local split = rspamd_str_split(policy['rua']:gsub('%s+', ''), ',')
              for _, m in ipairs(split) do
                local url = rspamd_url.create(upool, m)
                if not url then
                  rspamd_logger.errx(rspamd_config, "couldn't extract reporting address: %s", policy['rua'])
                else
                  local urlt = url:to_table()
                  if urlt['protocol'] ~= 'mailto' then
                    rspamd_logger.errx(rspamd_config, 'invalid URL: %s', url)
                  else
                    if urlt['tld'] == rspamd_util.get_tld(reporting_domain) then
                      reporting_addrs[string.format('%s@%s', urlt['user'], urlt['host'])] = true
                    else
                      to_verify[string.format('%s@%s', urlt['user'], urlt['host'])] = urlt['host']
                    end
                  end
                end
              end
              upool:destroy()
              domain_policy['pct'] = policy['pct'] or 100
              domain_policy['adkim'] = policy['adkim'] or 'r'
              domain_policy['aspf'] = policy['aspf'] or 'r'
              domain_policy['p'] = policy['p'] or 'none'
              domain_policy['sp'] = policy['sp'] or 'none'
              if next(to_verify) then
                verify_reporting_address()
              elseif next(reporting_addrs) then
                make_report()
              else
                rspamd_logger.errx(rspamd_config, 'no reporting address for %s', reporting_domain)
                delete_reports()
              end
            end
          end
        end

        rspamd_config:get_resolver():resolve('txt', {
          ev_base = ev_base,
          name = string.format('_dmarc.%s', reporting_domain),
          callback = check_addr_cb,
        })
      end
      get_reporting_domain = function()
        reporting_domain = nil
        reporting_addrs = {}
        domain_policy = {}
        cursor = 0
        local function get_reporting_domain_cb(err, data)
          if err then
            rspamd_logger.errx(cfg, 'unable to get DMARC domain: %s', err)
          else
            if type(data) == 'userdata' then
              reporting_domain = nil
            else
              report_key = data
              local tmp = rspamd_str_split(data, redis_keys.join_char)
              reporting_domain = tmp[2]
            end
            if not reporting_domain then
              rspamd_logger.infox(cfg, 'no more domains to generate reports for')
            else
              get_reporting_address()
            end
          end
        end
        local idx_key = table.concat({redis_keys.index_prefix, want_period}, redis_keys.join_char)
        local ret = rspamd_redis.redis_make_request_taskless(ev_base,
          rspamd_config,
          redis_params,
          nil,
          true, -- is write
          get_reporting_domain_cb, --callback
          'SPOP', -- command
          {idx_key}
        )
        if not ret then
          rspamd_logger.errx(cfg, 'unable to get DMARC domain')
        end
      end
      local function send_reports(time)
        rspamd_logger.infox(rspamd_config, 'sending reports ostensibly %1', time)
        pool:set_variable(VAR_NAME, time)
        local yesterday = os.date('!*t', rspamd_util.get_time() - INTERVAL)
        local today = os.date('!*t', rspamd_util.get_time())
        report_start = os.time({
          year = yesterday.year,
          month = yesterday.month,
          day = yesterday.day,
          hour = 0}) + tz_offset
        report_end = os.time({
          year = today.year,
          month = today.month,
          day = today.day,
          hour = 0}) + tz_offset
        want_period = table.concat({
          yesterday.year,
          string.format('%02d', yesterday.month),
          string.format('%02d', yesterday.day)
        })
        get_reporting_domain()
      end
      -- Push reports at regular intervals
      local function schedule_regular_send()
        rspamd_config:add_periodic(ev_base, INTERVAL, function ()
          send_reports()
          return true
        end)
      end
      -- Push reports to backend and reschedule check
      local function schedule_intermediate_send(when)
        rspamd_config:add_periodic(ev_base, when, function ()
          schedule_regular_send()
          send_reports(rspamd_util.get_time())
          return false
        end)
      end
      -- Try read statefile on startup
      local stamp
      local f, err = io.open(statefile, 'r')
      if err then
        rspamd_logger.errx(rspamd_config, 'failed to open statefile: %s', err)
      end
      if f then
        io.input(f)
        stamp = tonumber(io.read())
        pool:set_variable(VAR_NAME, stamp)
      end
      local time = rspamd_util.get_time()
      if not stamp then
        lua_util.debugm(N, rspamd_config, 'no state found - sending reports immediately')
        schedule_regular_send()
        send_reports(time)
        return
      end
      local delta = stamp - time + INTERVAL
      if delta <= 0 then
        lua_util.debugm(N, rspamd_config, 'last send is too old - sending reports immediately')
        schedule_regular_send()
        send_reports(time)
        return
      end
      lua_util.debugm(N, rspamd_config, 'scheduling next send in %s seconds', delta)
      schedule_intermediate_send(delta)
    end)
  end
end
if type(opts['actions']) == 'table' then
  dmarc_actions = opts['actions']
end
if type(opts['report_settings']) == 'table' then
  for k, v in pairs(opts['report_settings']) do
    report_settings[k] = v
  end
end
if opts['send_reports'] then
  for _, e in ipairs({'email', 'domain', 'org_name'}) do
    if not report_settings[e] then
      rspamd_logger.errx(rspamd_config, 'missing required setting: report_settings.%s', e)
      return
    end
  end
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
  name = dmarc_symbols['allow'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['reject'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['quarantine'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['softfail'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['dnsfail'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['badpolicy'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})
rspamd_config:register_symbol({
  name = dmarc_symbols['na'],
  parent = id,
  group = 'policies',
  groups = {'dmarc'},
  type = 'virtual'
})

rspamd_config:register_dependency('DMARC_CHECK', symbols['spf_allow_symbol'])
rspamd_config:register_dependency('DMARC_CHECK', symbols['dkim_allow_symbol'])

-- DMARC munging support

if opts.munging then
  local lua_maps = require "lua_maps"
  local lua_maps_expressions = require "lua_maps_expressions"
  local lua_mime = require "lua_mime"

  local munging_defaults = {
    reply_goes_to_list = false,
    dmarc_mitigate_allow_only = true, -- perform munging based on DMARC_POLICY_ALLOW only
    munge_from = true, -- replace from with something like <orig name> via <rcpt user>
    list_map = nil, -- map of maillist domains
    munge_map_condition = nil, -- maps expression to enable munging
  }

  local munging_opts = lua_util.override_defaults(munging_defaults, opts.munging)

  if not munging_opts.list_map  then
    rspamd_logger.errx(rspamd_config, 'cannot enable DMARC munging with no list_map parameter')

    return
  end

  munging_opts.list_map = lua_maps.map_add_from_ucl(munging_opts.list_map,
      'set', 'DMARC munging map')

  if not munging_opts.list_map  then
    rspamd_logger.errx(rspamd_config, 'cannot enable DMARC munging with invalid list_map (invalid map)')

    return
  end

  if munging_opts.munge_map_condition then
    munging_opts.munge_map_condition = lua_maps_expressions.create(rspamd_config,
            munging_opts.munge_map_condition, N)
  end

  local function dmarc_munge_callback(task)
    if not task:has_symbol(dmarc_symbols.allow) then
      lua_util.debugm(N, task, 'skip munging, no %s symbol',
              dmarc_symbols.allow)
      -- Excepted
      return
    end
    -- TODO: Add policy check to skip munging for non-strict policies
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
        if r.domain and munging_opts.list_map:get_key(r.domain) then
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

    local via_name = rcpt_found.user
    local via_addr = rcpt_found.addr

    local from = task:get_from({ 'mime', 'orig'})

    if not from or not from[1] then
      lua_util.debugm(task, 'skip munging, from is bad')
      -- Excepted
      return
    end

    from = from[1]

    if from.name then
      from.name = string.format('%s via %s', from.name, via_name)
    else
      from.name = string.format('%s via %s', from.user or 'unknown', via_name)
    end

    local hdr_encoded = rspamd_util.fold_header('From',
            rspamd_util.mime_header_encode(string.format('%s <%s>',
                    from.name, via_addr)))
    lua_mime.modify_headers({
      remove = {['From'] = {0}},
      add = {
        ['From'] = {order = 1, value = hdr_encoded},
        ['Reply-To'] = {order = 0, value = from.addr}
      }
      })
    lua_util.debugm(N, task, 'munged DMARC header for %s: %s -> %s',
            from.domain, hdr_encoded, from.addr)
    rspamd_logger.infox(task, 'munged DMARC header for %s', from.domain)
  end

  rspamd_config:register_symbol({
    name = 'DMARC_MUNGED',
    type = 'normal',
    callback = dmarc_munge_callback
  })

  rspamd_config:register_dependency('DMARC_MUNGED', 'DMARC_CHECK')
  -- To avoid dkim signing issues
  rspamd_config:register_dependency('DKIM_SIGNED', 'DMARC_MUNGED')
  rspamd_config:register_dependency('ARC_SIGNED', 'DMARC_MUNGED')
end