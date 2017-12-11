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

local rspamd_resolver = require "rspamd_resolver"
local rspamd_logger = require "rspamd_logger"
local mempool = require "rspamd_mempool"
local rspamd_tcp = require "rspamd_tcp"
local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"
local rspamd_redis = require "lua_redis"
local check_local = false
local check_authed = false

if confighelp then
  return
end

local N = 'dmarc'
local no_sampling_domains
local no_reporting_domains
local statefile = string.format('%s/%s', rspamd_paths['DBDIR'], 'dmarc_reports_last_sent')
local VAR_NAME = 'dmarc_reports_last_sent'
local INTERVAL = 86400
local pool = mempool.create()

local report_settings = {
  helo = 'rspamd',
  hscan_count = 1000,
  smtp = '127.0.0.1',
  smtp_port = 25,
  retries = 2,
}
local report_template = [[From: "Rspamd" <%s>
To: %s
Subject: Report Domain: %s
	Submitter: %s
	Report-ID: <%s>
Date: %s
MIME-Version: 1.0
Message-ID: <%s>
Content-Type: multipart/alternative;
	boundary="----=_NextPart_000_024E_01CC9B0A.AFE54C00"

This is a multipart message in MIME format.

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

This is an aggregate report from %s.

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: text/xml
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
	filename="%s!%s!%s!%s.xml"

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

local function escape_xml(goo)
  return xml_grammar:match(goo)
end

-- Default port for redis upstreams
local redis_params = nil
-- 2 days
local dmarc_reporting = false
local dmarc_actions = {}

local E = {}

local take_report_sha
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

local function load_scripts(cfg, ev_base)
  local function redis_report_script_cb(err, data)
    if err then
      rspamd_logger.errx(cfg, 'DMARC report script loading failed: ' .. err)
    else
      take_report_sha = tostring(data)
      rspamd_logger.infox(cfg, 'Loaded DMARC report script with SHA %s', take_report_sha)
    end
  end
  local ret = rspamd_redis.redis_make_request_taskless(ev_base,
    rspamd_config,
    redis_params,
    nil,
    true, -- is write
    redis_report_script_cb, --callback
    'SCRIPT', -- command
    {'LOAD', take_report_script}
  )
  if not ret then
    rspamd_logger.errx(cfg, 'Unable to load DMARC report script')
  end
end

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

local function dmarc_report(task, spf_ok, dkim_ok, disposition,
    sampled_out, hfromdom, spfdom, dres, spf_result)
  local ip = task:get_from_ip()
  if not ip:is_valid() then
    return nil
  end
  local rspamd_lua_utils = require "lua_util"
  if rspamd_lua_utils.is_rspamc_or_controller(task) then return end
  local dkim_pass = table.concat(dres.pass or E, '|')
  local dkim_fail = table.concat(dres.fail or E, '|')
  local dkim_temperror = table.concat(dres.temperror or E, '|')
  local dkim_permerror = table.concat(dres.permerror or E, '|')
  local res = table.concat({
    ip:to_string(), spf_ok, dkim_ok,
    disposition, (sampled_out and 'sampled_out' or ''), hfromdom,
    dkim_pass, dkim_fail, dkim_temperror, dkim_permerror, spfdom, spf_result}, ',')

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
  local hfromdom = ((from or E)[1] or E).domain
  local dmarc_domain, spf_domain
  local ip_addr = task:get_ip()
  local dkim_results = {}
  local dmarc_checks = task:get_mempool():get_variable('dmarc_checks', 'int') or 0

  if dmarc_checks ~= 2 then
    rspamd_logger.infox(task, "skip DMARC checks as either SPF or DKIM were not checked");
    return
  end

  if ((not check_authed and task:get_user()) or
      (not check_local and ip_addr and ip_addr:is_local())) then
    rspamd_logger.infox(task, "skip DMARC checks for local networks and authorized users");
    return
  end
  if hfromdom and hfromdom ~= '' and not (from or E)[2] then
    dmarc_domain = rspamd_util.get_tld(hfromdom)
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
        task:get_message_id(), hfromdom)
    else
      if string.match(err, 'NOSCRIPT') then
        load_scripts(rspamd_config, task:get_ev_base())
      end
      rspamd_logger.errx(task, '<%1> dmarc report is not saved for %2: %3',
        task:get_message_id(), hfromdom, err)
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
              if dmarc_domain ~= hfromdom then
                dmarc_policy = 'reject'
              end
            elseif (subdomain_policy == 'quarantine') then
              if dmarc_domain ~= hfromdom then
                dmarc_policy = 'quarantine'
              end
            elseif (subdomain_policy == 'none') then
              if dmarc_domain ~= hfromdom then
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
    spf_domain = ((task:get_from(1) or E)[1] or E).domain
    if not spf_domain or spf_domain == '' then
      spf_domain = task:get_helo() or ''
    end

    if task:has_symbol(symbols['spf_allow_symbol']) then
      if strict_spf and rspamd_util.strequal_caseless(spf_domain, hfromdom) then
        spf_ok = true
      elseif strict_spf then
        table.insert(reason, "SPF not aligned (strict)")
      end
      if not strict_spf then
        local spf_tld = rspamd_util.get_tld(spf_domain)
        if rspamd_util.strequal_caseless(spf_tld, dmarc_domain) then
          spf_ok = true
        else
          table.insert(reason, "SPF not aligned (relaxed)")
        end
      end
    else
      table.insert(reason, "No valid SPF")
    end
    local das = task:get_symbol(symbols['dkim_allow_symbol'])
    if ((das or E)[1] or E).options then
      dkim_results.pass = {}
      for _,domain in ipairs(das[1]['options']) do
        table.insert(dkim_results.pass, domain)
        if strict_dkim and rspamd_util.strequal_caseless(hfromdom, domain) then
          dkim_ok = true
        elseif strict_dkim then
          table.insert(reason, "DKIM not aligned (strict)")
        end
        if not strict_dkim then
          local dkim_tld = rspamd_util.get_tld(domain)
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
    local spf_tmpfail, dkim_tmpfail

    if not (spf_ok or dkim_ok) then
      local reason_str = table.concat(reason, ", ")
      res = 1.0
      spf_tmpfail = task:get_symbol(symbols['spf_tempfail_symbol'])
      dkim_tmpfail = task:get_symbol(symbols['dkim_tempfail_symbol'])
      if (spf_tmpfail or dkim_tmpfail) then
        if ((dkim_tmpfail or E)[1] or E).options then
          dkim_results.tempfail = {}
          for _,domain in ipairs(dkim_tmpfail[1]['options']) do
            table.insert(dkim_results.tempfail, domain)
          end
        end
        task:insert_result(dmarc_symbols['dnsfail'], 1.0, lookup_domain .. ' : ' .. 'SPF/DKIM temp error', dmarc_policy)
        return maybe_force_action('dnsfail')
      end
      if dmarc_policy == 'quarantine' then
        if not pct or pct == 100 then
          task:insert_result(dmarc_symbols['quarantine'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
          disposition = "quarantine"
        else
          if (math.random(100) > pct) then
            if (not no_sampling_domains or not no_sampling_domains:get_key(dmarc_domain)) then
              task:insert_result(dmarc_symbols['softfail'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy, "sampled_out")
              sampled_out = true
            else
              task:insert_result(dmarc_symbols['quarantine'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy, "local_policy")
              disposition = "quarantine"
            end
          else
            task:insert_result(dmarc_symbols['quarantine'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
            disposition = "quarantine"
          end
        end
      elseif dmarc_policy == 'reject' then
        if not pct or pct == 100 then
          task:insert_result(dmarc_symbols['reject'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
          disposition = "reject"
        else
          if (math.random(100) > pct) then
            if (not no_sampling_domains or not no_sampling_domains:get_key(dmarc_domain)) then
              task:insert_result(dmarc_symbols['quarantine'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy, "sampled_out")
              disposition = "quarantine"
              sampled_out = true
            else
              task:insert_result(dmarc_symbols['reject'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy, "local_policy")
              disposition = "reject"
            end
          else
            task:insert_result(dmarc_symbols['reject'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
            disposition = "reject"
          end
        end
      else
        task:insert_result(dmarc_symbols['softfail'], res, lookup_domain .. ' : ' .. reason_str, dmarc_policy)
      end
    else
      task:insert_result(dmarc_symbols['allow'], res, lookup_domain, dmarc_policy)
    end

    if rua and redis_params and dmarc_reporting then

      if no_reporting_domains then
        if no_reporting_domains:get_key(dmarc_domain) or no_reporting_domains:get_key(rspamd_util.get_tld(dmarc_domain)) then
          rspamd_logger.infox(task, 'DMARC reporting suppressed for %1', dmarc_domain)
          return maybe_force_action(disposition)
        end
      end

      local spf_result
      if spf_ok then
        spf_result = 'pass'
      elseif spf_tmpfail then
        spf_result = 'temperror'
      else
        if task:get_symbol(symbols.spf_deny_symbol) then
          spf_result = 'fail'
        elseif task:get_symbol(symbols.spf_softfail_symbol) then
          spf_result = 'softfail'
        elseif task:get_symbol(symbols.spf_neutral_symbol) then
          spf_result = 'neutral'
        elseif task:get_symbol(symbols.spf_permfail_symbol) then
          spf_result = 'permerror'
        else
          spf_result = 'none'
        end
      end
      local dkim_deny = ((task:get_symbol(symbols.dkim_deny_symbol) or E)[1] or E).options
      if dkim_deny then
        dkim_results.fail = {}
        for _, domain in ipairs(dkim_deny) do
          table.insert(dkim_results.fail, domain)
        end
      end
      local dkim_permerror = ((task:get_symbol(symbols.dkim_permfail_symbol) or E)[1] or E).options
      if dkim_permerror then
        dkim_results.permerror = {}
        for _, domain in ipairs(dkim_permerror) do
          table.insert(dkim_results.permerror, domain)
        end
      end
      -- Prepare and send redis report element
      local period = os.date('%Y%m%d', task:get_date({format = 'connect', gmt = true}))
      local dmarc_domain_key = table.concat({redis_keys.report_prefix, hfromdom, period}, redis_keys.join_char)
      local report_data = dmarc_report(task, spf_ok and 'pass' or 'fail', dkim_ok and 'pass' or 'fail', disposition, sampled_out,
        hfromdom, spf_domain, dkim_results, spf_result)
      local idx_key = table.concat({redis_keys.index_prefix, period}, redis_keys.join_char)

      if report_data then
        local ret = rspamd_redis.redis_make_request(task,
          redis_params, -- connect params
          hfromdom, -- hash key
          true, -- is write
          dmarc_report_cb, --callback
          'EVALSHA', -- command
          {take_report_sha, 2, idx_key, dmarc_domain_key, hfromdom, report_data} -- arguments
        )
        if not ret then
          rspamd_logger.errx(task, 'Unable to schedule redis request')
        end
      end
    end

    return maybe_force_action(disposition)

  end

  -- Do initial request
  local resolve_name = '_dmarc.' .. hfromdom
  task:get_resolver():resolve_txt({
    task=task,
    name = resolve_name,
    callback = dmarc_dns_cb,
    forced = true})
end

local opts = rspamd_config:get_all_opt('options')
if type(opts) == 'table' then
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
no_sampling_domains = rspamd_map_add(N, 'no_sampling_domains', 'map', 'Domains not to apply DMARC sampling to')
no_reporting_domains = rspamd_map_add(N, 'no_reporting_domains', 'map', 'Domains not to apply DMARC reporting to')

if opts['symbols'] then
  for k,_ in pairs(dmarc_symbols) do
    if opts['symbols'][k] then
      dmarc_symbols[k] = opts['symbols'][k]
    end
  end
end

if opts['reporting'] == true then
  redis_params = rspamd_parse_redis_server('dmarc')
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'cannot parse servers parameter')
  elseif not opts['send_reports'] then
    dmarc_reporting = true
    rspamd_config:add_on_load(function(cfg, ev_base, worker)
      load_scripts(cfg, ev_base)
    end)
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
    rspamd_config:add_on_load(function(cfg, ev_base, worker)
      load_scripts(cfg, ev_base)
      if not (worker:get_name() == 'controller' and worker:get_index() == 0) then return end
      local rresolver = rspamd_resolver.init(ev_base, rspamd_config)
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
      end)
      local get_reporting_domain, reporting_domain, report_start, report_end, report_id, want_period, report_key
      local reporting_addr = {}
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
          table.insert(buf, string.format('<reason>%s</reason>', data.override))
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
        report_id = string.format('%s.%d.%d', reporting_domain, report_start, report_end)
        rspamd_logger.debugm(N, rspamd_config, 'new report: %s', report_id)
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
              local tmp = rspamd_str_split(split[10], '|')
              for _, d in ipairs(tmp) do
                table.insert(row.dkim_results, {domain = d, result = 'permerror'})
              end
            end
            table.insert(entries, row)
          end,
          header = function()
              return table.concat({
                '<?xml version="1.0" encoding="utf-8"?><feedback><report_metadata><org_name>',
                escape_xml(report_settings.org_name), '</org_name><email>',
                escape_xml(report_settings.email), '</email><report_id>',
                report_id, '</report_id><date_range><begin>', report_start,
                '</begin><end>', report_end, '</end></date_range></report_metadata><policy_published><domain>',
                reporting_domain, '</domain><adkim>', escape_xml(domain_policy.adkim), '</adkim><aspf>',
                escape_xml(domain_policy.aspf), '</aspf><p>', escape_xml(domain_policy.p),
                '</p><sp>', escape_xml(domain_policy.sp), '</sp><pct>', escape_xml(domain_policy.pct),
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
        if retry > report_settings.retries then
          rspamd_logger.errx(rspamd_config, "Couldn't send mail for %s: retries exceeded", reporting_domain)
          return get_reporting_domain()
        end
        local tmp_addr = {}
        for k in pairs(reporting_addr) do
          table.insert(tmp_addr, k)
        end
        local encoded = rspamd_util.encode_base64(table.concat({xmlf('header'), xmlf('entries'), xmlf('footer')}), 78)
        local function mail_cb(err, data, conn)
          local function no_error(merr, mdata, wantcode)
            wantcode = wantcode or '2'
            if merr then
              rspamd_logger.errx(ev_base, 'got error in tcp callback: %s', merr)
              if conn then
                conn:close()
              end
              send_report_via_email(xmlf, retry+1)
              return false
            end
            if mdata then
              if type(mdata) ~= 'string' then
                mdata = tostring(mdata)
              end
              if string.sub(mdata, 1, 1) ~= wantcode then
                rspamd_logger.errx(ev_base, 'got bad smtp response: %s', mdata)
                if conn then
                  conn:close()
                end
                send_report_via_email(xmlf, retry+1)
                return false
              end
            else
              rspamd_logger.errx(ev_base, 'no data')
              if conn then
                conn:close()
              end
              send_report_via_email(xmlf, retry+1)
              return false
            end
            return true
          end
          local function all_done_cb(merr, mdata)
            if conn then
              conn:close()
            end
            get_reporting_domain()
            return true
          end
          local function quit_done_cb(merr, mdata)
            conn:add_read(all_done_cb, '\r\n')
          end
          local function quit_cb(merr, mdata)
            if no_error(merr, mdata) then
              conn:add_write(quit_done_cb, 'QUIT\r\n')
            end
          end
          local function pre_quit_cb(merr, mdata)
            if no_error(merr, '2') then
              conn:add_read(quit_cb, '\r\n')
            end
          end
          local function data_done_cb(merr, mdata)
            if no_error(merr, mdata, '3') then
              local atmp = {}
              for k in pairs(reporting_addr) do
                table.insert(atmp, k)
              end
              local addr_string = table.concat(atmp, ', ')
              local rhead = string.format(report_template, report_settings.email, addr_string,
                reporting_domain, report_settings.domain, report_id, rspamd_util.time_to_string(rspamd_util.get_time()),
                rspamd_util.random_hex(12) .. '@rspamd', report_settings.domain, report_settings.domain, reporting_domain,
                report_start, report_end)
              conn:add_write(pre_quit_cb, {rhead, encoded, report_footer, '\r\n.\r\n'})
            end
          end
          local function data_cb(merr, mdata)
            if no_error(merr, '2') then
              conn:add_read(data_done_cb, '\r\n')
            end
          end
          local function rcpt_done_cb(merr, mdata)
            if no_error(merr, mdata) then
              conn:add_write(data_cb, 'DATA\r\n')
            end
          end
          local from_done_cb
          local function rcpt_cb(merr, mdata)
            if no_error(merr, '2') then
              if tmp_addr[1] then
                conn:add_read(from_done_cb, '\r\n')
              else
                conn:add_read(rcpt_done_cb, '\r\n')
              end
            end
          end
          from_done_cb = function(merr, mdata)
            if no_error(merr, mdata) then
              conn:add_write(rcpt_cb, {'RCPT TO: <', table.remove(tmp_addr), '>\r\n'})
            end
          end
          local function from_cb(merr, mdata)
            if no_error(merr, '2') then
              conn:add_read(from_done_cb, '\r\n')
            end
          end
            local function hello_done_cb(merr, mdata)
            if no_error(merr, mdata) then
              conn:add_write(from_cb, {'MAIL FROM: <', report_settings.email, '>\r\n'})
            end
          end
          local function hello_cb(merr)
            if no_error(merr, '2') then
              conn:add_read(hello_done_cb, '\r\n')
            end
          end
          if no_error(err, data) then
            conn:add_write(hello_cb, {'HELO ', report_settings.helo, '\r\n'})
          end
        end
        rspamd_tcp.request({
          ev_base = ev_base,
          callback = mail_cb,
          config = rspamd_config,
          stop_pattern = '\r\n',
          host = report_settings.smtp,
          port = report_settings.smtp_port,
          resolver = rresolver,
        })
      end
      local function make_report()
        if type(report_settings.override_address) == 'string' then
          reporting_addr = {[report_settings.override_address] = true}
        end
        if type(report_settings.additional_address) == 'string' then
          reporting_addr[report_settings.additional_address] = true
        end
        rspamd_logger.infox(ev_base, 'sending report for %s <%s>', reporting_domain, table.concat(reporting_addr, ','))
        local dmarc_xml = dmarc_report_xml()
        local dmarc_push_cb
        dmarc_push_cb = function(err, data)
          if err then
            rspamd_logger.errx(ev_base, 'Redis request failed: %s', err)
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
                rspamd_logger.errx(ev_base, 'Failed to schedule redis request')
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
          rspamd_logger.errx(rspamd_config, 'Failed to schedule redis request')
          -- XXX: data is orphaned; replace key or delete data
          get_reporting_domain()
        end
      end
      local function delete_reports()
        local function delete_reports_cb(err)
          if err then
            rspamd_logger.errx(rspamd_config, 'Error deleting reports: %s', err)
          end
          rspamd_logger.infox(rspamd_config, 'Deleted reports for %s', reporting_domain)
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
          rspamd_logger.errx(rspamd_config, 'Failed to schedule redis request')
          get_reporting_domain()
        end
      end
      local function verify_reporting_address()
        local function verifier(test_addr, vdom)
          local retry = 0
          local function verify_cb(resolver, to_resolve, results, err, _, authenticated)
            if err then
              if err == 'no records with this name' or err == 'requested record is not found' then
                rspamd_logger.infox(rspamd_config, 'Reports to %s for %s not authorised', test_addr, reporting_domain)
                to_verify[test_addr] = nil
              else
                rspamd_logger.errx(rspamd_config, 'Lookup error [%s]: %s', to_resolve, err)
                if retry < report_settings.retries then
                  retry = retry + 1
                  rspamd_config:get_resolver():resolve_txt(nil, pool,
                    string.format('%s._report._dmarc.%s', reporting_domain, vdom), verify_cb)
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
                reporting_addr[test_addr] = true
              end
            end
            local t, nvdom = next(to_verify)
            if not t then
              if next(reporting_addr) then
                make_report()
              else
                rspamd_logger.infox(rspamd_config, 'No valid reporting addresses for %s', reporting_domain)
                delete_reports()
              end
            else
              verifier(t, nvdom)
            end
          end
          rspamd_config:get_resolver():resolve_txt(nil, pool,
            string.format('%s._report._dmarc.%s', reporting_domain, vdom), verify_cb)
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
                rspamd_config:get_resolver():resolve_txt(nil, pool,
                string.format('_dmarc.%s', esld), check_addr_cb)
              else
                rspamd_logger.errx(rspamd_config, 'No DMARC record found for %s', reporting_domain)
                delete_reports()
              end
            else
              rspamd_logger.errx(rspamd_config, 'Lookup error [%s]: %s', to_resolve, err)
              if retry < report_settings.retries then
                retry = retry + 1
                rspamd_config:get_resolver():resolve_txt(nil, pool,
                  to_resolve, check_addr_cb)
              else
                rspamd_logger.errx(rspamd_config, "Couldn't get reporting address for %s: retries exceeded", reporting_domain)
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
                policy = elts
              end
            end
            if not found_policy then
              rspamd_logger.errx(rspamd_config, 'No policy: %s', to_resolve)
              if reporting_domain ~= esld then
                rspamd_config:get_resolver():resolve_txt(nil, pool,
                string.format('_dmarc.%s', esld), check_addr_cb)
              else
                delete_reports()
              end
            elseif failed_policy then
              rspamd_logger.errx(rspamd_config, 'Duplicate policies: %s', to_resolve)
              delete_reports()
            elseif not policy['rua'] then
              rspamd_logger.errx(rspamd_config, 'No reporting address: %s', to_resolve)
              delete_reports()
            else
              local upool = mempool.create()
              local split = rspamd_str_split(policy['rua'], ',')
              for _, m in ipairs(split) do
                local url = rspamd_url.create(upool, m)
                if not url then
                  rspamd_logger.errx(rspamd_config, 'Couldnt extract reporting address: %s', policy['rua'])
                else
                  local urlt = url:to_table()
                  if urlt['protocol'] ~= 'mailto' then
                    rspamd_logger.errx(rspamd_config, 'Invalid URL: %s', url)
                  else
                    if urlt['tld'] == rspamd_util.get_tld(reporting_domain) then
                      reporting_addr[string.format('%s@%s', urlt['user'], urlt['host'])] = true
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
              elseif next(reporting_addr) then
                make_report()
              else
                rspamd_logger.errx(rspamd_config, 'No reporting address for %s', reporting_domain)
                delete_reports()
              end
            end
          end
        end
        rspamd_config:get_resolver():resolve_txt(nil, pool,
          string.format('_dmarc.%s', reporting_domain), check_addr_cb)
      end
      get_reporting_domain = function()
        reporting_domain = nil
        reporting_addr = {}
        domain_policy = {}
        cursor = 0
        local function get_reporting_domain_cb(err, data)
          if err then
            rspamd_logger.errx(cfg, 'Unable to get DMARC domain: %s', err)
          else
            if type(data) == 'userdata' then
              reporting_domain = nil
            else
              report_key = data
              local tmp = rspamd_str_split(data, redis_keys.join_char)
              reporting_domain = tmp[2]
            end
            if not reporting_domain then
              rspamd_logger.infox(cfg, 'No more domains to generate reports for')
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
          rspamd_logger.errx(cfg, 'Unable to get DMARC domain')
        end
      end
      local function send_reports(time)
        rspamd_logger.infox(ev_base, 'sending reports ostensibly %1', time)
        pool:set_variable(VAR_NAME, time)
        local yesterday = os.date('!*t', rspamd_util.get_time() - INTERVAL)
        local today = os.date('!*t', rspamd_util.get_time())
        report_start = os.time({year = yesterday.year, month = yesterday.month, day = yesterday.day, hour = 0}) + tz_offset
        report_end = os.time({year = today.year, month = today.month, day = today.day, hour = 0}) + tz_offset
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
        rspamd_logger.errx('Failed to open statefile: %s', err)
      end
      if f then
        io.input(f)
        stamp = tonumber(io.read())
        pool:set_variable(VAR_NAME, stamp)
      end
      local time = rspamd_util.get_time()
      if not stamp then
        rspamd_logger.debugm(N, rspamd_config, 'No state found - sending reports immediately')
        schedule_regular_send()
        send_reports(time)
        return
      end
      local delta = stamp - time + INTERVAL
      if delta <= 0 then
        rspamd_logger.debugm(N, rspamd_config, 'Last send is too old - sending reports immediately')
        schedule_regular_send()
        send_reports(time)
        return
      end
      rspamd_logger.debugm(N, rspamd_config, 'Scheduling next send in %s seconds', delta)
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
if dmarc_reporting then
  for _, e in ipairs({'email', 'domain', 'org_name'}) do
    if not report_settings[e] then
      rspamd_logger.errx(rspamd_config, 'Missing required setting: report_settings.%s', e)
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

