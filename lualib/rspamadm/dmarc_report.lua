--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local argparse = require "argparse"
local lua_util = require "lua_util"
local logger = require "rspamd_logger"
local lua_redis = require "lua_redis"
local dmarc_common = require "plugins/dmarc"
local lupa = require "lupa"
local rspamd_mempool = require "rspamd_mempool"
local rspamd_url = require "rspamd_url"
local rspamd_text = require "rspamd_text"
local rspamd_util = require "rspamd_util"
local rspamd_dns = require "rspamd_dns"

local N = 'dmarc_report'

-- Define command line options
local parser = argparse()
    :name "rspamadm dmarc_report"
    :description "Dmarc reports sending tool"
    :help_description_margin(30)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

parser:flag "-v --verbose"
      :description "Enable dmarc specific logging"

parser:flag "-n --no-opt"
      :description "Do not reset reporting data/send reports"

parser:argument "date"
       :description "Date to process (today by default)"
       :argname "<YYYYMMDD>"
       :args "*"
parser:option "-b --batch-size"
      :description "Send reports in batches up to <batch-size> messages"
      :argname "<number>"
      :convert(tonumber)
      :default "10"

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
	boundary="----=_NextPart_{= uuid =}"

This is a multipart message in MIME format.

------=_NextPart_{= uuid =}
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

This is an aggregate report from {= submitter =}.

Report domain: {= reporting_domain =}
Submitter: {= submitter =}
Report ID: {= report_id =}

------=_NextPart_{= uuid =}
Content-Type: application/gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
	filename="{= submitter =}!{= reporting_domain =}!{= report_start =}!{= report_end =}.xml.gz"

]]
local report_footer = [[

------=_NextPart_{= uuid =}--]]

local dmarc_settings = {}
local redis_params
local redis_attrs = {
  config = rspamd_config,
  ev_base = rspamadm_ev_base,
  session = rspamadm_session,
  log_obj = rspamd_config,
  resolver = rspamadm_dns_resolver,
}
local pool

local function load_config(opts)
  local _r,err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end
end

-- Concat elements using redis_keys.join_char
local function redis_prefix(...)
  return table.concat({...}, dmarc_settings.reporting.redis_keys.join_char)
end



local function get_rua(rep_key)
  local parts = lua_util.str_split(rep_key, dmarc_settings.reporting.redis_keys.join_char)

  if #parts >= 3 then
    return parts[3]
  end

  return nil
end

local function get_domain(rep_key)
  local parts = lua_util.str_split(rep_key, dmarc_settings.reporting.redis_keys.join_char)

  if #parts >= 3 then
    return parts[2]
  end

  return nil
end

local function gen_uuid()
  local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
  return string.gsub(template, '[xy]', function (c)
    local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
    return string.format('%x', v)
  end)
end

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
-- Enable xml escaping in lupa templates
lupa.filters.escape_xml = escape_xml

-- Creates report XML header
local function report_header(reporting_domain, report_start, report_end, domain_policy)
  local report_id = string.format('%s.%d.%d',
      reporting_domain, report_start, report_end)
  local xml_template = [[
<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>{= report_settings.org_name | escape_xml =}</org_name>
    <email>{= report_settings.email | escape_xml =}</email>
    <report_id>{= report_id =}</report_id>
    <date_range>
      <begin>{= report_start =}</begin>
      <end>{= report_end =}</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>{= reporting_domain | escape_xml =}</domain>
    <adkim>{= domain_policy.adkim | escape_xml =}</adkim>
    <aspf>{= domain_policy.aspf | escape_xml =}</aspf>
    <p>{= domain_policy.p | escape_xml =}</p>
    <sp>{= domain_policy.sp | escape_xml =}</sp>
    <pct>{= domain_policy.pct | escape_xml =}</pct>
  </policy_published>
]]
  return lua_util.jinja_template(xml_template, {
    report_settings = dmarc_settings.reporting,
    report_id = report_id,
    report_start = report_start,
    report_end = report_end,
    domain_policy = domain_policy,
    reporting_domain = reporting_domain,
  }, true)
end

-- Generate xml entry for a preprocessed redis row
local function entry_to_xml(data)
  local xml_template = [[<record>
  <row>
    <source_ip>{= data.ip =}</source_ip>
    <count>{= data.count =}</count>
    <policy_evaluated>
      <disposition>{= data.disposition =}</disposition>
      <dkim>{= data.dkim_disposition =}</dkim>
      <spf>{= data.spf_disposition =}</spf>
      {% if data.override and data.override ~= '' -%}
      <reason><type>{= data.override =}</type></reason>
      {%- endif %}
    </policy_evaluated>
  </row>
  <identifiers>
    <header_from>{= data.header_from =}</header_from>
  </identifiers>
  <auth_results>
    {% if data.dkim_results[1] -%}
    {% for d in data.dkim_results -%}
    <dkim>
      <domain>{= d.domain =}</domain>
      <result>{= d.result =}</result>
    </dkim>
    {%- endfor %}
    {%- endif %}
    <spf>
      <domain>{= data.spf_domain =}</domain>
      <result>{= data.spf_result =}</result>
    </spf>
  </auth_results>
</record>
]]
  return lua_util.jinja_template(xml_template, {data = data}, true)
end

-- Process a report entry stored in Redis splitting it to a lua table
local function process_report_entry(data, score)
  local split = lua_util.str_split(data, ',')
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
    count = tonumber(score),
  }
  -- Process dkim entries
  local function dkim_entries_process(dkim_data, result)
    if dkim_data and dkim_data ~= '' then
      local dkim_elts = lua_util.str_split(dkim_data, '|')
      for _, d in ipairs(dkim_elts) do
        table.insert(row.dkim_results, {domain = d, result = result})
      end
    end
  end
  dkim_entries_process(split[7], 'pass')
  dkim_entries_process(split[8], 'fail')
  dkim_entries_process(split[9], 'temperror')
  dkim_entries_process(split[9], 'permerror')

  return row
end

-- Process a single rua entry, validating in DNS if needed
local function process_rua(dmarc_domain, rua)
  local parts = lua_util.str_split(rua, ',')

  -- Remove size limitation, as we don't care about them
  local addrs = {}
  for _,a in ipairs(parts) do
    local u = rspamd_url.create(pool, a:gsub('!%d+[kmg]?$', ''))
    if u then
      -- Check each address for sanity
      if dmarc_domain == u:get_tld() or dmarc_domain == u:get_host() then
        -- Same domain - always include
        table.insert(addrs, u)
      else
        -- We need to check authority
        local resolve_str = string.format('%s._report._dmarc.%s',
            dmarc_domain, u:get_host())
        local is_ok, results = rspamd_dns.request({
          config = rspamd_config,
          session = rspamadm_session,
          type = 'txt',
          name = resolve_str,
        })

        if not is_ok then
          logger.errx('cannot resolve %s: %s; exclude %s', resolve_str, results, a)
        else
          local found = false
          for _,t in ipairs(results) do
            if string.match(t, 'v=DMARC1') then
              found = true
              break
            end
          end

          if not found then
            logger.errx('%s is not authorized to process reports on %s', dmarc_domain, u:get_host())
          else
            -- All good
            table.insert(addrs, u)
          end
        end
      end
    end
  end

  if #addrs > 0 then
    return addrs
  end

  return nil
end

-- Validate reporting domain, extracting rua and checking 3rd party report domains
-- This function returns a full dmarc record processed + rua as a list of url objects
local function validate_reporting_domain(reporting_domain)
  -- Now check the domain policy
  -- DMARC domain is a esld for the reporting domain
  local dmarc_domain = rspamd_util.get_tld(reporting_domain)
  local is_ok, results = rspamd_dns.request({
    config = rspamd_config,
    session = rspamadm_session,
    type = 'txt',
    name = '_dmarc.' .. dmarc_domain ,
  })

  if not is_ok or not results then
    logger.errx('cannot resolve _dmarc.%s: %s', dmarc_domain, results)
    return nil
  end

  for _,r in ipairs(results) do
    local processed,rec = dmarc_common.dmarc_check_record(rspamd_config, r, false)
    if processed and rec.rua then
      -- We need to check or alter rua if needed
      local processed_rua = process_rua(dmarc_domain, rec.rua)
      if processed_rua then
        rec = rec.raw_elts
        rec.rua = processed_rua

        -- Fill defaults in a record to avoid nils in a report
        rec['pct'] = rec['pct'] or 100
        rec['adkim'] = rec['adkim'] or 'r'
        rec['aspf'] = rec['aspf'] or 'r'
        rec['p'] = rec['p'] or 'none'
        rec['sp'] = rec['sp'] or 'none'
        return rec
      end
      return nil
    end
  end

  return nil
end

-- Returns a list of recipients from a table as a string processing elements if needed
local function rcpt_list(tbl, func)
  local res = {}
  for _,r in ipairs(tbl) do
    if func then
      table.insert(res, func(r))
    else
      table.insert(res, r)
    end
  end

  return table.concat(res, ',')
end

-- Synchronous smtp send function
local function send_reports_by_smtp(opts, reports, finish_cb)
  local lua_smtp = require "lua_smtp"
  local reports_failed = 0
  local reports_sent = 0
  local report_settings = dmarc_settings.reporting

  local function gen_sendmail_cb(report, args)
    return function(ret, err)
      -- We modify this from all callbacks
      args.nreports = args.nreports - 1
      if not ret then
        logger.errx("Couldn't send mail for %s: %s", report.reporting_domain, err)
        reports_failed = reports_failed + 1
      else
        reports_sent = reports_sent + 1
        lua_util.debugm(N, 'successfully sent a report for %s: %s bytes sent',
            report.reporting_domain, #report.message)
      end

      -- Tail call to the next batch or to the final function
      if args.nreports == 0 then
        if args.next_start > #reports then
          finish_cb(reports_sent, reports_failed)
        else
          args.cont_func(args.next_start)
        end
      end
    end
  end

  local function send_data_in_batches(cur_batch)
    local nreports = math.min(#reports - cur_batch + 1, opts.batch_size)
    local next_start = cur_batch + nreports
    lua_util.debugm(N, 'send data for %s domains (from %s to %s)',
        nreports, cur_batch, next_start-1)
    -- Shared across all closures
    local gen_args = {
      cont_func = send_data_in_batches,
      nreports = nreports,
      next_start = next_start
    }
    for i=cur_batch,next_start-1 do
      local report = reports[i]
      lua_smtp.sendmail({
        ev_base = rspamadm_ev_base,
        session = rspamadm_session,
        config = rspamd_config,
        host = report_settings.smtp,
        port = report_settings.smtp_port or 25,
        resolver = rspamadm_dns_resolver,
        from = report_settings.email,
        recipients = report.rcpts,
        helo = report_settings.helo or 'rspamd.localhost',
      },
          report.message,
          gen_sendmail_cb(report, gen_args))
    end
  end

  send_data_in_batches(1)
end

local function prepare_report(opts, start_time, rep_key)
  local rua = get_rua(rep_key)
  local reporting_domain = get_domain(rep_key)

  if not rua then
    logger.errx('report %s has no valid rua, skip it', rep_key)
    return nil
  end
  if not reporting_domain then
    logger.errx('report %s has no valid reporting_domain, skip it', rep_key)
    return nil
  end

  local ret, results = lua_redis.request(redis_params, redis_attrs,
      {'EXISTS', rep_key})

  if not ret or not results or results == 0 then
    return nil
  end

  -- Rename report key to avoid races
  if not opts.no_opt then
    lua_redis.request(redis_params, redis_attrs,
        {'RENAME', rep_key, rep_key .. '_processing'})
    rep_key = rep_key .. '_processing'
  end

  local dmarc_record = validate_reporting_domain(reporting_domain)
  lua_util.debugm(N, 'process reporting domain %s: %s', reporting_domain, dmarc_record)

  if not dmarc_record then
    if not opts.no_opt then
      lua_redis.request(redis_params, redis_attrs,
          {'DEL', rep_key})
    end
    logger.messagex('Cannot process reports for domain %s; invalid dmarc record', reporting_domain)
    return nil
  end

  -- Get all reports for a domain
  ret, results = lua_redis.request(redis_params, redis_attrs,
      {'ZRANGE', rep_key, '0', '-1', 'WITHSCORES'})
  local report_entries = {}
  local end_time = os.time()
  table.insert(report_entries,
      report_header(reporting_domain, start_time, end_time, dmarc_record))
  for i=1,#results,2 do
    local xml_record = entry_to_xml(process_report_entry(results[i], results[i + 1]))
    table.insert(report_entries, xml_record)
  end
  table.insert(report_entries, '</feedback>')
  local xml_to_compress = rspamd_text.fromtable(report_entries)
  lua_util.debugm(N, 'got xml: %s', xml_to_compress)

  -- Prepare SMTP message
  local report_settings = dmarc_settings.reporting
  local rcpt_string = rcpt_list(dmarc_record.rua, function(rua_elt)
    return string.format('%s@%s', rua_elt:get_user(), rua_elt:get_host())
  end)
  local bcc_string
  if report_settings.bcc_addrs then
    bcc_string = rcpt_list(report_settings.bcc_addrs)
  end
  local uuid = gen_uuid()
  local rhead = lua_util.jinja_template(report_template, {
    from_name = report_settings.from_name,
    from_addr = report_settings.email,
    rcpt = rcpt_string,
    bcc = bcc_string,
    uuid = uuid,
    reporting_domain = reporting_domain,
    submitter = report_settings.domain,
    report_id = string.format('%s.%d.%d', reporting_domain, start_time,
        end_time),
    report_date = rspamd_util.time_to_string(rspamd_util.get_time()),
    message_id = rspamd_util.random_hex(16) .. '@' .. report_settings.msgid_from,
    report_start = start_time,
    report_end = end_time
  }, true)
  local rfooter = lua_util.jinja_template(report_footer, {
    uuid = uuid,
  }, true)
  local message = rspamd_text.fromtable{
    (rhead:gsub("\n", "\r\n")),
    rspamd_util.encode_base64(rspamd_util.gzip_compress(xml_to_compress), 73),
    rfooter:gsub("\n", "\r\n"),
  }


  lua_util.debugm(N, 'got final message: %s', message)

  if not opts.no_opt then
    lua_redis.request(redis_params, redis_attrs,
        {'DEL', rep_key})
  end

  local report_rcpts = lua_util.str_split(rcpt_string, ',')

  if report_settings.bcc_addrs then
    for _,b in ipairs(report_settings.bcc_addrs) do
      table.insert(report_rcpts, b)
    end
  end

  return {
    message = message,
    rcpts = report_rcpts,
    reporting_domain = reporting_domain
  }
end

local function process_report_date(opts, start_time, date)
  local idx_key = redis_prefix(dmarc_settings.reporting.redis_keys.index_prefix, date)
  local ret, results = lua_redis.request(redis_params, redis_attrs,
      {'EXISTS', idx_key})

  if not ret or not results or results == 0 then
    logger.messagex('No reports for %s', date)
    return {}
  end

  -- Rename index key to avoid races
  if not opts.no_opt then
    lua_redis.request(redis_params, redis_attrs,
        {'RENAME', idx_key, idx_key .. '_processing'})
    idx_key = idx_key .. '_processing'
  end
  ret, results = lua_redis.request(redis_params, redis_attrs,
      {'SMEMBERS', idx_key})

  if not ret or not results then
    -- Remove bad key
    if not opts.no_opt then
      lua_redis.request(redis_params, redis_attrs,
          {'DEL', idx_key})
    end
    logger.messagex('Cannot get reports for %s', date)
    return {}
  end

  local reports = {}
  for _,rep in ipairs(results) do
    local report = prepare_report(opts, start_time, rep)

    if report then
      table.insert(reports, report)
    end
  end

  -- Shuffle reports to make sending more fair
  lua_util.shuffle(reports)
  -- Remove processed key
  if not opts.no_opt then
    lua_redis.request(redis_params, redis_attrs,
        {'DEL', idx_key})
  end

  return reports
end

local function handler(args)
  local opts = parser:parse(args)

  pool = rspamd_mempool.create()
  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())

  if opts.verbose then
    lua_util.enable_debug_modules('dmarc', N)
  end

  dmarc_settings = rspamd_config:get_all_opt('dmarc')
  if not dmarc_settings or not dmarc_settings.reporting or not dmarc_settings.reporting.enabled then
    logger.errx('dmarc reporting is not enabled, exiting')
    os.exit(1)
  end

  dmarc_settings = lua_util.override_defaults(dmarc_common.default_settings, dmarc_settings)
  redis_params = lua_redis.parse_redis_server('dmarc', dmarc_settings)

  if not redis_params then
    logger.errx('Redis is not configured, exiting')
    os.exit(1)
  end

  for _, e in ipairs({'email', 'domain', 'org_name'}) do
    if not dmarc_settings.reporting[e] then
      logger.errx('Missing required setting: dmarc.reporting.%s', e)
      return
    end
  end

  local ret,results = lua_redis.request(redis_params, redis_attrs, {
    'GET', 'rspamd_dmarc_last_collection'
  })

  local start_time
  if not ret or not tonumber(results) then
    start_time = os.time() - 86400
  else
    start_time = tonumber(results)
  end

  lua_util.debugm(N, 'previous last report date is %s', start_time)

  if not opts.date or #opts.date == 0 then
    local now = os.time()
    opts.date = {}
    while now >= start_time do
      table.insert(opts.date, os.date('!%Y%m%d', now))
      now = now - 86400
    end
  end

  local ndates = 0
  local nreports = 0
  local all_reports = {}
  for _,date in ipairs(opts.date) do
    lua_util.debugm(N, 'Process date %s', date)
    local reports_for_date = process_report_date(opts, start_time, date)
    if #reports_for_date > 0 then
      ndates = ndates + 1
      nreports = nreports + #reports_for_date

      for _,r in ipairs(reports_for_date) do
        table.insert(all_reports, r)
      end
    end
  end

  local function finish_cb(nsuccess, nfail)
    if not opts.no_opt then
      lua_util.debugm(N, 'set last report date to %s', os.time())
      -- Hack to avoid coroutines + async functions mess: we use async redis call here
      redis_attrs.callback = function()
        logger.messagex('Reporting collection has finished %s dates processed, %s reports: %s completed, %s failed',
            ndates, nreports, nsuccess, nfail)
      end
      lua_redis.request(redis_params, redis_attrs,
          {'SETEX', 'rspamd_dmarc_last_collection', dmarc_settings.reporting.keys_expire * 2,
           tostring(os.time())})
    else
      logger.messagex('Reporting collection has finished %s dates processed, %s reports: %s completed, %s failed',
          ndates, nreports, nsuccess, nfail)
    end

    pool:destroy()
  end
  send_reports_by_smtp(opts, all_reports, finish_cb)
end

return {
  name = 'dmarc_report',
  aliases = {'dmarc_reporting'},
  handler = handler,
  description = parser._description
}