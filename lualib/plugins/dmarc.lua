--[[
Copyright (c) 2015-2026, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

-- Common dmarc stuff
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local N = "dmarc"

local exports = {}

exports.default_settings = {
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
    report_local_controller = false, -- Store reports for local/controller scans (for testing only)
    redis_keys = {
      index_prefix = 'dmarc_idx',
      report_prefix = 'dmarc_rpt',
      join_char = ';',
    },
    helo = 'rspamd.localhost',
    smtp = '127.0.0.1',
    smtp_port = 25,
    retries = 2,
    from_name = 'Rspamd',
    msgid_from = 'rspamd',
    enabled = false,
    max_entries = 1000,
    keys_expire = 172800,
    only_domains = nil,
  },
  actions = {},
}


-- Returns a key used to be inserted into dmarc report sample
exports.dmarc_report = function(task, settings, data)
  local rspamd_lua_utils = require "lua_util"
  local E = {}

  local ip = task:get_from_ip()
  if not ip or not ip:is_valid() then
    rspamd_logger.infox(task, 'cannot store dmarc report for %s: no valid source IP',
      data.domain)
    return nil
  end

  ip = ip:to_string()

  if rspamd_lua_utils.is_rspamc_or_controller(task) and not settings.reporting.report_local_controller then
    rspamd_logger.infox(task, 'cannot store dmarc report for %s from IP %s: has come from controller/rspamc',
      data.domain, ip)
    return
  end

  local dkim_pass = table.concat(data.dkim_results.pass or E, '|')
  local dkim_fail = table.concat(data.dkim_results.fail or E, '|')
  local dkim_temperror = table.concat(data.dkim_results.temperror or E, '|')
  local dkim_permerror = table.concat(data.dkim_results.permerror or E, '|')
  local disposition_to_return = data.disposition
  local res = table.concat({
    ip, data.spf_ok, data.dkim_ok,
    disposition_to_return, (data.sampled_out and 'sampled_out' or ''), data.domain,
    dkim_pass, dkim_fail, dkim_temperror, dkim_permerror, data.spf_domain, data.spf_result }, ',')

  return res
end

exports.gen_munging_callback = function(munging_opts, settings)
  local lua_mime = require "lua_mime"
  return function(task)
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
      local s = task:get_symbol(settings.symbols.allow) or { [1] = {} }
      local sopts = s[1].options or {}

      local seen_strict
      for _, o in ipairs(sopts) do
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
      local accepted, trace = munging_opts.munge_map_condition:process(task)
      if not accepted then
        lua_util.debugm(N, task, 'skip munging, maps condition not satisfied: (%s)',
          trace)
        -- Excepted
        return
      end
    end
    -- Now, look for domain for munging
    local mr = task:get_recipients({ 'mime', 'orig' })
    local rcpt_found
    if mr then
      for _, r in ipairs(mr) do
        if r.domain and munging_opts.list_map:get_key(r.addr) then
          rcpt_found = r
          break
        end
      end
    end

    if not rcpt_found then
      lua_util.debugm(N, task, 'skip munging, recipients are not in list_map')
      -- Excepted
      return
    end

    local from = task:get_from({ 'mime', 'orig' })

    if not from or not from[1] then
      lua_util.debugm(N, task, 'skip munging, from is bad')
      -- Excepted
      return
    end

    from = from[1]
    local via_user = rcpt_found.user
    local via_addr = rcpt_found.addr
    local via_name

    if from.name == "" then
      via_name = string.format('%s via %s', from.user or 'unknown', via_user)
    else
      via_name = string.format('%s via %s', from.name, via_user)
    end

    local via_from_folded = lua_util.fold_header_with_encoding(task, 'From',
      string.format('%s <%s>', via_name, via_addr), { structured = true })
    local orig_from_folded = lua_util.fold_header_with_encoding(task, 'X-Original-From',
      string.format('%s <%s>', from.name or '', from.addr), { structured = true })
    local add_hdrs = {
      ['From'] = { order = 1, value = via_from_folded },
      ['X-Original-From'] = { order = 0, value = orig_from_folded },
    }
    local remove_hdrs = { ['From'] = 0 }

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

    add_hdrs['Reply-To'] = { order = 0, value = nreply }

    lua_mime.modify_headers(task, {
      remove = remove_hdrs,
      add = add_hdrs
    })
    lua_util.debugm(N, task, 'munged DMARC header for %s: %s -> %s',
      from.domain, via_from_folded, from.addr)
    rspamd_logger.infox(task, 'munged DMARC header for %s', from.addr)
    task:insert_result('DMARC_MUNGED', 1.0, from.addr)
  end
end

-- The longest `rua` of a record that is used: a few addresses fit, and what
-- is longer is not kept in the storage of reports for every message
local max_rua_length = 1024

-- Reads a record into its tags.
--
-- A record is `v=DMARC1` followed by tags separated by semicolons. What a
-- record publishes must not depend on a tag that this code does not know or
-- cannot read: such a tag is passed over and the ones after it are still
-- read (RFC 7489, 6.3: unknown tags are ignored). White space is allowed
-- around the name, the equals sign and the value. A tag given twice has no
-- defined meaning; the first one is taken, so that the result does not
-- depend on the order in which a table is walked. Names are compared without
-- regard to the case, and the values are lowered as well.
--
-- Returns nil if this is not a DMARC record at all.
local function dmarc_parse_record(record)
  if type(record) ~= 'string' then
    return nil
  end

  local rest = record:match('^%s*[vV]%s*=%s*DMARC1%s*(.*)$')

  if not rest then
    return nil
  end

  if #rest > 0 then
    -- The version is a tag as any other: a separator follows it. A backslash
    -- is taken for one too, as it has always been here
    if not rest:find('^[;\\]') then
      return nil
    end
  end

  local elts = {}

  for part in rest:gmatch('[^;\\]+') do
    local key, value = part:match('^%s*([%w_%-]+)%s*=%s*(.-)%s*$')

    if key and #value > 0 then
      key = key:lower()

      if elts[key] == nil then
        elts[key] = value:lower()
      end
    end
  end

  return elts
end

--[[
-- Used to check dmarc record, check elements and produce dmarc policy processed
-- result.
-- Returns:
--     false,false - record is garbage
--     false,error_message - record is invalid
--     true,policy_table - record is valid and parsed
]]
local function dmarc_check_record(log_obj, record, is_tld)
  local failed_policy
  local result = {
    dmarc_policy = 'none'
  }

  local elts = dmarc_parse_record(record)
  lua_util.debugm(N, log_obj, "got DMARC record: %s, tld_flag=%s, processed=%s",
    record, is_tld, elts)

  if elts then

    local dkim_pol = elts['adkim']
    if dkim_pol then
      if dkim_pol == 's' then
        result.strict_dkim = true
      elseif dkim_pol ~= 'r' then
        failed_policy = 'adkim tag has invalid value: ' .. dkim_pol
        return false, failed_policy
      end
    end

    local spf_pol = elts['aspf']
    if spf_pol then
      if spf_pol == 's' then
        result.strict_spf = true
      elseif spf_pol ~= 'r' then
        failed_policy = 'aspf tag has invalid value: ' .. spf_pol
        return false, failed_policy
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
        return false, failed_policy
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
        return false, failed_policy
      end
    end
    -- A percentage is a whole number from 0 to 100; anything else is not a
    -- value of the tag, and the default of 100 stands
    local pct = elts['pct']
    if pct and pct:find('^%d%d?%d?$') then
      pct = tonumber(pct)
      if pct <= 100 then
        result.pct = pct
      end
    end

    -- Where the reports go. This string is stored and used as a part of a
    -- key, so it is bounded and has no control characters in it
    local rua = elts['rua']
    if rua and #rua <= max_rua_length and not rua:find('%c') then
      result.rua = rua
    end
    result.raw_elts = elts
  else
    return false, false -- Ignore garbage
  end

  return true, result
end

exports.dmarc_check_record = dmarc_check_record

return exports
