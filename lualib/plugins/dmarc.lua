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

-- Common dmarc stuff
local rspamd_logger = require "rspamd_logger"
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
    enabled = false,
    max_entries = 1000,
    keys_expire = 172800,
    only_domains = nil,
  },
  actions = {},
}


-- Returns a key used to be inserted into dmarc report sample
exports.dmarc_report = function (task, settings, data)
  local rspamd_lua_utils = require "lua_util"
  local E = {}

  local ip = task:get_from_ip()
  if ip and not ip:is_valid() then
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
    dkim_pass, dkim_fail, dkim_temperror, dkim_permerror, data.spf_domain, data.spf_result}, ',')

  return res
end


exports.gen_munging_callback = function(munging_opts, settings)
  local lua_util = require "lua_util"
  local rspamd_util = require "rspamd_util"
  local lua_mime = require "lua_mime"
  return function (task)
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
end

return exports