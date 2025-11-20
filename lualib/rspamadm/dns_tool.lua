--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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
local rspamd_logger = require "rspamd_logger"
local ansicolors = require "ansicolors"
local bit = require "bit"

local parser = argparse()
    :name "rspamadm dnstool"
    :description "DNS tools provided by Rspamd"
    :help_description_margin(30)
    :command_target("command")
    :require_command(true)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

local spf = parser:command "spf"
                  :description "Extracts spf records"
spf:mutex(
    spf:option "-d --domain"
       :description "Domain to use"
       :argname("<domain>"),
    spf:option "-f --from"
       :description "SMTP from to use"
       :argname("<from>")
)

spf:option "-i --ip"
   :description "Source IP address to use"
   :argname("<ip>")
spf:flag "-a --all"
   :description "Print all records"

local spf_flatten = parser:command "spf-flatten"
                          :description "Flattens SPF records by resolving all includes and optimizing"
spf_flatten:argument "domain"
           :description "Domain to flatten SPF for"
           :argname("<domain>")
spf_flatten:option "-f --format"
           :description "Output format: default, json, compact"
           :argname("<format>")
           :default("default")

local function printf(fmt, ...)
  if fmt then
    io.write(string.format(fmt, ...))
  end
  io.write('\n')
end

local function highlight(str)
  return ansicolors.white .. str .. ansicolors.reset
end

local function green(str)
  return ansicolors.green .. str .. ansicolors.reset
end

local function red(str)
  return ansicolors.red .. str .. ansicolors.reset
end

local function load_config(opts)
  local _r, err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r, err = rspamd_config:parse_rcl({ 'logging', 'worker' })
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end
end

local function spf_handler(opts)
  local rspamd_spf = require "rspamd_spf"
  local rspamd_task = require "rspamd_task"
  local rspamd_ip = require "rspamd_ip"

  local task = rspamd_task.create(rspamd_config, rspamadm_ev_base)
  task:set_session(rspamadm_session)
  task:set_resolver(rspamadm_dns_resolver)

  if opts.ip then
    opts.ip = rspamd_ip.fromstring(opts.ip)
    task:set_from_ip(opts.ip)
  else
    opts.all = true
  end

  if opts.from then
    local rspamd_parsers = require "rspamd_parsers"
    local addr_parsed = rspamd_parsers.parse_mail_address(opts.from)
    if addr_parsed then
      task:set_from('smtp', addr_parsed[1])
    else
      io.stderr:write('Invalid from addr\n')
      os.exit(1)
    end
  elseif opts.domain then
    task:set_from('smtp', { user = 'user', domain = opts.domain })
  else
    io.stderr:write('Neither domain nor from specified\n')
    os.exit(1)
  end

  local function flag_to_str(fl)
    if bit.band(fl, rspamd_spf.flags.temp_fail) ~= 0 then
      return "temporary failure"
    elseif bit.band(fl, rspamd_spf.flags.perm_fail) ~= 0 then
      return "permanent failure"
    elseif bit.band(fl, rspamd_spf.flags.na) ~= 0 then
      return "no spf record"
    end

    return "unknown flag: " .. tostring(fl)
  end

  local function display_spf_results(elt, colored)
    local dec = function(e)
      return e
    end
    local policy_decode = function(e)
      if e == rspamd_spf.policy.fail then
        return 'reject'
      elseif e == rspamd_spf.policy.pass then
        return 'pass'
      elseif e == rspamd_spf.policy.soft_fail then
        return 'soft fail'
      elseif e == rspamd_spf.policy.neutral then
        return 'neutral'
      end

      return 'unknown'
    end

    if colored then
      dec = function(e)
        return highlight(e)
      end

      if elt.result == rspamd_spf.policy.pass then
        dec = function(e)
          return green(e)
        end
      elseif elt.result == rspamd_spf.policy.fail then
        dec = function(e)
          return red(e)
        end
      end

    end
    printf('%s: %s', highlight('Policy'), dec(policy_decode(elt.result)))
    printf('%s: %s', highlight('Network'), dec(elt.addr))

    if elt.str then
      printf('%s: %s', highlight('Original'), elt.str)
    end
  end

  local function cb(record, flags, err)
    if record then
      local result, flag_or_policy, error_or_addr
      if opts.ip then
        result, flag_or_policy, error_or_addr = record:check_ip(opts.ip)
      elseif opts.all then
        result = true
      end
      if opts.ip and not opts.all then
        if result then
          display_spf_results(error_or_addr, true)
        else
          printf('Not matched: %s', error_or_addr)
        end

        os.exit(0)
      end

      if result then
        printf('SPF record for %s; digest: %s',
            highlight(opts.domain or opts.from), highlight(record:get_digest()))
        for _, elt in ipairs(record:get_elts()) do
          if result and error_or_addr and elt.str and elt.str == error_or_addr.str then
            printf("%s", highlight('*** Matched ***'))
            display_spf_results(elt, true)
            printf('------')
          else
            display_spf_results(elt, false)
            printf('------')
          end
        end
      else
        printf('Error getting SPF record: %s (%s flag)', err,
            flag_to_str(flag_or_policy or flags))
      end
    else
      printf('Cannot get SPF record: %s', err)
    end
  end
  rspamd_spf.resolve(task, cb)
end

local function spf_flatten_handler(opts)
  local rspamd_spf = require "rspamd_spf"
  local rspamd_task = require "rspamd_task"

  if not opts.domain then
    io.stderr:write('Domain is required\n')
    os.exit(1)
  end

  local task = rspamd_task.create(rspamd_config, rspamadm_ev_base)
  task:set_session(rspamadm_session)
  task:set_resolver(rspamadm_dns_resolver)
  task:set_from('smtp', { user = 'user', domain = opts.domain })

  local function has_macro(str)
    return str and str:find('%%')
  end

  local function result_to_qualifier(result)
    if result == rspamd_spf.policy.pass then
      return '+'
    elseif result == rspamd_spf.policy.fail then
      return '-'
    elseif result == rspamd_spf.policy.soft_fail then
      return '~'
    elseif result == rspamd_spf.policy.neutral then
      return '?'
    end
    return '+'
  end

  local function is_all_mechanism(str)
    return str and str:match('^[+-~?]?all$')
  end

  local function is_valid_ip_net(addr)
    if not addr or addr == '' or addr == 'any' then
      return false
    end
    return addr:match('^[0-9]') or addr:match('^[a-fA-F0-9]*:')
  end

  local function has_macro_unresolved_flag(elt)
    if not elt.flags then
      return false
    end
    local RSPAMD_SPF_FLAG_MACRO_UNRESOLVED = bit.lshift(1, 14)
    return bit.band(elt.flags, RSPAMD_SPF_FLAG_MACRO_UNRESOLVED) ~= 0
  end

  local function collect_mechanisms(elts)
    local ipv4_nets = {}
    local ipv6_nets = {}
    local dynamic_mechanisms = {}
    local other_mechanisms = {}
    local seen_all = false

    for _, elt in ipairs(elts) do
      local processed = false

      if elt.str and is_all_mechanism(elt.str) then
        local qualifier = result_to_qualifier(elt.result)
        local all_mech = (qualifier == '+' and 'all') or (qualifier .. 'all')
        table.insert(other_mechanisms, all_mech)
        seen_all = true
        processed = true
      elseif elt.str and (has_macro(elt.str) or elt.str:match('^[+-~?]?redirect')) then
        table.insert(other_mechanisms, elt.str)
        processed = true
      elseif has_macro_unresolved_flag(elt) then
        table.insert(other_mechanisms, elt.str)
        processed = true
      elseif elt.addr and not seen_all and is_valid_ip_net(elt.addr) then
        local qualifier = result_to_qualifier(elt.result)
        local net = elt.addr

        if net:find(':') then
          table.insert(ipv6_nets, { net = net, qual = qualifier })
        else
          table.insert(ipv4_nets, { net = net, qual = qualifier })
        end
        processed = true
      end

      if not processed and elt.str and not elt.str:match('^[+-~?]?include:') then
        table.insert(other_mechanisms, elt.str)
      end
    end

    return ipv4_nets, ipv6_nets, dynamic_mechanisms, other_mechanisms
  end

  local function optimize_ip_net(net, is_ipv6)
    local default_mask = is_ipv6 and '/128' or '/32'
    if net:sub(-#default_mask) == default_mask then
      return net:sub(1, -#default_mask - 1)
    end
    return net
  end

  local function build_spf_record(ipv4_nets, ipv6_nets, dynamic_mechanisms, other_mechanisms, includes)
    local parts = { 'v=spf1' }

    if includes then
      for _, inc in ipairs(includes) do
        table.insert(parts, 'include:' .. inc)
      end
    end

    for _, mech in ipairs(dynamic_mechanisms) do
      table.insert(parts, mech)
    end

    for _, item in ipairs(ipv4_nets) do
      local prefix = item.qual == '+' and '' or item.qual
      local optimized_net = optimize_ip_net(item.net, false)
      table.insert(parts, prefix .. 'ip4:' .. optimized_net)
    end

    for _, item in ipairs(ipv6_nets) do
      local prefix = item.qual == '+' and '' or item.qual
      local optimized_net = optimize_ip_net(item.net, true)
      table.insert(parts, prefix .. 'ip6:' .. optimized_net)
    end

    for _, mech in ipairs(other_mechanisms) do
      table.insert(parts, mech)
    end

    return table.concat(parts, ' ')
  end

  local function split_networks_into_chunks(ipv4_nets, ipv6_nets, base_domain, all_mechanism)
    local max_record_length = 450
    local chunks = {}
    local current_chunk_v4 = {}
    local current_chunk_v6 = {}
    local all_v4 = {}
    local all_v6 = {}

    local all_mechs = all_mechanism and {all_mechanism} or {}

    for _, item in ipairs(ipv4_nets) do
      table.insert(all_v4, item)
    end
    for _, item in ipairs(ipv6_nets) do
      table.insert(all_v6, item)
    end

    local chunk_idx = 1
    local function finalize_chunk()
      if #current_chunk_v4 > 0 or #current_chunk_v6 > 0 then
        local record = build_spf_record(current_chunk_v4, current_chunk_v6, {}, all_mechs, nil)
        table.insert(chunks, {
          name = string.format('%d._spf.%s', chunk_idx, base_domain),
          record = record
        })
        chunk_idx = chunk_idx + 1
        current_chunk_v4 = {}
        current_chunk_v6 = {}
      end
    end

    for _, item in ipairs(all_v4) do
      local single_item_test = build_spf_record({item}, {}, {}, all_mechs, nil)
      if #single_item_test > max_record_length then
        printf('Warning: IPv4 network %s is too large to fit in a single SPF record, skipping', item.net)
      else
        table.insert(current_chunk_v4, item)
        local test_record = build_spf_record(current_chunk_v4, current_chunk_v6, {}, all_mechs, nil)
        if #test_record > max_record_length then
          table.remove(current_chunk_v4)
          finalize_chunk()
          table.insert(current_chunk_v4, item)
        end
      end
    end

    for _, item in ipairs(all_v6) do
      local single_item_test = build_spf_record({}, {item}, {}, all_mechs, nil)
      if #single_item_test > max_record_length then
        printf('Warning: IPv6 network %s is too large to fit in a single SPF record, skipping', item.net)
      else
        table.insert(current_chunk_v6, item)
        local test_record = build_spf_record(current_chunk_v4, current_chunk_v6, {}, all_mechs, nil)
        if #test_record > max_record_length then
          table.remove(current_chunk_v6)
          finalize_chunk()
          table.insert(current_chunk_v6, item)
        end
      end
    end

    finalize_chunk()
    return chunks
  end

  local function cb(record, flags, err)
    if not record then
      printf('Cannot get SPF record: %s', err)
      os.exit(1)
    end

    local elts = record:get_elts()
    local ipv4_nets, ipv6_nets, dynamic_mechanisms, other_mechanisms = collect_mechanisms(elts)

    local all_mechanism = nil
    local other_without_all = {}
    for _, mech in ipairs(other_mechanisms) do
      if is_all_mechanism(mech) then
        all_mechanism = mech
      else
        table.insert(other_without_all, mech)
      end
    end

    local test_record = build_spf_record(ipv4_nets, ipv6_nets, dynamic_mechanisms, other_mechanisms, nil)
    local needs_split = #test_record > 450

    if opts.format == 'json' then
      local ucl = require "ucl"
      local result = {
        domain = opts.domain,
        ipv4_count = #ipv4_nets,
        ipv6_count = #ipv6_nets,
        dynamic_mechanisms = dynamic_mechanisms,
        other_mechanisms = other_mechanisms,
        needs_split = needs_split
      }

      if needs_split then
        local chunks = split_networks_into_chunks(ipv4_nets, ipv6_nets, opts.domain, all_mechanism)
        local include_names = {}
        for _, chunk in ipairs(chunks) do
          table.insert(include_names, chunk.name)
        end
        local main_record = build_spf_record({}, {}, dynamic_mechanisms, other_without_all, include_names)
        if all_mechanism then
          main_record = main_record .. ' ' .. all_mechanism
        end

        result.main_record = main_record
        result.additional_records = {}
        for _, chunk in ipairs(chunks) do
          table.insert(result.additional_records, {
            name = chunk.name,
            value = chunk.record
          })
        end
      else
        result.record = test_record
      end

      printf('%s', ucl.to_format(result, 'json'))
    elseif opts.format == 'compact' then
      if needs_split then
        local chunks = split_networks_into_chunks(ipv4_nets, ipv6_nets, opts.domain, all_mechanism)
        local include_names = {}
        for _, chunk in ipairs(chunks) do
          table.insert(include_names, chunk.name)
        end
        local main_record = build_spf_record({}, {}, dynamic_mechanisms, other_without_all, include_names)
        if all_mechanism then
          main_record = main_record .. ' ' .. all_mechanism
        end

        printf('%s. IN TXT "%s"', opts.domain, main_record)
        for _, chunk in ipairs(chunks) do
          printf('%s. IN TXT "%s"', chunk.name, chunk.record)
        end
      else
        printf('%s. IN TXT "%s"', opts.domain, test_record)
      end
    else
      printf('Flattened SPF record for %s:', highlight(opts.domain))
      printf('')
      printf('Found %s IPv4 networks, %s IPv6 networks, %s dynamic mechanisms, %s other mechanisms',
             highlight(tostring(#ipv4_nets)),
             highlight(tostring(#ipv6_nets)),
             highlight(tostring(#dynamic_mechanisms)),
             highlight(tostring(#other_mechanisms)))
      printf('')

      if needs_split then
        printf('%s: Needs splitting (full length: %d)', red('Result'), #test_record)
        printf('')

        local chunks = split_networks_into_chunks(ipv4_nets, ipv6_nets, opts.domain, all_mechanism)
        local include_names = {}
        for _, chunk in ipairs(chunks) do
          table.insert(include_names, chunk.name)
        end

        local main_record = build_spf_record({}, {}, dynamic_mechanisms, other_without_all, include_names)
        if all_mechanism then
          main_record = main_record .. ' ' .. all_mechanism
        end

        printf('%s:', highlight('Main record'))
        printf('%s', main_record)
        printf('')

        for _, chunk in ipairs(chunks) do
          printf('%s:', highlight('TXT record for ' .. chunk.name))
          printf('%s', chunk.record)
          printf('')
        end
      else
        printf('%s: Single record (length: %d)', green('Result'), #test_record)
        printf('')
        printf('%s', test_record)
      end
    end
  end

  rspamd_spf.resolve(task, cb)
end

local function handler(args)
  local opts = parser:parse(args)
  load_config(opts)

  local command = opts.command

  if command == 'spf' then
    spf_handler(opts)
  elseif command == 'spf-flatten' then
    spf_flatten_handler(opts)
  else
    parser:error('command %s is not implemented', command)
  end
end

return {
  name = 'dnstool',
  aliases = { 'dns', 'dns_tool' },
  handler = handler,
  description = parser._description
}
