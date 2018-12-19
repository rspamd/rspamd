--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2013-2015, Andrew Lewis <nerf@judo.za.org>

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

if confighelp then
  return
end

local hash = require 'rspamd_cryptobox_hash'
local rspamd_logger = require 'rspamd_logger'
local rspamd_util = require 'rspamd_util'
local fun = require 'fun'
local lua_util = require 'lua_util'
local ts = require("tableshape").types

-- This plugin implements various types of RBL checks
-- Documentation can be found here:
-- https://rspamd.com/doc/modules/rbl.html

local E = {}
local N = 'rbl'

local local_exclusions

local default_monitored = '1.0.0.127'

local function validate_dns(lstr)
  if lstr:match('%.%.') then
    -- two dots in a row
    return false
  end
  for v in lstr:gmatch('[^%.]+') do
    if not v:match('^[%w-]+$') or v:len() > 63
      or v:match('^-') or v:match('-$') then
      -- too long label or weird labels
      return false
    end
  end
  return true
end

local function maybe_make_hash(data, rule)
  if rule.hash then
    local h = hash.create_specific(rule.hash, data)
    local s
    if rule.hash_format then
      if rule.hash_format == 'base32' then
        s = h:base32()
      elseif rule.hash_format == 'base64' then
        s = h:base64()
      else
        s = h:hex()
      end
    else
      s = h:hex()
    end

    if rule.hash_len then
      s = s:sub(1, rule.hash_len)
    end

    return s
  else
    return data
  end
end

local function is_excluded_ip(rip)
  if local_exclusions and local_exclusions:get_key(rip) then
    return true
  end
  return false
end

local function ip_to_rbl(ip)
  return table.concat(ip:inversed_str_octets(), '.')
end

local function gen_check_rcvd_conditions(rbl, received_total)
  local min_pos = tonumber(rbl['received_min_pos'])
  local max_pos = tonumber(rbl['received_max_pos'])
  local match_flags = rbl['received_flags']
  local nmatch_flags = rbl['received_nflags']
  local function basic_received_check(rh)
    if not (rh['real_ip'] and rh['real_ip']:is_valid()) then return false end
    if ((rh['real_ip']:get_version() == 6 and rbl['ipv6']) or
      (rh['real_ip']:get_version() == 4 and rbl['ipv4'])) and
      ((rbl['exclude_private_ips'] and not rh['real_ip']:is_local()) or
      not rbl['exclude_private_ips']) and ((rbl['exclude_local_ips'] and
      not is_excluded_ip(rh['real_ip'])) or not rbl['exclude_local_ips']) then
        return true
    else
      return false
    end
  end
  if not (max_pos or min_pos or match_flags or nmatch_flags) then
    return basic_received_check
  end
  return function(rh, pos)
    if not basic_received_check() then return false end
    local got_flags = rh['flags'] or E
    if min_pos then
      if min_pos < 0 then
        if min_pos == -1 then
          if (pos ~= received_total) then
            return false
          end
        else
          if pos <= (received_total - (min_pos*-1)) then
            return false
          end
        end
      elseif pos < min_pos then
        return false
      end
    end
    if max_pos then
      if max_pos < -1 then
        if (received_total - (max_pos*-1)) >= pos then
          return false
        end
      elseif max_pos > 0 then
        if pos > max_pos then
          return false
        end
      end
    end
    if match_flags then
      for _, flag in ipairs(match_flags) do
        if not got_flags[flag] then
          return false
        end
      end
    end
    if nmatch_flags then
      for _, flag in ipairs(nmatch_flags) do
        if got_flags[flag] then
          return false
        end
      end
    end
    return true
  end
end

local function rbl_dns_process(task, rbl, to_resolve, results, err)
  if err and (err ~= 'requested record is not found' and
      err ~= 'no records with this name') then
    rspamd_logger.errx(task, 'error looking up %s: %s', to_resolve, err)
  end
  if not results then
    lua_util.debugm(N, task,
        'DNS RESPONSE: label=%1 results=%2 error=%3 rbl=%4',
        to_resolve, false, err, rbl.symbol)
    return
  else
    lua_util.debugm(N, task,
        'DNS RESPONSE: label=%1 results=%2 error=%3 rbl=%4',
        to_resolve, true, err, rbl.symbol)
  end

  if rbl.returncodes == nil and rbl.symbol ~= nil then
    task:insert_result(rbl.symbol, 1, to_resolve)
    return
  end

  for _,result in ipairs(results) do
    local ipstr = result:to_string()
    lua_util.debugm(N, task, '%s DNS result %s', to_resolve, ipstr)
    local foundrc = false
    -- Check return codes
    for s,i in pairs(rbl.returncodes) do
      for _,v in ipairs(i) do
        if string.find(ipstr, '^' .. v .. '$') then
          foundrc = true
          task:insert_result(s, 1, to_resolve .. ' : ' .. ipstr)
          break
        end
      end
    end
    if not foundrc then
      if rbl.unknown and rbl.symbol then
        task:insert_result(rbl.symbol, 1, to_resolve)
      else
        rspamd_logger.errx(task, 'RBL %1 returned unknown result: %2',
            rbl.rbl, ipstr)
      end
    end
  end
end

local function gen_rbl_callback(rule)
  -- Here, we have functional approach: we form a pipeline of functions
  -- f1, f2, ... fn. Each function accepts task and return boolean value
  -- that allows to process pipeline further
  -- Each function in the pipeline can add something to `dns_req` vector as a side effect

  local function add_dns_request(req, forced, requests_table)
    if requests_table[req] then
      -- Duplicate request
      if forced and not requests_table[req].forced then
        requests_table[req].forced = true
      end
    else
      local nreq = {
        forced = forced,
        n = string.format('%s.%s',
            maybe_make_hash(req, rule),
            rule.rbl)
      }
      requests_table[req] = nreq
    end
  end

  local function is_alive(_, _)
    if rule.monitored then
      if not rule.monitored:alive() then
        return false
      end
    end

    return true
  end

  local function check_user(task, _)
    if task:get_user() then
      return false
    end

    return true
  end

  local function check_local(task, _)
    local ip = task:get_from_ip()

    if not ip:is_valid() then
      ip = nil
    end

    if ip and ip:is_local() or is_excluded_ip(ip) then
      return false
    end

    return true
  end

  local function check_helo(task, requests_table)
    local helo = task:get_helo()

    if not helo then
      return false
    end

    add_dns_request(helo, true, requests_table)
  end

  local function check_dkim(task, requests_table)
    local das = task:get_symbol('DKIM_TRACE')
    local mime_from_domain
    local ret = false

    if das and das[1] and das[1].options then

      if rule.dkim_match_from then
        -- We check merely mime from
        mime_from_domain = ((task:get_from('mime') or E)[1] or E).domain
        if mime_from_domain then
          mime_from_domain = rspamd_util.get_tld(mime_from_domain)
        end
      end

      for _, d in ipairs(das[1].options) do

        local domain,result = d:match('^([^%:]*):([%+%-%~])$')

        -- We must ignore bad signatures, omg
        if domain and result and result == '+' then
          if rule.dkim_match_from then
            -- We check merely mime from
            local domain_tld = domain
            if not rule.dkim_domainonly then
              -- Adjust
              domain_tld = rspamd_util.get_tld(domain)
            end

            if mime_from_domain and mime_from_domain == domain_tld then
              add_dns_request(domain_tld, true, requests_table)
              ret = true
            end
          else
            if rule.dkim_domainonly then
              add_dns_request(rspamd_util.get_tld(domain), false, requests_table)
              ret = true
            else
              add_dns_request(domain, false, requests_table)
              ret = true
            end
          end
        end
      end
    end

    return ret
  end

  local function check_emails(task, requests_table)
    local emails = task:get_emails()

    if not emails then
      return false
    end

    for _,email in ipairs(emails) do
      if rule.emails_domainonly then
        add_dns_request(email:get_tld(), false, requests_table)
      else
        if rule.hash then
          -- Leave @ as is
          add_dns_request(string.format('%s@%s',
              email:get_user(), email:get_domain()), false, requests_table)
        else
          -- Replace @ with .
          add_dns_request(string.format('%s.%s',
              email:get_user(), email:get_domain()), false, requests_table)
        end
      end
    end

    return true
  end

  local function check_from(task, requests_table)
    local ip = task:get_from_ip()

    if not ip or not ip:is_valid() then
      return true
    end
    if (ip:get_version() == 6 and rule.ipv6) or
        (ip:get_version() == 4 and rule.ipv4) then
      add_dns_request(ip_to_rbl(ip), true, requests_table)
    end

    return true
  end

  local function check_received(task, requests_table)
    local received = fun.filter(function(h)
      return not h['flags']['artificial']
    end, task:get_received_headers()):totable()

    local received_total = #received
    local check_conditions = gen_check_rcvd_conditions(rule, received_total)

    for pos,rh in ipairs(received) do
      if check_conditions(rh, pos) then
        add_dns_request(ip_to_rbl(rh.real_ip), false, requests_table)
      end
    end

    return true
  end

  local function check_rdns(task, requests_table)
    local hostname = task:get_hostname()
    if hostname == nil or hostname == 'unknown' then
      return false
    end

    add_dns_request(hostname, true, requests_table)

    return true
  end

  -- Create function pipeline depending on rbl settings
  local pipeline = {
    is_alive, -- generic for all
  }

  if rule.exclude_users then
    pipeline[#pipeline + 1] = check_user
  end

  if rule.exclude_local or rule.exclude_private_ips then
    pipeline[#pipeline + 1] = check_local
  end

  if rule.helo then
    pipeline[#pipeline + 1] = check_helo
  end

  if rule.dkim then
    pipeline[#pipeline + 1] = check_dkim
  end

  if rule.emails then
    pipeline[#pipeline + 1] = check_emails
  end

  if rule.from then
    pipeline[#pipeline + 1] = check_from
  end

  if rule.received then
    pipeline[#pipeline + 1] = check_received
  end

  if rule.rdns then
    pipeline[#pipeline + 1] = check_rdns
  end

  return function(task)
    -- DNS requests to issue (might be hashed afterwards)
    local dns_req = {}

    local function rbl_dns_callback(_, to_resolve, results, err)
      rbl_dns_process(task, rule, to_resolve, results, err)
    end

    -- Execute functions pipeline
    for _,f in ipairs(pipeline) do
      if not f(task, dns_req) then
        lua_util.debugm(N, task, "skip rbl check: %s; pipeline condition returned false",
            rule.symbol)
        return
      end
    end

    -- Now check all DNS requests pending and emit them
    local r = task:get_resolver()
    for name,p in pairs(dns_req) do
      if validate_dns(p.n) then
        lua_util.debugm(N, task, "rbl %s; resolve %s -> %s",
            rule.symbol, name, p.n)
        r:resolve_a({
          task = task,
          name = p.n,
          callback = rbl_dns_callback,
          forced = p.forced
        })
      else
        rspamd_logger.warnx(task, 'cannot send invalid DNS request %s for %s',
            p.n, rule.symbol)
      end
    end
  end
end

-- Configuration
local opts = rspamd_config:get_all_opt(N)
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  lua_util.disable_module(N, "config")
  return
end

-- Plugin defaults should not be changed - override these in config
-- New defaults should not alter behaviour
local default_defaults = {
  ['default_enabled'] = true,
  ['default_ipv4'] = true,
  ['default_ipv6'] = true,
  ['default_received'] = false,
  ['default_from'] = true,
  ['default_unknown'] = false,
  ['default_rdns'] = false,
  ['default_helo'] = false,
  ['default_dkim'] = false,
  ['default_dkim_domainonly'] = true,
  ['default_emails'] = false,
  ['default_emails_domainonly'] = false,
  ['default_exclude_private_ips'] = true,
  ['default_exclude_users'] = false,
  ['default_exclude_local'] = true,
  ['default_is_whitelist'] = false,
  ['default_ignore_whitelist'] = false,
}
-- Enrich with defaults
for default, default_v in pairs(default_defaults) do
  if opts[default] == nil then
    opts[default] = default_v
  end
end

if(opts['local_exclude_ip_map'] ~= nil) then
  local_exclusions = rspamd_map_add(N, 'local_exclude_ip_map', 'radix',
    'RBL exclusions map')
end

local white_symbols = {}
local black_symbols = {}

local rule_schema = ts.shape({
  enabled = ts.boolean:is_optional(),
  disabled = ts.boolean:is_optional(),
  rbl = ts.string,
  symbol = ts.string:is_optional(),
  returncodes = ts.map_of(
      ts.string / string.upper,
      (
          ts.array_of(ts.string) + (ts.string / function(s)
            return { s }
          end)
      )
  ):is_optional(),
  whitelist_exception = (
      ts.array_of(ts.string) + (ts.string / function(s) return {s} end)
  ):is_optional(),
  local_exclude_ip_map = ts.string:is_optional(),
  hash = ts.one_of{"sha1", "sha256", "sha384", "sha512", "md5", "blake2"}:is_optional(),
  hash_format = ts.one_of{"hex", "base32", "base64"}:is_optional(),
  hash_len = (ts.integer + ts.string / tonumber):is_optional(),
}, {
  extra_fields = ts.map_of(ts.string, ts.boolean)
})


local monitored_addresses = {}

local function add_rbl(key, rbl)
  if not rbl.symbol then
    rbl.symbol = key:upper()
  end

  local flags_tbl = {'no_squeeze'}
  if rbl.is_whitelist then
    flags_tbl[#flags_tbl + 1] = 'nice'
  end

  if not (rbl.dkim or rbl.emails) then
    flags_tbl[#flags_tbl + 1] = 'empty'
  end

  local id = rspamd_config:register_symbol{
    type = 'callback',
    callback = gen_rbl_callback(rbl),
    name = rbl.symbol,
    flags = table.concat(flags_tbl, ',')
  }

  if rbl.dkim then
    rspamd_config:register_dependency(rbl.symbol, 'DKIM_CHECK')
  end

  if rbl.returncodes then
    for s,_ in pairs(rbl['returncodes']) do
      rspamd_config:register_symbol({
        name = s,
        parent = id,
        type = 'virtual'
      })

      if rbl.is_whitelist then
        if rbl.whitelist_exception then
          local foundException = false
          for _, e in ipairs(rbl.whitelist_exception) do
            if e == s then
              foundException = true
              break
            end
          end
          if not foundException then
            table.insert(white_symbols, s)
          end
        else
          table.insert(white_symbols, s)
        end
      else
        if rbl.ignore_whitelist == false then
          table.insert(black_symbols, s)
        end
      end
    end
  end

  if not rbl.is_whitelist and rbl.ignore_whitelist == false then
    table.insert(black_symbols, rbl.symbol)
  end
  -- Process monitored
  if not rbl.disable_monitoring and not rbl.is_whitelist then
    if not monitored_addresses[rbl.rbl] then
      monitored_addresses[rbl.rbl] = true
      rbl.monitored = rspamd_config:register_monitored(rbl['rbl'], 'dns',
          {
            rcode = 'nxdomain',
            prefix = rbl.monitored_address or default_monitored
          })
    end
  end
end

for key,rbl in pairs(opts.rbls or opts.rules) do
  if type(rbl) ~= 'table' or rbl.disabled == true or rbl.enabled == false then
    rspamd_logger.infox(rspamd_config, 'disable rbl "%s"', key)
  else
    for default,_ in pairs(default_defaults) do
      local rbl_opt = default:sub(#('default_') + 1)
      if rbl[rbl_opt] == nil then
        rbl[rbl_opt] = opts[default]
      end
    end

    local res,err = rule_schema:transform(rbl)
    if not res then
      rspamd_logger.errx(rspamd_config, 'invalid config for %s: %s, RBL is DISABLED',
          key, err)
    else
      add_rbl(key, res)
    end
  end -- rbl.enabled
end

-- We now create two symbols:
-- * RBL_CALLBACK_WHITE that depends on all symbols white
-- * RBL_CALLBACK that depends on all symbols black to participate in depends chains

local function rbl_callback_white(task)
  local found_whitelist = false
  for _, w in ipairs(white_symbols) do
    if task:has_symbol(w) then
      lua_util.debugm(N, task,'found whitelist %s', w)
      found_whitelist = true
      break
    end
  end

  if found_whitelist then
    -- Disable all symbols black
    for _, b in ipairs(black_symbols) do
      lua_util.debugm(N, task,'disable %s, whitelist found', b)
      task:disable_symbol(b)
    end
  end
  lua_util.debugm(N, task, "finished rbl whitelists processing")
end

local function rbl_callback_fin(task)
  -- Do nothing
  lua_util.debugm(N, task, "finished rbl processing")
end

rspamd_config:register_symbol{
  type = 'callback',
  callback = rbl_callback_white,
  name = 'RBL_CALLBACK_WHITE',
  flags = 'nice,empty,no_squeeze'
}

rspamd_config:register_symbol{
  type = 'callback',
  callback = rbl_callback_fin,
  name = 'RBL_CALLBACK',
  flags = 'empty,no_squeeze'
}

for _, w in ipairs(white_symbols) do
  rspamd_config:register_dependency('RBL_CALLBACK_WHITE', w)
end

for _, b in ipairs(black_symbols) do
  rspamd_config:register_dependency(b, 'RBL_CALLBACK_WHITE')
  rspamd_config:register_dependency('RBL_CALLBACK', b)
end
