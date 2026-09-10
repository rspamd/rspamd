--[[
Copyright (c) 2013-2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- Load RBL common module early to register schema for confighelp
local rbl_common = require "plugins/rbl"

if confighelp then
  return
end

local hash = require 'rspamd_cryptobox_hash'
local rspamd_logger = require 'rspamd_logger'
local rspamd_util = require 'rspamd_util'
local rspamd_ip = require "rspamd_ip"
local fun = require 'fun'
local lua_util = require 'lua_util'
local selectors = require "lua_selectors"
local bit = require 'bit'
local lua_maps = require "lua_maps"
local rspamd_url = require "rspamd_url"

-- This plugin implements various types of RBL checks
-- Documentation can be found here:
-- https://rspamd.com/doc/modules/rbl.html

local E = {}
local N = 'rbl'

-- Checks that could be performed by rbl module
local local_exclusions
local disabled_rbl_suffixes -- Map of disabled rbl suffixes
local white_symbols = {}
local black_symbols = {}
local monitored_addresses = {}
local known_selectors = {} -- map from selector string to selector id
local url_flag_bits = rspamd_url.flags

local function get_monitored(rbl)
  local function is_random_monitored()
    -- Explicit definition
    if type(rbl.random_monitored) == 'boolean' then
      return rbl.random_monitored
    end

    -- We check 127.0.0.1 for merely RBLs with `from` or `received` and only if
    -- they don't have `no_ip` attribute at the same time
    --
    -- Convert to a boolean variable using the common idiom
    return (not (rbl.from or rbl.received)
        or rbl.no_ip)
        and true or false
  end

  local default_monitored = '1.0.0.127'
  local ret = {
    rcode = 'nxdomain',
    prefix = default_monitored,
    random = is_random_monitored(),
  }

  if rbl.monitored_address then
    ret.prefix = rbl.monitored_address
  end

  lua_util.debugm(N, rspamd_config,
      'added monitored address: %s (%s random)',
      ret.prefix, ret.random)

  return ret
end

local function validate_dns(lstr)
  if lstr:match('%.%.') then
    -- two dots in a row
    return false, "two dots in a row"
  end
  if not rspamd_util.is_valid_utf8(lstr) then
    -- invalid utf8 detected
    return false, "invalid utf8"
  end
  for v in lstr:gmatch('[^%.]+') do
    if v:len() > 63 then
      -- too long label
      return false, "too long label"
    end
    if v:match('^-') or v:match('-$') then
      -- dash at the beginning or end of label
      return false, "dash at the beginning or end of label"
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
  local min_pos = tonumber(rbl.received_min_pos)
  local max_pos = tonumber(rbl.received_max_pos)
  local match_flags = rbl.received_flags
  local nmatch_flags = rbl.received_nflags

  local function basic_received_check(rh)
    if not (rh.real_ip and rh.real_ip:is_valid()) then
      return false
    end
    if ((rh.real_ip:get_version() == 6 and rbl.ipv6) or
        (rh.real_ip:get_version() == 4 and rbl.ipv4)) and
        ((rbl.exclude_local and not rh.real_ip:is_local() or is_excluded_ip(rh.real_ip)) or not rbl.exclude_local) then
      return true
    else
      return false
    end
  end

  local function positioned_received_check(rh, pos)
    if not rh or not basic_received_check(rh) then
      return false
    end
    local got_flags = rh.flags or E
    if min_pos then
      if min_pos < 0 then
        if min_pos == -1 then
          if (pos ~= received_total) then
            return false
          end
        else
          if pos <= (received_total - math.abs(min_pos)) then
            return false
          end
        end
      elseif pos < min_pos then
        return false
      end
    end
    if max_pos then
      if max_pos < -1 then
        if (received_total - math.abs(max_pos)) >= pos then
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

  if not (max_pos or min_pos or match_flags or nmatch_flags) then
    return basic_received_check
  else
    return positioned_received_check
  end
end

local matchers = {}

matchers.radix = function(_, _, real_ip, map)
  return map and map:get_key(real_ip) or false
end

matchers.equality = function(codes, to_match)
  if type(codes) ~= 'table' then
    return codes == to_match
  end
  for _, ip in ipairs(codes) do
    if to_match == ip then
      return true
    end
  end
  return false
end

matchers.luapattern = function(codes, to_match)
  if type(codes) ~= 'table' then
    return string.find(to_match, '^' .. codes .. '$') and true or false
  end
  for _, pattern in ipairs(codes) do
    if string.find(to_match, '^' .. pattern .. '$') then
      return true
    end
  end
  return false
end

matchers.regexp = function(_, to_match, _, map)
  return map and map:get_key(to_match) or false
end

matchers.glob = function(_, to_match, _, map)
  return map and map:get_key(to_match) or false
end

local function rbl_dns_process(task, rbl, to_resolve, results, err, resolve_table_elt, match)
  local function make_option(origin, ip, label)
    if ip then
      return string.format('%s:%s:%s',
          origin,
          label,
          ip)
    else
      return string.format('%s:%s',
          origin,
          label)
    end
  end

  -- merge_checks false restores the pre-4.1.6 one-insertion-per-check behavior
  local merge_checks = rbl.merge_checks ~= false

  local function insert_results(s, ip)
    -- Only the first insertion of a symbol carries score; later spellings just add options
    local scored_symbols = {}

    local function insert_origin_labels(sym_name, origin, labels)
      table.sort(labels)

      if merge_checks then
        local weight = scored_symbols[sym_name] and 0.0 or 1.0
        scored_symbols[sym_name] = true
        task:insert_result(sym_name, weight,
            make_option(origin, ip, table.concat(labels, ',')))
      else
        for _, label in ipairs(labels) do
          task:insert_result(sym_name, 1.0, make_option(origin, ip, label))
        end
      end
    end

    for origin, origin_labels in pairs(resolve_table_elt.origins) do
      if rbl.symbols_prefixes then
        local by_prefix = {}
        for label in pairs(origin_labels) do
          local prefix = rbl.symbols_prefixes[label]
          local sym_name
          if not prefix then
            rspamd_logger.warnx(task, 'unlisted symbol prefix for %s', label)
            sym_name = s
          else
            sym_name = prefix .. '_' .. s
          end
          if not by_prefix[sym_name] then
            by_prefix[sym_name] = {}
          end
          by_prefix[sym_name][#by_prefix[sym_name] + 1] = tostring(label)
        end
        for sym_name, labels in pairs(by_prefix) do
          insert_origin_labels(sym_name, origin, labels)
        end
      else
        local labels = {}
        for label in pairs(origin_labels) do
          labels[#labels + 1] = tostring(label)
        end
        insert_origin_labels(s, origin, labels)
      end
    end
  end

  if err and (err ~= 'requested record is not found' and
      err ~= 'no records with this name') then
    rspamd_logger.infox(task, 'error looking up %s: %s', to_resolve, err)
    -- Report every merged origin, but only the first insertion carries weight
    local failed_origins = lua_util.keys(resolve_table_elt.origins)
    table.sort(failed_origins)
    for i, origin in ipairs(failed_origins) do
      task:insert_result(rbl.symbol .. '_FAIL', i == 1 and 1.0 or 0.0,
          string.format('%s:%s', origin, err))
    end
    return
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

  if rbl.returncodes == nil and rbl.returnbits == nil and rbl.symbol ~= nil then
    insert_results(rbl.symbol)
    return
  end

  local returncodes_maps = rbl.returncodes_maps or {}

  for _, result in ipairs(results) do
    local ipstr = result:to_string()
    lua_util.debugm(N, task, '%s DNS result %s', to_resolve, ipstr)
    local foundrc = false
    -- Check return codes
    if rbl.returnbits then
      local ipnum = result:to_number()
      for s, bits in pairs(rbl.returnbits) do
        for _, check_bit in ipairs(bits) do
          if bit.band(ipnum, check_bit) == check_bit then
            foundrc = true
            insert_results(s)
            -- Here, we continue with other bits
          end
        end
      end
    elseif rbl.returncodes then
      for s, codes in pairs(rbl.returncodes) do
        local res = match(codes, ipstr, result, returncodes_maps[s])
        if res then
          foundrc = true
          insert_results(s)
        end
      end
    end

    if not foundrc then
      if rbl.unknown and rbl.symbol then
        insert_results(rbl.symbol, ipstr)
      else
        lua_util.debugm(N, task, '%1 returned unknown result: %2',
            to_resolve, ipstr)
      end
    end
  end

end

local function gen_rbl_callback(rule)
  local function is_whitelisted(task, req, req_str, whitelist, what)
    if rule.ignore_whitelist then
      lua_util.debugm(N, task,
          'ignore whitelisting checks to %s by %s: ignore whitelist is being set',
          req_str, rule.symbol)
      return false
    end

    if rule.whitelist then
      if rule.whitelist:get_key(req) then
        lua_util.debugm(N, task,
            'whitelisted %s on %s',
            req_str, rule.symbol)

        return true
      end
    end

    -- Maybe whitelisted by some other rbl rule
    if whitelist then
      local wl = whitelist[req_str]
      if wl then
        for _, wl_entry in ipairs(wl) do
          lua_util.debugm(N, task,
              'whitelisted request to %s by %s (%s) rbl rule (%s checked type, %s whitelist type)',
              req_str, wl_entry.type, wl_entry.symbol, what, wl_entry.type)
          if wl_entry.type == what then
            -- This was decided to be a bad idea as in case of whitelisting a request to blacklist
            -- is not even sent
            --task:adjust_result(wl_entry.symbol, 0.0 / 0.0, rule.symbol)

            return true
          end
        end
      end
    end

    return false
  end

  local function add_dns_request(task, req, forced, is_ip, requests_table, label, whitelist)
    -- Discard empty queries to avoid querying the RBL suffix itself
    if not is_ip and (not req or req == '') then
      lua_util.debugm(N, task, 'skip empty RBL request for %s (%s)',
          rule.symbol, label)
      return
    end

    local req_str = tostring(req)

    if whitelist and is_whitelisted(task, req, req_str, whitelist, label) then
      return
    end

    if is_ip then
      req = ip_to_rbl(req)
    end

    if requests_table[req] then
      -- Duplicate request
      local nreq = requests_table[req]
      if forced and not nreq.forced then
        nreq.forced = true
      end
      if not nreq.what[label] then
        nreq.what[label] = true
        lua_util.debugm(N, task, 'merging duplicate RBL request for %s: %s (%s added to %s)',
            rule.symbol, req_str, label,
            table.concat(lua_util.keys(nreq.what), ','))
      end
      if not nreq.origins[req_str] then
        nreq.origins[req_str] = {}
      end
      nreq.origins[req_str][label] = true

      return true, nreq -- Duplicate
    else
      local nreq

      local resolve_ip = rule.resolve_ip and not is_ip
      if rule.process_script then
        local processed = rule.process_script(req, rule.rbl, task, resolve_ip)

        if processed then
          nreq = {
            forced = forced,
            n = tostring(processed):lower(),
            orig = req_str,
            resolve_ip = resolve_ip,
            what = { [label] = true },
            origins = { [req_str] = { [label] = true } },
          }
          requests_table[req] = nreq
        end
      else
        local to_resolve
        -- Strip trailing dots first so hashing treats "foo." and "foo" alike
        local origin = tostring(req):gsub('%.+$', '')

        if not resolve_ip then
          origin = maybe_make_hash(origin, rule)
          to_resolve = string.format('%s.%s',
              origin,
              rule.rbl)
        else
          -- First, resolve origin stuff without hashing or anything
          to_resolve = origin
        end
        to_resolve = to_resolve:lower()

        nreq = {
          forced = forced,
          n = to_resolve,
          orig = req_str,
          resolve_ip = resolve_ip,
          what = { [label] = true },
          origins = { [req_str] = { [label] = true } },
        }
        requests_table[req] = nreq
      end
      return false, nreq
    end
  end

  -- Here, we have functional approach: we form a pipeline of functions
  -- f1, f2, ... fn. Each function accepts task and return boolean value
  -- that allows to process pipeline further
  -- Each function in the pipeline can add something to `dns_req` vector as a side effect
  local function is_alive(_, _)
    if rule.monitored then
      if not rule.monitored:alive() then
        return false
      end
    end

    return true
  end

  local function is_allowed(task, _)
    if disabled_rbl_suffixes then
      if disabled_rbl_suffixes:get_key(rule.rbl) then
        lua_util.debugm(N, task, 'skip rbl check: %s; disabled by suffix', rule.rbl)
        return false
      end
    end

    return true
  end

  local function check_required_symbols(task, _)
    if rule.require_symbols then
      return fun.all(function(sym)
        task:has_symbol(sym)
      end, rule.require_symbols)
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

    if ip and not ip:is_valid() then
      ip = nil
    end

    if ip and ip:is_local() or is_excluded_ip(ip) then
      return false
    end

    return true
  end

  local function check_helo(task, requests_table, whitelist)
    local helo = task:get_helo()

    if not helo then
      -- Avoid pipeline breaking
      return true
    end

    add_dns_request(task, helo, true, false, requests_table,
        'helo', whitelist)

    return true
  end

  local function check_dkim(task, requests_table, whitelist)
    local das = task:get_symbol('DKIM_TRACE')
    local mime_from_domain

    if das and das[1] and das[1].options then

      if rule.dkim_match_from then
        -- We check merely mime from
        mime_from_domain = ((task:get_from('mime') or E)[1] or E).domain
        if mime_from_domain then
          local mime_from_domain_tld = rule.url_full_hostname and
              mime_from_domain or rspamd_util.get_tld(mime_from_domain)

          if rule.url_compose_map then
            mime_from_domain = rule.url_compose_map:process_url(task, mime_from_domain_tld, mime_from_domain)
          else
            mime_from_domain = mime_from_domain_tld
          end
        end
      end

      for _, d in ipairs(das[1].options) do

        local domain, result = d:match('^([^%:]*):([%+%-%~])$')

        -- We must ignore bad signatures, omg
        if domain and result and result == '+' then
          if rule.dkim_match_from then
            -- We check merely mime from
            local domain_tld = domain
            if not rule.dkim_domainonly then
              -- Adjust
              domain_tld = rspamd_util.get_tld(domain)

              if rule.url_compose_map then
                domain_tld = rule.url_compose_map:process_url(task, domain_tld, domain)
              elseif rule.url_full_hostname then
                domain_tld = domain
              end
            end

            if mime_from_domain and mime_from_domain == domain_tld then
              add_dns_request(task, domain_tld, true, false, requests_table,
                  'dkim', whitelist)
            end
          else
            if rule.dkim_domainonly then
              local domain_tld = rspamd_util.get_tld(domain)
              if rule.url_compose_map then
                domain_tld = rule.url_compose_map:process_url(task, domain_tld, domain)
              elseif rule.url_full_hostname then
                domain_tld = domain
              end
              add_dns_request(task, domain_tld,
                  false, false, requests_table, 'dkim', whitelist)
            else
              add_dns_request(task, domain, false, false, requests_table,
                  'dkim', whitelist)
            end
          end
        end
      end
    end

    return true
  end

  local function check_urls(task, requests_table, whitelist)
    local esld_lim = 1

    if rule.url_compose_map then
      esld_lim = nil -- Avoid esld limit as we use custom composition rules
    end
    local ex_params = {
      task = task,
      limit = rule.requests_limit,
      ignore_redirected = true,
      ignore_ip = rule.no_ip,
      need_images = rule.images,
      need_emails = false,
      need_content = rule.content_urls,
      esld_limit = esld_lim,
      no_cache = true,
    }

    if rule.numeric_urls then
      if rule.content_urls then
        if not rule.images then
          ex_params.flags_mode = 'explicit'
          ex_params.flags = { 'numeric' }
          ex_params.filter = function(url)
            return (bit.band(url:get_flags_num(), url_flag_bits.image) == 0)
          end
        else
          ex_params.filter = function(url)
            return (bit.band(url:get_flags_num(), url_flag_bits.numeric) ~= 0)
          end
        end
      elseif rule.images then
        ex_params.filter = function(url)
          return (bit.band(url:get_flags_num(), url_flag_bits.numeric) ~= 0)
        end
      else
        ex_params.flags_mode = 'explicit'
        ex_params.flags = { 'numeric' }
        ex_params.filter = function(url)
          return (bit.band(url:get_flags_num(), url_flag_bits.content) == 0)
        end
      end
    elseif not rule.urls and (rule.content_urls or rule.images) then
      ex_params.flags_mode = 'explicit'
      ex_params.flags = {}
      if rule.content_urls then
        table.insert(ex_params.flags, 'content')
      end
      if rule.images then
        table.insert(ex_params.flags, 'image')
      end
    end

    local urls = lua_util.extract_specific_urls(ex_params)

    for _, u in ipairs(urls) do
      local flags = u:get_flags_num()

      if bit.band(flags, url_flag_bits.numeric) ~= 0 then
        -- For numeric urls we convert data to the ip address and
        -- reverse octets. See #3948 for details
        local to_resolve = u:get_host()
        local addr = rspamd_ip.from_string(to_resolve)

        if addr then
          to_resolve = table.concat(addr:inversed_str_octets(), ".")
        end
        add_dns_request(task, to_resolve, false,
            false, requests_table, 'url', whitelist)
      else
        local url_hostname = u:get_host()
        local url_tld = rule.url_full_hostname and url_hostname or u:get_tld()
        if rule.url_compose_map then
          url_tld = rule.url_compose_map:process_url(task, url_tld, url_hostname)
        end
        add_dns_request(task, url_tld, false,
            false, requests_table, 'url', whitelist)
      end
    end

    return true
  end

  local function check_from(task, requests_table, whitelist)
    local ip = task:get_from_ip()

    if not ip or not ip:is_valid() then
      return true
    end
    if (ip:get_version() == 6 and rule.ipv6) or
        (ip:get_version() == 4 and rule.ipv4) then
      add_dns_request(task, ip, true, true,
          requests_table, 'from',
          whitelist)
    end

    return true
  end

  local function check_received(task, requests_table, whitelist)
    local received = fun             .filter(function(h)
      return not h['flags']['artificial']
    end, task:get_received_headers()):totable()

    local received_total = #received
    local check_conditions = gen_check_rcvd_conditions(rule, received_total)
    local from_ip = task:get_from_ip()

    for pos, rh in ipairs(received) do
      if check_conditions(rh, pos) then
        if rh.real_ip ~= from_ip or (rh.real_ip == from_ip and not rule.from) then
          add_dns_request(task, rh.real_ip, false, true,
              requests_table, 'received',
              whitelist)
        else
          lua_util.debugm(N, task, 'rbl %s; skip check_received for %s:' ..
              'Received IP same as From IP and will be checked only in check_from function',
              rule.symbol, rh.real_ip)
        end
      end
    end

    return true
  end

  local function check_rdns(task, requests_table, whitelist)
    local hostname = task:get_hostname()
    if hostname == nil or hostname == 'unknown' then
      return true
    end

    add_dns_request(task, hostname, true, false,
        requests_table, 'rdns', whitelist)

    return true
  end

  local function check_selector(task, requests_table, whitelist)
    for selector_label, selector in pairs(rule.selectors) do
      local res = selector(task)

      if res and type(res) == 'table' then
        for _, r in ipairs(res) do
          add_dns_request(task, r, false, false, requests_table,
              selector_label, whitelist)
        end
      elseif res then
        add_dns_request(task, res, false, false,
            requests_table, selector_label, whitelist)
      end
    end

    return true
  end

  local function check_email_table(task, email_tbl, requests_table, whitelist, what)
    lua_util.remove_email_aliases(email_tbl)
    email_tbl.domain = email_tbl.domain:lower()
    email_tbl.user = email_tbl.user:lower()

    if email_tbl.domain == '' or email_tbl.user == '' then
      rspamd_logger.infox(task, "got an email with some empty parts: '%s@%s'; skip it in the checks",
          email_tbl.user, email_tbl.domain)
      return
    end

    if rule.emails_domainonly then
      add_dns_request(task, email_tbl.domain, false, false, requests_table,
          what, whitelist)
    else
      -- Also check WL for domain only
      if is_whitelisted(task,
          email_tbl.domain,
          email_tbl.domain,
          whitelist,
          what) then
        return
      end
      local delimiter = '.'
      if rule.emails_delimiter then
        delimiter = rule.emails_delimiter
      else
        if rule.hash then
          delimiter = '@'
        end
      end
      add_dns_request(task, string.format('%s%s%s',
          email_tbl.user, delimiter, email_tbl.domain), false, false,
          requests_table, what, whitelist)
    end
  end

  local function check_emails(task, requests_table, whitelist)
    local ex_params = {
      task = task,
      limit = rule.requests_limit,
      filter = function(u)
        return u:get_protocol() == 'mailto'
      end,
      need_emails = true,
      prefix = 'rbl_email'
    }

    if rule.emails_domainonly then
      if not rule.url_compose_map then
        ex_params.esld_limit = 1
      end
      ex_params.prefix = 'rbl_email_domainonly'
    end

    local emails = lua_util.extract_specific_urls(ex_params)

    for _, email in ipairs(emails) do
      local domain
      if rule.emails_domainonly and not rule.url_full_hostname then
        if rule.url_compose_map then
          domain = rule.url_compose_map:process_url(task, email:get_tld(), email:get_host())
        else
          domain = email:get_tld()
        end
      else
        domain = email:get_host()
      end

      local email_tbl = {
        domain = domain or '',
        user = email:get_user() or '',
        addr = tostring(email),
      }
      check_email_table(task, email_tbl, requests_table, whitelist, 'email')
    end

    return true
  end

  local function check_replyto(task, requests_table, whitelist)
    local function get_raw_header(name)
      return ((task:get_header_full(name) or {})[1] or {})['value']
    end

    local replyto = get_raw_header('Reply-To')
    if replyto then
      local rt = rspamd_util.parse_mail_address(replyto, task:get_mempool())
      lua_util.debugm(N, task, 'check replyto %s', rt[1])

      if rt and rt[1] and (rt[1].addr and #rt[1].addr > 0) then
        check_email_table(task, rt[1], requests_table, whitelist, 'replyto')
      end
    end

    return true
  end

  -- Create function pipeline depending on rbl settings
  local pipeline = {
    is_allowed, -- check if rbl is allowed
    is_alive, -- check monitored status
    check_required_symbols -- if we have require_symbols then check those symbols
  }
  local description = {
    'allowed',
    'alive',
    'required_symbols',
  }

  if rule.exclude_users then
    pipeline[#pipeline + 1] = check_user
    description[#description + 1] = 'user'
  end

  if rule.exclude_local then
    pipeline[#pipeline + 1] = check_local
    description[#description + 1] = 'local'
  end

  if rule.helo then
    pipeline[#pipeline + 1] = check_helo
    description[#description + 1] = 'helo'
  end

  if rule.dkim then
    pipeline[#pipeline + 1] = check_dkim
    description[#description + 1] = 'dkim'
  end

  if rule.emails then
    pipeline[#pipeline + 1] = check_emails
    description[#description + 1] = 'emails'
  end
  if rule.replyto then
    pipeline[#pipeline + 1] = check_replyto
    description[#description + 1] = 'replyto'
  end

  if rule.urls or rule.content_urls or rule.images or rule.numeric_urls then
    pipeline[#pipeline + 1] = check_urls
    description[#description + 1] = 'urls'
  end

  if rule.from then
    pipeline[#pipeline + 1] = check_from
    description[#description + 1] = 'ip'
  end

  if rule.received then
    pipeline[#pipeline + 1] = check_received
    description[#description + 1] = 'received'
  end

  if rule.rdns then
    pipeline[#pipeline + 1] = check_rdns
    description[#description + 1] = 'rdns'
  end

  if rule.selector then
    pipeline[#pipeline + 1] = check_selector
    description[#description + 1] = 'selector'
  end

  if not rule.returncodes_matcher then
    rule.returncodes_matcher = 'equality'
  end
  local match = matchers[rule.returncodes_matcher]

  local callback_f = function(task)
    -- DNS requests to issue (might be hashed afterwards)
    local dns_req = {}
    local whitelist = task:cache_get('rbl_whitelisted') or {}

    local function gen_rbl_dns_callback(resolve_table_elt)
      return function(_, to_resolve, results, err)
        rbl_dns_process(task, rule, to_resolve, results, err, resolve_table_elt, match)
      end
    end

    -- Execute functions pipeline
    for i, f in ipairs(pipeline) do
      if not f(task, dns_req, whitelist) then
        lua_util.debugm(N, task,
            "skip rbl check: %s; pipeline condition %s (%s) returned false",
            rule.symbol, i, description[i])
        return
      end
    end

    -- Now check all DNS requests pending and emit them
    -- Deduplicate by actual DNS query name to merge equivalent queries from different checks
    local deduped_req = {}
    for _, req in pairs(dns_req) do
      local dedupe_key = tostring(req.n):lower()
      req.n = dedupe_key
      local existing = deduped_req[dedupe_key]
      if existing then
        for label, _ in pairs(req.what) do
          if not existing.what[label] then
            existing.what[label] = true
          end
        end
        for origin, labels in pairs(req.origins) do
          if not existing.origins[origin] then
            existing.origins[origin] = {}
          end
          for label in pairs(labels) do
            existing.origins[origin][label] = true
          end
        end
        if req.forced and not existing.forced then
          existing.forced = true
        end
        lua_util.debugm(N, task, 'merging DNS request for %s: %s (same query %s)',
            rule.symbol, req.orig, req.n)
      else
        deduped_req[dedupe_key] = req
      end
    end

    local r = task:get_resolver()
    -- Used for 2 passes ip resolution
    local resolved_req = {}
    local nresolved = 0

    -- This is called when doing resolve_ip phase...
    local function gen_rbl_ip_dns_callback(orig_resolve_table_elt)
      return function(_, _, results, err)
        if not err then
          for _, dns_res in ipairs(results) do
            -- Check if we have rspamd{ip} userdata
            if type(dns_res) == 'userdata' then
              -- Add result as an actual RBL request
              local nreq
              for label in pairs(orig_resolve_table_elt.what) do
                _, nreq = add_dns_request(task, dns_res, false, true,
                    resolved_req, label)
              end

              local ip_str = tostring(dns_res)
              nreq.origins[ip_str] = nil
              for origin, labels in pairs(orig_resolve_table_elt.origins) do
                local resolved_origin = string.format('%s:%s', ip_str, origin)
                if not nreq.origins[resolved_origin] then
                  nreq.origins[resolved_origin] = {}
                end
                for label in pairs(labels) do
                  nreq.origins[resolved_origin][label] = true
                end
              end
            end
          end
        end

        nresolved = nresolved - 1

        if nresolved == 0 then
          -- Emit real RBL requests as there are no ip resolution requests
          for name, req in pairs(resolved_req) do
            local val_res, val_error = validate_dns(req.n)
            if val_res then
              lua_util.debugm(N, task, "rbl %s; resolve %s -> %s",
                  rule.symbol, name, req.n)
              r:resolve_a({
                task = task,
                name = req.n,
                callback = gen_rbl_dns_callback(req),
                forced = req.forced
              })
            else
              rspamd_logger.warnx(task, 'cannot send invalid DNS request %s for %s: %s',
                  req.n, rule.symbol, val_error)
            end
          end
        end
      end
    end

    for name, req in pairs(deduped_req) do
      local val_res, val_error = validate_dns(req.n)
      if val_res then
        lua_util.debugm(N, task, "rbl %s; resolve %s -> %s",
            rule.symbol, name, req.n)

        if req.resolve_ip then
          -- Deal with both ipv4 and ipv6
          -- Resolve names first
          if (rule.ipv4 == nil or rule.ipv4) and r:resolve_a({
            task = task,
            name = req.n,
            callback = gen_rbl_ip_dns_callback(req),
            forced = req.forced
          }) then
            nresolved = nresolved + 1
          end
          if (rule.ipv6 == nil or rule.ipv6) and r:resolve('aaaa', {
            task = task,
            name = req.n,
            callback = gen_rbl_ip_dns_callback(req),
            forced = req.forced
          }) then
            nresolved = nresolved + 1
          end
        else
          r:resolve_a({
            task = task,
            name = req.n,
            callback = gen_rbl_dns_callback(req),
            forced = req.forced
          })
        end

      else
        rspamd_logger.warnx(task, 'cannot send invalid DNS request %s for %s: %s',
            req.n, rule.symbol, val_error)
      end
    end
  end

  return callback_f, string.format('checks: %s', table.concat(description, ','))
end

local map_match_types = {
  glob = true,
  radix = true,
  regexp = true,
}

local function add_rbl(key, rbl, global_opts)
  if not rbl.symbol then
    rbl.symbol = key:upper()
  end

  local flags_tbl = { 'no_squeeze' }
  if rbl.is_whitelist then
    flags_tbl[#flags_tbl + 1] = 'nice'
  end

  -- Check if rbl is available for empty tasks
  if not (rbl.emails or rbl.urls or rbl.dkim or rbl.received or rbl.selector or rbl.replyto) or
      rbl.is_empty then
    flags_tbl[#flags_tbl + 1] = 'empty'
  end

  if rbl.selector then

    rbl.selectors = {}
    -- Selector strings: the symbols they need are registered as dependencies
    rbl.selector_strings = {}
    if type(rbl.selector) ~= 'table' then
      rbl.selector = { ['selector'] = rbl.selector }
    end

    for selector_label, selector in pairs(rbl.selector) do
      table.insert(rbl.selector_strings, selector)
      if known_selectors[selector] then
        lua_util.debugm(N, rspamd_config, 'reuse selector id %s',
            known_selectors[selector].id)
        rbl.selectors[selector_label] = known_selectors[selector].selector
      else

        if type(rbl.selector_flatten) ~= 'boolean' then
          -- Fail-safety
          rbl.selector_flatten = true
        end
        local sel = selectors.create_selector_closure(rspamd_config, selector, '',
            rbl.selector_flatten)

        if not sel then
          rspamd_logger.errx(rspamd_config, 'invalid selector for rbl rule %s: %s', key, selector)
          return false
        end

        rbl.selector = sel
        known_selectors[selector] = {
          selector = sel,
          id = #lua_util.keys(known_selectors) + 1,
        }
        rbl.selectors[selector_label] = known_selectors[selector].selector
      end
    end

  end

  if rbl.process_script then
    local ret, f = lua_util.callback_from_string(rbl.process_script)

    if ret then
      rbl.process_script = f
    else
      rspamd_logger.errx(rspamd_config,
          'invalid process script for rbl rule %s: %s; %s',
          key, rbl.process_script, f)
      return false
    end
  end

  if rbl.whitelist then
    local def_type = 'set'
    if rbl.from or rbl.received then
      def_type = 'radix'
    end
    rbl.whitelist = lua_maps.map_add_from_ucl(rbl.whitelist, def_type,
        'RBL whitelist for ' .. rbl.symbol)
    rspamd_logger.infox(rspamd_config, 'added %s whitelist for RBL %s',
        def_type, rbl.symbol)
  end

  local match_type = rbl.returncodes_matcher
  if match_type and rbl.returncodes and map_match_types[match_type] then
    if not rbl.returncodes_maps then
      rbl.returncodes_maps = {}
    end
    for label, v in pairs(rbl.returncodes) do
      if type(v) ~= 'table' then
        v = { v }
      end
      rbl.returncodes_maps[label] = lua_maps.map_add_from_ucl(v, match_type,
          string.format('%s_%s RBL returncodes', label, rbl.symbol))
    end
  end

  if rbl.url_compose_map then
    local lua_urls_compose = require "lua_urls_compose"
    rbl.url_compose_map = lua_urls_compose.add_composition_map(rspamd_config, rbl.url_compose_map)

    if rbl.url_compose_map then
      rspamd_logger.infox(rspamd_config, 'added url composition map for RBL %s',
          rbl.symbol)
    end
  end

  if not rbl.whitelist and not rbl.ignore_url_whitelist and (global_opts.url_whitelist or rbl.url_whitelist) and
      (rbl.urls or rbl.emails or rbl.dkim or rbl.replyto) and
      not (rbl.from or rbl.received) then
    local def_type = 'set'
    rbl.whitelist = lua_maps.map_add_from_ucl(rbl.url_whitelist or global_opts.url_whitelist, def_type,
        'RBL url whitelist for ' .. rbl.symbol)
    rspamd_logger.infox(rspamd_config, 'added URL whitelist for RBL %s',
        rbl.symbol)
  end

  local callback, description = gen_rbl_callback(rbl)

  if callback then
    local id

    if rbl.symbols_prefixes then
      id = rspamd_config:register_symbol {
        type = 'callback',
        callback = callback,
        groups = { 'rbl' },
        name = rbl.symbol .. '_CHECK',
        flags = table.concat(flags_tbl, ',')
      }

      for _, prefix in pairs(rbl.symbols_prefixes) do
        -- For unknown results...
        rspamd_config:register_symbol {
          type = 'virtual',
          parent = id,
          group = 'rbl',
          score = 0,
          name = prefix .. '_' .. rbl.symbol,
        }
      end
      if not (rbl.is_whitelist or rbl.ignore_whitelist) then
        table.insert(black_symbols, rbl.symbol .. '_CHECK')
      else
        lua_util.debugm(N, rspamd_config, 'rule %s ignores whitelists: rbl.is_whitelist = %s, ' ..
            'rbl.ignore_whitelist = %s',
            rbl.symbol, rbl.is_whitelist, rbl.ignore_whitelist)
      end
    else
      id = rspamd_config:register_symbol {
        type = 'callback',
        callback = callback,
        name = rbl.symbol,
        groups = { 'rbl' },
        group = 'rbl',
        score = 0,
        flags = table.concat(flags_tbl, ',')
      }
      if not (rbl.is_whitelist or rbl.ignore_whitelist) then
        table.insert(black_symbols, rbl.symbol)
      else
        lua_util.debugm(N, rspamd_config, 'rule %s ignores whitelists: rbl.is_whitelist = %s, ' ..
            'rbl.ignore_whitelist = %s',
            rbl.symbol, rbl.is_whitelist, rbl.ignore_whitelist)
      end
    end

    rspamd_logger.infox(rspamd_config, 'added rbl rule %s: %s',
        rbl.symbol, description)
    lua_util.debugm(N, rspamd_config, 'rule dump for %s: %s',
        rbl.symbol, rbl)

    local check_sym = rbl.symbols_prefixes and rbl.symbol .. '_CHECK' or rbl.symbol

    for _, selector_str in ipairs(rbl.selector_strings or {}) do
      -- Symbols used by the selector must be checked before the rule
      selectors.register_dependencies(rspamd_config, check_sym, selector_str)
    end

    if rbl.dkim then
      -- Weak: RBL has other query sources; DKIM-domain queries just won't happen
      rspamd_config:register_dependency(check_sym, 'DKIM_CHECK')
    end

    if rbl.require_symbols then
      for _, dep in ipairs(rbl.require_symbols) do
        rspamd_config:register_dependency(check_sym, dep)
      end
    end

    -- Failure symbol
    rspamd_config:register_symbol {
      type = 'virtual',
      flags = 'nostat',
      name = rbl.symbol .. '_FAIL',
      parent = id,
      score = 0.0,
    }

    local function process_return_code(suffix)
      local function process_specific_suffix(s)
        if s ~= rbl.symbol then
          -- hack

          rspamd_config:register_symbol {
            type = 'virtual',
            parent = id,
            name = s,
            group = 'rbl',
            score = 0,
          }
        end
        if rbl.is_whitelist then
          if rbl.whitelist_exception then
            local found_exception = false
            for _, e in ipairs(rbl.whitelist_exception) do
              if e == s then
                found_exception = true
                break
              end
            end
            if not found_exception then
              table.insert(white_symbols, s)
            end
          else
            table.insert(white_symbols, s)
          end
        else
          if not rbl.ignore_whitelist then
            table.insert(black_symbols, s)
          end
        end
      end

      if rbl.symbols_prefixes then
        for _, prefix in pairs(rbl.symbols_prefixes) do
          process_specific_suffix(prefix .. '_' .. suffix)
        end
      else
        process_specific_suffix(suffix)
      end

    end

    if rbl.returncodes then
      for s, _ in pairs(rbl.returncodes) do
        process_return_code(s)
      end
    end

    if rbl.returnbits then
      for s, _ in pairs(rbl.returnbits) do
        process_return_code(s)
      end
    end

    -- Process monitored
    if not rbl.disable_monitoring then
      if not monitored_addresses[rbl.rbl] then
        monitored_addresses[rbl.rbl] = true
        rbl.monitored = rspamd_config:register_monitored(rbl.rbl, 'dns',
            get_monitored(rbl))
      end
    end
    return true
  end

  return false
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


opts = lua_util.override_defaults(rbl_common.default_options, opts)

if opts.rules and opts.rbls then
  -- Common issue :(
  rspamd_logger.infox(rspamd_config, 'merging `rules` and `rbls` keys for compatibility')
  opts.rbls = lua_util.override_defaults(opts.rbls, opts.rules)
end

if (opts['local_exclude_ip_map'] ~= nil) then
  local_exclusions = lua_maps.map_add(N, 'local_exclude_ip_map', 'radix',
      'RBL exclusions map')
end

-- TODO: this code should be universal for all modules that use selectors to allow
-- maps usage from selectors registered for a specific module
if type(opts.attached_maps) == 'table' then
  opts.attached_maps_processed = {}
  for i, map in ipairs(opts.attached_maps) do
    -- Store maps in the configuration table to keep lifetime track
    opts.attached_maps_processed[i] = lua_maps.map_add_from_ucl(map)
    if opts.attached_maps_processed[i] == nil then
      rspamd_logger.warnx(rspamd_config, "cannot parse attached map: %s", map)
    end
  end
end

if opts.disabled_rbl_suffixes_map then
  disabled_rbl_suffixes = lua_maps.map_add_from_ucl(opts.disabled_rbl_suffixes_map, 'set',
      'Disabled suffixes for RBL')
end

for key, rbl in pairs(opts.rbls) do
  if type(rbl) ~= 'table' or rbl.disabled == true or rbl.enabled == false then
    rspamd_logger.infox(rspamd_config, 'disable rbl "%s"', key)
  else
    -- Aliases
    if type(rbl.ignore_default) == 'boolean' then
      rbl.ignore_defaults = rbl.ignore_default
    end
    if type(rbl.ignore_whitelists) == 'boolean' then
      rbl.ignore_whitelist = rbl.ignore_whitelists
    end
    -- Propagate default options from opts to rule
    if not rbl.ignore_defaults then
      for default_opt_key, _ in pairs(rbl_common.default_options) do
        local rbl_opt = default_opt_key:sub(#('default_') + 1)
        if rbl[rbl_opt] == nil then
          rbl[rbl_opt] = opts[default_opt_key]
        end
      end
    end

    if not rbl.requests_limit then
      rbl.requests_limit = rspamd_config:get_dns_max_requests()
    end

    local res, err = rbl_common.rule_schema:transform(rbl)
    if not res then
      rspamd_logger.errx(rspamd_config, 'invalid config for %s: %s, RBL is DISABLED',
          key, err)
    else
      res = rbl_common.convert_checks(res, rbl.symbol or key:upper())
      -- Aliases
      if res.return_codes then
        res.returncodes = res.return_codes
      end
      if res.return_bits then
        res.returnbits = res.return_bits
      end

      if not res then
        rspamd_logger.errx(rspamd_config, 'invalid config for %s: %s, RBL is DISABLED',
            key, err)
      else
        add_rbl(key, res, opts)
      end
    end
  end -- rbl.enabled
end

-- We now create two symbols:
-- * RBL_CALLBACK_WHITE that depends on all symbols white
-- * RBL_CALLBACK that depends on all symbols black to participate in depends chains
local function rbl_callback_white(task)
  local whitelisted_elements = {}
  for _, w in ipairs(white_symbols) do
    local ws = task:get_symbol(w)
    if ws and ws[1] then
      ws = ws[1]
      if not ws.options then
        ws.options = {}
      end
      for _, opt in ipairs(ws.options) do
        local elt, what = opt:match('^([^:]+):([^:]+)')
        lua_util.debugm(N, task, 'found whitelist from %s: %s(%s)', w,
            elt, what)
        if elt and what then
          if not whitelisted_elements[elt] then
            whitelisted_elements[elt] = {}
          end
          -- `what` might be a comma-joined list of labels (merged request)
          for label in what:gmatch('[^,]+') do
            table.insert(whitelisted_elements[elt], {
              type = label,
              symbol = w,
            })
          end
        end
      end
    end
  end

  task:cache_set('rbl_whitelisted', whitelisted_elements)

  lua_util.debugm(N, task, "finished rbl whitelists processing")
end

local function rbl_callback_fin(task)
  -- Do nothing
  lua_util.debugm(N, task, "finished rbl processing")
end

rspamd_config:register_symbol {
  type = 'callback',
  callback = rbl_callback_white,
  name = 'RBL_CALLBACK_WHITE',
  flags = 'nice,empty,no_squeeze',
  groups = { 'rbl' },
  augmentations = { string.format("timeout=%f", rspamd_config:get_dns_timeout() or 0.0) },
}

rspamd_config:register_symbol {
  type = 'callback',
  callback = rbl_callback_fin,
  name = 'RBL_CALLBACK',
  flags = 'empty,no_squeeze',
  groups = { 'rbl' },
  augmentations = { string.format("timeout=%f", rspamd_config:get_dns_timeout() or 0.0) },
}

for _, w in ipairs(white_symbols) do
  rspamd_config:register_dependency('RBL_CALLBACK_WHITE', w)
end

for _, b in ipairs(black_symbols) do
  rspamd_config:register_dependency(b, 'RBL_CALLBACK_WHITE')
  rspamd_config:register_dependency('RBL_CALLBACK', b)
end
