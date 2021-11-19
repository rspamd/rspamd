--[[
Copyright (c) 2011-2020, Vsevolod Stakhov <vsevolod@highsecure.ru>
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
local rspamd_ip = require "rspamd_ip"
local fun = require 'fun'
local lua_util = require 'lua_util'
local selectors = require "lua_selectors"
local bit = require 'bit'
local lua_maps = require "lua_maps"
local rbl_common = require "plugins/rbl"
local rspamd_url = require "rspamd_url"

-- This plugin implements various types of RBL checks
-- Documentation can be found here:
-- https://rspamd.com/doc/modules/rbl.html

local E = {}
local N = 'rbl'

-- Checks that could be performed by rbl module
local local_exclusions
local white_symbols = {}
local black_symbols = {}
local monitored_addresses = {}
local known_selectors = {} -- map from selector string to selector id
local url_flag_bits = rspamd_url.flags

local function get_monitored(rbl)
  local default_monitored = '1.0.0.127'
  local ret = {
    rcode = 'nxdomain',
    prefix = default_monitored,
    random = false,
  }

  if rbl.monitored_address then
    ret.prefix = rbl.monitored_address
  end

  if rbl.dkim or rbl.urls or rbl.emails then
    ret.random = true
  end

  lua_util.debugm(N, rspamd_config,
      'added monitored address: %s (%s random)',
      ret.prefix, ret.random)

  return ret
end

local function validate_dns(lstr)
  if lstr:match('%.%.') then
    -- two dots in a row
    return false
  end
  if not rspamd_util.is_valid_utf8(lstr) then
    -- invalid utf8 detected
    return false
  end
  for v in lstr:gmatch('[^%.]+') do
    if v:len() > 63 or v:match('^-') or v:match('-$') then
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

local function rbl_dns_process(task, rbl, to_resolve, results, err, resolve_table_elt)
  local function make_option(ip, label)
    if ip then
      return string.format('%s:%s:%s',
          resolve_table_elt.orig,
          label,
          ip)
    else
      return string.format('%s:%s',
          resolve_table_elt.orig,
          label)
    end
  end

  local function insert_result(s, ip, label)
    if rbl.symbols_prefixes then
      local prefix = rbl.symbols_prefixes[label]

      if not prefix then
        rspamd_logger.warnx(task, 'unlisted symbol prefix for %s', label)
        task:insert_result(s, 1.0, make_option(ip, label))
      else
        task:insert_result(prefix .. '_' .. s, 1.0, make_option(ip, label))
      end
    else
      task:insert_result(s, 1.0, make_option(ip, label))
    end
  end

  local function insert_results(s, ip)
    for label in pairs(resolve_table_elt.what) do
      insert_result(s, ip, label)
    end
  end

  if err and (err ~= 'requested record is not found' and
      err ~= 'no records with this name') then
    rspamd_logger.infox(task, 'error looking up %s: %s', to_resolve, err)
    task:insert_result(rbl.symbol .. '_FAIL', 1, string.format('%s:%s',
        resolve_table_elt.orig, err))
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

  for _,result in ipairs(results) do
    local ipstr = result:to_string()
    lua_util.debugm(N, task, '%s DNS result %s', to_resolve, ipstr)
    local foundrc = false
    -- Check return codes
    if rbl.returnbits then
      local ipnum = result:to_number()
      for s,bits in pairs(rbl.returnbits) do
        for _,check_bit in ipairs(bits) do
          if bit.band(ipnum, check_bit) == check_bit then
            foundrc = true
            insert_results(s)
            -- Here, we continue with other bits
          end
        end
      end
    elseif rbl.returncodes then
      for s, codes in pairs(rbl.returncodes) do
        for _,v in ipairs(codes) do
          if string.find(ipstr, '^' .. v .. '$') then
            foundrc = true
            insert_results(s)
            break
          end
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
        lua_util.debugm(N, task,
            'whitelisted request to %s by %s (%s) rbl rule (%s checked type, %s whitelist type)',
            req_str, wl.type, wl.symbol, what, wl.type)
        if wl.type == what then
          -- This was decided to be a bad idea as in case of whitelisting a request to blacklist
          -- is not even sent
          --task:adjust_result(wl.symbol, 0.0 / 0.0, rule.symbol)

          return true
        end
      end
    end

    return false
  end

  local function add_dns_request(task, req, forced, is_ip, requests_table, label, whitelist)
    local req_str = req
    if is_ip then
      req_str = tostring(req)
    end

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
      end

      return true,nreq -- Duplicate
    else
      local nreq

      local resolve_ip = rule.resolve_ip and not is_ip
      if rule.process_script then
        local processed = rule.process_script(req, rule.rbl, task, resolve_ip)

        if processed then
          nreq = {
            forced = forced,
            n = processed,
            orig = req_str,
            resolve_ip = resolve_ip,
            what = {[label] = true},
          }
          requests_table[req] = nreq
        end
      else
        local to_resolve
        local orign = req

        if not resolve_ip then
          orign = maybe_make_hash(req, rule)
          to_resolve = string.format('%s.%s',
              orign,
              rule.rbl)
        else
          -- First, resolve origin stuff without hashing or anything
          to_resolve = orign
        end

        nreq = {
          forced = forced,
          n = to_resolve,
          orig = req_str,
          resolve_ip = resolve_ip,
          what = {[label] = true},
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
      return false
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

        local domain,result = d:match('^([^%:]*):([%+%-%~])$')

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
      need_content = rule.content_urls or false,
      esld_limit = esld_lim,
      no_cache = true,
    }

    if not rule.urls then
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

    for _,u in ipairs(urls) do
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
    local received = fun.filter(function(h)
      return not h['flags']['artificial']
    end, task:get_received_headers()):totable()

    local received_total = #received
    local check_conditions = gen_check_rcvd_conditions(rule, received_total)

    for pos,rh in ipairs(received) do
      if check_conditions(rh, pos) then
        add_dns_request(task, rh.real_ip, false, true,
            requests_table, 'received',
            whitelist)
      end
    end

    return true
  end

  local function check_rdns(task, requests_table, whitelist)
    local hostname = task:get_hostname()
    if hostname == nil or hostname == 'unknown' then
      return false
    end

    add_dns_request(task, hostname, true, false,
        requests_table, 'rdns', whitelist)

    return true
  end

  local function check_selector(task, requests_table, whitelist)
    for selector_label, selector in pairs(rule.selectors) do
      local res = selector(task)

      if res and type(res) == 'table' then
          for _,r in ipairs(res) do
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
      filter = function(u) return u:get_protocol() == 'mailto' end,
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

    for _,email in ipairs(emails) do
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
        domain = domain,
        user = email:get_user(),
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
    is_alive, -- generic for all
  }
  local description = {
    'alive',
  }

  if rule.exclude_users then
    pipeline[#pipeline + 1] = check_user
    description[#description + 1] = 'user'
  end

  if rule.exclude_local or rule.exclude_private_ips then
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

  if rule.urls or rule.content_urls or rule.images then
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

  local callback_f = function(task)
    -- DNS requests to issue (might be hashed afterwards)
    local dns_req = {}
    local whitelist = task:cache_get('rbl_whitelisted') or {}

    local function gen_rbl_dns_callback(resolve_table_elt)
      return function(_, to_resolve, results, err)
        rbl_dns_process(task, rule, to_resolve, results, err, resolve_table_elt)
      end
    end

    -- Execute functions pipeline
    for i,f in ipairs(pipeline) do
      if not f(task, dns_req, whitelist) then
        lua_util.debugm(N, task,
            "skip rbl check: %s; pipeline condition %s returned false",
            rule.symbol, i)
        return
      end
    end

    -- Now check all DNS requests pending and emit them
    local r = task:get_resolver()
    -- Used for 2 passes ip resolution
    local resolved_req = {}
    local nresolved = 0

    -- This is called when doing resolve_ip phase...
    local function gen_rbl_ip_dns_callback(orig_resolve_table_elt)
      return function(_, _, results, err)
        if not err then
          for _,dns_res in ipairs(results) do
            -- Check if we have rspamd{ip} userdata
            if type(dns_res) == 'userdata' then
              -- Add result as an actual RBL request
              local label = next(orig_resolve_table_elt.what)
              local dup,nreq = add_dns_request(task, dns_res, false, true,
                  resolved_req, label)
              -- Add original name
              if not dup then
                nreq.orig = nreq.orig .. ':' .. orig_resolve_table_elt.n
              end
            end
          end
        end

        nresolved = nresolved - 1

        if nresolved == 0 then
          -- Emit real RBL requests as there are no ip resolution requests
          for name, req in pairs(resolved_req) do
            if validate_dns(req.n) then
              lua_util.debugm(N, task, "rbl %s; resolve %s -> %s",
                  rule.symbol, name, req.n)
              r:resolve_a({
                task = task,
                name = req.n,
                callback = gen_rbl_dns_callback(req),
                forced = req.forced
              })
            else
              rspamd_logger.warnx(task, 'cannot send invalid DNS request %s for %s',
                  req.n, rule.symbol)
            end
          end
        end
      end
    end

    for name, req in pairs(dns_req) do
      if validate_dns(req.n) then
        lua_util.debugm(N, task, "rbl %s; resolve %s -> %s",
            rule.symbol, name, req.n)

        if req.resolve_ip then
          -- Deal with both ipv4 and ipv6
          -- Resolve names first
          if r:resolve_a({
            task = task,
            name = req.n,
            callback = gen_rbl_ip_dns_callback(req),
            forced = req.forced
          }) then
            nresolved = nresolved + 1
          end
          if r:resolve('aaaa', {
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
        rspamd_logger.warnx(task, 'cannot send invalid DNS request %s for %s',
            req.n, rule.symbol)
      end
    end
  end

  return callback_f,string.format('checks: %s', table.concat(description, ','))
end

local function add_rbl(key, rbl, global_opts)
  if not rbl.symbol then
    rbl.symbol = key:upper()
  end

  local flags_tbl = {'no_squeeze'}
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
    if type(rbl.selector) ~= 'table' then
      rbl.selector = {['selector'] = rbl.selector}
    end

    for selector_label, selector in pairs(rbl.selector) do
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
          rspamd_logger.errx('invalid selector for rbl rule %s: %s', key, selector)
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

  if rbl.url_compose_map then
    local lua_urls_compose = require "lua_urls_compose"
    rbl.url_compose_map = lua_urls_compose.add_composition_map(rspamd_config, rbl.url_compose_map)

    if rbl.url_compose_map then
      rspamd_logger.infox(rspamd_config, 'added url composition map for RBL %s',
          rbl.symbol)
    end
  end

  if not rbl.whitelist and global_opts.url_whitelist and
      (rbl.urls or rbl.emails or rbl.dkim or rbl.replyto) and
      not (rbl.from or rbl.received) then
    local def_type = 'set'
    rbl.whitelist = lua_maps.map_add_from_ucl(global_opts.url_whitelist, def_type,
        'RBL url whitelist for ' .. rbl.symbol)
    rspamd_logger.infox(rspamd_config, 'added URL whitelist for RBL %s',
        rbl.symbol)
  end

  local callback,description = gen_rbl_callback(rbl)

  if callback then
    local id

    if rbl.symbols_prefixes then
      id = rspamd_config:register_symbol{
        type = 'callback',
        callback = callback,
        name = rbl.symbol .. '_CHECK',
        flags = table.concat(flags_tbl, ',')
      }

      for _,prefix in pairs(rbl.symbols_prefixes) do
        -- For unknown results...
        rspamd_config:register_symbol{
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
      id = rspamd_config:register_symbol{
        type = 'callback',
        callback = callback,
        name = rbl.symbol,
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

    if rbl.dkim then
      rspamd_config:register_dependency(rbl.symbol, 'DKIM_CHECK')
    end

    if rbl.require_symbols then
      for _,dep in ipairs(rbl.require_symbols) do
        rspamd_config:register_dependency(rbl.symbol, dep)
      end
    end

    -- Failure symbol
    rspamd_config:register_symbol{
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

          rspamd_config:register_symbol{
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
        for _,prefix in pairs(rbl.symbols_prefixes) do
          process_specific_suffix(prefix .. '_' .. suffix)
        end
      else
        process_specific_suffix(suffix)
      end

    end

    if rbl.returncodes then
      for s,_ in pairs(rbl.returncodes) do
        process_return_code(s)
      end
    end

    if rbl.returnbits then
      for s,_ in pairs(rbl.returnbits) do
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

if(opts['local_exclude_ip_map'] ~= nil) then
  local_exclusions = lua_maps.map_add(N, 'local_exclude_ip_map', 'radix',
    'RBL exclusions map')
end

for key,rbl in pairs(opts.rbls ) do
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
      for default_opt_key,_ in pairs(rbl_common.default_options) do
        local rbl_opt = default_opt_key:sub(#('default_') + 1)
        if rbl[rbl_opt] == nil then
          rbl[rbl_opt] = opts[default_opt_key]
        end
      end
    end

    if not rbl.requests_limit then
      rbl.requests_limit = rspamd_config:get_dns_max_requests()
    end

    local res,err = rbl_common.rule_schema:transform(rbl)
    if not res then
      rspamd_logger.errx(rspamd_config, 'invalid config for %s: %s, RBL is DISABLED',
          key, err)
    else
      res = rbl_common.convert_checks(res)
      -- Aliases
      if res.return_codes then res.returncodes = res.return_codes end
      if res.return_bits then res.returnbits = res.return_bits end

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
      if not ws.options then ws.options = {} end
      for _,opt in ipairs(ws.options) do
        local elt,what = opt:match('^([^:]+):([^:]+)')
        lua_util.debugm(N, task,'found whitelist from %s: %s(%s)', w,
            elt, what)
        if elt and what then
          whitelisted_elements[elt] = {
            type = what,
            symbol = w,
          }
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
