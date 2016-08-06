--[[
Copyright (c) 2011-2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2013-2015, Alexey Savelyev <info@homeweb.ru>

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


-- Weight for checks_hellohost and checks_hello: 5 - very hard, 4 - hard, 3 - meduim, 2 - low, 1 - very low.
-- From HFILTER_HELO_* and HFILTER_HOSTNAME_* symbols the maximum weight is selected in case of their actuating.


--local dumper = require 'pl.pretty'.dump
local rspamd_regexp = require "rspamd_regexp"
local rspamd_logger = require "rspamd_logger"
local rspamc_local_helo = "rspamc.local"
local checks_hellohost = {
  ['[.-]gprs[.-]'] = 5, ['gprs[.-][0-9]'] = 5, ['[0-9][.-]?gprs'] = 5,
  ['[.-]cdma[.-]'] = 5, ['cdma[.-][0-9]'] = 5, ['[0-9][.-]?cdma'] = 5,
  ['[.-]homeuser[.-]'] = 5, ['homeuser[.-][0-9]'] = 5, ['[0-9][.-]?homeuser'] = 5,
  ['[.-]dhcp[.-]'] = 5, ['dhcp[.-][0-9]'] = 5, ['[0-9][.-]?dhcp'] = 5,
  ['[.-]catv[.-]'] = 5, ['catv[.-][0-9]'] = 5, ['[0-9][.-]?catv'] = 5,
  ['[.-]wifi[.-]'] = 5, ['wifi[.-][0-9]'] = 5, ['[0-9][.-]?wifi'] = 5,
  ['[.-]dial-?up[.-]'] = 5, ['dial-?up[.-][0-9]'] = 5, ['[0-9][.-]?dial-?up'] = 5,
  ['[.-]dynamic[.-]'] = 5, ['dynamic[.-][0-9]'] = 5, ['[0-9][.-]?dynamic'] = 5,
  ['[.-]dyn[.-]'] = 5, ['dyn[.-][0-9]'] = 5, ['[0-9][.-]?dyn'] = 5,
  ['[.-]clients?[.-]'] = 1, ['clients?[.-][0-9]{2,}'] = 5, ['[0-9]{3,}[.-]?clients?'] = 5,
  ['[.-]dynip[.-]'] = 5, ['dynip[.-][0-9]'] = 5, ['[0-9][.-]?dynip'] = 5,
  ['[.-]broadband[.-]'] = 5, ['broadband[.-][0-9]'] = 5, ['[0-9][.-]?broadband'] = 5,
  ['[.-]broad[.-]'] = 5, ['broad[.-][0-9]'] = 5, ['[0-9][.-]?broad'] = 5,
  ['[.-]bredband[.-]'] = 5, ['bredband[.-][0-9]'] = 5, ['[0-9][.-]?bredband'] = 5,
  ['[.-]nat[.-]'] = 5, ['nat[.-][0-9]'] = 5, ['[0-9][.-]?nat'] = 5,
  ['[.-]pptp[.-]'] = 5, ['pptp[.-][0-9]'] = 5, ['[0-9][.-]?pptp'] = 5,
  ['[.-]pppoe[.-]'] = 5, ['pppoe[.-][0-9]'] = 5, ['[0-9][.-]?pppoe'] = 5,
  ['[.-]ppp[.-]'] = 5, ['ppp[.-][0-9]'] = 5, ['[0-9][.-]?ppp'] = 5,
  ['[.-]modem[.-]'] = 5, ['modem[.-][0-9]'] = 5, ['[0-9][.-]?modem'] = 5,
  ['[.-]cablemodem[.-]'] = 5, ['cablemodem[.-][0-9]'] = 5, ['[0-9][.-]?cablemodem'] = 5,
  ['[.-]comcast[.-]'] = 5, ['comcast[.-][0-9]'] = 5, ['[0-9][.-]?comcast'] = 5,
  ['[.-][a|x]?dsl-dynamic[.-]'] = 5, ['[a|x]?dsl-dynamic[.-]?[0-9]'] = 5, ['[0-9][.-]?[a|x]?dsl-dynamic'] = 5,
  ['[.-][a|x]?dsl[.-]'] = 4, ['[a|x]?dsl[.-]?[0-9]'] = 4, ['[0-9][.-]?[a|x]?dsl'] = 4,
  ['[.-][a|x]?dsl-line[.-]'] = 4, ['[a|x]?dsl-line[.-]?[0-9]'] = 4, ['[0-9][.-]?[a|x]?dsl-line'] = 4,
  ['[.-]in-?addr[.-]'] = 4, ['in-?addr[.-][0-9]'] = 4, ['[0-9][.-]?in-?addr'] = 4,
  ['[.-]pool[.-]'] = 4, ['pool[.-][0-9]'] = 4, ['[0-9][.-]?pool'] = 4,
  ['[.-]fibertel[.-]'] = 4, ['fibertel[.-][0-9]'] = 4, ['[0-9][.-]?fibertel'] = 4,
  ['[.-]fbx[.-]'] = 4, ['fbx[.-][0-9]'] = 4, ['[0-9][.-]?fbx'] = 4,
  ['[.-]unused-addr[.-]'] = 3, ['unused-addr[.-][0-9]'] = 3, ['[0-9][.-]?unused-addr'] = 3,
  ['[.-]cable[.-]'] = 3, ['cable[.-][0-9]'] = 3, ['[0-9][.-]?cable'] = 3,
  ['[.-]kabel[.-]'] = 3, ['kabel[.-][0-9]'] = 3, ['[0-9][.-]?kabel'] = 3,
  ['[.-]host[.-]'] = 2, ['host[.-][0-9]'] = 2, ['[0-9][.-]?host'] = 2,
  ['[.-]customers?[.-]'] = 1, ['customers?[.-][0-9]'] = 1, ['[0-9][.-]?customers?'] = 1,
  ['[.-]user[.-]'] = 1, ['user[.-][0-9]'] = 1, ['[0-9][.-]?user'] = 1,
  ['[.-]peer[.-]'] = 1, ['peer[.-][0-9]'] = 1, ['[0-9][.-]?peer'] = 1
}

local checks_hello = {
  ['^[^\\.]+$'] = 5, -- for helo=COMPUTER, ANNA, etc... Without dot in helo
  ['^(dsl)?(device|speedtouch)\\.lan$'] = 5,
  ['\\.(lan|local|home|localdomain|intra|in-addr.arpa|priv|online|user|veloxzon)$'] = 5
}

local checks_hello_badip = {
  ['^0\\.'] = 5,
  ['^::1$'] = 5, --loopback ipv4, ipv6
  ['^127\\.'] = 5,
  ['^10\\.'] = 5,
  ['^192\\.168\\.'] = 5, --local ipv4
  ['^172\\.1[6-9]\\.'] = 5,
  ['^172\\.2[0-9]\\.'] = 5,
  ['^172\\.3[01]\\.'] = 5,  --local ipv4
  ['^169\\.254\\.'] = 5, --chanel ipv4
  ['^192\\.0\\.0\\.'] = 5, --IETF Protocol
  ['^192\\.88\\.99\\.'] = 5, --RFC3068
  ['^100.6[4-9]\\.'] = 5,
  ['^100.[7-9]\\d\\.'] = 5,
  ['^100.1[01]\\d\\.'] = 5,
  ['^100.12[0-7]\\d\\.'] = 5, --RFC6598
  ['^\\d\\.\\d\\.\\d\\.255$'] = 5, --multicast ipv4
  ['^192\\.0\\.2\\.'] = 5,
  ['^198\\.51\\.100\\.'] = 5,
  ['^203\\.0\\.113\\.'] = 5,  --sample
  ['^fe[89ab][0-9a-f]::'] = 5,
  ['^fe[cdf][0-9a-f]:'] = 5, --local ipv6 (fe80:: - febf::, fec0:: - feff::)
  ['^2001:db8::'] = 5, --reserved RFC 3849 for ipv6
  ['^fc00::'] = 5,
  ['^ffxx::'] = 5 --unicast, multicast ipv6
}

local checks_hello_bareip = {
  '^\\d+[x.-]\\d+[x.-]\\d+[x.-]\\d+$', --bareip ipv4,
  '^[0-9a-f]+:' --bareip ipv6
}

-- Table of compiled regexps indexed by pattern
local compiled_regexp = {
}

local config = {
  ['helo_enabled'] = false,
  ['hostname_enabled'] = false,
  ['from_enabled'] = false,
  ['rcpt_enabled'] = false,
  ['mid_enabled'] = false,
  ['url_enabled'] = false
}

local function check_regexp(str, regexp_text)
  if not compiled_regexp[regexp_text] then
    compiled_regexp[regexp_text] = rspamd_regexp.create(regexp_text, 'i')
  end

  if compiled_regexp[regexp_text] then
    return compiled_regexp[regexp_text]:match(str)
  end

  return false
end

local function check_fqdn(domain)
  if check_regexp(domain, '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z0-9-]{2,63}\\.?$)') then
    return true
  end
  return false
end

-- host: host for check
-- symbol_suffix: suffix for symbol
-- eq_ip: ip for comparing or empty string
-- eq_host: host for comparing or empty string
local function check_host(task, host, symbol_suffix, eq_ip, eq_host)
  local failed_address = 0
  local resolved_address = {}

  local function check_host_cb_mx(resolver, to_resolve, results, err)
    task:inc_dns_req()
    if not results then
      task:insert_result('HFILTER_' .. symbol_suffix .. '_NORES_A_OR_MX', 1.0)
    else
      for _,mx in pairs(results) do
        if mx['name'] then
          local failed_mx_address = 0
          -- Capture failed_mx_address
          local function check_host_cb_mx_a(resolver, to_resolve, results, err)
            task:inc_dns_req()

            if not results then
              failed_mx_address = failed_mx_address + 1
            end

            if failed_mx_address >= 2 then
              task:insert_result('HFILTER_' .. symbol_suffix .. '_NORESOLVE_MX', 1.0)
            end
          end

          task:get_resolver():resolve('a', {
            task=task,
            name = mx['name'],
            callback = check_host_cb_mx_a
          })
          task:get_resolver():resolve('aaaa', {
            task = task,
            name = mx['name'],
            callback = check_host_cb_mx_a
          })
        end
      end
    end
  end
  local function check_host_cb_a(resolver, to_resolve, results, err)
    task:inc_dns_req()

    if not results then
      failed_address = failed_address + 1
    else
      for _,result in pairs(results) do
        table.insert(resolved_address, result:to_string())
      end
    end

    if failed_address >= 2 then
      -- No A or AAAA records
      if eq_ip and eq_ip ~= '' then
        for _,result in pairs(resolved_address) do
          if result == eq_ip then
            return true
          end
        end
        task:insert_result('HFILTER_' .. symbol_suffix .. '_IP_A', 1.0)
      end
      task:get_resolver():resolve_mx({
        task = task,
        name = host,
        callback = check_host_cb_mx
      })
    end
  end

  if host then
    host = string.lower(host)
  else
    return false
  end
  if eq_host then
    eq_host = string.lower(eq_host)
  else
    eq_host = ''
  end

  if check_fqdn(host) then
    if eq_host == '' or eq_host ~= 'unknown' or eq_host ~= host then
      task:get_resolver():resolve('a', {
        task=task,
        name = host,
        callback = check_host_cb_a
      })
      -- Check ipv6 as well
      task:get_resolver():resolve('aaaa', {
        task = task,
        name = host,
        callback = check_host_cb_a
      })
    end
  else
    task:insert_result('HFILTER_' .. symbol_suffix .. '_NOT_FQDN', 1.0)
  end

  return true
end

--
local function hfilter(task)
  -- Links checks
  if config['url_enabled'] then
    local parts = task:get_text_parts()
    if parts then
      local plain_text_part = nil
      local html_text_part = nil
      for _,p in ipairs(parts) do
        if p:is_html() then
          html_text_part = p
        else
          plain_text_part = p
        end
      end

      if html_text_part then
        local hc = html_text_part:get_html()
        if hc then
          local url_len = 0
          hc:foreach_tag('a', function(tag, len)
            url_len = url_len + len
            return false
          end)

          local plen = html_text_part:get_length()

          if url_len > 0 and plen > 0 then
            local rel = url_len / plen
            if rel > 0.8 then
              task:insert_result('HFILTER_URL_ONLY', (rel - 0.8) * 5.0)
              local lines =  html_text_part:get_lines_count()
              if lines > 0 and lines < 2 then
                task:insert_result('HFILTER_URL_ONELINE', 1.00)
              end
            end
          end
        elseif plain_text_part then
          local url_len = plain_text_part:get_urls_length()
          local plen = plain_text_part:get_length()

          if plen > 0 and url_len > 0 then
            local rel = url_len / plen
            if rel > 0.8 then
              task:insert_result('HFILTER_URL_ONLY', (rel - 0.8) * 5.0)
              local lines =  plain_text_part:get_lines_count()
              if lines > 0 and lines < 2 then
                task:insert_result('HFILTER_URL_ONELINE', 1.00)
              end
            end
          end
        end
      end
    end
  end

  --No more checks for auth user
  if task:get_user() ~= nil then
    return false
  end

  --local message = task:get_message()
  local ip = false
  local rip = task:get_from_ip()
  if rip and rip:is_valid() then
    ip = rip:to_string()
  end

  -- Check's HELO
  local weight_helo = 0
  if config['helo_enabled'] then
    local helo = task:get_helo()
    if helo then
      if helo ~= rspamc_local_helo then
        helo = string.gsub(helo, '[%[%]]', '')
        -- Regexp check HELO (checks_hello_badip)
        local find_badip = false
        for regexp,weight in pairs(checks_hello_badip) do
          if check_regexp(helo, regexp) then
            task:insert_result('HFILTER_HELO_BADIP', 1.0)
            find_badip = true
            break
          end
        end

        -- Regexp check HELO (checks_hello_bareip)
        local find_bareip = false
        if not find_badip then
          for _,regexp in pairs(checks_hello_bareip) do
            if check_regexp(helo, regexp) then
              task:insert_result('HFILTER_HELO_BAREIP', 1.0)
              find_bareip = true
              break
            end
          end
        end

        if not find_badip and not find_bareip then
          -- Regexp check HELO (checks_hello)
          for regexp,weight in pairs(checks_hello) do
            if check_regexp(helo, regexp) then
              weight_helo = weight
              break
            end
          end
          -- Regexp check HELO (checks_hellohost)
          for regexp,weight in pairs(checks_hellohost) do
            if check_regexp(helo, regexp) then
              if weight > weight_helo then
                weight_helo = weight
              end
              break
            end
          end
          --FQDN check HELO
          if ip and helo and weight_helo == 0 then
            check_host(task, helo, 'HELO', ip)
          end
        end
      end
    end
  end

  -- Check's HOSTNAME
  local weight_hostname = 0
  if config['hostname_enabled'] then
    local hostname = task:get_hostname()
    if hostname then
      -- Check regexp HOSTNAME
      if hostname == 'unknown' then
        task:insert_result('HFILTER_HOSTNAME_UNKNOWN', 1.00)
      else
        for regexp,weight in pairs(checks_hellohost) do
          if check_regexp(hostname, regexp) then
            weight_hostname = weight
            break
          end
        end
      end
    end
  end

  --Insert weight's for HELO or HOSTNAME
  if weight_helo > 0 and weight_helo >= weight_hostname then
    task:insert_result('HFILTER_HELO_' .. weight_helo, 1.0)
  elseif weight_hostname > 0 and weight_hostname > weight_helo then
    task:insert_result('HFILTER_HOSTNAME_' .. weight_hostname, 1.0)
  end

  -- MAILFROM checks --
  local frombounce = false
  if config['from_enabled'] then
    local from = task:get_from(1)
    if from then
      --FROM host check
      for _,fr in ipairs(from) do
        local fr_split = rspamd_str_split(fr['addr'], '@')
        if table.maxn(fr_split) == 2 then
          check_host(task, fr_split[2], 'FROMHOST', '', '')
          if fr_split[1] == 'postmaster' then
            frombounce = true
          end
        end
      end
    else
      if helo and helo ~= rspamc_local_helo then
        task:insert_result('HFILTER_FROM_BOUNCE', 1.00)
        frombounce = true
      end
    end
  end

  -- Recipients checks --
  if config['rcpt_enabled'] then
    local rcpt = task:get_recipients()
    if rcpt then
      local count_rcpt = table.maxn(rcpt)
      if frombounce then
        if count_rcpt > 1 then
          task:insert_result('HFILTER_RCPT_BOUNCEMOREONE', 1.00)
        end
      end
    end
  end

  --Message ID host check
  if config['mid_enabled'] then
    local message_id = task:get_message_id()
    if message_id then
      local mid_split = rspamd_str_split(message_id, '@')
      if table.maxn(mid_split) == 2 and not string.find(mid_split[2], 'local') then
        check_host(task, mid_split[2], 'MID')
      end
    end
  end

  return false
end

local symbols_enabled = {}

local symbols_helo = {
  "HFILTER_HELO_BAREIP",
  "HFILTER_HELO_BADIP",
  "HFILTER_HELO_1",
  "HFILTER_HELO_2",
  "HFILTER_HELO_3",
  "HFILTER_HELO_4",
  "HFILTER_HELO_5",
  "HFILTER_HELO_NORESOLVE_MX",
  "HFILTER_HELO_NORES_A_OR_MX",
  "HFILTER_HELO_IP_A",
  "HFILTER_HELO_NOT_FQDN"
}
local symbols_hostname = {
  "HFILTER_HOSTNAME_1",
  "HFILTER_HOSTNAME_2",
  "HFILTER_HOSTNAME_3",
  "HFILTER_HOSTNAME_4",
  "HFILTER_HOSTNAME_5",
  "HFILTER_HOSTNAME_UNKNOWN"
}
local symbols_rcpt = {
  "HFILTER_RCPT_BOUNCEMOREONE"
}
local symbols_mid = {
  "HFILTER_MID_NORESOLVE_MX",
  "HFILTER_MID_NORES_A_OR_MX",
  "HFILTER_MID_NOT_FQDN"
}
local symbols_url = {
  "HFILTER_URL_ONLY",
  "HFILTER_URL_ONELINE"
}
local symbols_from = {
  "HFILTER_FROMHOST_NORESOLVE_MX",
  "HFILTER_FROMHOST_NORES_A_OR_MX",
  "HFILTER_FROMHOST_NOT_FQDN",
  "HFILTER_FROM_BOUNCE"
}

local opts = rspamd_config:get_all_opt('hfilter')
if opts then
  for k,v in pairs(opts) do
    config[k] = v
  end
end

local function append_t(t, a)
  for _,v in ipairs(a) do table.insert(t, v) end
end
if config['helo_enabled'] then
  append_t(symbols_enabled, symbols_helo)
end
if config['hostname_enabled'] then
  append_t(symbols_enabled, symbols_hostname)
end
if config['from_enabled'] then
  append_t(symbols_enabled, symbols_from)
end
if config['rcpt_enabled'] then
  append_t(symbols_enabled, symbols_rcpt)
end
if config['mid_enabled'] then
  append_t(symbols_enabled, symbols_mid)
end
if config['url_enabled'] then
  append_t(symbols_enabled, symbols_url)
end

--dumper(symbols_enabled)
if table.maxn(symbols_enabled) > 0 then
  rspamd_config:register_symbols(hfilter, 1.0, "HFILTER", symbols_enabled);
end
