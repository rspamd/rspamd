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


-- Weight for checks_hellohost and checks_hello: 5 - very hard, 4 - hard, 3 - medium, 2 - low, 1 - very low.
-- From HFILTER_HELO_* and HFILTER_HOSTNAME_* symbols the maximum weight is selected in case of their actuating.

if confighelp then
  return
end

local rspamd_regexp = require "rspamd_regexp"
local lua_util = require "lua_util"
local rspamc_local_helo = "rspamc.local"
local checks_hellohost = [[
/[-.0-9][0-9][.-]?nat/i 5
/homeuser[.-][0-9]/i 5
/[-.0-9][0-9][.-]?unused-addr/i 3
/[-.0-9][0-9][.-]?pppoe/i 5
/[-.0-9][0-9][.-]?dynamic/i 5
/[.-]catv[.-]/i 5
/unused-addr[.-][0-9]/i 3
/comcast[.-][0-9]/i 5
/[.-]broadband[.-]/i 5
/[0-9][.-]?fbx/i 4
/[.-]peer[.-]/i 1
/[.-]homeuser[.-]/i 5
/[-.0-9][0-9][.-]?catv/i 5
/customers?[.-][0-9]/i 1
/[.-]wifi[.-]/i 5
/[0-9][.-]?kabel/i 3
/dynip[.-][0-9]/i 5
/[.-]broad[.-]/i 5
/[a|x]?dsl-line[.-]?[0-9]/i 4
/[-.0-9][0-9][.-]?ppp/i 5
/pool[.-][0-9]/i 4
/[.-]nat[.-]/i 5
/gprs[.-][0-9]/i 5
/brodband[.-][0-9]/i 5
/[.-]gprs[.-]/i 5
/[.-]user[.-]/i 1
/[-.0-9][0-9][.-]?in-?addr/i 4
/[.-]host[.-]/i 2
/[.-]fbx[.-]/i 4
/dynamic[.-][0-9]/i 5
/[-.0-9][0-9][.-]?peer/i 1
/[-.0-9][0-9][.-]?pool/i 4
/[-.0-9][0-9][.-]?user/i 1
/[.-]cdma[.-]/i 5
/user[.-][0-9]/i 1
/[-.0-9][0-9][.-]?customers?/i 1
/ppp[.-][0-9]/i 5
/kabel[.-][0-9]/i 3
/dhcp[.-][0-9]/i 5
/peer[.-][0-9]/i 1
/[-.0-9][0-9][.-]?host/i 2
/clients?[.-][0-9]{2,}/i 5
/host[.-][0-9]/i 2
/[.-]ppp[.-]/i 5
/[.-]dhcp[.-]/i 5
/[.-]comcast[.-]/i 5
/cable[.-][0-9]/i 3
/[-.0-9][0-9][.-]?dial-?up/i 5
/[-.0-9][0-9][.-]?bredband/i 5
/[-.0-9][0-9][.-]?[a|x]?dsl-line/i 4
/[.-]dial-?up[.-]/i 5
/[.-]cablemodem[.-]/i 5
/pppoe[.-][0-9]/i 5
/[.-]unused-addr[.-]/i 3
/pptp[.-][0-9]/i 5
/broadband[.-][0-9]/i 5
/[.-][a|x]?dsl-line[.-]/i 4
/[.-]customers?[.-]/i 1
/[-.0-9][0-9][.-]?fibertel/i 4
/[-.0-9][0-9][.-]?comcast/i 5
/[.-]dynamic[.-]/i 5
/cdma[.-][0-9]/i 5
/[0-9][.-]?broad/i 5
/fbx[.-][0-9]/i 4
/catv[.-][0-9]/i 5
/[-.0-9][0-9][.-]?homeuser/i 5
/[-.0-9][.-]pppoe[.-]/i 5
/[-.0-9][.-]dynip[.-]/i 5
/[-.0-9][0-9][.-]?[a|x]?dsl/i 4
/[-.0-9][0-9]{3,}[.-]?clients?/i 5
/[-.0-9][0-9][.-]?pptp/i 5
/[.-]clients?[.-]/i 1
/[.-]in-?addr[.-]/i 4
/[.-]pool[.-]/i 4
/[a|x]?dsl[.-]?[0-9]/i 4
/[.-][a|x]?dsl[.-]/i 4
/[-.0-9][0-9][.-]?[a|x]?dsl-dynamic/i 5
/dial-?up[.-][0-9]/i 5
/[-.0-9][0-9][.-]?cablemodem/i 5
/[a|x]?dsl-dynamic[.-]?[0-9]/i 5
/[.-]pptp[.-]/i 5
/[.-][a|x]?dsl-dynamic[.-]/i 5
/[0-9][.-]?wifi/i 5
/fibertel[.-][0-9]/i 4
/dyn[.-][0-9][-.0-9]/i 5
/[-.0-9][0-9][.-]broadband/i 5
/[-.0-9][0-9][.-]cable/i 3
/broad[.-][0-9]/i 5
/[-.0-9][0-9][.-]gprs/i 5
/cablemodem[.-][0-9]/i 5
/[-.0-9][0-9][.-]modem/i 5
/[-.0-9][0-9][.-]dyn/i 5
/[-.0-9][0-9][.-]dynip/i 5
/[-.0-9][0-9][.-]cdma/i 5
/[.-]modem[.-]/i 5
/[.-]kabel[.-]/i 3
/[.-]cable[.-]/i 3
/in-?addr[.-][0-9]/i 4
/nat[.-][0-9]/i 5
/[.-]fibertel[.-]/i 4
/[.-]bredband[.-]/i 5
/modem[.-][0-9]/i 5
/[0-9][.-]?dhcp/i 5
/wifi[.-][0-9]/i 5
]]
local checks_hellohost_map

local checks_hello = [[
/^[^\.]+$/i 5 # for helo=COMPUTER, ANNA, etc... Without dot in helo
/^(dsl)?(device|speedtouch)\.lan$/i 5
/\.(lan|local|home|localdomain|intra|in-addr.arpa|priv|user|veloxzon)$ 5
]]
local checks_hello_map

local checks_hello_badip = [[
/^\d\.\d\.\d\.255$/i 1
/^192\.0\.0\./i 1
/^2001:db8::/i 1
/^10\./i 1
/^192\.0\.2\./i 1
/^172\.1[6-9]\./i 1
/^192\.168\./i 1
/^::1$/i 1 # loopback ipv4, ipv6
/^ffxx::/i 1
/^fc00::/i 1
/^203\.0\.113\./i 1
/^fe[cdf][0-9a-f]:/i 1
/^100.12[0-7]\d\./i 1
/^fe[89ab][0-9a-f]::/i 1
/^169\.254\./i 1
/^0\./i 1
/^198\.51\.100\./i 1
/^172\.3[01]\./i 1
/^100.[7-9]\d\./i 1
/^100.1[01]\d\./i 1
/^127\./i 1
/^100.6[4-9]\./i 1
/^192\.88\.99\./i 1
/^172\.2[0-9]\./i 1
]]
local checks_hello_badip_map

local checks_hello_bareip = [[
/^\d+[x.-]\d+[x.-]\d+[x.-]\d+$/
/^[0-9a-f]+:/
]]
local checks_hello_bareip_map

local config = {
  ['helo_enabled'] = false,
  ['hostname_enabled'] = false,
  ['from_enabled'] = false,
  ['rcpt_enabled'] = false,
  ['mid_enabled'] = false,
  ['url_enabled'] = false
}

local compiled_regexp = {} -- cache of regexps
local check_local = false
local check_authed = false
local N = "hfilter"

local function check_regexp(str, regexp_text)
  local re = compiled_regexp[regexp_text]
  if not re then
    re = rspamd_regexp.create(regexp_text, 'i')
    compiled_regexp[regexp_text] = re
  end

  return re:match(str)
end

local function add_static_map(data)
  return rspamd_config:add_map{
    type = 'regexp_multi',
    url = {
      upstreams = 'static',
      data = data,
    }
  }
end

local function check_fqdn(domain)
  if check_regexp(domain,
      '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z0-9-]{2,63}\\.?$)') then
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

  local function check_host_cb_mx(_, to_resolve, results, err)
    if err and (err ~= 'requested record is not found' and err ~= 'no records with this name') then
        lua_util.debugm(N, task, 'error looking up %s: %s', to_resolve, err)
    end
    if not results then
      task:insert_result('HFILTER_' .. symbol_suffix .. '_NORES_A_OR_MX', 1.0,
        to_resolve)
    else
      for _,mx in pairs(results) do
        if mx['name'] then
          local failed_mx_address = 0
          -- Capture failed_mx_address
          local function check_host_cb_mx_a(_, _, mx_results)
            if not mx_results then
              failed_mx_address = failed_mx_address + 1
            end

            if failed_mx_address >= 2 then
              task:insert_result('HFILTER_' .. symbol_suffix .. '_NORESOLVE_MX',
                1.0, mx['name'])
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
  local function check_host_cb_a(_, _, results)
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
        task:insert_result('HFILTER_' .. symbol_suffix .. '_IP_A', 1.0, host)
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
    if eq_host == '' or eq_host ~= host then
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
    task:insert_result('HFILTER_' .. symbol_suffix .. '_NOT_FQDN', 1.0, host)
  end

  return true
end

--
local function hfilter_callback(task)
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
      local hc = nil
      if html_text_part then
        hc = html_text_part:get_html()
        if hc then
          local url_len = 0
          hc:foreach_tag('a', function(_, len)
            url_len = url_len + len
            return false
          end)

          local plen = html_text_part:get_length()

          if url_len > 0 and plen > 0 then
            local rel = url_len / plen
            if rel > 0.8 then
              local sc = (rel - 0.8) * 5.0
              if sc > 1.0 then sc = 1.0 end
              task:insert_result('HFILTER_URL_ONLY', sc, tostring(sc))
              local lines =  html_text_part:get_lines_count()
              if lines > 0 and lines < 2 then
                task:insert_result('HFILTER_URL_ONELINE', 1.00,
                  string.format('html:%d:%d', math.floor(sc), lines))
              end
            end
          end
        end
      end
      if not hc and plain_text_part then
        local url_len = plain_text_part:get_urls_length()
        local plen = plain_text_part:get_length()

        if plen > 0 and url_len > 0 then
          local rel = url_len / plen
          if rel > 0.8 then
            local sc = (rel - 0.8) * 5.0
            if sc > 1.0 then sc = 1.0 end
            task:insert_result('HFILTER_URL_ONLY', sc, tostring(sc))
            local lines = plain_text_part:get_lines_count()
            if lines > 0 and lines < 2 then
              task:insert_result('HFILTER_URL_ONELINE', 1.00,
                string.format('plain:%d:%d', math.floor(rel), lines))
            end
          end
        end
      end
    end
  end

  --No more checks for auth user or local network
  local rip = task:get_from_ip()
  if ((not check_authed and task:get_user()) or
      (not check_local and rip and rip:is_local())) then
    return false
  end

  --local message = task:get_message()
  local ip = false
  if rip and rip:is_valid() then
    ip = rip:to_string()
  end

  -- Check's HELO
  local weight_helo = 0
  local helo
  if config['helo_enabled'] then
    helo = task:get_helo()
    if helo then
      if helo ~= rspamc_local_helo then
        helo = string.gsub(helo, '[%[%]]', '')
        -- Regexp check HELO (checks_hello_badip)
        local find_badip = false
        local values = checks_hello_badip_map:get_key(helo)
        if values then
          task:insert_result('HFILTER_HELO_BADIP', 1.0, helo, values)
          find_badip = true
        end

        -- Regexp check HELO (checks_hello_bareip)
        local find_bareip = false
        if not find_badip then
          values = checks_hello_bareip_map:get_key(helo)
          if values then
            task:insert_result('HFILTER_HELO_BAREIP', 1.0, helo, values)
            find_bareip = true
          end
        end

        if not find_badip and not find_bareip then
          -- Regexp check HELO (checks_hello)
          local weights = checks_hello_map:get_key(helo)
          for _,weight in ipairs(weights or {}) do
            weight = tonumber(weight) or 0
            if weight > weight_helo then
              weight_helo = weight
            end
          end
          -- Regexp check HELO (checks_hellohost)
          weights = checks_hellohost_map:get_key(helo)
          for _,weight in ipairs(weights or {}) do
            weight = tonumber(weight) or 0
            if weight > weight_helo then
              weight_helo = weight
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
  local hostname = task:get_hostname()

  if config['hostname_enabled'] then
    if hostname then
      -- Check regexp HOSTNAME
      local weights = checks_hellohost_map:get_key(hostname)
      for _,weight in ipairs(weights or {}) do
        weight = tonumber(weight) or 0
        if weight > weight_hostname then
          weight_hostname = weight
        end
      end
    else
      task:insert_result('HFILTER_HOSTNAME_UNKNOWN', 1.00)
    end
  end

  --Insert weight's for HELO or HOSTNAME
  if weight_helo > 0 and weight_helo >= weight_hostname then
    task:insert_result('HFILTER_HELO_' .. weight_helo, 1.0, helo)
  elseif weight_hostname > 0 and weight_hostname > weight_helo then
    task:insert_result('HFILTER_HOSTNAME_' .. weight_hostname, 1.0, hostname)
  end

  -- MAILFROM checks --
  local frombounce = false
  if config['from_enabled'] then
    local from = task:get_from(1)
    if from then
      --FROM host check
      for _,fr in ipairs(from) do
        local fr_split = rspamd_str_split(fr['addr'], '@')
        if #fr_split == 2 then
          check_host(task, fr_split[2], 'FROMHOST', '', '')
          if fr_split[1] == 'postmaster' then
            frombounce = true
          end
        end
      end
    else
      if helo and helo ~= rspamc_local_helo then
        task:insert_result('HFILTER_FROM_BOUNCE', 1.00, helo)
        frombounce = true
      end
    end
  end

  -- Recipients checks --
  if config['rcpt_enabled'] then
    local rcpt = task:get_recipients()
    if rcpt then
      local count_rcpt = #rcpt
      if frombounce then
        if count_rcpt > 1 then
          task:insert_result('HFILTER_RCPT_BOUNCEMOREONE', 1.00,
            tostring(count_rcpt))
        end
      end
    end
  end

  --Message ID host check
  if config['mid_enabled'] then
    local message_id = task:get_message_id()
    if message_id then
      local mid_split = rspamd_str_split(message_id, '@')
      if #mid_split == 2 and not string.find(mid_split[2], 'local') then
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

local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
    false, false)
check_local = auth_and_local_conf[1]
check_authed = auth_and_local_conf[2]

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
  checks_hello_bareip_map = add_static_map(checks_hello_bareip)
  checks_hello_badip_map = add_static_map(checks_hello_badip)
  checks_hellohost_map = add_static_map(checks_hellohost)
  checks_hello_map = add_static_map(checks_hello)
  append_t(symbols_enabled, symbols_helo)
end
if config['hostname_enabled'] then
  if not checks_hellohost_map then
    checks_hellohost_map = add_static_map(checks_hellohost)
  end
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
if #symbols_enabled > 0 then
  local id = rspamd_config:register_symbol{
    name = 'HFILTER',
    callback = hfilter_callback,
    type = 'callback,mime',
    score = 0.0,
  }
  rspamd_config:set_metric_symbol({
    name = 'HFILTER',
    score = 0.0,
    group = 'hfilter'
  })
  for _,sym in ipairs(symbols_enabled) do
    rspamd_config:register_symbol{
      type = 'virtual,mime',
      score = 1.0,
      parent = id,
      name = sym,
    }
    rspamd_config:set_metric_symbol({
      name = sym,
      score = 0.0,
      group = 'hfilter'
    })
  end
else
  lua_util.disable_module(N, "config")
end
