--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2019, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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

--[[
@module icap
This module contains icap access functions.
Currently tested with
 - Symantec (Rspam <3.2)
 - Sophos Savdi
 - ClamAV/c-icap
 - Kaspersky Web Traffic Security
 - Trend Micro IWSVA
 - F-Secure Internet Gatekeeper
 - McAfee Web Gateway

@TODO
 - Preview / Continue
 - Reqmod URL's
 - Content-Type / Filename
]] --

--[[
Configuration Notes:

C-ICAP Squidclamav
  scheme = "squidclamav";

ESET Gateway Security / Antivirus for Linux example:
  scheme = "scan";

F-Secure Internet Gatekeeper example:
  scheme = "respmod";
  x_client_header = true;
  x_rcpt_header = true;
  x_from_header = true;

Kaspersky Web Traffic Security example:
  scheme = "av/respmod";

McAfee Web Gateway 11 (Headers must be activated with personal extra Rules)
  scheme = "respmod";
  x_client_header = true;

Sophos SAVDI example:
  scheme as configured in savdi.conf

Symantec example:
  scheme = "avscan";

Trend Micro IWSVA example:
  scheme = "avscan";
]] --


local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"
local rspamd_util = require "rspamd_util"
local rspamd_version = rspamd_version


local N = 'icap'

local function icap_config(opts)

  local icap_conf = {
    name = N,
    scan_mime_parts = true,
    scan_all_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    scheme = "scan",
    default_port = 1344,
    ssl = false,
    no_ssl_verify = false,
    timeout = 10.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: threat found with icap scanner: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    dynamic_scan = false,
    user_agent = "Rspamd",
    x_client_header = false,
    x_rcpt_header = false,
    x_from_header = false,
    req_headers_enabled = true,
    req_fake_url = "http://127.0.0.1/mail",
    http_headers_enabled = true,
  }

  icap_conf = lua_util.override_defaults(icap_conf, opts)

  if not icap_conf.prefix then
    icap_conf.prefix = 'rs_' .. icap_conf.name .. '_'
  end

  if not icap_conf.log_prefix then
    icap_conf.log_prefix = icap_conf.name .. ' (' .. icap_conf.type .. ')'
  end

  if not icap_conf.log_prefix then
    if icap_conf.name:lower() == icap_conf.type:lower() then
      icap_conf.log_prefix = icap_conf.name
    else
      icap_conf.log_prefix = icap_conf.name .. ' (' .. icap_conf.type .. ')'
    end
  end

  if not icap_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  icap_conf.upstreams = upstream_list.create(rspamd_config,
    icap_conf.servers,
    icap_conf.default_port)

  if icap_conf.upstreams then
    lua_util.add_debug_alias('external_services', icap_conf.name)
    return icap_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    icap_conf.servers)
  return nil
end

local function icap_check(task, content, digest, rule, maybe_part)
  local function icap_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local http_headers = {}
    local req_headers = {}
    local tcp_options = {}

    -- Build extended User Agent
    if rule.user_agent == "extended" then
      rule.user_agent = string.format("Rspamd/%s-%s (%s/%s)",
          rspamd_version('main'),
          rspamd_version('id'),
          rspamd_util.get_hostname(),
          string.sub(task:get_uid(), 1,6))
    end

    -- Build the icap queries
    local options_request = {
      string.format("OPTIONS icap://%s/%s ICAP/1.0\r\n", addr:to_string(), rule.scheme),
      string.format('Host: %s\r\n', addr:to_string()),
      string.format("User-Agent: %s\r\n", rule.user_agent),
      "Encapsulated: null-body=0\r\n\r\n",
    }
    if rule.user_agent == "none" then
      table.remove(options_request, 3)
    end

    local respond_headers = {
        -- Add main RESPMOD header before any other
        string.format('RESPMOD icap://%s/%s ICAP/1.0\r\n', addr:to_string(), rule.scheme),
        string.format('Host: %s\r\n', addr:to_string()),
    }

    local size = tonumber(#content)
    local chunked_size = string.format("%x", size)

    local function icap_callback(err, conn)

      local function icap_requery(err_m, info)
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          lua_util.debugm(rule.name, task,
              '%s: %s Request Error: %s - retries left: %s',
              rule.log_prefix, info, err_m, retransmits)

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s',
            rule.log_prefix, addr, addr:get_port())

          tcp_options.host = addr:to_string()
          tcp_options.port = addr:get_port()

          tcp.request(tcp_options)

        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
            'exceed - error: %s', rule.log_prefix, err_m or '')
          common.yield_result(task, rule, 'failed - error: ' .. err_m or '',
              0.0, 'fail', maybe_part)
        end
      end

      local function get_req_headers()

        local req_hlen = 2
        table.insert(req_headers, string.format('GET %s HTTP/1.0\r\n', rule.req_fake_url))
        table.insert(req_headers, string.format('Date: %s\r\n', rspamd_util.time_to_string(rspamd_util.get_time())))
        --table.insert(http_headers, string.format('Content-Type: %s\r\n', 'text/html'))
        if rule.user_agent ~= "none" then 
          table.insert(req_headers, string.format("User-Agent: %s\r\n", rule.user_agent))
        end

        for _, h in ipairs(req_headers) do
          req_hlen = req_hlen + tonumber(#h)
        end

        return req_hlen, req_headers

      end

      local function get_http_headers()
        local http_hlen = 2
        table.insert(http_headers, 'HTTP/1.0 200 OK\r\n')
        table.insert(http_headers, string.format('Date: %s\r\n', rspamd_util.time_to_string(rspamd_util.get_time())))
        table.insert(http_headers, string.format('Server: %s\r\n', 'Apache/2.4'))
        if rule.user_agent ~= "none" then 
          table.insert(http_headers, string.format("User-Agent: %s\r\n", rule.user_agent))
        end
        --table.insert(http_headers, string.format('Content-Type: %s\r\n', 'text/html'))
        table.insert(http_headers, string.format('Content-Length: %s\r\n', size))

        for _, h in ipairs(http_headers) do
          http_hlen = http_hlen + tonumber(#h)
        end

        return http_hlen, http_headers

      end

      local function get_respond_query()
        local req_hlen = 0
        local resp_req_headers
        local http_hlen = 0
        local resp_http_headers

        -- Append all extra headers
        if rule.user_agent ~= "none" then 
          table.insert(respond_headers, string.format("User-Agent: %s\r\n", rule.user_agent))
        end

        if rule.req_headers_enabled then
          req_hlen, resp_req_headers = get_req_headers()
        end
        if rule.http_headers_enabled then
          http_hlen, resp_http_headers = get_http_headers()
        end

        if rule.req_headers_enabled and rule.http_headers_enabled then
          local res_body_hlen = req_hlen + http_hlen
          table.insert(respond_headers, string.format('Encapsulated: req-hdr=0, res-hdr=%s, res-body=%s\r\n', req_hlen, res_body_hlen))
        elseif rule.http_headers_enabled then
          table.insert(respond_headers, string.format('Encapsulated: res-hdr=0, res-body=%s\r\n', http_hlen))
        else
          table.insert(respond_headers, 'Encapsulated: res-body=0\r\n')
        end

        table.insert(respond_headers, '\r\n')
        for _,h in ipairs(resp_req_headers) do table.insert(respond_headers, h) end
        table.insert(respond_headers, '\r\n')
        for _,h in ipairs(resp_http_headers) do table.insert(respond_headers, h) end
        table.insert(respond_headers, '\r\n')
        table.insert(respond_headers, chunked_size .. '\r\n')
        table.insert(respond_headers, content)
        table.insert(respond_headers, '\r\n0\r\n\r\n')
        return respond_headers
      end

      local function add_respond_header(name, value)
        if name and value then
          table.insert(respond_headers, string.format('%s: %s\r\n', name, value))
        end
      end

      local function icap_result_header_table(result)
        local icap_headers = {}
        for s in result:gmatch("[^\r\n]+") do
          if string.find(s, '^ICAP') then
            icap_headers['icap'] = tostring(s)
          end
          if string.find(s, '[%a%d-+]-:') then
            local _,_,key,value = tostring(s):find("([%a%d-+]-):%s?(.+)")
            if key ~= nil then
              icap_headers[key] = tostring(value)
            end
          end
        end
        lua_util.debugm(rule.name, task, '%s: icap_headers: %s',
            rule.log_prefix, icap_headers)
        return icap_headers
      end

      local function icap_parse_result(icap_headers)

        local threat_string = {}

        --[[
        @ToDo: handle type in response

        Generic Strings:
          X-Infection-Found: Type=0; Resolution=2; Threat=Troj/DocDl-OYC;
          X-Infection-Found: Type=0; Resolution=2; Threat=W97M.Downloader;

        Symantec String:
          X-Infection-Found: Type=2; Resolution=2; Threat=Container size violation
          X-Infection-Found: Type=2; Resolution=2; Threat=Encrypted container violation;

        Sophos Strings:
          X-Virus-ID: Troj/DocDl-OYC

        Kaspersky Web Traffic Security Strings:
          X-Virus-ID: HEUR:Backdoor.Java.QRat.gen
          X-Response-Info: blocked
          X-Virus-ID: no threats
          X-Response-Info: blocked
          X-Response-Info: passed

        Trend Micro IWSVA Strings:
          X-Virus-ID: Trojan.W97M.POWLOAD.SMTHF1
          X-Infection-Found: Type=0; Resolution=2; Threat=Trojan.W97M.POWLOAD.SMTHF1;

        F-Secure Internet Gatekeeper Strings:
          X-FSecure-Scan-Result: infected
          X-FSecure-Infection-Name: "Malware.W97M/Agent.32584203"
          X-FSecure-Infected-Filename: "virus.doc"

        ESET File Security for Linux 7.0
          X-Infection-Found: Type=0; Resolution=0; Threat=VBA/TrojanDownloader.Agent.JOA;
          X-Virus-ID: Trojaner
          X-Response-Info: Blocked

        McAfee Web Gateway 11 (Headers must be activated with personal extra Rules)
          X-Virus-ID: EICAR test file
          X-Media-Type: text/plain
          X-Block-Result: 80
          X-Block-Reason: Malware found
          X-Block-Reason: Archive not supported
          X-Block-Reason: Media Type (Block List)

        C-ICAP Squidclamav
          X-Infection-Found: Type=0; Resolution=2; Threat={HEX}EICAR.TEST.3.UNOFFICIAL;
          X-Virus-ID: {HEX}EICAR.TEST.3.UNOFFICIAL
        ]] --

        -- Generic ICAP Headers
        if icap_headers['X-Infection-Found'] then
          local _,_,icap_type,_,icap_threat =
            icap_headers['X-Infection-Found']:find("Type=(.-); Resolution=(.-); Threat=(.-);$")

          if not icap_type or icap_type == 2 then
            -- error returned
            lua_util.debugm(rule.name, task,
                '%s: icap error X-Infection-Found: %s', rule.log_prefix, icap_threat)
            common.yield_result(task, rule, icap_threat, 0,
                'fail', maybe_part)
          else
            lua_util.debugm(rule.name, task,
                '%s: icap X-Infection-Found: %s', rule.log_prefix, icap_threat)
            table.insert(threat_string, icap_threat)
          end

        elseif icap_headers['X-Virus-ID'] and icap_headers['X-Virus-ID'] ~= "no threats" then
          lua_util.debugm(rule.name, task,
              '%s: icap X-Virus-ID: %s', rule.log_prefix, icap_headers['X-Virus-ID'])

          if string.find(icap_headers['X-Virus-ID'], ', ') then
            local vnames = lua_util.str_split(string.gsub(icap_headers['X-Virus-ID'], "%s", ""), ',') or {}

            for _,v in ipairs(vnames) do
              table.insert(threat_string, v)
            end
          else
            table.insert(threat_string, icap_headers['X-Virus-ID'])
          end
        -- FSecure X-Headers
        elseif icap_headers['X-FSecure-Scan-Result'] and icap_headers['X-FSecure-Scan-Result'] ~= "clean" then

          local infected_filename = ""
          local infection_name = "-unknown-"

          if icap_headers['X-FSecure-Infected-Filename'] then
            infected_filename = string.gsub(icap_headers['X-FSecure-Infected-Filename'], '[%s"]', '')
          end
          if icap_headers['X-FSecure-Infection-Name'] then
            infection_name = string.gsub(icap_headers['X-FSecure-Infection-Name'], '[%s"]', '')
          end

          lua_util.debugm(rule.name, task,
              '%s: icap X-FSecure-Infection-Name (X-FSecure-Infected-Filename): %s (%s)',
              rule.log_prefix, infection_name, infected_filename)

          if string.find(infection_name, ', ') then
            local vnames = lua_util.str_split(infection_name, ',') or {}

            for _,v in ipairs(vnames) do
              table.insert(threat_string, v)
            end
          else
            table.insert(threat_string, infection_name)
          end
        -- McAfee Web Gateway manual extra headers
        elseif icap_headers['X-MWG-Block-Reason'] and icap_headers['X-MWG-Block-Reason'] ~= "" then
          table.insert(threat_string, icap_headers['X-MWG-Block-Reason'])
        end

        if #threat_string > 0 then
          common.yield_result(task, rule, threat_string, rule.default_score, nil, maybe_part)
          common.save_cache(task, digest, rule, threat_string, rule.default_score, maybe_part)
        else
          common.save_cache(task, digest, rule, 'OK', 0, maybe_part)
          common.log_clean(task, rule)
        end
      end

      local function icap_r_respond_cb(err_m, data, connection)
        if err_m or connection == nil then
          icap_requery(err_m, "icap_r_respond_cb")
        else
          local result = tostring(data)
          conn:close()

          local icap_headers = icap_result_header_table(result) or {}
          -- Find ICAP/1.x 2xx response
          if icap_headers.icap and string.find(icap_headers.icap, 'ICAP%/1%.. 2%d%d') then
            icap_parse_result(icap_headers)
          elseif icap_headers.icap and string.find(icap_headers.icap, 'ICAP%/1%.. [45]%d%d') then
            -- Find ICAP/1.x 5/4xx response
            --[[
            Symantec String:
              ICAP/1.0 539 Aborted - No AV scanning license
            SquidClamAV/C-ICAP:
              ICAP/1.0 500 Server error
            ]]--
            rspamd_logger.errx(task, '%s: ICAP ERROR: %s', rule.log_prefix, icap_headers.icap)
            common.yield_result(task, rule, icap_headers.icap, 0.0,
                'fail', maybe_part)
            return false
          else
            rspamd_logger.errx(task, '%s: unhandled response |%s|',
              rule.log_prefix, string.gsub(result, "\r\n", ", "))
            common.yield_result(task, rule,
                'unhandled icap response: ' .. icap_headers.icap or "-",
                0.0, 'fail', maybe_part)
          end
        end
      end

      local function icap_w_respond_cb(err_m, connection)
        if err_m or connection == nil then
          icap_requery(err_m, "icap_w_respond_cb")
        else
          connection:add_read(icap_r_respond_cb, '\r\n\r\n')
        end
      end

      local function icap_r_options_cb(err_m, data, connection)
        if err_m or connection == nil then
          icap_requery(err_m, "icap_r_options_cb")
        else
          local icap_headers = icap_result_header_table(tostring(data))

          if icap_headers.icap and string.find(icap_headers.icap, 'ICAP%/1%.. 2%d%d') then
            if icap_headers['Methods'] and string.find(icap_headers['Methods'], 'RESPMOD') then
              -- Preview is currently ununsed
              --if icap_headers['Allow'] and string.find(icap_headers['Allow'], '204') then
              --  add_respond_header('Allow', '204')
              --end

              if rule.x_client_header then
                local client = task:get_from_ip()
                if client then add_respond_header('X-Client-IP', client:to_string()) end
              end

              -- F-Secure extra headers
              if icap_headers['Server'] and string.find(icap_headers['Server'], 'F-Secure ICAP Server') then

                if rule.x_rcpt_header then
                  local rcpt_to = task:get_principal_recipient()
                  if rcpt_to then add_respond_header('X-Rcpt-To', rcpt_to) end
                end

                if rule.x_from_header then
                  local mail_from = task:get_principal_recipient()
                  if mail_from and mail_from[1] then add_respond_header('X-Rcpt-To', mail_from[1].addr) end
                end

              end

              conn:add_write(icap_w_respond_cb, get_respond_query())

            else
              rspamd_logger.errx(task, '%s: RESPMOD method not advertised: Methods: %s',
                rule.log_prefix, icap_headers['Methods'])
              common.yield_result(task, rule, 'NO RESPMOD', 0.0,
                  'fail', maybe_part)
            end
          else
            rspamd_logger.errx(task, '%s: OPTIONS query failed: %s',
              rule.log_prefix, icap_headers.icap or "-")
            common.yield_result(task, rule, 'OPTIONS query failed', 0.0,
                'fail', maybe_part)
          end
        end
      end

      if err or conn == nil then
        icap_requery(err, "options_request")
      else
        -- set upstream ok
        if upstream then upstream:ok() end
        conn:add_read(icap_r_options_cb, '\r\n\r\n')
      end
    end

    tcp_options.task = task
    tcp_options.stop_pattern = '\r\n'
    tcp_options.read = false
    tcp_options.timeout = rule.timeout
    tcp_options.callback = icap_callback
    tcp_options.data = options_request

    if rule.ssl then
      tcp_options.ssl = true
      if rule.no_ssl_verify then
        tcp_options.no_ssl_verify = true
      end
    end

    tcp_options.host = addr:to_string()
    tcp_options.port = addr:get_port()

    tcp.request(tcp_options)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      icap_check_uncached, maybe_part) then
    return
  else
    icap_check_uncached()
  end

end

return {
  type = {N, 'virus', 'virus', 'scanner'},
  description = 'generic icap antivirus',
  configure = icap_config,
  check = icap_check,
  name = N
}
