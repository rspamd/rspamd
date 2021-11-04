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
 - C-ICAP Squidclamav / echo
 - F-Secure Internet Gatekeeper
 - Kaspersky Web Traffic Security
 - Kaspersky Scan Engine 2.0
 - McAfee Web Gateway 11
 - Sophos Savdi
 - Symantec (Rspamd <3.2, >=3.2 untested)
 - Trend Micro IWSVA 6.0
 - Trend Micro Web Gateway

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
  x_client_header = true;

Kaspersky Web Traffic Security (as configured in kavicapd.xml):
  scheme = "resp";
  x_client_header = true;

McAfee Web Gateway 11 (Headers must be activated with personal extra Rules)
  scheme = "respmod";
  x_client_header = true;

Sophos SAVDI example:
  # scheme as configured in savdi.conf (name option in service section)
  scheme = "respmod";

Symantec example:
  scheme = "avscan";

Trend Micro IWSVA example (X-Virus-ID/X-Infection-Found headers must be activated):
  scheme = "avscan";
  x_client_header = true;

Trend Micro Web Gateway example (X-Virus-ID/X-Infection-Found headers must be activated):
  scheme = "interscan";
  x_client_header = true;
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
    use_http_result_header = true,
    use_http_3xx_as_threat = false,
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
      "Connection: keep-alive\r\n",
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
          tcp_options.callback = icap_callback
          tcp_options.data = options_request

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
          table.insert(respond_headers,
              string.format("User-Agent: %s\r\n", rule.user_agent))
        end

        if rule.req_headers_enabled then
          req_hlen, resp_req_headers = get_req_headers()
        end
        if rule.http_headers_enabled then
          http_hlen, resp_http_headers = get_http_headers()
        end

        if rule.req_headers_enabled and rule.http_headers_enabled then
          local res_body_hlen = req_hlen + http_hlen
          table.insert(respond_headers,
              string.format('Encapsulated: req-hdr=0, res-hdr=%s, res-body=%s\r\n',
                  req_hlen, res_body_hlen))
        elseif rule.http_headers_enabled then
          table.insert(respond_headers,
              string.format('Encapsulated: res-hdr=0, res-body=%s\r\n',
                  http_hlen))
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

      local function result_header_table(result)
        local icap_headers = {}
        for s in result:gmatch("[^\r\n]+") do
          if string.find(s, '^ICAP') then
            icap_headers['icap'] = tostring(s)
          elseif string.find(s, '^HTTP') then
            icap_headers['http'] = tostring(s)
          elseif string.find(s, '[%a%d-+]-:') then
            local _,_,key,value = tostring(s):find("([%a%d-+]-):%s?(.+)")
            if key ~= nil then
              icap_headers[key:lower()] = tostring(value)
            end
          end
        end
        lua_util.debugm(rule.name, task, '%s: icap_headers: %s',
            rule.log_prefix, icap_headers)
        return icap_headers
      end

      local function icap_parse_result(headers)

        local threat_string = {}

        --[[
        @ToDo: handle type in response

        Generic Strings:
          icap: X-Infection-Found: Type=0; Resolution=2; Threat=Troj/DocDl-OYC;
          icap: X-Infection-Found: Type=0; Resolution=2; Threat=W97M.Downloader;

        Symantec String:
          icap: X-Infection-Found: Type=2; Resolution=2; Threat=Container size violation
          icap: X-Infection-Found: Type=2; Resolution=2; Threat=Encrypted container violation;

        Sophos Strings:
          icap: X-Virus-ID: Troj/DocDl-OYC
          http: X-Blocked: Virus found during virus scan
          http: X-Blocked-By: Sophos Anti-Virus

        Kaspersky Web Traffic Security Strings:
          icap: X-Virus-ID: HEUR:Backdoor.Java.QRat.gen
          icap: X-Response-Info: blocked
          icap: X-Virus-ID: no threats
          icap: X-Response-Info: blocked
          icap: X-Response-Info: passed
          http: HTTP/1.1 403 Forbidden

        Kaspersky Scan Engine 2.0 (ICAP mode)
          icap: X-Virus-ID: EICAR-Test-File
          http: HTTP/1.0 403 Forbidden

        Trend Micro Strings:
          icap: X-Virus-ID: Trojan.W97M.POWLOAD.SMTHF1
          icap: X-Infection-Found: Type=0; Resolution=2; Threat=Trojan.W97M.POWLOAD.SMTHF1;
          http: HTTP/1.1 403 Forbidden (TMWS Blocked)
          http: HTTP/1.1 403 Forbidden

        F-Secure Internet Gatekeeper Strings:
          icap: X-FSecure-Scan-Result: infected
          icap: X-FSecure-Infection-Name: "Malware.W97M/Agent.32584203"
          icap: X-FSecure-Infected-Filename: "virus.doc"

        ESET File Security for Linux 7.0
          icap: X-Infection-Found: Type=0; Resolution=0; Threat=VBA/TrojanDownloader.Agent.JOA;
          icap: X-Virus-ID: Trojaner
          icap: X-Response-Info: Blocked

        McAfee Web Gateway 11 (Headers must be activated with personal extra Rules)
          icap: X-Virus-ID: EICAR test file
          icap: X-Media-Type: text/plain
          icap: X-Block-Result: 80
          icap: X-Block-Reason: Malware found
          icap: X-Block-Reason: Archive not supported
          icap: X-Block-Reason: Media Type (Block List)
          http: HTTP/1.0 403 VirusFound

        C-ICAP Squidclamav
          icap/http: X-Infection-Found: Type=0; Resolution=2; Threat={HEX}EICAR.TEST.3.UNOFFICIAL;
          icap/http: X-Virus-ID: {HEX}EICAR.TEST.3.UNOFFICIAL
          http: HTTP/1.0 307 Temporary Redirect
        ]] --

        -- Generic ICAP Headers
        if headers['x-infection-found'] then
          local _,_,icap_type,_,icap_threat =
            headers['x-infection-found']:find("Type=(.-); Resolution=(.-); Threat=(.-);$")

          if not icap_type or icap_type == 2 then
            -- error returned
            lua_util.debugm(rule.name, task,
                '%s: icap error X-Infection-Found: %s', rule.log_prefix, icap_threat)
            common.yield_result(task, rule, icap_threat, 0,
                'fail', maybe_part)
            return true
          else
            lua_util.debugm(rule.name, task,
                '%s: icap X-Infection-Found: %s', rule.log_prefix, icap_threat)
            table.insert(threat_string, icap_threat)
          end

        elseif headers['x-virus-id'] and headers['x-virus-id'] ~= "no threats" then
          lua_util.debugm(rule.name, task,
              '%s: icap X-Virus-ID: %s', rule.log_prefix, headers['x-virus-id'])

          if string.find(headers['x-virus-id'], ', ') then
            local vnames = lua_util.str_split(string.gsub(headers['x-virus-id'], "%s", ""), ',') or {}

            for _,v in ipairs(vnames) do
              table.insert(threat_string, v)
            end
          else
            table.insert(threat_string, headers['x-virus-id'])
          end
        -- FSecure X-Headers
        elseif headers['x-fsecure-scan-result'] and headers['x-fsecure-scan-result'] ~= "clean" then

          local infected_filename = ""
          local infection_name = "-unknown-"

          if headers['x-fsecure-infected-filename'] then
            infected_filename = string.gsub(headers['x-fsecure-infected-filename'], '[%s"]', '')
          end
          if headers['x-fsecure-infection-name'] then
            infection_name = string.gsub(headers['x-fsecure-infection-name'], '[%s"]', '')
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
        elseif headers['x-mwg-block-reason'] and headers['x-mwg-block-reason'] ~= "" then
          table.insert(threat_string, headers['x-mwg-block-reason'])
        -- Sophos SAVDI special http headers
        elseif headers['x-blocked'] and headers['x-blocked'] ~= "" then
          table.insert(threat_string, headers['x-blocked'])
        -- last try HTTP [4]xx return
        elseif headers.http and string.find(headers.http, '^HTTP%/[12]%.. [4]%d%d') then
          local message = string.format("pseudo-virus (blocked): %s", string.gsub(headers.http, 'HTTP%/[12]%.. ', ''))
          table.insert(threat_string, message)
        elseif rule.use_http_3xx_as_threat and headers.http and string.find(headers.http, '^HTTP%/[12]%.. [3]%d%d') then
          local message = string.format("pseudo-virus (redirect): %s", string.gsub(headers.http, 'HTTP%/[12]%.. ', ''))
          table.insert(threat_string, message)
        end

        if #threat_string > 0 then
          common.yield_result(task, rule, threat_string, rule.default_score, nil, maybe_part)
          common.save_cache(task, digest, rule, threat_string, rule.default_score, maybe_part)
          return true
        else
          return false
        end
      end

      local function icap_r_respond_http_cb(err_m, data, connection)
        if err_m or connection == nil then
          icap_requery(err_m, "icap_r_respond_http_cb")
        else
          local result = tostring(data)

          local icap_http_headers = result_header_table(result) or {}
          -- Find HTTP/[12].x [234]xx response
          if icap_http_headers.http and string.find(icap_http_headers.http, 'HTTP%/[12]%.. [234]%d%d') then
            local icap_http_header_result = icap_parse_result(icap_http_headers)
            if icap_http_header_result then
              -- Threat found - close connection
              connection:close()
            else
              common.save_cache(task, digest, rule, 'OK', 0, maybe_part)
              common.log_clean(task, rule)
            end
          else
            rspamd_logger.errx(task, '%s: unhandled response |%s|',
              rule.log_prefix, string.gsub(result, "\r\n", ", "))
            common.yield_result(task, rule,
                'unhandled icap response: ' .. icap_http_headers.icap or "-",
                0.0, 'fail', maybe_part)
          end
        end
      end

      local function icap_r_respond_cb(err_m, data, connection)
        if err_m or connection == nil then
          icap_requery(err_m, "icap_r_respond_cb")
        else
          local result = tostring(data)

          local icap_headers = result_header_table(result) or {}
          -- Find ICAP/1.x 2xx response
          if icap_headers.icap and string.find(icap_headers.icap, 'ICAP%/1%.. 2%d%d') then
            local icap_header_result = icap_parse_result(icap_headers)
            if icap_header_result then
              -- Threat found - close connection
              connection:close()
            elseif not icap_header_result
              and rule.use_http_result_header
              and icap_headers.encapsulated
              and not string.find(icap_headers.encapsulated, 'null%-body=0')
              then
              -- Try to read encapsulated HTTP Headers
              lua_util.debugm(rule.name, task, '%s: no ICAP virus header found - try HTTP headers',
                rule.log_prefix)
              connection:add_read(icap_r_respond_http_cb, '\r\n\r\n')
            else
              connection:close()
              common.save_cache(task, digest, rule, 'OK', 0, maybe_part)
              common.log_clean(task, rule)
            end
          elseif icap_headers.icap and string.find(icap_headers.icap, 'ICAP%/1%.. [45]%d%d') then
            -- Find ICAP/1.x 5/4xx response
            --[[
            Symantec String:
              ICAP/1.0 539 Aborted - No AV scanning license
            SquidClamAV/C-ICAP:
              ICAP/1.0 500 Server error
            Eset:
              ICAP/1.0 405 Forbidden
            TrendMicro:
              ICAP/1.0 400 Bad request
            McAfee:
              ICAP/1.0 418 Bad composition
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
          local icap_headers = result_header_table(tostring(data))

          if icap_headers.icap and string.find(icap_headers.icap, 'ICAP%/1%.. 2%d%d') then
            if icap_headers['methods'] and string.find(icap_headers['methods'], 'RESPMOD') then
              -- Allow "204 No Content" responses
              -- https://datatracker.ietf.org/doc/html/rfc3507#section-4.6
              if icap_headers['allow'] and string.find(icap_headers['allow'], '204') then
                add_respond_header('Allow', '204')
              end

              if rule.x_client_header then
                local client = task:get_from_ip()
                if client then add_respond_header('X-Client-IP', client:to_string()) end
              end

              -- F-Secure extra headers
              if icap_headers['server'] and string.find(icap_headers['server'], 'f-secure icap server') then

                if rule.x_rcpt_header then
                  local rcpt_to = task:get_principal_recipient()
                  if rcpt_to then add_respond_header('X-Rcpt-To', rcpt_to) end
                end

                if rule.x_from_header then
                  local mail_from = task:get_principal_recipient()
                  if mail_from and mail_from[1] then add_respond_header('X-Rcpt-To', mail_from[1].addr) end
                end

              end

              if icap_headers.connection and icap_headers.connection:lower() == 'close' then
                lua_util.debugm(rule.name, task, '%s: OPTIONS request Connection: %s - using new connection',
                  rule.log_prefix, icap_headers.connection)
                connection:close()
                tcp_options.callback = icap_w_respond_cb
                tcp_options.data = get_respond_query()
                tcp.request(tcp_options)
              else
                connection:add_write(icap_w_respond_cb, get_respond_query())
              end

            else
              rspamd_logger.errx(task, '%s: RESPMOD method not advertised: Methods: %s',
                rule.log_prefix, icap_headers['methods'])
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
