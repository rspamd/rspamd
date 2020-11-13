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

--[[[
-- @module icap
-- This module contains icap access functions.
-- Currently tested with
--  - Symantec
--  - Sophos Savdi
--  - ClamAV/c-icap
--  - Kaspersky Web Traffic Security
--  - Trend Micro IWSVA
--  - F-Secure Internet Gatekeeper Strings
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"
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
    timeout = 10.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: threat found with icap scanner: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    dynamic_scan = false,
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

local function icap_check(task, content, digest, rule)
  local function icap_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local respond_headers = {}

    -- Build the icap queries
    local options_request = {
      string.format("OPTIONS icap://%s:%s/%s ICAP/1.0\r\n", addr:to_string(), addr:get_port(), rule.scheme),
      string.format('Host: %s\r\n', addr:to_string()),
      string.format("User-Agent: Rspamd/%s-%s\r\n", rspamd_version('main'), rspamd_version('id')),
      "Encapsulated: null-body=0\r\n\r\n",
    }
    local size = string.format("%x", tonumber(#content))

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

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule.timeout,
            stop_pattern = '\r\n',
            data = options_request,
            read = false,
            callback = icap_callback,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
            'exceed - error: %s', rule.log_prefix, err_m or '')
          common.yield_result(task, rule, 'failed - error: ' .. err_m or '', 0.0, 'fail')
        end
      end

      local function get_respond_query()
        table.insert(respond_headers, 1, string.format(
            'RESPMOD icap://%s:%s/%s ICAP/1.0\r\n', addr:to_string(), addr:get_port(), rule.scheme))
        table.insert(respond_headers, '\r\n')
        table.insert(respond_headers, size .. '\r\n')
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
            icap_headers['icap'] = s
          end
          if string.find(s, '[%a%d-+]-:') then
            local _,_,key,value = tostring(s):find("([%a%d-+]-):%s?(.+)")
            if key ~= nil then
              icap_headers[key] = value
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
        ]] --

        if icap_headers['X-Infection-Found'] then
          local _,_,icap_type,_,icap_threat =
            icap_headers['X-Infection-Found']:find("Type=(.-); Resolution=(.-); Threat=(.-);$")

          if not icap_type or icap_type == 2 then
            -- error returned
            lua_util.debugm(rule.name, task,
                '%s: icap error X-Infection-Found: %s', rule.log_prefix, icap_threat)
            common.yield_result(task, rule, icap_threat, 0, 'fail')
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
        end
        if #threat_string > 0 then
          common.yield_result(task, rule, threat_string, rule.default_score)
          common.save_cache(task, digest, rule, threat_string, rule.default_score)
        else
          common.save_cache(task, digest, rule, 'OK', 0)
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
            common.yield_result(task, rule, icap_headers.icap, 0.0, 'fail')
            return false
          else
            rspamd_logger.errx(task, '%s: unhandled response |%s|',
              rule.log_prefix, string.gsub(result, "\r\n", ", "))
            common.yield_result(task, rule, 'unhandled icap response: ' .. icap_headers.icap or "-", 0.0, 'fail')
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
              if icap_headers['Allow'] and string.find(icap_headers['Allow'], '204') then
                add_respond_header('Allow', '204')
              end
              if icap_headers['Service'] and string.find(icap_headers['Service'], 'IWSVA 6.5') then
                add_respond_header('Encapsulated', 'res-hdr=0 res-body=0')
              else
                add_respond_header('Encapsulated', 'res-body=0')
              end
              if icap_headers['Server'] and string.find(icap_headers['Server'], 'F-Secure ICAP Server') then
                local from = task:get_from('mime')
                local rcpt_to = task:get_principal_recipient()
                local client = task:get_from_ip()
                if client then add_respond_header('X-Client-IP', client:to_string()) end
                add_respond_header('X-Mail-From', from[1].addr)
                add_respond_header('X-Rcpt-To', rcpt_to)
              end

              conn:add_write(icap_w_respond_cb, get_respond_query())

            else
              rspamd_logger.errx(task, '%s: RESPMOD method not advertised: Methods: %s',
                rule.log_prefix, icap_headers['Methods'])
              common.yield_result(task, rule, 'NO RESPMOD', 0.0, 'fail')
            end
          else
            rspamd_logger.errx(task, '%s: OPTIONS query failed: %s',
              rule.log_prefix, icap_headers.icap or "-")
            common.yield_result(task, rule, 'OPTIONS query failed', 0.0, 'fail')
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

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule.timeout,
      stop_pattern = '\r\n',
      data = options_request,
      read = false,
      callback = icap_callback,
    })
  end

  if common.condition_check_and_continue(task, content, rule, digest, icap_check_uncached) then
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
