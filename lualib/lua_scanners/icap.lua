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
-- Currently tested with Symantec, Sophos Savdi, ClamAV/c-icap
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = 'icap'

local function icap_check(task, content, digest, rule)
  local function icap_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local respond_headers = {}

    -- Build the icap queries
    local options_request = {
      "OPTIONS icap://" .. addr:to_string() .. ":" .. addr:get_port() .. "/" .. rule.scheme .. " ICAP/1.0\r\n",
      "Host:" .. addr:to_string() .. "\r\n",
      "User-Agent: Rspamd\r\n",
      "Encapsulated: null-body=0\r\n\r\n",
    }
    local size = string.format("%x", tonumber(#content))

    local function get_respond_query()
      table.insert(respond_headers, 1,
          'RESPMOD icap://' .. addr:to_string() .. ':' .. addr:get_port() .. '/'
        .. rule.scheme .. ' ICAP/1.0\r\n')
      table.insert(respond_headers, 'Encapsulated: res-body=0\r\n')
      table.insert(respond_headers, '\r\n')
      table.insert(respond_headers, size .. '\r\n')
      table.insert(respond_headers, content)
      table.insert(respond_headers, '\r\n0\r\n\r\n')
      return respond_headers
    end

    local function add_respond_header(name, value)
      table.insert(respond_headers, name .. ': ' .. value .. '\r\n' )
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
      Kaspersky Strings:
        X-Virus-ID: HEUR:Backdoor.Java.QRat.gen
        X-Response-Info: blocked

        X-Virus-ID: no threats
        X-Response-Info: blocked

        X-Response-Info: passed
      ]] --

      if icap_headers['X-Infection-Found'] ~= nil then
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

      elseif icap_headers['X-Virus-ID'] ~= nil and icap_headers['X-Virus-ID'] ~= "no threats" then
        lua_util.debugm(rule.name, task,
            '%s: icap X-Virus-ID: %s', rule.log_prefix, icap_headers['X-Virus-ID'])

        if string.find(icap_headers['X-Virus-ID'], ', ') then
          local vnames = rspamd_str_split(string.gsub(icap_headers['X-Virus-ID'], "%s", ""), ',') or {}

          for _,v in ipairs(vnames) do
            table.insert(threat_string, v)
          end
        else
          table.insert(threat_string, icap_headers['X-Virus-ID'])
        end
      end

      if #threat_string > 0 then
        common.yield_result(task, rule, threat_string, rule.default_score)
        common.save_av_cache(task, digest, rule, threat_string, rule.default_score)
      else
        common.save_av_cache(task, digest, rule, 'OK', 0)
        common.log_clean(task, rule)
      end
    end

    local function icap_r_respond_cb(err, data, conn)
      local result = tostring(data)
      conn:close()

      local icap_headers = icap_result_header_table(result)
      -- Find ICAP/1.x 2xx response
      if string.find(icap_headers.icap, 'ICAP%/1%.. 2%d%d') then
        icap_parse_result(icap_headers)
      elseif string.find(icap_headers.icap, 'ICAP%/1%.. [45]%d%d') then
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
        common.yield_result(task, rule, 'unhandled icap response: ' .. icap_headers.icap, 0.0, 'fail')
      end
    end

    local function icap_w_respond_cb(err, conn)
      conn:add_read(icap_r_respond_cb, '\r\n\r\n')
    end

    local function icap_r_options_cb(err, data, conn)
      local icap_headers = icap_result_header_table(tostring(data))

      if string.find(icap_headers.icap, 'ICAP%/1%.. 2%d%d') then
        if icap_headers['Methods'] ~= nil and string.find(icap_headers['Methods'], 'RESPMOD') then
          if icap_headers['Allow'] ~= nil and string.find(icap_headers['Allow'], '204') then
            add_respond_header('Allow', '204')
          end
          conn:add_write(icap_w_respond_cb, get_respond_query())
        else
          rspamd_logger.errx(task, '%s: RESPMOD method not advertised: Methods: %s',
            rule.log_prefix, icap_headers['Methods'])
          common.yield_result(task, rule, 'NO RESPMOD', 0.0, 'fail')
        end
      else
        rspamd_logger.errx(task, '%s: OPTIONS query failed: %s',
          rule.log_prefix, icap_headers.icap)
        common.yield_result(task, rule, 'OPTIONS query failed', 0.0, 'fail')
      end
    end

    local function icap_callback(err, conn)

      local function icap_requery(error)
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          lua_util.debugm(rule.name, task,
              '%s: Request Error: %s - retries left: %s',
              rule.log_prefix, error, retransmits)

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
            'exceed - err: %s', rule.log_prefix, error)
          common.yield_result(task, rule, 'failed - err: ' .. error, 0.0, 'fail')
        end
      end

      if err then
        icap_requery(err)
      else
        -- set upstream ok
        if upstream then upstream:ok() end
        conn:add_read(icap_r_options_cb, '\r\n\r\n')
      end
    end

    if rule.dynamic_scan then
      local pre_check, pre_check_msg = common.check_metric_results(task, rule)
      if pre_check then
        rspamd_logger.infox(task, '%s: aborting: %s', rule.log_prefix, pre_check_msg)
        return true
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
  if common.need_av_check(task, content, rule) then
    if common.check_av_cache(task, digest, rule, icap_check_uncached) then
      return
    else
      icap_check_uncached()
    end
  end
end


local function icap_config(opts)

  local icap_conf = {
    name = N,
    scan_mime_parts = true,
    scan_all_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    scheme = "scan",
    default_port = 4020,
    timeout = 10.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: threat found with icap scanner: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
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

return {
  type = {N, 'virus', 'virus', 'scanner'},
  description = 'generic icap antivirus',
  configure = icap_config,
  check = icap_check,
  name = N
}
