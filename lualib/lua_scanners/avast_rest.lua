--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2022, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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
-- @module avast_rest
-- This module contains Avast Business Antivirus for Linux Rest-API integration support
-- https://www.avast.com/business/products/linux-antivirus#pc
--]]

local rspamd_util = require "rspamd_util"
local http = require "rspamd_http"
local ucl = require "ucl"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local common = require "lua_scanners/common"

local N = 'avast_rest'

local function avast_rest_config(opts)

  local default_conf = {
    name = N,
    default_port = 8080,
    use_https = false,
    use_files = false,
    timeout = 5.0,
    log_clean = false,
    tmpdir = '/tmp',
    retransmits = 1,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: virus message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    warnings_as_threat = false,
    -- https://repo.avcdn.net/linux-av/doc/avast-techdoc.pdf
    parameter = {
      --email = false,
      --full = false,
      archives = true,
      --pup = false,
      --heuristics = 40,
      --detections = false,
    },
  }

  default_conf = lua_util.override_defaults(default_conf, opts)

  if not default_conf.prefix then
    default_conf.prefix = 'rs_' .. default_conf.name .. '_'
  end

  if not default_conf.log_prefix then
    if default_conf.name:lower() == default_conf.type:lower() then
      default_conf.log_prefix = default_conf.name
    else
      default_conf.log_prefix = default_conf.name .. ' (' .. default_conf.type .. ')'
    end
  end

  if not default_conf.servers and default_conf.socket then
    default_conf.servers = default_conf.socket
  end

  if not default_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  default_conf.upstreams = upstream_list.create(rspamd_config,
      default_conf.servers,
      default_conf.default_port)

  if default_conf.upstreams then
    lua_util.add_debug_alias('antivirus', default_conf.name)
    return default_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      default_conf['servers'])
  return nil
end

local function avast_rest_check(task, content, digest, rule, maybe_part)
  local function avast_rest_check_uncached()

    local function make_url(addr, filename)
      local url
      local suffix = '/v1/scan?'

      local param_tbl = {}
      if rule.use_files then
        rule.parameter['path'] = filename
      else
        rule.parameter['filename'] = filename
      end
      if not rule.parameter.email and not rule.scan_mime_parts then
        rule.parameter['email'] = true
      end
      for k,v  in pairs(rule.parameter) do
        table.insert(param_tbl, string.format('%s=%s', k, tostring(v)))
      end

      if rule.use_https then
        url = string.format('https://%s:%d%s%s', tostring(addr), addr:get_port(), suffix,
          table.concat(param_tbl, '&'))
      else
        url = string.format('http://%s:%d%s%s', tostring(addr), addr:get_port(), suffix,
          table.concat(param_tbl, '&'))
      end
      return url
    end

    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local request_data = {
      task = task,
      timeout = rule.timeout,
    }

    local filename
    if rule.use_files then
      filename =  string.format('%s/%s.tmp',
          rule.tmpdir, rspamd_util.random_hex(32))
      local message_fd = rspamd_util.create_file(filename)

      if not message_fd then
        rspamd_logger.errx('cannot store file for avast_rest scan: %s', filename)
        return
      end

      if type(content) == 'string' then
        -- Create rspamd_text
        local rspamd_text = require "rspamd_text"
        content = rspamd_text.fromstring(content)
      end
      content:save_in_file(message_fd)

      -- Ensure cleanup
      task:get_mempool():add_destructor(function()
        os.remove(filename)
        rspamd_util.close_file(message_fd)
      end)

      request_data.headers = {
        ['X-Correlation-Id'] = string.sub(task:get_uid(), 1,6)
      }

      request_data.url = make_url(addr, filename)
    else

      if rule.scan_mime_parts then

        local _, _, mime_attr = maybe_part:get_type_full()
        local det_ext = maybe_part:get_detected_ext()

        if mime_attr.name then
          local ext,_ = common.gen_extension(mime_attr.name)
          if ext then
            filename = string.format('file.%s', ext)
          end
        elseif det_ext then
          filename = string.format('file.%s', det_ext)
        else
          filename = "file.txt"
        end
      else
        filename = "file.eml"
      end
      request_data.url = make_url(addr, filename)
      request_data.headers = {
        ['Content-Type'] = 'application/octet-stream',
        ['X-Correlation-Id'] = string.sub(task:get_uid(), 1,6)
      }
      request_data.body = content
    end

    lua_util.debugm(rule.name, task, '%s: request: url: %s, headers: %s, size: %s',
      rule.log_prefix, request_data.url, request_data.headers, #request_data.body)

    local function avast_rest_callback(http_err, code, body, headers)

      local function requery()
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          lua_util.debugm(rule.name, task,
              '%s: Request Error: %s - retries left: %s',
              rule.log_prefix, http_err, retransmits)

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()
          request_data.url = make_url(addr, filename)

          lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s',
              rule.log_prefix, addr, addr:get_port())

          http.request(request_data)
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
              'exceed', rule.log_prefix)
          task:insert_result(rule.symbol_fail, 0.0, 'failed to scan and '..
              'retransmits exceed')
        end
      end

      if http_err then
        requery()
      else
        -- Parse the response
        if upstream then upstream:ok() end
        if code ~= 200 then
          rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
          common.yield_result(task, rule, string.format('Bad HTTP code: %s', code), 1.0, 'fail', maybe_part)
          return
        end
        local data = string.gsub(tostring(body), '[\r\n%s]$', '')
        lua_util.debugm(rule.name, task, '%s: got reply data: "%s"',
            rule.log_prefix, data)

        local ucl_parser = ucl.parser()
        local ok, ucl_err = ucl_parser:parse_string(tostring(body))
        if not ok then
          rspamd_logger.errx(task, "%s error parsing json response, retry: %s",
            rule.log_prefix, ucl_err)
        end
        local result = ucl_parser:get_object()
        lua_util.debugm(N, task, '%s: JSON OBJECT - %s', rule.log_prefix, result)

        local threat_tbl = {}
        if result and result.issues and #result.issues > 0 then
          for _,r in ipairs(result.issues) do
            lua_util.debugm(N, task, '%s: found issue - %s', rule.log_prefix, r)
            if r.virus then
              threat_tbl[r.virus] = true
            elseif r.detections and type(r.detections) == 'table' and #r.detections > 0 then
              for _,d in ipairs(r.detections) do
                if d.virus then
                  threat_tbl[d.virus] = true
                end
              end
            end

            if r.warning_id then
              -- 42056 - msg: Archive is password protected
              -- 42110 - msg: The file is a decompression bomb
              -- 42125 - msg: ZIP archive is corrupted
              -- 42140 - msg: ISO archive is corrupted
              -- 42144 - msg: OLE archive is corrupted

              if tostring(r.warning_id) == '42056' then
                rspamd_logger.warnx(task, '%s: PASSWORD warning: id: %s - msg: %s',
                rule.log_prefix, r.warning_id, r.warning_str)
                  threat_tbl['ENCRYPTED'] = 'encrypted'
              elseif tostring(r.warning_id) == '42110' then
                rspamd_logger.warnx(task, '%s: ZIP BOMB warning: id: %s - msg: %s',
                rule.log_prefix, r.warning_id, r.warning_str)
                if rule.warnings_as_threat then
                  threat_tbl['WARN:'..r.warning_str] = true
                end
              elseif tostring(r.warning_id) == '42125'
                or tostring(r.warning_id) == '42140'
                or tostring(r.warning_id) == '42144'
                then
                rspamd_logger.warnx(task, '%s: CORRUPT warning: id: %s - msg: %s',
                  rule.log_prefix, r.warning_id, r.warning_str)
                if rule.warnings_as_threat then
                  threat_tbl['WARN:'..r.warning_str] = 'fail'
                end
              else
                rspamd_logger.warnx(task, '%s: generic warning: id: %s - msg: %s',
                rule.log_prefix, r.warning_id, r.warning_str)
                if rule.warnings_as_threat then
                  threat_tbl['WARN:'..r.warning_str] = 'fail'
                end
              end
            end
          end
        else
          table.insert(threat_tbl, 'OK')
          if rule.log_clean then
            rspamd_logger.infox(task, '%s: message or mime_part is clean',
                rule.log_prefix)
          else
            lua_util.debugm(rule.name, task, '%s: message or mime_part is clean',
                rule.log_prefix)
          end
        end

        if lua_util.nkeys(threat_tbl) > 0 then
          for v,c in pairs(threat_tbl) do
            if type(c) == 'string' then
              common.yield_result(task, rule, v, 1.0, c, maybe_part)
            else
              common.yield_result(task, rule, v, 1.0, nil, maybe_part)
            end
          end
          common.save_cache(task, digest, rule, threat_tbl, 1.0, maybe_part)
        end
      end
    end

    request_data.callback = avast_rest_callback
    http.request(request_data)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      avast_rest_check_uncached, maybe_part) then
    return
  else

    avast_rest_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'Avast Rest-API interface',
  configure = avast_rest_config,
  check = avast_rest_check,
  name = N
}
