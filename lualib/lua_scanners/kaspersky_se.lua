--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
-- @module kaspersky_se
-- This module contains Kaspersky Scan Engine integration support
-- https://www.kaspersky.com/scan-engine
--]]

local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local http = require "rspamd_http"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = 'kaspersky_se'

local function kaspersky_se_config(opts)

  local default_conf = {
    name = N,
    default_port = 9999,
    use_https = false,
    use_files = false,
    timeout = 5.0,
    log_clean = false,
    tmpdir = '/tmp',
    retransmits = 1,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
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
    lua_util.add_debug_alias('external_services', default_conf.name)
    return default_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      default_conf['servers'])
  return nil
end

local function kaspersky_se_check(task, content, digest, rule, maybe_part)
  local function kaspersky_se_check_uncached()
    local function make_url(addr)
      local url
      local suffix = '/scanmemory'

      if rule.use_files then
        suffix = '/scanfile'
      end
      if rule.use_https then
        url = string.format('https://%s:%d%s', tostring(addr),
            addr:get_port(), suffix)
      else
        url = string.format('http://%s:%d%s', tostring(addr),
            addr:get_port(), suffix)
      end

      return url
    end

    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local url = make_url(addr)
    local hdrs = {
      ['X-KAV-ProtocolVersion'] = '1',
      ['X-KAV-Timeout'] = tostring(rule.timeout * 1000),
    }

    if task:has_from() then
      hdrs['X-KAV-ObjectURL'] = string.format('[from:%s]', task:get_from()[1].addr)
    end

    local req_body

    if rule.use_files then
      local fname =  string.format('%s/%s.tmp',
          rule.tmpdir, rspamd_util.random_hex(32))
      local message_fd = rspamd_util.create_file(fname)

      if not message_fd then
        rspamd_logger.errx('cannot store file for kaspersky_se scan: %s', fname)
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
        os.remove(fname)
        rspamd_util.close_file(message_fd)
      end)

      req_body = fname
    else
      req_body = content
    end

    local request_data = {
      task = task,
      url = url,
      body = req_body,
      headers = hdrs,
      timeout = rule.timeout,
    }

    local function kas_callback(http_err, code, body, headers)

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
          url = make_url(addr)

          lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s',
              rule.log_prefix, addr, addr:get_port())
          request_data.url = url

          http.request(request_data)
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
              'exceed', rule.log_prefix)
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and '..
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
          task:insert_result(rule.symbol_fail, 1.0, 'Bad HTTP code: ' .. code)
          return
        end
        local data = string.gsub(tostring(body), '[\r\n%s]$', '')
        local cached
        lua_util.debugm(rule.name, task, '%s: got reply data: "%s"',
            rule.log_prefix, data)

        if data:find('^CLEAN') then
          -- Handle CLEAN replies
          if data == 'CLEAN' then
            cached = 'OK'
            if rule['log_clean'] then
              rspamd_logger.infox(task, '%s: message or mime_part is clean',
                  rule.log_prefix)
            else
              lua_util.debugm(rule.name, task, '%s: message or mime_part is clean',
                  rule.log_prefix)
            end
          elseif data == 'CLEAN AND CONTAINS OFFICE MACRO' then
            common.yield_result(task, rule, 'File contains macros',
                0.0, 'macro', maybe_part)
            cached = 'MACRO'
          else
            rspamd_logger.errx(task, '%s: unhandled clean response: %s', rule.log_prefix, data)
            common.yield_result(task, rule, 'unhandled response:' .. data,
                0.0, 'fail', maybe_part)
          end
        elseif data == 'SERVER_ERROR' then
          rspamd_logger.errx(task, '%s: error: %s', rule.log_prefix, data)
          common.yield_result(task, rule, 'error:' .. data,
              0.0, 'fail', maybe_part)
        elseif string.match(data, 'DETECT (.+)') then
          local vname = string.match(data, 'DETECT (.+)')
          common.yield_result(task, rule, vname, 1.0, nil, maybe_part)
          cached = vname
        elseif string.match(data, 'NON_SCANNED %((.+)%)') then
          local why = string.match(data, 'NON_SCANNED %((.+)%)')

          if why == 'PASSWORD PROTECTED' then
            rspamd_logger.errx(task, '%s: File is encrypted', rule.log_prefix)
            common.yield_result(task, rule, 'File is encrypted: '.. why,
                0.0, 'encrypted', maybe_part)
            cached = 'ENCRYPTED'
          else
            common.yield_result(task, rule, 'unhandled response:' .. data,
                0.0, 'fail', maybe_part)
          end
        else
          rspamd_logger.errx(task, '%s: unhandled response: %s', rule.log_prefix, data)
          common.yield_result(task, rule, 'unhandled response:' .. data,
              0.0, 'fail', maybe_part)
        end

        if cached then
          common.save_cache(task, digest, rule, cached, 1.0, maybe_part)
        end

      end
    end

    request_data.callback = kas_callback
    http.request(request_data)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      kaspersky_se_check_uncached, maybe_part) then
    return
  else

    kaspersky_se_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'Kaspersky Scan Engine interface',
  configure = kaspersky_se_config,
  check = kaspersky_se_check,
  name = N
}
