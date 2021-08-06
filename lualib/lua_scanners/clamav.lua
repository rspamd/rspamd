--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
-- @module clamav
-- This module contains clamav access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = "clamav"

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function clamav_config(opts)
  local clamav_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 3310,
    log_clean = false,
    timeout = 5.0, -- FIXME: this will break task_timeout!
    detection_category = "virus",
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
  }

  clamav_conf = lua_util.override_defaults(clamav_conf, opts)

  if not clamav_conf.prefix then
    clamav_conf.prefix = 'rs_' .. clamav_conf.name .. '_'
  end

  if not clamav_conf.log_prefix then
    if clamav_conf.name:lower() == clamav_conf.type:lower() then
      clamav_conf.log_prefix = clamav_conf.name
    else
      clamav_conf.log_prefix = clamav_conf.name .. ' (' .. clamav_conf.type .. ')'
    end
  end

  if not clamav_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  clamav_conf['upstreams'] = upstream_list.create(rspamd_config,
      clamav_conf['servers'],
      clamav_conf.default_port)

  if clamav_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', clamav_conf.name)
    return clamav_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      clamav_conf['servers'])
  return nil
end

local function clamav_check(task, content, digest, rule, maybe_part)
  local function clamav_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local header = rspamd_util.pack("c9 c1 >I4", "zINSTREAM", "\0",
        #content)
    local footer = rspamd_util.pack(">I4", 0)

    local function clamav_callback(err, data)
      if err then

        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(rule.name, task, '%s: error: %s; retry IP: %s; retries left: %s',
              rule.log_prefix, err, addr, retransmits)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = clamav_callback,
            data = { header, content, footer },
            stop_pattern = '\0'
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule.log_prefix)
          common.yield_result(task, rule,
              'failed to scan and retransmits exceed', 0.0, 'fail',
              maybe_part)
        end

      else
        upstream:ok()
        data = tostring(data)
        local cached
        lua_util.debugm(rule.name, task, '%s: got reply: %s',
            rule.log_prefix, data)
        if data == 'stream: OK' then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s: message or mime_part is clean',
                rule.log_prefix)
          else
            lua_util.debugm(rule.name, task, '%s: message or mime_part is clean', rule.log_prefix)
          end
        else
          local vname = string.match(data, 'stream: (.+) FOUND')
          if string.find(vname, '^Heuristics%.Encrypted') then
            rspamd_logger.errx(task, '%s: File is encrypted', rule.log_prefix)
            common.yield_result(task, rule, 'File is encrypted: '.. vname,
                0.0, 'encrypted', maybe_part)
            cached = 'ENCRYPTED'
          elseif string.find(vname, '^Heuristics%.OLE2%.ContainsMacros') then
            rspamd_logger.errx(task, '%s: ClamAV Found an OLE2 Office Macro', rule.log_prefix)
            common.yield_result(task, rule, vname, 0.0, 'macro', maybe_part)
            cached = 'MACRO'
          elseif string.find(vname, '^Heuristics%.Limits%.Exceeded') then
            rspamd_logger.errx(task, '%s: ClamAV Limits Exceeded', rule.log_prefix)
            common.yield_result(task, rule, 'Limits Exceeded: '.. vname, 0.0,
                'fail', maybe_part)
          elseif vname then
            common.yield_result(task, rule, vname, 1.0, nil, maybe_part)
            cached = vname
          else
            rspamd_logger.errx(task, '%s: unhandled response: %s', rule.log_prefix, data)
            common.yield_result(task, rule, 'unhandled response:' .. vname, 0.0,
                'fail', maybe_part)
          end
        end
        if cached then
          common.save_cache(task, digest, rule, cached, 1.0, maybe_part)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = clamav_callback,
      data = { header, content, footer },
      stop_pattern = '\0'
    })
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      clamav_check_uncached, maybe_part) then
    return
  else
    clamav_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'clamav antivirus',
  configure = clamav_config,
  check = clamav_check,
  name = N
}
