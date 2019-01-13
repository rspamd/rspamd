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
    scan_mime_parts = true;
    scan_text_mime = false;
    scan_image_mime = false;
    default_port = 3310,
    log_clean = false,
    timeout = 5.0, -- FIXME: this will break task_timeout!
    detection_category = "virus",
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
  }

  for k,v in pairs(opts) do
    clamav_conf[k] = v
  end

  if not clamav_conf.prefix then
    clamav_conf.prefix = 'rs_cl'
  end

  if not clamav_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  clamav_conf['upstreams'] = upstream_list.create(rspamd_config,
      clamav_conf['servers'],
      clamav_conf.default_port)

  if clamav_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', N)
    return clamav_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      clamav_conf['servers'])
  return nil
end

local function clamav_check(task, content, digest, rule)
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

          lua_util.debugm(N, task, '%s [%s]: retry IP: %s', rule['symbol'], rule['type'], addr)

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
          rspamd_logger.errx(task, '%s [%s]: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
        end

      else
        upstream:ok()
        data = tostring(data)
        local cached
        lua_util.debugm(N, task, '%s [%s]: got reply: %s', rule['symbol'], rule['type'], data)
        if data == 'stream: OK' then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s [%s]: message or mime_part is clean', rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s [%s]: message or mime_part is clean', rule['symbol'], rule['type'])
          end
        else
          local vname = string.match(data, 'stream: (.+) FOUND')
          if vname then
            common.yield_result(task, rule, vname, N)
            cached = vname
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'unhandled response')
          end
        end
        if cached then
          common.save_av_cache(task, digest, rule, cached, N)
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

  if common.need_av_check(task, content, rule, N) then
    if common.check_av_cache(task, digest, rule, clamav_check_uncached, N) then
      return
    else
      clamav_check_uncached()
    end
  end
end

return {
  type = 'antivirus',
  description = 'clamav antivirus',
  configure = clamav_config,
  check = clamav_check,
  name = 'clamav'
}