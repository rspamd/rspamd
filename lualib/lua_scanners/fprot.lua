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
-- @module fprot
-- This module contains fprot access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = "fprot"

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function fprot_config(opts)
  local fprot_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 10200,
    timeout = 5.0, -- FIXME: this will break task_timeout!
    log_clean = false,
    detection_category = "virus",
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
  }

  fprot_conf = lua_util.override_defaults(fprot_conf, opts)

  if not fprot_conf.prefix then
    fprot_conf.prefix = 'rs_' .. fprot_conf.name .. '_'
  end

  if not fprot_conf.log_prefix then
    if fprot_conf.name:lower() == fprot_conf.type:lower() then
      fprot_conf.log_prefix = fprot_conf.name
    else
      fprot_conf.log_prefix = fprot_conf.name .. ' (' .. fprot_conf.type .. ')'
    end
  end

  if not fprot_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  fprot_conf['upstreams'] = upstream_list.create(rspamd_config,
      fprot_conf['servers'],
      fprot_conf.default_port)

  if fprot_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', fprot_conf.name)
    return fprot_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      fprot_conf['servers'])
  return nil
end

local function fprot_check(task, content, digest, rule, maybe_part)
  local function fprot_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local scan_id = task:get_queue_id()
    if not scan_id then scan_id = task:get_uid() end
    local header = string.format('SCAN STREAM %s SIZE %d\n', scan_id,
        #content)
    local footer = '\n'

    local function fprot_callback(err, data)
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
            callback = fprot_callback,
            data = { header, content, footer },
            stop_pattern = '\n'
          })
        else
          rspamd_logger.errx(task,
              '%s [%s]: failed to scan, maximum retransmits exceed',
              rule['symbol'], rule['type'])
          common.yield_result(task, rule, 'failed to scan and retransmits exceed',
              0.0, 'fail', maybe_part)
        end
      else
        upstream:ok()
        data = tostring(data)
        local cached
        local clean = string.match(data, '^0 <clean>')
        if clean then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task,
                '%s [%s]: message or mime_part is clean',
                rule['symbol'], rule['type'])
          end
        else
          -- returncodes: 1: infected, 2: suspicious, 3: both, 4-255: some error occured
          -- see http://www.f-prot.com/support/helpfiles/unix/appendix_c.html for more detail
          local vname = string.match(data, '^[1-3] <[%w%s]-: (.-)>')
          if not vname then
            rspamd_logger.errx(task, 'Unhandled response: %s', data)
          else
            common.yield_result(task, rule, vname, 1.0, nil, maybe_part)
            cached = vname
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
      callback = fprot_callback,
      data = { header, content, footer },
      stop_pattern = '\n'
    })
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      fprot_check_uncached, maybe_part) then
    return
  else
    fprot_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'fprot antivirus',
  configure = fprot_config,
  check = fprot_check,
  name = N
}
