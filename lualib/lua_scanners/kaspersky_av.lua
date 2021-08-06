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
-- @module kaspersky
-- This module contains kaspersky antivirus access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = "kaspersky"

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function kaspersky_config(opts)
  local kaspersky_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    product_id = 0,
    log_clean = false,
    timeout = 5.0,
    retransmits = 1, -- use local files, retransmits are useless
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    tmpdir = '/tmp',
  }

  kaspersky_conf = lua_util.override_defaults(kaspersky_conf, opts)

  if not kaspersky_conf.prefix then
    kaspersky_conf.prefix = 'rs_' .. kaspersky_conf.name .. '_'
  end

  if not kaspersky_conf.log_prefix then
    if kaspersky_conf.name:lower() == kaspersky_conf.type:lower() then
      kaspersky_conf.log_prefix = kaspersky_conf.name
    else
      kaspersky_conf.log_prefix = kaspersky_conf.name .. ' (' .. kaspersky_conf.type .. ')'
    end
  end

  if not kaspersky_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  kaspersky_conf['upstreams'] = upstream_list.create(rspamd_config,
      kaspersky_conf['servers'], 0)

  if kaspersky_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', kaspersky_conf.name)
    return kaspersky_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      kaspersky_conf['servers'])
  return nil
end

local function kaspersky_check(task, content, digest, rule, maybe_part)
  local function kaspersky_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local fname = string.format('%s/%s.tmp',
        rule.tmpdir, rspamd_util.random_hex(32))
    local message_fd = rspamd_util.create_file(fname)
    local clamav_compat_cmd = string.format("nSCAN %s\n", fname)

    if not message_fd then
      rspamd_logger.errx('cannot store file for kaspersky scan: %s', fname)
      return
    end

    if type(content) == 'string' then
      -- Create rspamd_text
      local rspamd_text = require "rspamd_text"
      content = rspamd_text.fromstring(content)
    end
    content:save_in_file(message_fd)

    -- Ensure file cleanup
    task:get_mempool():add_destructor(function()
      os.remove(fname)
      rspamd_util.close_file(message_fd)
    end)


    local function kaspersky_callback(err, data)
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
            callback = kaspersky_callback,
            data = { clamav_compat_cmd },
            stop_pattern = '\n'
          })
        else
          rspamd_logger.errx(task,
              '%s [%s]: failed to scan, maximum retransmits exceed',
              rule['symbol'], rule['type'])
          common.yield_result(task, rule,
              'failed to scan and retransmits exceed', 0.0, 'fail',
              maybe_part)
        end

      else
        upstream:ok()
        data = tostring(data)
        local cached
        lua_util.debugm(rule.name, task,
            '%s [%s]: got reply: %s',
            rule['symbol'], rule['type'], data)
        if data == 'stream: OK' or data == fname .. ': OK' then
          cached = 'OK'
          common.log_clean(task, rule)
        else
          local vname = string.match(data, ': (.+) FOUND')
          if vname then
            common.yield_result(task, rule, vname, 1.0, nil, maybe_part)
            cached = vname
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            common.yield_result(task, rule, 'unhandled response',
                0.0, 'fail', maybe_part)
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
      callback = kaspersky_callback,
      data = { clamav_compat_cmd },
      stop_pattern = '\n'
    })
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      kaspersky_check_uncached, maybe_part) then
    return
  else
    kaspersky_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'kaspersky antivirus',
  configure = kaspersky_config,
  check = kaspersky_check,
  name = N
}
