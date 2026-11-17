--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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
-- @module savapi
-- This module contains avira savapi antivirus access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = "sophos"

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function sophos_config(opts)
  local sophos_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 4010,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
  }

  sophos_conf = lua_util.override_defaults(sophos_conf, opts)

  if not sophos_conf.prefix then
    sophos_conf.prefix = 'rs_' .. sophos_conf.name .. '_'
  end

  if not sophos_conf.log_prefix then
    if sophos_conf.name:lower() == sophos_conf.type:lower() then
      sophos_conf.log_prefix = sophos_conf.name
    else
      sophos_conf.log_prefix = sophos_conf.name .. ' (' .. sophos_conf.type .. ')'
    end
  end

  if not sophos_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  sophos_conf['upstreams'] = upstream_list.create(rspamd_config,
      sophos_conf['servers'],
      sophos_conf.default_port)

  if sophos_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', sophos_conf.name)
    return sophos_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      sophos_conf['servers'])
  return nil
end

local function sophos_check(task, content, digest, rule, maybe_part)
  local function sophos_check_uncached ()
    local upstream = common.get_upstream_or_fail(task, rule, maybe_part)
    if not upstream then
      return
    end
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local protocol = 'SSSP/1.0\n'
    local streamsize = string.format('SCANDATA %d\n', #content)
    local bye = 'BYE\n'
    -- The incomplete last line of the previous chunk of this attempt
    local pending = ''

    local function sophos_callback(err, data, conn)

      if err then
        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1
          -- A new attempt starts a new dialog
          pending = ''

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          if not upstream then
            common.yield_result(task, rule,
                'no upstream available for retry', 0.0, 'fail', maybe_part)
            return
          end
          addr = upstream:get_addr()

          lua_util.debugm(rule.name, task, '%s: error: %s; retry IP: %s; retries left: %s',
              rule.log_prefix, err, addr, retransmits)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            upstream = upstream,
            timeout = rule['timeout'],
            callback = sophos_callback,
            data = { protocol, streamsize, content, bye }
          })
        else
          rspamd_logger.errx(task, '%s [%s]: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          common.yield_result(task, rule, 'failed to scan and retransmits exceed',
              0.0, 'fail', maybe_part)
        end
      else
        data = pending .. tostring(data)
        lua_util.debugm(rule.name, task,
            '%s [%s]: got reply: %s', rule['symbol'], rule['type'], data)
        -- A line may be split across reads: keep the unterminated tail
        local complete = data
        pending = ''
        if not data:find('[\r\n]$') then
          local tail_start = data:find('[^\r\n]*$')
          pending = data:sub(tail_start)
          complete = data:sub(1, tail_start - 1)
        end
        -- SSSP is line based: a chunk may hold several lines and a terminal
        -- line (VIRUS, DONE, FAIL, REJ) wins over the progress lines (OK, ACC)
        local vname, done_ok, fail_0212, rej4, rej1, progress
        for line in complete:gmatch('[^\r\n]+') do
          vname = vname or line:match('^VIRUS (%S+) ')
          done_ok = done_ok or line:find('^DONE OK') ~= nil
          fail_0212 = fail_0212 or line:find('^FAIL 0212') ~= nil
          rej4 = rej4 or line:find('^REJ 4') ~= nil
          rej1 = rej1 or line:find('^REJ 1') ~= nil
          progress = progress or line:find('^ACC') ~= nil or line:find('^OK SSSP') ~= nil
        end
        local cached
        if vname then
          common.yield_result(task, rule, vname, 1.0, nil, maybe_part)
          common.save_cache(task, digest, rule, vname, 1.0, maybe_part)
        else
          if done_ok then
            if rule['log_clean'] then
              rspamd_logger.infox(task, '%s: message or mime_part is clean', rule.log_prefix)
            else
              lua_util.debugm(rule.name, task,
                  '%s: message or mime_part is clean', rule.log_prefix)
            end
            cached = 'OK'
          elseif fail_0212 then
            rspamd_logger.warnx(task, 'Message is encrypted (FAIL 0212): %s', data)
            common.yield_result(task, rule, 'SAVDI: Message is encrypted (FAIL 0212)',
                0.0, 'encrypted', maybe_part)
            cached = 'ENCRYPTED'
          elseif rej4 then
            rspamd_logger.warnx(task, 'Message is oversized (REJ 4): %s', data)
            common.yield_result(task, rule, 'SAVDI: Message oversized (REJ 4)',
                0.0, 'fail', maybe_part)
            -- explicitly set REJ1 message when SAVDIreports a protocol error
          elseif rej1 then
            rspamd_logger.errx(task, 'SAVDI (Protocol error (REJ 1)): %s', data)
            common.yield_result(task, rule, 'SAVDI: Protocol error (REJ 1)',
                0.0, 'fail', maybe_part)
          elseif progress or pending ~= '' then
            -- not finished - continue
            conn:add_read(sophos_callback)
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            common.yield_result(task, rule, 'unhandled response: ' .. data,
                0.0, 'fail', maybe_part)
          end
          if cached then
            common.save_cache(task, digest, rule, cached, 1.0, maybe_part)
          end
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      upstream = upstream,
      timeout = rule['timeout'],
      callback = sophos_callback,
      data = { protocol, streamsize, content, bye }
    })
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      sophos_check_uncached, maybe_part) then
    return
  else
    sophos_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'sophos antivirus',
  configure = sophos_config,
  check = sophos_check,
  name = N
}
