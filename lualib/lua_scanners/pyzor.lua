--[[
Copyright (c) 2018, Carsten Rosenberg <c.rosenberg@heinlein-support.de>
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
-- @module pyzor
-- This module contains pyzor access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"
local ucl = require "ucl"

local N = 'pyzor'
local categories = {'pyzor','bulk', 'hash', 'scanner'}

local function pyzor_config(opts)

  local pyzor_conf = {
    text_part_min_words = 2,
    default_port = 5953,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    detection_category = "hash",
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: Pyzor bulk message found: "${VIRUS}"',
    default_score = 1,
    action = false,
  }

  pyzor_conf = lua_util.override_defaults(pyzor_conf, opts)

  if not pyzor_conf.prefix then
    pyzor_conf.prefix = 'rext_' .. N .. '_'
  end

  if not pyzor_conf.log_prefix then
    pyzor_conf.log_prefix = N .. ' (' .. pyzor_conf.detection_category .. ')'
  end

  if not pyzor_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  pyzor_conf['upstreams'] = upstream_list.create(rspamd_config,
      pyzor_conf['servers'],
      pyzor_conf.default_port)

  if pyzor_conf['upstreams'] then
    lua_util.add_debug_alias('external_services', N)
    return pyzor_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      pyzor_conf['servers'])
  return nil
end

local function pyzor_check(task, content, digest, rule)
  local function pyzor_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local function pyzor_callback(err, data, conn)

      if err then

        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s: retry IP: %s:%s err: %s',
              rule.log_prefix, addr, addr:get_port(), err)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            shutdown = true,
            data = { "CHECK\n" , content },
            callback = pyzor_callback,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed',
              rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0,
              'failed to scan and retransmits exceed')
        end
      else
        -- Parse the response
        if upstream then upstream:ok() end

        lua_util.debugm(N, task, '%s: returned data: %s', rule.log_prefix, tostring(data))
        local ucl_parser = ucl.parser()
        local ok, py_err = ucl_parser:parse_string(tostring(data))
        if not ok then
          rspamd_logger.errx(task, "error parsing response: %s", py_err)
          return
        end

        local resp = ucl_parser:get_object()
        local whitelisted = tonumber(resp["WL-Count"])
        local reported = tonumber(resp["Count"])

        --rspamd_logger.infox(task, "%s - count=%s wl=%s", addr:to_string(), reported, whitelisted)

        --[[
        @todo: Implement math function to calc the score dynamically based on return values.
        Maybe check spamassassin implementation.
        ]] --
        local entries = reported - whitelisted

        local weight = 0

        if entries >= 100 then
          weight = 1.5
        elseif entries >= 25 then
          weight = 1.25
        elseif entries >= 5 then
          weight = 1.0
        elseif entries >= 1 and whitelisted == 0 then
          weight = 0.2
        end

        if whitelisted >= 100 then
          weight = weight - 1.5
        elseif whitelisted >= 25 then
          weight = weight - 1.25
        elseif whitelisted >= 5 then
          weight = weight - 1.0
        elseif whitelisted >= 1 then
          weight = weight - 0.2
        end

        local info = string.format("count=%d wl=%d", reported, whitelisted)
        local threat_string = string.format("bl_%d_wl_%d", reported, whitelisted)

        if weight > 0 then
          lua_util.debugm(N, task, '%s: returned result is spam - info: %s', rule.log_prefix, info)
          common.yield_result(task, rule, threat_string, N, weight)
          common.save_av_cache(task, digest, rule, threat_string, N)
        else
          if rule.log_clean then
            rspamd_logger.infox(task, '%s: clean, returned result is ham - info: %s', rule.log_prefix, info)
          else
            lua_util.debugm(N, task, '%s: returned result is ham - info: %s', rule.log_prefix, info)
          end
          common.save_av_cache(task, digest, rule, 'OK', N)
        end

      end
    end

    if common.text_parts_min_words(task, rule.text_part_min_words) then
      rspamd_logger.infox(task, '%s: #words is less then text_part_min_words: %s',
          rule.log_prefix, rule.text_part_min_words)
      return
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule.timeout,
      shutdown = true,
      data = { "CHECK\n" , content },
      callback = pyzor_callback,
    })
  end
  if common.need_av_check(task, content, rule, N) then
    if common.check_av_cache(task, digest, rule, pyzor_check_uncached, N) then
      return
    else
      pyzor_check_uncached()
    end
  end
end


return {
  type = categories,
  description = 'pyzor bulk scanner',
  configure = pyzor_config,
  check = pyzor_check,
  name = 'pyzor'
}