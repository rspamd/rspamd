--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2018, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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
-- @module razor
-- This module contains razor access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = 'razor'

local function razor_config(opts)

  local razor_conf = {
    name = N,
    default_port = 11342,
    timeout = 5.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "hash",
    default_score = 1,
    action = false,
    dynamic_scan = false,
    symbol_fail = 'RAZOR_FAIL',
    symbol = 'RAZOR',
  }

  razor_conf = lua_util.override_defaults(razor_conf, opts)

  if not razor_conf.prefix then
    razor_conf.prefix = 'rs_' .. razor_conf.name .. '_'
  end

  if not razor_conf.log_prefix then
    razor_conf.log_prefix = razor_conf.name
  end

  if not razor_conf.servers and razor_conf.socket then
    razor_conf.servers = razor_conf.socket
  end

  if not razor_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  razor_conf.upstreams = upstream_list.create(rspamd_config,
      razor_conf.servers,
      razor_conf.default_port)

  if razor_conf.upstreams then
    lua_util.add_debug_alias('external_services', razor_conf.name)
    return razor_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      razor_conf['servers'])
  return nil
end


local function razor_check(task, content, digest, rule)
  local function razor_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local function razor_callback(err, data, conn)

      local function razor_requery()
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          lua_util.debugm(rule.name, task, '%s: Request Error: %s - retries left: %s',
            rule.log_prefix, err, retransmits)

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s',
            rule.log_prefix, addr, addr:get_port())

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule.timeout or 2.0,
            shutdown = true,
            data = content,
            callback = razor_callback,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
            'exceed', rule.log_prefix)
          common.yield_result(task, rule, 'failed to scan and retransmits exceed', 0.0, 'fail')
        end
      end

      if err then

        razor_requery()

      else
        -- Parse the response
        if upstream then upstream:ok() end

        --[[
        @todo: Razorsocket currently only returns ham or spam. When the wrapper is fixed we should add dynamic scores here.
        Maybe check spamassassin implementation.

        This implementation is based on https://github.com/cgt/rspamd-plugins
        Thanks @cgt!
        ]] --

        local threat_string = tostring(data)
        if threat_string == "spam" then
          lua_util.debugm(N, task, '%s: returned result is spam', rule['symbol'], rule['type'])
          common.yield_result(task, rule, threat_string, rule.default_score)
          common.save_cache(task, digest, rule, threat_string, rule.default_score)
        elseif threat_string == "ham" then
          if rule.log_clean then
            rspamd_logger.infox(task, '%s: returned result is ham', rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s: returned result is ham', rule['symbol'], rule['type'])
          end
          common.save_cache(task, digest, rule, 'OK', rule.default_score)
        else
          rspamd_logger.errx(task,"%s - unknown response from razorfy: %s", addr:to_string(), threat_string)
        end

      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule.timeout or 2.0,
      shutdown = true,
      data = content,
      callback = razor_callback,
    })
  end

  if common.condition_check_and_continue(task, content, rule, digest, razor_check_uncached) then
    return
  else
    razor_check_uncached()
  end
end

return {
  type = {'razor','spam', 'hash', 'scanner'},
  description = 'razor bulk scanner',
  configure = razor_config,
  check = razor_check,
  name = N
}
