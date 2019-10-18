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
-- @module dcc
-- This module contains dcc access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"
local fun = require "fun"

local N = 'dcc'

local function dcc_config(opts)

  local dcc_conf = {
    name = N,
    default_port = 10045,
    timeout = 5.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: bulk message found: "${VIRUS}"',
    detection_category = "hash",
    default_score = 1,
    action = false,
    client = '0.0.0.0',
    symbol_fail = 'DCC_FAIL',
    symbol = 'DCC_REJECT',
    symbol_bulk = 'DCC_BULK',
    body_max = 999999,
    fuz1_max = 999999,
    fuz2_max = 999999,
  }

  dcc_conf = lua_util.override_defaults(dcc_conf, opts)

  if not dcc_conf.prefix then
    dcc_conf.prefix = 'rs_' .. dcc_conf.name .. '_'
  end

  if not dcc_conf.log_prefix then
    dcc_conf.log_prefix = dcc_conf.name
  end

  if not dcc_conf.servers and dcc_conf.socket then
    dcc_conf.servers = dcc_conf.socket
  end

  if not dcc_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  dcc_conf.upstreams = upstream_list.create(rspamd_config,
      dcc_conf.servers,
      dcc_conf.default_port)

  if dcc_conf.upstreams then
    lua_util.add_debug_alias('external_services', dcc_conf.name)
    return dcc_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      dcc_conf['servers'])
  return nil
end

local function dcc_check(task, content, digest, rule)
  local function dcc_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local client =  rule.client

    local client_ip = task:get_from_ip()
    if client_ip and client_ip:is_valid() then
      client = client_ip:to_string()
    end
    local client_host = task:get_hostname()
    if client_host then
      client = client .. "\r" .. client_host
    end

    -- HELO
    local helo = task:get_helo() or ''

    -- Envelope From
    local ef = task:get_from()
    local envfrom = 'test@example.com'
    if ef and ef[1] then
      envfrom = ef[1]['addr']
    end

    -- Envelope To
    local envrcpt = 'test@example.com'
    local rcpts = task:get_recipients();
    if rcpts then
      local dcc_recipients = table.concat(fun.totable(fun.map(function(rcpt)
        return rcpt['addr'] end,
          rcpts)), '\n')
      if dcc_recipients then
        envrcpt = dcc_recipients
      end
    end

    -- Build the DCC query
    -- https://www.dcc-servers.net/dcc/dcc-tree/dccifd.html#Protocol
    local request_data = {
      "header\n",
      client .. "\n",
      helo .. "\n",
      envfrom .. "\n",
      envrcpt .. "\n",
      "\n",
      content
    }

    local function dcc_callback(err, data, conn)

      local function dcc_requery()
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
            timeout = rule.timeout or 2.0,
            shutdown = true,
            data = request_data,
            callback = dcc_callback,
            body_max = 999999,
            fuz1_max = 999999,
            fuz2_max = 999999,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
            'exceed', rule.log_prefix)
          common.yield_result(task, rule, 'failed to scan and retransmits exceed', 0.0, 'fail')
        end
      end

      if err then

        dcc_requery()

      else
        -- Parse the response
        if upstream then upstream:ok() end
        local _,_,result,disposition,header = tostring(data):find("(.-)\n(.-)\n(.-)$")
        lua_util.debugm(rule.name, task, 'DCC result=%1 disposition=%2 header="%3"',
            result, disposition, header)

        if header then
          -- Unfold header
          header = header:gsub('\r?\n%s*', ' ')
          local _,_,info = header:find("; (.-)$")
          if (result == 'R') then
            -- Reject
            common.yield_result(task, rule, info, rule.default_score)
            common.save_cache(task, digest, rule, info, rule.default_score)
          elseif (result == 'T') then
            -- Temporary failure
            rspamd_logger.warnx(task, 'DCC returned a temporary failure result: %s', result)
            dcc_requery()
          elseif result == 'A' then

              local opts = {}
              local score = 0.0
              info = info:lower()
              local rep = info:match('rep=([^=%s]+)')

              -- Adjust reputation if available
              if rep then rep = tonumber(rep) end
              if not rep then
                rep = 1.0
              end

              local function check_threshold(what, num, lim)
                local rnum
                if num == 'many' then
                  rnum = lim
                else
                  rnum = tonumber(num)
                end

                if rnum and rnum >= lim then
                  opts[#opts + 1] = string.format('%s=%s', what, num)
                  score = score + rep / 3.0
                end
              end

              info = info:lower()
              local body = info:match('body=([^=%s]+)')

              if body then
                check_threshold('body', body, rule.body_max)
              end

              local fuz1 = info:match('fuz1=([^=%s]+)')

              if fuz1 then
                check_threshold('fuz1', fuz1, rule.fuz1_max)
              end

              local fuz2 = info:match('fuz2=([^=%s]+)')

              if fuz2 then
                check_threshold('fuz2', fuz2, rule.fuz2_max)
              end

              if #opts > 0 and score > 0 then
                task:insert_result(rule.symbol_bulk,
                    score,
                    opts)
                common.save_cache(task, digest, rule, opts, score)
              else
                common.save_cache(task, digest, rule, 'OK')
                if rule.log_clean then
                  rspamd_logger.infox(task, '%s: clean, returned result A - info: %s',
                      rule.log_prefix, info)
                else
                  lua_util.debugm(rule.name, task, '%s: returned result A - info: %s',
                      rule.log_prefix, info)
              end
            end
          elseif result == 'G' then
            -- do nothing
            common.save_cache(task, digest, rule, 'OK')
            if rule.log_clean then
              rspamd_logger.infox(task, '%s: clean, returned result G - info: %s', rule.log_prefix, info)
            else
              lua_util.debugm(rule.name, task, '%s: returned result G - info: %s', rule.log_prefix, info)
            end
          elseif result == 'S' then
            -- do nothing
            common.save_cache(task, digest, rule, 'OK')
            if rule.log_clean then
              rspamd_logger.infox(task, '%s: clean, returned result S - info: %s', rule.log_prefix, info)
            else
              lua_util.debugm(rule.name, task, '%s: returned result S - info: %s', rule.log_prefix, info)
            end
          else
            -- Unknown result
            rspamd_logger.warnx(task, '%s: result error: %1', rule.log_prefix, result);
            common.yield_result(task, rule, 'error: ' .. result, 0.0, 'fail')
          end
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule.timeout or 2.0,
      shutdown = true,
      data = request_data,
      callback = dcc_callback,
      body_max = 999999,
      fuz1_max = 999999,
      fuz2_max = 999999,
    })
  end

  if common.condition_check_and_continue(task, content, rule, digest, dcc_check_uncached) then
    return
  else
    dcc_check_uncached()
  end

end

return {
  type = {'dcc','bulk', 'hash', 'scanner'},
  description = 'dcc bulk scanner',
  configure = dcc_config,
  check = dcc_check,
  name = N
}
