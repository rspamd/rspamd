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
-- @module vadesecure
-- This module contains Vadesecure Filterd interface
--]]

local lua_util = require "lua_util"
local http = require "rspamd_http"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"

local N = 'vadesecure'

local function vade_check(task, content, digest, rule)
  local function vade_url(addr)
    local url
    if rule.use_https then
      url = string.format('https://%s:%d/%s', tostring(addr),
          rule.default_port, rule.url)
    else
      url = string.format('http://%s:%d/%s', tostring(addr),
          rule.default_port, rule.url)
    end

    return url
  end

  local upstream = rule.upstreams:get_upstream_round_robin()
  local addr = upstream:get_addr()
  local retransmits = rule.retransmits

  local url = vade_url(addr)
  local hdrs = {}

  local helo = task:get_helo()
  if helo then
    hdrs['X-Helo'] = helo
  end
  local mail_from = task:get_from('smtp') or {}
  if mail_from[1] and #mail_from[1].addr > 1 then
    hdrs['X-Mailfrom'] = mail_from[1].addr
  end

  local rcpt_to = task:get_recipients('smtp')
  if rcpt_to then
    hdrs['X-Rcptto'] = {}
    for _, r in ipairs(rcpt_to) do
      table.insert(hdrs['X-Rcptto'], r.addr)
    end
  end

  local fip = task:get_from_ip()
  if fip and fip:is_valid() then
    hdrs['X-Inet'] = tostring(fip)
  end

  local request_data = {
    task = task,
    url = url,
    body = task:get_content(),
    headers = hdrs,
    timeout = rule.timeout,
  }

  local function vade_callback(http_err, code, body, headers)

    local function vade_requery()
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
        url = vade_url(addr)

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
      vade_requery()
    else
      -- Parse the response
      if upstream then upstream:ok() end
      if code ~= 200 then
        task:insert_result(rule.symbol_fail, 1.0, 'Bad HTTP code: ' .. code)
        return
      end
      local parser = ucl.parser()
      local ret, err = parser:parse_string(body)
      if not ret then
        rspamd_logger.errx(task, 'Weird response body (raw): %s', body)
        task:insert_result(rule.symbol_fail, 1.0, 'Parser error: ' .. err)
        return
      end
      local obj = parser:get_object()
      local verdict = obj.verdict
      if not verdict then
        rspamd_logger.errx(task, 'Weird response JSON: %s', obj)
        task:insert_result(rule.symbol_fail, 1.0, 'No verdict/unknown verdict')
        return
      end
      local vparts = lua_util.rspamd_str_split(verdict, ":")
      verdict = table.remove(vparts, 1) or verdict

      local sym = rule.symbols[verdict]
      if not sym then
        sym = rule.symbols.other
      end

      if type(sym) == 'table' then
        local lvl = 'low'
        if vparts and vparts[1] then
          lvl = vparts[1]
        end

        if sym[lvl] then
          sym = sym[lvl]
        else
          sym = rule.symbols.other
        end
      end

      local opts = {}
      if obj.score then
        table.insert(opts, 'score=' .. obj.score)
      end
      if obj.elapsed then
        table.insert(opts, 'elapsed=' .. obj.elapsed)
      end

      if rule.log_spamcause and obj.spamcause then
        rspamd_logger.infox(task, 'vadesecure returned verdict="%s", score=%s, spamcause="%s"',
            verdict, obj.score, obj.spamcause)
      end

      if #vparts > 0 then
        table.insert(opts, 'verdict=' .. verdict .. ';' .. table.concat(vparts, ':'))
      end

      task:insert_result(sym, 1.0, opts)
    end
  end

  request_data.callback = vade_callback
  http.request(request_data)
end


local function vade_config(opts)

  local vade_conf = {
    name = N,
    default_port = 23808,
    url = '/api/v1/scan',
    use_https = false,
    timeout = 5.0,
    log_clean = false,
    retransmits = 1,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "hash",
    default_score = 1,
    action = false,
    log_spamcause = true,
    symbol_fail = 'VADE_FAIL',
    symbol = 'VADE_CHECK',
    symbols = {
      clean = 'VADE_CLEAN',
      spam = {
        high = 'VADE_SPAM_HIGH',
        medium = 'VADE_SPAM_MEDIUM',
        low = 'VADE_SPAM_LOW'
      },
      malware = 'VADE_MALWARE',
      scam = 'VADE_SCAM',
      phishing = 'VADE_PHISHING',
      ['commercial:dce'] = 'VADE_DCE',
      suspect = 'VADE_SUSPECT',
      bounce = 'VADE_BOUNCE',
      other = 'VADE_OTHER',
    }
  }

  vade_conf = lua_util.override_defaults(vade_conf, opts)

  if not vade_conf.prefix then
    vade_conf.prefix = 'rs_' .. vade_conf.name .. '_'
  end

  if not vade_conf.log_prefix then
    if vade_conf.name:lower() == vade_conf.type:lower() then
      vade_conf.log_prefix = vade_conf.name
    else
      vade_conf.log_prefix = vade_conf.name .. ' (' .. vade_conf.type .. ')'
    end
  end

  if not vade_conf.servers and vade_conf.socket then
    vade_conf.servers = vade_conf.socket
  end

  if not vade_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  vade_conf.upstreams = upstream_list.create(rspamd_config,
      vade_conf.servers,
      vade_conf.default_port)

  if vade_conf.upstreams then
    lua_util.add_debug_alias('external_services', vade_conf.name)
    return vade_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      vade_conf['servers'])
  return nil
end

return {
  type = {'vadesecure', 'scanner'},
  description = 'VadeSecure Filterd interface',
  configure = vade_config,
  check = vade_check,
  name = N
}
