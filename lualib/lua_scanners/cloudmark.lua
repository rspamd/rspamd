--[[
Copyright (c) 2021, Alexander Moisseev <moiseev@mezonplus.ru>

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
-- @module cloudmark
-- This module contains Cloudmark v2 interface
--]]

local lua_util = require "lua_util"
local http = require "rspamd_http"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local rspamd_util = require "rspamd_util"
local common = require "lua_scanners/common"
local fun = require "fun"
local lua_mime = require "lua_mime"

local N = 'cloudmark'
-- Boundary for multipart transfers, generated on module init
local static_boundary = rspamd_util.random_hex(32)

local function cloudmark_url(rule, addr, maybe_url)
  local url
  local port = addr:get_port()

  maybe_url = maybe_url or rule.url
  if port == 0 then
    port = rule.default_port
  end
  if rule.use_https then
    url = string.format('https://%s:%d%s', tostring(addr),
        port, maybe_url)
  else
    url = string.format('http://%s:%d%s', tostring(addr),
        port, maybe_url)
  end

  return url
end

-- Detect cloudmark max size
local function cloudmark_preload(rule, cfg, ev_base, _)
  local upstream = rule.upstreams:get_upstream_round_robin()
  local addr = upstream:get_addr()
  local function max_message_size_cb(http_err, code, body, _)
    if http_err then
      rspamd_logger.errx(ev_base, 'HTTP error when getting max message size: %s',
          http_err)
      return
    end
    if code ~= 200 then
      rspamd_logger.errx(ev_base, 'bad HTTP code when getting max message size: %s', code)
    end
    local parser = ucl.parser()
    local ret, err = parser:parse_string(body)
    if not ret then
      rspamd_logger.errx(ev_base, 'could not parse response body [%s]: %s', body, err)
      return
    end
    local obj = parser:get_object()
    local ms = obj.maxMessageSize
    if not ms then
      rspamd_logger.errx(ev_base, 'missing maxMessageSize in the response body (JSON): %s', obj)
      return
    end

    rule.max_size = ms
    lua_util.debugm(N, cfg, 'set maximum message size set to %s bytes', ms)
  end
  http.request({
    ev_base = ev_base,
    config = cfg,
    url =  cloudmark_url(rule, addr, '/score/v2/max-message-size'),
    callback = max_message_size_cb,
  })
end

local function cloudmark_config(opts)

  local cloudmark_conf = {
    name = N,
    default_port = 2713,
    url = '/score/v2/message',
    use_https = false,
    timeout = 5.0,
    log_clean = false,
    retransmits = 1,
    score_threshold = 90, -- minimum score to considerate reply
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    max_message = 0,
    detection_category = "hash",
    default_score = 1,
    action = false,
    log_spamcause = true,
    symbol_fail = 'CLOUDMARK_FAIL',
    symbol = 'CLOUDMARK_CHECK',
    symbol_spam = 'CLOUDMARK_SPAM',
    add_headers = false, -- allow addition of the headers from Cloudmark
  }

  cloudmark_conf = lua_util.override_defaults(cloudmark_conf, opts)

  if not cloudmark_conf.prefix then
    cloudmark_conf.prefix = 'rs_' .. cloudmark_conf.name .. '_'
  end

  if not cloudmark_conf.log_prefix then
    if cloudmark_conf.name:lower() == cloudmark_conf.type:lower() then
      cloudmark_conf.log_prefix = cloudmark_conf.name
    else
      cloudmark_conf.log_prefix = cloudmark_conf.name .. ' (' .. cloudmark_conf.type .. ')'
    end
  end

  if not cloudmark_conf.servers and cloudmark_conf.socket then
    cloudmark_conf.servers = cloudmark_conf.socket
  end

  if not cloudmark_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  cloudmark_conf.upstreams = upstream_list.create(rspamd_config,
      cloudmark_conf.servers,
      cloudmark_conf.default_port)

  if cloudmark_conf.upstreams then

    cloudmark_conf.symbols = {{ symbol = cloudmark_conf.symbol_spam, score = 5.0 }}
    cloudmark_conf.preloads = {cloudmark_preload}
    lua_util.add_debug_alias('external_services', cloudmark_conf.name)
    return cloudmark_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      cloudmark_conf['servers'])
  return nil
end

-- Converts a key-value map to the table representing multipart body, with the following values:
-- `data`: data of the part
-- `filename`: optional filename
-- `content-type`: content type of the element (optional)
-- `content-transfer-encoding`: optional CTE header
local function table_to_multipart_body(tbl, boundary)
  local seen_data = false
  local out = {}

  for k,v in pairs(tbl) do
    if v.data then
      seen_data = true
      table.insert(out, string.format('--%s\r\n', boundary))
      if v.filename then
        table.insert(out,
            string.format('Content-Disposition: form-data; name="%s"; filename="%s"\r\n',
                k, v.filename))
      else
        table.insert(out,
            string.format('Content-Disposition: form-data; name="%s"\r\n', k))
      end
      if v['content-type'] then
        table.insert(out,
            string.format('Content-Type: %s\r\n', v['content-type']))
      else
        table.insert(out, 'Content-Type: text/plain\r\n')
      end
      if v['content-transfer-encoding'] then
        table.insert(out,
            string.format('Content-Transfer-Encoding: %s\r\n',
                v['content-transfer-encoding']))
      else
        table.insert(out, 'Content-Transfer-Encoding: binary\r\n')
      end
      table.insert(out, '\r\n')
      table.insert(out, v.data)
      table.insert(out, '\r\n')
    end
  end

  if seen_data then
    table.insert(out, string.format('--%s--\r\n', boundary))
  end

  return out
end

local function parse_cloudmark_reply(task, rule, body)
  local parser = ucl.parser()
  local ret, err = parser:parse_string(body)
  if not ret then
    rspamd_logger.errx(task, '%s: bad response body (raw): %s', N, body)
    task:insert_result(rule.symbol_fail, 1.0, 'Parser error: ' .. err)
    return
  end
  local obj = parser:get_object()
  lua_util.debugm(N, task, 'cloudmark reply is: %s', obj)

  if not obj.score then
    rspamd_logger.errx(task, '%s: bad response body (raw): %s', N, body)
    task:insert_result(rule.symbol_fail, 1.0, 'Parser error: no score')
    return
  end

  if obj.analysis then
    -- Report analysis string
    rspamd_logger.infox(task, 'cloudmark report string: %s', obj.analysis)
  end

  local score = tonumber(obj.score) or 0
  if score >= rule.score_threshold then
    task:insert_result(rule.symbol_spam, 1.0, tostring(score))
  end

  if rule.add_headers and type(obj.appendHeaders) == 'table' then
    local headers_add = fun.tomap(fun.map(function(h)
      return h.headerField,{
        order = 1, value = h.body
      }
    end, obj.appendHeaders))
    lua_mime.modify_headers(task, {
      add = headers_add
    })
  end

end

local function cloudmark_check(task, content, digest, rule, maybe_part)
  local function cloudmark_check_uncached()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local url = cloudmark_url(rule, addr)
    local message_data = task:get_content()
    if rule.max_message and rule.max_message > 0 and #message_data > rule.max_message then
      task:insert_result(rule['symbol_fail'], 0.0, 'Message too large: ' .. #message_data)
      return
    end
    local request = {
      rfc822 = {
        ['Content-Type'] = 'message/rfc822',
        data = message_data,
      }
    }

    local helo = task:get_helo()
    if helo then
      request['heloDomain'] = {
        data = helo,
      }
    end
    local mail_from = task:get_from('smtp') or {}
    if mail_from[1] and #mail_from[1].addr > 1 then
      request['mailFrom'] = {
        data = mail_from[1].addr
      }
    end

    local rcpt_to = task:get_recipients('smtp')
    if rcpt_to then
      request['rcptTo'] = {
        data = table.concat(fun.totable(fun.map(function(r) return r.addr  end, rcpt_to)), ',')
      }
    end

    local fip = task:get_from_ip()
    if fip and fip:is_valid() then
      request['connIp'] = tostring(fip)
    end

    local hostname = task:get_hostname()
    if hostname then
      request['fromHost'] = hostname
    end

    local request_data = {
      task = task,
      url = url,
      body = table_to_multipart_body(request, static_boundary),
      headers = {
        ['Content-Type'] = string.format('multipart/form-data; boundary="%s"', static_boundary)
      },
      timeout = rule.timeout,
    }

    local function cloudmark_callback(http_err, code, body, headers)

      local function cloudmark_requery()
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          lua_util.debugm(rule.name, task,
              '%s: request Error: %s - retries left: %s',
              rule.log_prefix, http_err, retransmits)

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()
          url = cloudmark_url(rule, addr)

          lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s',
              rule.log_prefix, addr, addr:get_port())
          request_data.url = url

          http.request(request_data)
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
              'exceed', rule.log_prefix)
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and '..
              'retransmits exceed')
          upstream:fail()
        end
      end

      if http_err then
        cloudmark_requery()
      else
        -- Parse the response
        if upstream then upstream:ok() end
        if code ~= 200 then
          rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
          task:insert_result(rule.symbol_fail, 1.0, 'Bad HTTP code: ' .. code)
          return
        end
        parse_cloudmark_reply(task, rule, body)
      end
    end

    request_data.callback = cloudmark_callback
    http.request(request_data)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      cloudmark_check_uncached, maybe_part) then
    return
  else
    cloudmark_check_uncached()
  end
end

return {
  type = {'cloudmark', 'scanner'},
  description = 'Cloudmark cartridge interface',
  configure = cloudmark_config,
  check = cloudmark_check,
  name = N,
}
