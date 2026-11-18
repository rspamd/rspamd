--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2019, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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
-- @module spamassassin
-- This module contains spamd access functions.
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = 'spamassassin'

local function spamassassin_config(opts)

  local spamassassin_conf = {
    N = N,
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 783,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    symbol = "SPAMD",
    message = '${SCANNER}: Spamassassin bulk message found: "${VIRUS}"',
    detection_category = "spam",
    default_score = 1,
    action = false,
    extended = false,
    symbol_type = 'postfilter',
    dynamic_scan = true,
  }

  spamassassin_conf = lua_util.override_defaults(spamassassin_conf, opts)

  if not spamassassin_conf.prefix then
    spamassassin_conf.prefix = 'rs_' .. spamassassin_conf.name .. '_'
  end

  if not spamassassin_conf.log_prefix then
    if spamassassin_conf.name:lower() == spamassassin_conf.type:lower() then
      spamassassin_conf.log_prefix = spamassassin_conf.name
    else
      spamassassin_conf.log_prefix = spamassassin_conf.name .. ' (' .. spamassassin_conf.type .. ')'
    end
  end

  if not spamassassin_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  spamassassin_conf.upstreams = upstream_list.create(rspamd_config,
      spamassassin_conf.servers,
      spamassassin_conf.default_port)

  if spamassassin_conf.upstreams then
    lua_util.add_debug_alias('external_services', spamassassin_conf.N)
    return spamassassin_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      spamassassin_conf.servers)
  return nil
end

local function spamassassin_check(task, content, digest, rule)
  local function spamassassin_check_uncached ()
    local upstream = common.get_upstream_or_fail(task, rule, nil)
    if not upstream then
      return
    end
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    -- Build the spamd query
    -- https://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
    local request_data = {
      "HEADERS SPAMC/1.5\r\n",
      "User: root\r\n",
      "Content-length: " .. #content .. "\r\n",
      "\r\n",
      content,
    }

    local spamassassin_callback

    local function spamassassin_request()
      -- The reply is read in chunks: spamd sends the status line, the
      -- Content-length header and then the headers, and closes the connection
      local reply = {}
      local reply_len = 0
      local done = false

      local function spamassassin_requery(error)
        done = true

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          lua_util.debugm(rule.name, task, '%s: Request Error: %s - retries left: %s',
              rule.log_prefix, error, retransmits)

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          if not upstream then
            common.yield_result(task, rule,
                'no upstream available for retry', 0.0, 'fail')
            return
          end
          addr = upstream:get_addr()

          lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s',
              rule.log_prefix, addr, addr:get_port())

          spamassassin_request()
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits ' ..
              'exceed - err: %s', rule.log_prefix, error)
          common.yield_result(task, rule, 'failed to scan and retransmits exceed: ' .. tostring(error), 0.0, 'fail')
        end
      end

      local function spamassassin_fail(reason)
        done = true
        rspamd_logger.errx(task, '%s: %s', rule.log_prefix, reason)
        common.yield_result(task, rule, reason, 0.0, 'fail')
      end

      -- Returns true when the headers block has been received completely
      local function reply_complete(text)
        local hdr_end = text:find('\r\n\r\n', 1, true)
        if not hdr_end then
          return false
        end
        local clen = text:sub(1, hdr_end):match('[\r\n]Content%-length:%s*(%d+)')
        if not clen then
          -- Cannot tell, wait for the end of the stream
          return false
        end
        return #text - (hdr_end + 3) >= tonumber(clen)
      end

      local function spamassassin_process(text)
        done = true

        -- SPAMD/1.1 0 EX_OK
        local proto_status = text:match('^SPAMD/[%d%.]+%s+(%d+)')
        if not proto_status then
          spamassassin_fail('unhandled response: ' .. text:sub(1, 128))
          return
        end
        if tonumber(proto_status) ~= 0 then
          spamassassin_fail('spamd error: ' .. text:sub(1, 128))
          return
        end

        --[[
        patterns tested against Spamassassin 3.4.6

        X-Spam-Status: No, score=1.1 required=5.0 tests=HTML_MESSAGE,MIME_HTML_ONLY,
          TVD_RCVD_SPACE_BRACKET,UNPARSEABLE_RELAY autolearn=no
          autolearn_force=no version=3.4.6
        ]] --
        local header = string.gsub(text, "[\r\n]+[\t ]", " ")

        local symbols
        local spam_score
        for s in header:gmatch("[^\r\n]+") do
          if string.find(s, '^X%-Spam%-Status: %S+, score') then
            spam_score = tonumber(s:match('score%=([%-%d%.]+)'))
            symbols = s:match('tests%=(.-)%sautolearn') or s:match('tests%=(.*)$') or ''
            symbols = string.gsub(symbols, "%s", "")
            break
          end
        end

        if not spam_score then
          spamassassin_fail('no X-Spam-Status in the reply: ' .. text:sub(1, 128))
          return
        end

        lua_util.debugm(rule.name, task, '%s: spam_score: %s, symbols: %s',
            rule.log_prefix, spam_score, symbols)

        if spam_score > 0 and #symbols > 0 and symbols ~= "none" then

          if rule.extended == false then
            common.yield_result(task, rule, symbols, spam_score)
            common.save_cache(task, digest, rule, symbols, spam_score)
          else
            local symbols_table = lua_util.str_split(symbols, ",")
            lua_util.debugm(rule.name, task, '%s: returned symbols as table: %s', rule.log_prefix, symbols_table)

            common.yield_result(task, rule, symbols_table, spam_score)
            common.save_cache(task, digest, rule, symbols_table, spam_score)
          end
        else
          common.save_cache(task, digest, rule, 'OK')
          common.log_clean(task, rule, 'no spam detected - spam score: ' .. spam_score .. ', symbols: ' .. symbols)
        end
      end

      spamassassin_callback = function(err, data, conn)
        if done then
          return
        end

        if data then
          local chunk = tostring(data)
          table.insert(reply, chunk)
          reply_len = reply_len + #chunk
          local text = table.concat(reply)
          reply = { text }
          if reply_complete(text) then
            if conn then
              conn:close()
            end
            spamassassin_process(text)
            return
          end
        end

        if err then
          -- spamd closes the connection when the reply is sent
          if reply_len > 0 and tostring(err):find('connection terminated', 1, true) then
            spamassassin_process(table.concat(reply))
          else
            spamassassin_requery(err)
          end
        end
      end

      local ok = tcp.request({
        task = task,
        host = addr:to_string(),
        port = addr:get_port(),
        upstream = upstream,
        timeout = rule['timeout'],
        data = request_data,
        callback = spamassassin_callback,
        partial = true,
        shutdown = true,
      })

      if not ok and not done then
        spamassassin_requery('cannot make a TCP connection')
      end
    end

    spamassassin_request()
  end

  if common.condition_check_and_continue(task, content, rule, digest, spamassassin_check_uncached) then
    return
  else
    spamassassin_check_uncached()
  end

end

return {
  type = { N, 'spam', 'scanner' },
  description = 'spamassassin spam scanner',
  configure = spamassassin_config,
  check = spamassassin_check,
  name = N
}
