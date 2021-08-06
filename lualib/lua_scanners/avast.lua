--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
-- @module avast
-- This module contains avast av access functions
--]]

local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = "avast"

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function avast_config(opts)
  local avast_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    timeout = 4.0, -- FIXME: this will break task_timeout!
    log_clean = false,
    detection_category = "virus",
    retransmits = 1,
    servers = nil, -- e.g. /var/run/avast/scan.sock
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    tmpdir = '/tmp',
  }

  avast_conf = lua_util.override_defaults(avast_conf, opts)

  if not avast_conf.prefix then
    avast_conf.prefix = 'rs_' .. avast_conf.name .. '_'
  end

  if not avast_conf.log_prefix then
    if avast_conf.name:lower() == avast_conf.type:lower() then
      avast_conf.log_prefix = avast_conf.name
    else
      avast_conf.log_prefix = avast_conf.name .. ' (' .. avast_conf.type .. ')'
    end
  end

  if not avast_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers/unix socket defined')

    return nil
  end

  avast_conf['upstreams'] = upstream_list.create(rspamd_config,
      avast_conf['servers'],
      0)

  if avast_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', avast_conf.name)
    return avast_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      avast_conf['servers'])
  return nil
end

local function avast_check(task, content, digest, rule, maybe_part)
  local function avast_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local CRLF = '\r\n'

    -- Common tcp options
    local tcp_opts = {
      stop_pattern = CRLF,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule.timeout,
      task = task
    }

    -- Regexps to process reply from avast
    local clean_re = rspamd_regexp.create_cached(
        [=[(?!\\)\t\[\+\]]=]
    )
    local virus_re = rspamd_regexp.create_cached(
        [[(?!\\)\t\[L\]\d\.\d\t\d\s(.*)]]
    )
    local error_re = rspamd_regexp.create_cached(
        [[(?!\\)\t\[E\]\d+\.0\tError\s\d+\s(.*)]]
    )

    -- Used to make a dialog
    local tcp_conn

    -- Save content in file as avast can work with files only
    local fname = string.format('%s/%s.avtmp',
        rule.tmpdir, rspamd_util.random_hex(32))
    local message_fd = rspamd_util.create_file(fname)

    if not message_fd then
      rspamd_logger.errx('cannot store file for avast scan: %s', fname)
      return
    end

    if type(content) == 'string' then
      -- Create rspamd_text
      local rspamd_text = require "rspamd_text"
      content = rspamd_text.fromstring(content)
    end
    content:save_in_file(message_fd)

    -- Ensure file cleanup on task processed
    task:get_mempool():add_destructor(function()
      os.remove(fname)
      rspamd_util.close_file(message_fd)
    end)

    -- Dialog stages closures
    local avast_helo_cb
    local avast_scan_cb
    local avast_scan_done_cb

    -- Utility closures
    local function maybe_retransmit()
      if retransmits > 0 then
        retransmits = retransmits - 1
      else
        rspamd_logger.errx(task,
            '%s [%s]: failed to scan, maximum retransmits exceed',
            rule['symbol'], rule['type'])
        common.yield_result(task, rule, 'failed to scan and retransmits exceed',
            0.0, 'fail', maybe_part)

        return
      end

      upstream = rule.upstreams:get_upstream_round_robin()
      addr = upstream:get_addr()
      tcp_opts.callback = avast_helo_cb

      local is_succ, err = tcp.request(tcp_opts)

      if not is_succ then
        rspamd_logger.infox(task, 'cannot create connection to avast server: %s (%s)',
            addr:to_string(true), err)
      else
        lua_util.debugm(rule.log_prefix, task, 'established connection to %s; retransmits=%s',
            addr:to_string(true), retransmits)
      end
    end

    local function no_connection_error(err)
      if err then
        if tcp_conn then
          tcp_conn:close()
          tcp_conn = nil

          rspamd_logger.infox(task, 'failed to request to avast (%s): %s',
              addr:to_string(true), err)
          maybe_retransmit()
        end

        return false
      end

      return true
    end


    -- Define callbacks
    avast_helo_cb = function (merr, mdata, conn)
      -- Called when we have established a connection but not read anything
      tcp_conn = conn

      if no_connection_error(merr) then
        -- Check mdata to ensure that it starts with 220
        if #mdata > 3 and tostring(mdata:span(1, 3)) == '220' then
          tcp_conn:add_write(avast_scan_cb, string.format(
              'SCAN %s%s', fname, CRLF))
        else
          rspamd_logger.errx(task, 'Unhandled response: %s', mdata)
        end
      end
    end


    avast_scan_cb = function(merr)
      -- Called when we have send request to avast and are waiting for reply
      if no_connection_error(merr) then
        tcp_conn:add_read(avast_scan_done_cb, CRLF)
      end
    end

    avast_scan_done_cb = function(merr, mdata)
      if no_connection_error(merr) then
        lua_util.debugm(rule.log_prefix, task, 'got reply from avast: %s',
            mdata)
        if #mdata > 4 then
          local beg = tostring(mdata:span(1, 3))

          if beg == '210' then
            -- Ignore 210, fire another read
            if tcp_conn then
              tcp_conn:add_read(avast_scan_done_cb, CRLF)
            end
          elseif beg == '200' then
            -- Final line
            upstream:ok()
            if tcp_conn then
              tcp_conn:close()
              tcp_conn = nil
            end
          else
            -- Check line using regular expressions
            local cached
            local ret = clean_re:search(mdata, false, true)

            if ret then
              cached = 'OK'
              if rule.log_clean then
                rspamd_logger.infox(task,
                    '%s [%s]: message or mime_part is clean',
                    rule.symbol, rule.type)
              end
            end

            if not cached then
              ret = virus_re:search(mdata, false, true)

              if ret then
                local vname = ret[1][2]

                if vname then
                  vname = vname:gsub('\\ ', ' '):gsub('\\\\', '\\')
                  common.yield_result(task, rule, vname, 1.0, nil, maybe_part)
                  cached = vname
                end
              end
            end

            if not cached then
              ret = error_re:search(mdata, false, true)

              if ret then
                rspamd_logger.errx(task, '%s: error: %s', rule.log_prefix, ret[1][2])
                common.yield_result(task, rule, 'error:' .. ret[1][2],
                    0.0, 'fail', maybe_part)
              end
            end

            if cached then
              common.save_cache(task, digest, rule, cached, 1.0, maybe_part)
            else
              -- Unexpected reply
              rspamd_logger.errx(task, '%s: unexpected reply: %s', rule.log_prefix, mdata)
            end
            -- Read more
            if tcp_conn then
              tcp_conn:add_read(avast_scan_done_cb, CRLF)
            end
          end
        end
      end
    end

    -- Send the real request
    maybe_retransmit()
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      avast_check_uncached, maybe_part) then
    return
  else
    avast_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'Avast antivirus',
  configure = avast_config,
  check = avast_check,
  name = N
}
