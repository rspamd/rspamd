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
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = "savapi"

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function savapi_config(opts)
  local savapi_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 4444, -- note: You must set ListenAddress in savapi.conf
    product_id = 0,
    log_clean = false,
    timeout = 15.0, -- FIXME: this will break task_timeout!
    retransmits = 1, -- FIXME: useless, for local files
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    tmpdir = '/tmp',
  }

  savapi_conf = lua_util.override_defaults(savapi_conf, opts)

  if not savapi_conf.prefix then
    savapi_conf.prefix = 'rs_' .. savapi_conf.name .. '_'
  end

  if not savapi_conf.log_prefix then
    if savapi_conf.name:lower() == savapi_conf.type:lower() then
      savapi_conf.log_prefix = savapi_conf.name
    else
      savapi_conf.log_prefix = savapi_conf.name .. ' (' .. savapi_conf.type .. ')'
    end
  end

  if not savapi_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  savapi_conf['upstreams'] = upstream_list.create(rspamd_config,
      savapi_conf['servers'],
      savapi_conf.default_port)

  if savapi_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', savapi_conf.name)
    return savapi_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      savapi_conf['servers'])
  return nil
end

local function savapi_check(task, content, digest, rule)
  local function savapi_check_uncached ()
    local upstream = common.get_upstream_or_fail(task, rule, nil)
    if not upstream then
      return
    end
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local fname = string.format('%s/%s.tmp',
        rule.tmpdir, rspamd_util.random_hex(32))
    local message_fd = rspamd_util.create_file(fname)

    if not message_fd then
      rspamd_logger.errx(task, 'cannot store file for savapi scan: %s', fname)
      common.yield_result(task, rule, 'cannot store file for scan', 0.0, 'fail')
      return
    end

    if type(content) == 'string' then
      -- Create rspamd_text
      local rspamd_text = require "rspamd_text"
      content = rspamd_text.fromstring(content)
    end
    content:save_in_file(message_fd)

    -- Ensure cleanup
    task:get_mempool():add_destructor(function()
      os.remove(fname)
      rspamd_util.close_file(message_fd)
    end)

    local vnames = {}
    -- The scan has a single outcome shared by all the attempts
    local finished = false

    local function finish_fail(reason, conn)
      if conn then
        conn:close()
      end
      if finished then
        return
      end
      finished = true
      rspamd_logger.errx(task, '%s: %s', rule.log_prefix, reason)
      common.yield_result(task, rule, reason, 0.0, 'fail')
    end

    -- Write callbacks get (err, conn) on success but (err, nil, conn) on error
    local function conn_of(a, b)
      return b or a
    end

    local function start_attempt()
      -- The verdict is per attempt: nothing seen in a failed one is merged into this
      vnames = {}
      -- Becomes true when this attempt has been handled (error or verdict)
      local dead = false

      local function on_error(err, conn)
        if dead or finished then
          if conn then
            conn:close()
          end
          return
        end
        dead = true
        if conn then
          conn:close()
        end

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then
          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          if not upstream then
            finish_fail('no upstream available for retry')
            return
          end
          addr = upstream:get_addr()

          lua_util.debugm(rule.name, task, '%s: error: %s; retry IP: %s; retries left: %s',
              rule.log_prefix, err, addr, retransmits)

          if not start_attempt() then
            finish_fail('failed to scan: ' .. tostring(err))
          end
        else
          finish_fail('failed to scan and retransmits exceed: ' .. tostring(err))
        end
      end

      -- QUIT is a courtesy: the verdict has been already delivered
      local function quit_cb(_, a, b)
        local conn = conn_of(a, b)
        if conn then
          conn:close()
        end
      end

      local function send_quit(conn)
        dead = true
        conn:add_write(quit_cb, 'QUIT\n')
      end

      local function report_virus_and_quit(conn)
        local vname = {}
        for virus, _ in pairs(vnames) do
          table.insert(vname, virus)
        end
        table.sort(vname)
        lua_util.debugm(rule.name, task, "%s: number of virus names found %s", rule['type'], #vname)
        finished = true
        common.yield_result(task, rule, vname)
        common.save_cache(task, digest, rule, vname)
        send_quit(conn)
      end

      local savapi_scan_read_cb

      -- The name of the infection in an alert line; nil if it cannot be found
      local function alert_name(result, code)
        return result:match('^%s*' .. code .. '.*<<<%s(.*)%s+;.*;.*') or
            result:match('^%s*' .. code .. '%s(.*)%s+;.*;.*')
      end

      -- Reads the next line of the dialog
      local function read_next(conn)
        conn:add_read(savapi_scan_read_cb, '\n')
      end

      --[[
      One line is read per call. SAVAPI sends a status line per event:
      310 (infected), 420 (infected, repairable) and 440 (infected, iframe)
      are alerts and are followed by more lines; 401, 421, 422, 430, 450 and
      499 are informational and do not change the verdict; 200/210 (clean)
      and 319 (end of the alerts) are the final lines; 220 (timeout) and
      350 (error) mean that the scan has failed
      --]]
      savapi_scan_read_cb = function(err, data, conn)
        if err then
          on_error(err, conn)
          return
        end
        local result = tostring(data)
        lua_util.debugm(rule.name, task, "%s: got reply: %s",
            rule.type, result)
        local code = result:match('^%s*(%d%d%d)')

        if code == '200' or code == '210' then
          -- Terminal response - clean (unless virus names have been reported)
          if next(vnames) then
            report_virus_and_quit(conn)
            return
          end
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s: message or mime_part is clean', rule['type'])
          end
          finished = true
          common.save_cache(task, digest, rule, 'OK')
          send_quit(conn)
        elseif code == '319' then
          -- Terminal response after the alerts
          if not next(vnames) then
            -- No alert line has been seen: take what the final line says
            vnames[alert_name(result, '319') or 'SAVAPI_UNKNOWN_INFECTION'] = 1
          end
          report_virus_and_quit(conn)
        elseif code == '310' or code == '420' or code == '440' then
          -- Non-terminal response
          local virus = alert_name(result, code)
          if not virus then
            dead = true
            finish_fail('virus result unparseable: ' .. result, conn)
            return
          end
          -- Store unique virus names
          vnames[virus] = 1
          -- More content is expected: the following bytes are still buffered
          read_next(conn)
        elseif code == '401' or code == '421' or code == '422' or code == '430' or
            code == '450' or code == '499' then
          -- Informational, the final line is still to come
          read_next(conn)
        elseif code == '220' or code == '350' then
          dead = true
          finish_fail('scan failed: ' .. result, conn)
        else
          -- Not a known status: the final line, EOF or the timeout decide
          lua_util.debugm(rule.name, task, '%s: skip an unknown reply: %s',
              rule.log_prefix, result)
          read_next(conn)
        end
      end

      local function scan_written_cb(err, a, b)
        local conn = conn_of(a, b)
        if err then
          on_error(err, conn)
          return
        end
        read_next(conn)
      end

      -- 100 PRODUCT:xyz
      local function greet2_cb(err, data, conn)
        if err then
          on_error(err, conn)
          return
        end
        local result = tostring(data)
        if result:match('^%s*100%s+PRODUCT') then
          lua_util.debugm(rule.name, task, "%s: scanning file: %s",
              rule['type'], fname)
          conn:add_write(scan_written_cb, string.format('SCAN %s\n', fname))
        else
          dead = true
          finish_fail('invalid product id ' .. tostring(rule['product_id']) .. ': ' .. result, conn)
        end
      end

      local function greet1_cb(err, a, b)
        local conn = conn_of(a, b)
        if err then
          on_error(err, conn)
          return
        end
        conn:add_read(greet2_cb, '\n')
      end

      -- 100 SAVAPI:4.0 greeting
      local function callback_init(err, data, conn)
        if err then
          on_error(err, conn)
          return
        end
        local result = tostring(data)

        if result:match('^%s*100%s+SAVAPI') then
          conn:add_write(greet1_cb, string.format('SET PRODUCT %s\n', rule['product_id']))
        else
          dead = true
          finish_fail('unexpected greeting: ' .. result, conn)
        end
      end

      -- A synchronous failure has already called callback_init with an error
      local ok = tcp.request({
        task = task,
        host = addr:to_string(),
        port = addr:get_port(),
        upstream = upstream,
        timeout = rule['timeout'],
        callback = callback_init,
        stop_pattern = '\n',
      })

      return ok or dead
    end

    if not start_attempt() then
      finish_fail('cannot make a TCP connection')
    end
  end

  if common.condition_check_and_continue(task, content, rule, digest, savapi_check_uncached) then
    return
  else
    savapi_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'savapi avira antivirus',
  configure = savapi_config,
  check = savapi_check,
  name = N
}
