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

local rspamd_tcp = require "rspamd_tcp"
local lua_util = require "lua_util"

local exports = {}

local CRLF = '\r\n'
local default_timeout = 10.0

--[[[
-- @function lua_smtp.sendmail(task, message, opts, callback)
--]]
local function sendmail(opts, message, callback)
  local stage = 'connect'

  local function mail_cb(err, data, conn)
    local function no_error_write(merr)
      if merr then
        callback(false, string.format('error on stage %s: %s',
            stage, merr))
        if conn then
          conn:close()
        end

        return false
      end

      return true
    end

    local function no_error_read(merr, mdata, wantcode)
      wantcode = wantcode or '2'
      if merr then
        callback(false, string.format('error on stage %s: %s',
          stage, merr))
        if conn then
          conn:close()
        end

        return false
      end
      if mdata then
        if type(mdata) ~= 'string' then
          mdata = tostring(mdata)
        end
        if string.sub(mdata, 1, 1) ~= wantcode then
          callback(false, string.format('bad smtp response on stage %s: "%s" when "%s" expected',
              stage, mdata, wantcode))
          if conn then
            conn:close()
          end
          return false
        end
      else
        callback(false, string.format('no data on stage %s',
            stage))
        if conn then
          conn:close()
        end
        return false
      end
      return true
    end

    -- After quit
    local function all_done_cb(merr, mdata)
      if conn then
        conn:close()
      end

      callback(true, nil)

      return true
    end

    -- QUIT stage
    local function quit_done_cb(_, _)
      conn:add_read(all_done_cb, CRLF)
    end
    local function quit_cb(merr, mdata)
      if no_error_read(merr, mdata) then
        conn:add_write(quit_done_cb, 'QUIT' .. CRLF)
      end
    end
    local function pre_quit_cb(merr, _)
      if no_error_write(merr) then
        stage = 'quit'
        conn:add_read(quit_cb, CRLF)
      end
    end

    -- DATA stage
    local function data_done_cb(merr, mdata)
      if no_error_read(merr, mdata, '3') then
        if type(message) == 'string' or type(message) == 'userdata' then
          conn:add_write(pre_quit_cb, {message, CRLF.. '.' .. CRLF})
        else
          table.insert(message, CRLF.. '.' .. CRLF)
          conn:add_write(pre_quit_cb, message)
        end
      end
    end
    local function data_cb(merr, _)
      if no_error_write(merr) then
        conn:add_read(data_done_cb, CRLF)
      end
    end

    -- RCPT phase
    local next_recipient
    local function rcpt_done_cb_gen(i)
      return function (merr, mdata)
        if no_error_read(merr, mdata) then
          if i == #opts.recipients then
            conn:add_write(data_cb, 'DATA' .. CRLF)
          else
            next_recipient(i + 1)
          end
        end
      end
    end

    local function rcpt_cb_gen(i)
      return function (merr, _)
        if no_error_write(merr, '2') then
          conn:add_read(rcpt_done_cb_gen(i), CRLF)
        end
      end
    end

    next_recipient = function(i)
      conn:add_write(rcpt_cb_gen(i),
          string.format('RCPT TO: <%s>%s', opts.recipients[i], CRLF))
    end

    -- FROM stage
    local function from_done_cb(merr, mdata)
      -- We need to iterate over recipients sequentially
      if no_error_read(merr, mdata, '2') then
        stage = 'rcpt'
        next_recipient(1)
      end
    end
    local function from_cb(merr, _)
      if no_error_write(merr) then
        conn:add_read(from_done_cb, CRLF)
      end
    end
    local function hello_done_cb(merr, mdata)
      if no_error_read(merr, mdata) then
        stage = 'from'
        conn:add_write(from_cb, string.format(
            'MAIL FROM: <%s>%s', opts.from, CRLF))
      end
    end

    -- HELO stage
    local function hello_cb(merr)
      if no_error_write(merr) then
        conn:add_read(hello_done_cb, CRLF)
      end
    end
    if no_error_read(err, data) then
      stage = 'helo'
      conn:add_write(hello_cb, string.format('HELO %s%s',
        opts.helo, CRLF))
    end
  end

  if type(opts.recipients) == 'string' then
    opts.recipients = {opts.recipients}
  end

  local tcp_opts = lua_util.shallowcopy(opts)
  tcp_opts.stop_pattern = CRLF
  tcp_opts.timeout = opts.timeout or default_timeout
  tcp_opts.callback = mail_cb

  if not rspamd_tcp.request(tcp_opts) then
    callback(false, 'cannot make a TCP connection')
  end
end

exports.sendmail = sendmail

return exports