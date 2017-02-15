--[[
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- A plugin that pushes metadata (or whole messages) to external services

local rspamd_http
local rspamd_tcp
local rspamd_util
local rspamd_logger = require "rspamd_logger"
local N = 'metadata_exporter'

local settings = {
  format = function(task)
    return task:get_content()
  end,
  mime_type = 'text/plain',
  defer = false,
  mail_from = '',
  helo = 'rspamd',
  email_template = [[From: "Rspamd" <%s>
To: <%s>
Subject: Spam alert
Date: %s
MIME-Version: 1.0
Message-ID: <%s>
Content-type: text/plain; charset=us-ascii

Spam received from user %s on IP %s - queue ID %s]],
}

local formatters = {
  email_alert = function(task)
    local auser = task:get_user() or '[not applicable]'
    local fip = task:get_from_ip() or '[unknown]'
    local qid = task:get_queue_id() or '[unknown]'
    return rspamd_logger.slog(settings.email_template,
      settings.mail_from, settings.mail_to,
      rspamd_util.time_to_string(rspamd_util.get_time()),
      rspamd_util.random_hex(12) .. '@rspamd',
      auser, tostring(fip), qid
    )
  end,
}

local selectors = {
  is_spam = function(task)
    local action = task:get_metric_action('default')
    return (action == 'reject' or action == 'add header') and true or false
  end,
  is_spam_authed = function(task)
    if not task:get_user() then
      return false
    end
    local action = task:get_metric_action('default')
    return (action == 'reject' or action == 'add header') and true or false
  end,
  is_reject = function(task)
    local action = task:get_metric_action('default')
    return (action == 'reject') and true or false
  end,
  is_reject_authed = function(task)
    if not task:get_user() then
      return false
    end
    local action = task:get_metric_action('default')
    return (action == 'reject') and true or false
  end,
}

local opts = rspamd_config:get_all_opt(N)
if not opts then return end
local redis_params
local process_settings = {
  select = function(key)
    settings.select = assert(load(opts['select']))()
  end,
  format = function(key)
    settings.format = assert(load(opts['format']))()
  end,
}
for k, v in pairs(opts) do
  local f = process_settings[k]
  if f then
    f()
  else
    settings[k] = v
  end
end
if settings.formatter then
  settings.format = formatters[settings.formatter]
  if not settings.format then
    rspamd_logger.errx(rspamd_config, 'No such formatter: %s', settings.formatter)
    return
  end
end
if settings.selector then
  settings.select = selectors[settings.selector]
  if not settings.select then
    rspamd_logger.errx(rspamd_config, 'No such selector: %s', settings.selector)
    return
  end
end
if not ((settings.url or settings.channel) or (settings.mail_to and settings.smtp)) then
  rspamd_logger.errx(rspamd_config, 'No backends configured')
  return
end
if settings.channel then
  redis_params = rspamd_parse_redis_server(N)
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'No redis servers are specified')
    return
  end
end
if settings.url then
  rspamd_http = require "rspamd_http"
end
if settings.mail_to then
  rspamd_tcp = require "rspamd_tcp"
  rspamd_util = require "rspamd_util"
end
if opts['mime_type'] then
  settings['mime_type'] = opts['mime_type']
end

local function metadata_exporter(task)
  local _,ret,upstream
  local function maybe_defer()
    if settings.defer then
      rspamd_logger.warnx(task, 'deferring message')
      task:set_metric_action('default', 'soft reject')
    end
  end
  local function mail_cb(err, data, conn)
    local function no_error(merr, mdata, wantcode)
      wantcode = wantcode or '2'
      if merr then
        rspamd_logger.errx(task, 'got error in tcp callback: %s', merr)
        if conn then
          conn:close()
        end
        maybe_defer()
        return false
      end
      if mdata then
        if type(mdata) ~= 'string' then
          mdata = tostring(mdata)
        end
        if string.sub(mdata, 1, 1) ~= wantcode then
          rspamd_logger.errx(task, 'got bad smtp response: %s', mdata)
          if conn then
            conn:close()
          end
          maybe_defer()
          return false
        end
      else
        rspamd_logger.errx(task, 'no data')
        if conn then
          conn:close()
        end
        maybe_defer()
        return false
      end
      return true
    end
    local function all_done_cb(merr, mdata)
      if settings.force_action then
        rspamd_logger.warnx(task, 'forcing action: %s', settings.force_action)
        task:set_metric_action('default', settings.force_action)
      end
      if conn then
        conn:close()
      end
    end
    local function quit_done_cb(merr, mdata)
      conn:add_read(all_done_cb, '\r\n')
    end
    local function quit_cb(merr, mdata)
      if no_error(merr, mdata) then
        conn:add_write(quit_done_cb, 'QUIT\r\n')
      end
    end
    local function pre_quit_cb(merr, mdata)
      if no_error(merr, '2') then
        conn:add_read(quit_cb, '\r\n')
      end
    end
    local function data_done_cb(merr, mdata)
      if no_error(merr, mdata, '3') then
        local msg = settings.format(task)
        conn:add_write(pre_quit_cb, msg .. '\r\n.\r\n')
      end
    end
    local function data_cb(merr, mdata)
      if no_error(merr, '2') then
        conn:add_read(data_done_cb, '\r\n')
      end
    end
    local function rcpt_done_cb(merr, mdata)
      if no_error(merr, mdata) then
        conn:add_write(data_cb, 'DATA\r\n')
      end
    end
    local function rcpt_cb(merr, mdata)
      if no_error(merr, '2') then
        conn:add_read(rcpt_done_cb, '\r\n')
      end
    end
    local function from_done_cb(merr, mdata)
      if no_error(merr, mdata) then
        conn:add_write(rcpt_cb, 'RCPT TO: <' .. settings.mail_to .. '>\r\n')
      end
    end
    local function from_cb(merr, mdata)
      if no_error(merr, '2') then
        conn:add_read(from_done_cb, '\r\n')
      end
    end
    local function hello_done_cb(merr, mdata)
      if no_error(merr, mdata) then
        conn:add_write(from_cb, 'MAIL FROM: <' .. settings.mail_from .. '>\r\n')
      end
    end
    local function hello_cb(merr)
      if no_error(merr, '2') then
        conn:add_read(hello_done_cb, '\r\n')
      end
    end
    if no_error(err, data) then
      conn:add_write(hello_cb, 'HELO ' .. settings.helo .. '\r\n')
    end
  end
  local function http_callback(err, code)
    if err then
      rspamd_logger.errx(task, 'got error %s in http callback', err)
      return maybe_defer()
    end
    if code ~= 200 then
      rspamd_logger.errx(task, 'got unexpected http status: %s', code)
      return maybe_defer()
    end
    if settings.force_action then
      rspamd_logger.warnx(task, 'forcing action: %s', settings.force_action)
      task:set_metric_action('default', settings.force_action)
    end
  end
  local function redis_set_cb(err)
    if err then
      rspamd_logger.errx(task, 'got error %s when publishing record on server %s',
          err, upstream:get_addr())
      return maybe_defer()
    end
    if settings.force_action then
      rspamd_logger.warnx(task, 'forcing action: %s', settings.force_action)
      task:set_metric_action('default', settings.force_action)
    end
  end
  if settings.select then
    if not settings.select(task) then return end
    rspamd_logger.debugm(N, task, 'Message selected for processing')
  end
  local data = settings.format(task)
  if not data then
    rspamd_logger.debugm(N, task, 'Format returned non-truthy value: %1', data)
    return
  end
  if settings.channel then
    ret,_,upstream = rspamd_redis_make_request(task,
      redis_params, -- connect params
      nil, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'PUBLISH', -- command
      {settings.channel, data} -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, 'error connecting to redis')
      maybe_defer()
    end
  end
  if settings.url then
    rspamd_http.request({
      task=task,
      url=settings.url,
      body=data,
      callback=http_callback,
      mime_type=settings['mime_type'],
    })
  end
  if (settings.mail_to and settings.smtp) then
    rspamd_tcp.request({
      task = task,
      callback = mail_cb,
      stop_pattern = '\r\n',
      host = settings.smtp,
      port = settings.smtp_port or 25,
    })
  end
end

rspamd_config:register_symbol({
  name = 'EXPORT_METADATA',
  type = 'postfilter',
  callback = metadata_exporter,
  priority = 10
})
