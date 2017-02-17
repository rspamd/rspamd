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

local redis_params
local rspamd_http = require "rspamd_http"
local rspamd_tcp = require "rspamd_tcp"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local N = 'metadata_exporter'

local settings = {
  pusher_enabled = {},
  pusher_format = {},
  pusher_select = {},
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
  default = function(task)
    return task:get_content()
  end,
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
  default = function(task)
    return true
  end,
  is_spam = function(task)
    local action = task:get_metric_action('default')
    return (action == 'reject' or action == 'add header')
  end,
  is_spam_authed = function(task)
    if not task:get_user() then
      return false
    end
    local action = task:get_metric_action('default')
    return (action == 'reject' or action == 'add header')
  end,
  is_reject = function(task)
    local action = task:get_metric_action('default')
    return (action == 'reject')
  end,
  is_reject_authed = function(task)
    if not task:get_user() then
      return false
    end
    local action = task:get_metric_action('default')
    return (action == 'reject')
  end,
}

local function maybe_defer(task)
  if settings.defer then
    rspamd_logger.warnx(task, 'deferring message')
    task:set_metric_action('default', 'soft reject')
  end
end

local function maybe_force_action(task)
  if settings.force_action then
    rspamd_logger.warnx(task, 'forcing action: %s', settings.force_action)
    task:set_metric_action('default', settings.force_action)
  end
end

local pushers = {
  redis_pubsub = function(task, formatted)
    local _,ret,upstream
    local function redis_pub_cb(err)
      if err then
        rspamd_logger.errx(task, 'got error %s when publishing on server %s',
            err, upstream:get_addr())
        return maybe_defer(task)
      end
      maybe_force_action(task)
    end
    ret,_,upstream = rspamd_redis_make_request(task,
      redis_params, -- connect params
      nil, -- hash key
      true, -- is write
      redis_pub_cb, --callback
      'PUBLISH', -- command
      {settings.channel, formatted} -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, 'error connecting to redis')
      maybe_defer(task)
    end
  end,
  http = function(task, formatted)
    local function http_callback(err, code)
      if err then
        rspamd_logger.errx(task, 'got error %s in http callback', err)
        return maybe_defer(task)
      end
      if code ~= 200 then
        rspamd_logger.errx(task, 'got unexpected http status: %s', code)
        return maybe_defer(task)
      end
      maybe_force_action(task)
    end
    rspamd_http.request({
      task=task,
      url=settings.url,
      body=formatted,
      callback=http_callback,
      mime_type=settings['mime_type'],
    })
  end,
  send_mail = function(task, formatted)
    local function mail_cb(err, data, conn)
      local function no_error(merr, mdata, wantcode)
        wantcode = wantcode or '2'
        if merr then
          rspamd_logger.errx(task, 'got error in tcp callback: %s', merr)
          if conn then
            conn:close()
          end
          maybe_defer(task)
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
            maybe_defer(task)
            return false
            end
        else
            rspamd_logger.errx(task, 'no data')
          if conn then
            conn:close()
          end
          maybe_defer(task)
          return false
        end
        return true
      end
      local function all_done_cb(merr, mdata)
        maybe_force_action(task)
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
          conn:add_write(pre_quit_cb, {formatted, '\r\n.\r\n'})
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
    rspamd_tcp.request({
      task = task,
      callback = mail_cb,
      stop_pattern = '\r\n',
      host = settings.smtp,
      port = settings.smtp_port or 25,
    })
  end,
}

local opts = rspamd_config:get_all_opt(N)
if not opts then return end
local process_settings = {
  select = function(val)
    selectors.custom = assert(load(val))()
  end,
  format = function(val)
    formatters.custom = assert(load(val))()
  end,
  push = function(key, val)
    pushers.custom = assert(load(val))()
  end,
  pusher_enabled = function(val)
    if type(val) == 'string' then
      if pushers[val] then
        settings.pusher_enabled[val] = true
      else
        rspamd_logger.errx(rspamd_config, 'Pusher type: %s is invalid', val)
      end
    elseif type(val) == 'table' then
      for _, v in ipairs(val) do
        if pushers[v] then
          settings.pusher_enabled[v] = true
        else
          rspamd_logger.errx(rspamd_config, 'Pusher type: %s is invalid', val)
        end
      end
    end
  end,
}
for k, v in pairs(opts) do
  local f = process_settings[k]
  if f then
    f(opts[k])
  else
    settings[k] = v
  end
end
if not next(settings.pusher_enabled) then
  if pushers.custom then
    rspamd_logger.infox(rspamd_config, 'Custom pusher implicitly enabled')
    settings.pusher_enabled.custom = true
  else
    -- Check legacy options
    if settings.url then
      rspamd_logger.warnx(rspamd_config, 'HTTP pusher implicitly enabled')
      settings.pusher_enabled.http = true
    end
    if settings.channel then
      rspamd_logger.warnx(rspamd_config, 'Redis Pubsub pusher implicitly enabled')
      settings.pusher_enabled.redis_pubsub = true
    end
    if settings.smtp and settings.mail_to then
      rspamd_logger.warnx(rspamd_config, 'Redis Pubsub pusher implicitly enabled')
      settings.pusher_enabled.send_mail = true
    end
  end
end
if not next(settings.pusher_enabled) then
  rspamd_logger.errx(rspamd_config, 'No push backend enabled')
  return
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
for k in pairs(settings.pusher_enabled) do
  local formatter = settings.pusher_format[k]
  local selector = settings.pusher_select[k]
  if not formatter then
    settings.pusher_format[k] = 'default'
    rspamd_logger.infox(rspamd_config, 'Using default formatter for %s pusher', k)
  else
    if not formatters[formatter] then
      rspamd_logger.errx(rspamd_config, 'No such formatter: %s - disabling %s', formatter, k)
      settings.pusher_enabled.k = nil
    end
  end
  if not selector then
    settings.pusher_select[k] = 'default'
    rspamd_logger.infox(rspamd_config, 'Using default selector for %s pusher', k)
  else
    if not selectors[selector] then
      rspamd_logger.errx(rspamd_config, 'No such selector: %s - disabling %s', selector, k)
      settings.pusher_enabled.k = nil
    end
  end
end
if settings.pusher_enabled.redis_pubsub then
  redis_params = rspamd_parse_redis_server(N)
  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'No redis servers are specified')
    settings.pusher_enabled.redis_pubsub = nil
  end
end
if settings.pusher_enabled.http then
  if not settings.url then
    rspamd_logger.errx(rspamd_config, 'No URL is specified')
    settings.pusher_enabled.http = nil
  end
end
if settings.pusher_enabled.send_mail then
  if not (settings.mail_to and settings.smtp) then
    rspamd_logger.errx(rspamd_config, 'No mail_to and/or smtp setting is specified')
    settings.pusher_enabled.send_mail = nil
  end
end
if not next(settings.pusher_enabled) then
  rspamd_logger.errx(rspamd_config, 'No push backend enabled')
  return
end

local function metadata_exporter(task)
  local results = {
    select = {},
    format = {},
  }
  for k in pairs(settings.pusher_enabled) do
    local selector = settings.pusher_select[k] or 'default'
    local selected = results.select[selector]
    if selected == nil then
      results.select[selector] = selectors[selector](task)
      selected = results.select[selector]
    end
    if selected then
      rspamd_logger.debugm(N, task, 'Message selected for processing')
      local formatter = settings.pusher_format[k]
      local formatted = results.format[k]
      if formatted == nil then
        results.format[formatter] = formatters[formatter](task)
        formatted = results.format[formatter]
      end
      if formatted then
        pushers[k](task, formatted)
      elseif formatted == nil then
        rspamd_logger.warnx(task, 'Formatter [%s] returned NIL', formatter)
      else
        rspamd_logger.debugm(N, task, 'Formatter [%s] returned non-truthy value [%s]', formatter, formatted)
      end
    end
  end
end

rspamd_config:register_symbol({
  name = 'EXPORT_METADATA',
  type = 'postfilter',
  callback = metadata_exporter,
  priority = 10
})
