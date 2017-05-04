--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>

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

-- A plugin that triggers, if a spam trapped email address was detected

local rspamd_logger = require "rspamd_logger"
local redis_params
local use_redis = false;
local M = 'spamtrap'

local settings = {
  symbol = 'SPAMTRAP',
  score = 0.0,
  learn_fuzzy = false,
  learn_spam = false,
  fuzzy_flag = 1,
  fuzzy_weight = 10.0,
  key_prefix = 'sptr_'
}

local function spamtrap_cb(task)
  local rcpts = task:get_recipients('smtp')
  local called_for_domain = false
  local target

  local function do_action(rcpt)
    if settings['learn_fuzzy'] then
      rspamd_plugins.fuzzy_check.learn(task,
        settings['fuzzy_flag'],
        settings['fuzzy_weight'])
    end
    if settings['learn_spam'] then
      task:set_flag("learn_spam")
    end
    task:insert_result(settings['symbol'],
      settings['score'],
      rcpt)

    if settings['action'] then
      task:set_pre_result(settings['action'],
        string.format('spamtrap found: <%s>', rcpt))
    end
  end

  local function redis_spamtrap_cb(err, data)
    if err ~= nil then
      rspamd_logger.errx(task, 'redis_spamtrap_cb received error: %1', err)
      return
    end

    if data and type(data) ~= 'userdata' then
      do_action(target)
    else
      if not called_for_domain then
        -- Recurse for @catchall domain
        target = rcpts[1]['domain']:lower()
        local key = settings['key_prefix'] .. '@' .. target
        local ret = rspamd_redis_make_request(task,
          redis_params, -- connect params
          key, -- hash key
          false, -- is write
          redis_spamtrap_cb, -- callback
          'GET', -- command
          {key} -- arguments
        )
        if not ret then
          rspamd_logger.errx(task, "redis request wasn't scheduled")
        end
        called_for_domain = true
      else
        rspamd_logger.debugm(M, task, 'skip spamtrap for %s', target)
      end
    end
  end

  -- Do not risk a FP by checking for more than one recipient
  if rcpts and #rcpts == 1 then
    target = rcpts[1]['addr']:lower()
    if use_redis then
      local key = settings['key_prefix'] .. target
      local ret = rspamd_redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_spamtrap_cb, -- callback
        'GET', -- command
        {key} -- arguments
      )
      if not ret then
        rspamd_logger.errx(task, "redis request wasn't scheduled")
      end
    elseif settings['map'] then
      if settings['map']:get_key(target) then
        do_action(target)
      else
        rspamd_logger.debugm(M, task, 'skip spamtrap for %s', target)
      end
    end
  end
end

-- Module setup
local opts = rspamd_config:get_all_opt('spamtrap')
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'module is unconfigured')
  return
end
if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end
  if settings['map'] then
    settings['map'] = rspamd_config:add_map{
      url = settings['map'],
      description = "Spamtrap map for %s", settings['symbol'],
      type = "regexp"
    }
  else
    redis_params = rspamd_parse_redis_server('spamtrap')
    if not redis_params then
      rspamd_logger.errx(
        rspamd_config, 'no redis servers are specified, disabling module')
      return
    end
    use_redis = true;
  end

  local id = rspamd_config:register_symbol({
    name = "SPAMTRAP_CHECK",
    type = "postfilter",
    callback = spamtrap_cb
  })
  rspamd_config:register_symbol({
    name = settings['symbol'],
    parent = id,
    type = 'virtual',
    score = settings.score
  })
end
