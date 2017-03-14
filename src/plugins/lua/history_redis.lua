--[[
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local redis_params

local settings = {
  key_prefix = 'rs_history', -- default key name
  nrows = 2000, -- default rows limit
  compress = true, -- use zstd compression when storing data in redis
}

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local fun = require "fun"
local ucl = require("ucl")
local E = {}

local function process_addr(addr)
  if addr then
    return addr.addr
  end

  return 'unknown'
end

local function normalise_results(tbl, task)
  local metric = tbl.default

  -- Convert stupid metric object
  if metric then
    tbl.symbols = {}
    local symbols, others = fun.partition(function(k, v)
      return type(v) == 'table' and v.score
    end, metric)

    fun.each(function(k, v) v.name = nil; tbl.symbols[k] = v; end, symbols)
    fun.each(function(k, v) tbl[k] = v end, others)

    -- Reset the original metric
    tbl.default = nil
  end

  -- Now, add recipients and senders
  tbl.sender_smtp = process_addr((task:get_from('smtp') or E)[1])
  tbl.sender_mime = process_addr((task:get_from('mime') or E)[1])
  tbl.rcpt_smtp = fun.totable(fun.map(process_addr, task:get_recipients('smtp') or {}))
  tbl.rcpt_mime = fun.totable(fun.map(process_addr, task:get_recipients('mime') or {}))
  tbl.user = task:get_user() or 'unknown'
  tbl.rmilter = nil
  tbl.messages = nil
  tbl.urls = nil

  tbl.subject = task:get_header('subject') or 'unknown'
end

local function history_save(task)
  local function redis_llen_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'got error %s when writing history row: %s',
          err)
    end
  end

  -- We skip saving it to the history
  if task:has_flag('no_log') then
    return
  end

  local data = task:get_protocol_reply{'metrics', 'basic'}
  local prefix = settings.key_prefix

  if data then
    normalise_results(data, task)
  else
    rspamd_logger.errx('cannot get protocol reply, skip saving in history')
    return
  end
  -- 1 is 'json-compact' but faster
  local json = ucl.to_format(data, 1)

  if settings.compress then
    json = tostring(rspamd_util.zstd_compress(json))
    -- Distinguish between compressed and non-compressed options
    prefix = prefix .. '_zst'
  end

  local ret, conn, _ = rspamd_redis_make_request(task,
    redis_params, -- connect params
    nil, -- hash key
    true, -- is write
    redis_llen_cb, --callback
    'LPUSH', -- command
    {prefix, json} -- arguments
  )

  if ret then
    conn:add_cmd('LTRIM', {prefix, '0', tostring(settings.nrows)})
  end
end

local function handle_history_request(task, conn, from, to, reset)
  local prefix = settings.key_prefix
  if settings.compress then
    -- Distinguish between compressed and non-compressed options
    prefix = prefix .. '_zst'
  end

  if reset then
    local function redis_ltrim_cb(err, _)
      if err then
        rspamd_logger.errx(task, 'got error %s when resetting history: %s',
          err)
        conn:send_error(504, '{"error": "' .. err .. '"}')
      else
        conn:send_string('{"success":true}')
      end
    end
    rspamd_redis_make_request(task,
      redis_params, -- connect params
      nil, -- hash key
      true, -- is write
      redis_ltrim_cb, --callback
      'LTRIM', -- command
      {prefix, '0', '0'} -- arguments
    )
  else
    local function redis_lrange_cb(err, data)
      if data then
        local reply = {
          version = 2,
        }

        if settings.compress then
          reply.rows = fun.totable(fun.filter(function(e) return e ~= nil end,
            fun.map(function(e)
              local _,dec = rspamd_util.zstd_decompress(e)
              if dec then
                return tostring(dec)
              end
              return nil
            end, data)))
        else
          reply.rows = data
        end
        conn:send_ucl(reply)
      else
       rspamd_logger.errx(task, 'got error %s when getting history: %s',
          err)
        conn:send_error(504, '{"error": "' .. err .. '"}')
      end
    end
    rspamd_redis_make_request(task,
      redis_params, -- connect params
      nil, -- hash key
      false, -- is write
      redis_lrange_cb, --callback
      'LRANGE', -- command
      {prefix, tostring(from), tostring(to)} -- arguments
    )
  end
end

local opts =  rspamd_config:get_all_opt('history_redis')
if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end

  redis_params = rspamd_parse_redis_server('history_redis')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
  else
    rspamd_config:register_symbol({
      name = 'HISTORY_SAVE',
      type = 'postfilter',
      callback = history_save,
      priority = 150
    })
    rspamd_plugins['history'] = {
      handler = handle_history_request
    }
  end
end