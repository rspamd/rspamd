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

if confighelp then
  rspamd_config:add_example(nil, 'history_redis',
      "Store history of checks for WebUI using Redis",
      [[
redis_history {
  # History key name
  key_prefix = 'rs_history{{HOSTNAME}}{{COMPRESS}}';
  # Expire in seconds for inactive keys, default to 5 days
  expire = 432000;
  # History rows limit
  nrows = 200;
  # Use zstd compression when storing data in redis
  compress = true;
  # Obfuscate subjects for privacy
  subject_privacy = false;
  # Default hash-algorithm to obfuscate subject
  subject_privacy_alg = 'blake2';
  # Prefix to show it's obfuscated
  subject_privacy_prefix = 'obf';
  # Cut the length of the hash if desired
  subject_privacy_length = 16;
}
  ]])
  return
end

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local fun = require "fun"
local ucl = require "ucl"
local ts = (require "tableshape").types
local E = {}
local N = "history_redis"

local template_env = {
  HOSTNAME = rspamd_util.get_hostname(),
}

local redis_params

local settings = {
  key_prefix = 'rs_history{{HOSTNAME}}{{COMPRESS}}', -- default key name template
  expire = nil, -- default no expire
  nrows = 200, -- default rows limit
  compress = true, -- use zstd compression when storing data in redis
  subject_privacy = false, -- subject privacy is off
  subject_privacy_alg = 'blake2', -- default hash-algorithm to obfuscate subject
  subject_privacy_prefix = 'obf', -- prefix to show it's obfuscated
  subject_privacy_length = 16, -- cut the length of the hash
}

local settings_schema = lua_redis.enrich_schema({
  key_prefix = ts.string,
  expire = (ts.number + ts.string / lua_util.parse_time_interval):is_optional(),
  nrows = ts.number,
  compress = ts.boolean,
  subject_privacy = ts.boolean:is_optional(),
  subject_privacy_alg = ts.string:is_optional(),
  subject_privacy_prefix = ts.string:is_optional(),
  subject_privacy_length = ts.number:is_optional(),
})

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
    local symbols, others = fun.partition(function(_, v)
      return type(v) == 'table' and v.score
    end, metric)

    fun.each(function(k, v)
      v.name = nil;
      tbl.symbols[k] = v;
    end, symbols)
    fun.each(function(k, v)
      tbl[k] = v
    end, others)

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
  tbl.action = task:get_metric_action()

  local seconds = task:get_timeval()['tv_sec']
  tbl.unix_time = seconds

  local subject = task:get_header('subject') or 'unknown'
  tbl.subject = lua_util.maybe_obfuscate_string(subject, settings, 'subject')
  tbl.size = task:get_size()
  local ip = task:get_from_ip()
  if ip and ip:is_valid() then
    tbl.ip = tostring(ip)
  else
    tbl.ip = 'unknown'
  end

  tbl.user = task:get_user() or 'unknown'
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

  local data = task:get_protocol_reply { 'metrics', 'basic' }
  local prefix = lua_util.jinja_template(settings.key_prefix, template_env, false, true)

  if data then
    normalise_results(data, task)
  else
    rspamd_logger.errx('cannot get protocol reply, skip saving in history')
    return
  end

  local json = ucl.to_format(data, 'json-compact')

  if settings.compress then
    json = rspamd_util.zstd_compress(json)
  end

  local ret, conn, _ = lua_redis.rspamd_redis_make_request(task,
      redis_params, -- connect params
      nil, -- hash key
      true, -- is write
      redis_llen_cb, --callback
      'LPUSH', -- command
      { prefix, json } -- arguments
  )

  if ret then
    conn:add_cmd('LTRIM', { prefix, '0', string.format('%d', settings.nrows - 1) })

    if settings.expire and settings.expire > 0 then
      conn:add_cmd('EXPIRE', { prefix, string.format('%d', settings.expire) })
    end
  end
end

local function handle_history_request(task, conn, from, to, reset)
  local prefix = lua_util.jinja_template(settings.key_prefix, template_env, false, true)

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
    lua_redis.rspamd_redis_make_request(task,
        redis_params, -- connect params
        nil, -- hash key
        true, -- is write
        redis_ltrim_cb, --callback
        'LTRIM', -- command
        { prefix, '0', '0' } -- arguments
    )
  else
    local function redis_lrange_cb(err, data)
      if data then
        local reply = {
          version = 2,
        }
        if settings.compress then
          local t1 = rspamd_util:get_ticks()

          data = fun.totable(fun.filter(function(e)
            return e ~= nil
          end,
              fun.map(function(e)
                local _, dec = rspamd_util.zstd_decompress(e)
                if dec then
                  return dec
                end
                return nil
              end, data)))
          lua_util.debugm(N, task, 'decompress took %s ms',
              (rspamd_util:get_ticks() - t1) * 1000.0)
          collectgarbage()
        end
        -- Parse elements using ucl
        local t1 = rspamd_util:get_ticks()
        data = fun.totable(
            fun.map(function(_, obj)
              return obj
            end,
                fun.filter(function(res, obj)
                  if res then
                    return true
                  end
                  return false
                end,
                    fun.map(function(elt)
                      local parser = ucl.parser()
                      local res, _ = parser:parse_text(elt)

                      if res then
                        return true, parser:get_object()
                      else
                        return false, nil
                      end
                    end, data))))
        lua_util.debugm(N, task, 'parse took %s ms',
            (rspamd_util:get_ticks() - t1) * 1000.0)
        collectgarbage()
        t1 = rspamd_util:get_ticks()
        reply.rows = data
        conn:send_ucl(reply)
        lua_util.debugm(N, task, 'process + sending took %s ms',
            (rspamd_util:get_ticks() - t1) * 1000.0)
        collectgarbage()
      else
        rspamd_logger.errx(task, 'got error %s when getting history: %s',
            err)
        conn:send_error(504, '{"error": "' .. err .. '"}')
      end
    end
    lua_redis.rspamd_redis_make_request(task,
        redis_params, -- connect params
        nil, -- hash key
        false, -- is write
        redis_lrange_cb, --callback
        'LRANGE', -- command
        { prefix, string.format('%d', from), string.format('%d', to) }, -- arguments
        { opaque_data = true }
    )
  end
end

local opts = rspamd_config:get_all_opt('history_redis')
if opts then
  settings = lua_util.override_defaults(settings, opts)
  local res, err = settings_schema:transform(settings)

  if not res then
    rspamd_logger.warnx(rspamd_config, '%s: plugin is misconfigured: %s', N, err)
    lua_util.disable_module(N, "config")
    return
  end
  settings = res

  if settings.compress then
    template_env.COMPRESS = '_zst'
  else
    template_env.COMPRESS = ''
  end

  redis_params = lua_redis.parse_redis_server('history_redis')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "redis")
  else
    rspamd_config:register_symbol({
      name = 'HISTORY_SAVE',
      type = 'idempotent',
      callback = history_save,
      flags = 'empty,explicit_disable,ignore_passthrough',
      augmentations = { string.format("timeout=%f", redis_params.timeout or 0.0) }
    })
    lua_redis.register_prefix(lua_util.jinja_template(settings.key_prefix, template_env, false, true), N,
        "Redis history", {
          type = 'list',
        })
    rspamd_plugins['history'] = {
      handler = handle_history_request
    }
  end
end
