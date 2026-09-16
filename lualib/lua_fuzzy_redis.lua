--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]

-- Lua module for fuzzy Redis backend: update path (following the Bayes pattern)
-- and the periodic count scan

local exports = {}
local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"

local N = "fuzzy_redis"

local function gen_update_functor(redis_params, update_script_id)
  -- Returns function(ev_base, prefix, updates, src, expire, callback)
  -- updates is an array of tables: {op, digest, flag, value, is_weak, shingle_keys}
  -- callback(success_boolean) is called when all operations complete
  return function(ev_base, prefix, updates, src, expire, callback)
    local n_ops = 0
    local n_completed = 0
    local has_error = false

    -- Count actual operations (skip "dup")
    for _, upd in ipairs(updates) do
      if upd.op ~= "dup" then
        n_ops = n_ops + 1
      end
    end

    -- Final step: INCR version key and invoke callback
    local function do_version_incr()
      local version_key = prefix .. src

      local function version_cb(err, _)
        if err then
          logger.errx(rspamd_config, '%s: version INCR failed for %s: %s',
              N, version_key, err)
        end
        callback(not has_error)
      end

      if not lua_redis.redis_make_request_taskless(ev_base, rspamd_config,
          redis_params, version_key, true, version_cb, 'INCR', { version_key }) then
        logger.errx(rspamd_config, '%s: cannot make version INCR request', N)
        callback(false)
      end
    end

    -- Called when one exec_redis_script completes
    local function on_op_complete()
      n_completed = n_completed + 1
      if n_completed >= n_ops then
        do_version_incr()
      end
    end

    -- If no actual operations, just do version INCR
    if n_ops == 0 then
      do_version_incr()
      return
    end

    for _, upd in ipairs(updates) do
      if upd.op ~= "dup" then
        local hash_key = prefix .. upd.digest

        -- Build KEYS array (only actual Redis key names) and ARGV (parameters)
        local keys = {
          hash_key,
        }

        -- Append shingle keys if present
        if upd.shingle_keys then
          for _, sk in ipairs(upd.shingle_keys) do
            keys[#keys + 1] = sk
          end
        end

        local args = {
          upd.op,
          tostring(upd.flag),
          tostring(upd.value),
          tostring(expire),
          tostring(upd.timestamp),
          tostring(upd.is_weak),
          upd.digest,
        }

        local function update_cb(err, _)
          if err then
            logger.errx(rspamd_config, '%s: update script failed: %s', N, err)
            has_error = true
          end
          on_op_complete()
        end

        lua_redis.exec_redis_script(update_script_id,
            { ev_base = ev_base, is_write = true, key = hash_key },
            update_cb, keys, args)
      end
    end
  end
end

-- Initialize fuzzy Redis update module
-- @param redis_params table returned by lua_redis.try_load_redis_servers
-- @return update functor or nil on error
exports.lua_fuzzy_redis_init = function(redis_params)
  if not redis_params then
    logger.errx(rspamd_config, '%s: no redis params provided', N)
    return nil
  end

  local update_script_id, err = lua_redis.load_redis_script_from_file(
      "fuzzy_update.lua", redis_params)
  if not update_script_id then
    logger.errx(rspamd_config, '%s: cannot load fuzzy_update.lua: %s', N,
        err or "unknown error")
    return nil
  end

  return gen_update_functor(redis_params, update_script_id)
end

--[[
Count scan

The number of stored hashes cannot be maintained by the update path: hashes
leave storage via TTL, and adds/deletes do not know whether a digest already
exists. Instead, the keyspace is walked with a slow, resumable SCAN and the
result is published into `prefix .. "_count"`, which workers read as before.

* only digest keys are matched: they are exactly prefix + 64 raw bytes, while
  shingle, version and service keys are all shorter
* the scan runs on one read server (a replica if configured), pinned for the
  whole pass as a cursor is meaningless elsewhere
* requests are paced so that at most `duty_cycle` of the time a SCAN is
  outstanding, backing off as Redis gets slower
* progress, the lock and the published count live on the write servers, so a
  restarted worker resumes the pass and several storages sharing a Redis
  scan it once
* with `stats_sample` > 0 the SCAN runs inside a read-only script that also
  reads every N-th digest found (chosen by the digest bytes, so the sample is
  stable across resumes) and returns aggregates: per flag count and weight,
  multi-flag and shingled hashes, age buckets. The pass publishes them scaled
  to the full count into `prefix .. "_stats"` for the storage worker; the
  wire protocol never exposes them
]]

local count_scan_defaults = {
  enabled = true,
  interval = 4 * 3600, -- minimum time between completed passes
  batch = 1000, -- SCAN COUNT hint
  duty_cycle = 0.1, -- maximum share of time a SCAN request is outstanding
  min_delay = 0.01, -- bounds of the pause between SCAN requests
  max_delay = 5.0,
  checkpoint_interval = 30.0, -- how often progress is persisted
  lock_ttl = 300,
  initial_delay = 30.0, -- first attempt after start, jittered
  error_backoff = 60.0,
  max_errors = 5, -- consecutive SCAN failures before the pass is suspended
  stats_sample = 10, -- read every N-th digest for content statistics, 0 disables them
}

local count_scanners = {}

local function glob_escape(s)
  return (string.gsub(s, '[%*%?%[%]\\]', '\\%0'))
end

local function normalize_count_scan_settings(opts)
  local settings = lua_util.override_defaults(count_scan_defaults, opts or {})

  for k, def in pairs(count_scan_defaults) do
    local v = settings[k]

    if type(def) == 'number' then
      if type(v) == 'string' then
        v = lua_util.parse_time_interval(v) or tonumber(v)
      end

      if type(v) ~= 'number' or v < 0 then
        return nil, string.format('invalid value for count_scan.%s: %s', k, tostring(settings[k]))
      end
    elseif type(v) ~= type(def) then
      return nil, string.format('invalid value for count_scan.%s: %s', k, tostring(settings[k]))
    end

    settings[k] = v
  end

  if settings.duty_cycle <= 0 or settings.duty_cycle > 1 then
    return nil, 'count_scan.duty_cycle must be in (0, 1]'
  end

  if settings.min_delay <= 0 or settings.batch < 1 or settings.lock_ttl < 1 then
    return nil, 'count_scan.min_delay, batch and lock_ttl must be positive'
  end

  settings.batch = math.floor(settings.batch)
  settings.lock_ttl = math.ceil(settings.lock_ttl)
  settings.max_delay = math.max(settings.max_delay, settings.min_delay)
  -- The sample is selected by two digest bytes
  settings.stats_sample = math.min(math.floor(settings.stats_sample), 65536)

  return settings
end

-- Reads a script that is sent with EVAL/EVALSHA to a pinned server, bypassing
-- the lua_redis script registry that routes by key
local function read_script_body(filename)
  local path = lua_util.join_path(rspamd_paths.LUALIBDIR, 'redis_scripts', filename)
  local f = io.open(path, 'r')

  if not f then
    return nil, string.format('cannot open %s', path)
  end

  local body = f:read('*all')
  f:close()

  if not body then
    return nil, string.format('cannot read %s', path)
  end

  body = lua_util.strip_lua_comments(body)
  local h = require("rspamd_cryptobox_hash").create_specific('sha1')
  h:update(body)

  return { body = body, sha = h:hex() }
end

local function new_stats()
  return {
    sampled = 0,
    multi_flag = 0,
    shingled = 0,
    shingle_slots = 0,
    ages = { 0, 0, 0, 0 },
    flags = {},
  }
end

-- Adds one reply of fuzzy_stats_scan.lua (see its header for the layout)
local function merge_stats_reply(stats, data)
  stats.sampled = stats.sampled + (tonumber(data[3]) or 0)
  stats.multi_flag = stats.multi_flag + (tonumber(data[4]) or 0)
  stats.shingled = stats.shingled + (tonumber(data[5]) or 0)
  stats.shingle_slots = stats.shingle_slots + (tonumber(data[6]) or 0)

  for i = 1, 4 do
    stats.ages[i] = (stats.ages[i] or 0) + (tonumber(data[6 + i]) or 0)
  end

  for i = 11, #data - 3, 4 do
    local flag = tostring(data[i])
    local count, sum, max = tonumber(data[i + 1]) or 0, tonumber(data[i + 2]) or 0,
    tonumber(data[i + 3]) or 0
    local fl = stats.flags[flag]

    if fl then
      fl.count, fl.sum, fl.max = fl.count + count, fl.sum + sum, math.max(fl.max, max)
    else
      stats.flags[flag] = { count = count, sum = sum, max = max }
    end
  end
end

local function decode_stats(str)
  if type(str) ~= 'string' or str == '' then
    return nil
  end

  local parser = ucl.parser()

  if not parser:parse_string(str) then
    return nil
  end

  local stats = parser:get_object()

  if type(stats) ~= 'table' or type(stats.flags) ~= 'table' or type(stats.ages) ~= 'table' then
    return nil
  end

  return stats
end

-- Scales the sampled aggregates to the whole storage
local function published_stats(stats, found, sample, extra)
  local scale = stats.sampled > 0 and (found / stats.sampled) or 0
  local function scaled(n)
    return math.floor(n * scale + 0.5)
  end

  local out = {
    sample = sample,
    sampled = stats.sampled,
    found = found,
    multi_flag = scaled(stats.multi_flag),
    shingled = scaled(stats.shingled),
    shingle_slots = scaled(stats.shingle_slots),
    age = {
      ['1d'] = scaled(stats.ages[1] or 0),
      ['7d'] = scaled(stats.ages[2] or 0),
      ['30d'] = scaled(stats.ages[3] or 0),
      older = scaled(stats.ages[4] or 0),
    },
    flags = {},
  }

  for flag, fl in pairs(stats.flags) do
    out.flags[flag] = {
      count = scaled(fl.count),
      avg_weight = fl.count > 0 and (fl.sum / fl.count) or 0,
      max_weight = fl.max,
    }
  end

  for k, v in pairs(extra) do
    out[k] = v
  end

  return ucl.to_format(out, 'json-compact')
end

-- Starts the count scan for a storage, must be called from one worker only
-- @param redis_params table returned by lua_redis.try_load_redis_servers
-- @param ev_base event loop
-- @param prefix storage prefix
-- @param opts optional `count_scan` table of the fuzzy worker
-- @return true if the scan is scheduled
exports.lua_fuzzy_redis_start_count_scan = function(redis_params, ev_base, prefix, opts)
  local settings, err = normalize_count_scan_settings(opts)

  if not settings then
    logger.errx(rspamd_config, '%s: %s; count scan disabled', N, err)
    return false
  end

  if not settings.enabled then
    logger.infox(rspamd_config, '%s: count scan is disabled for prefix %s', N, prefix)
    return false
  end

  local scan_id = string.format('%s:%s', prefix, redis_params.hash or '')

  if count_scanners[scan_id] then
    return true
  end

  local script_id
  script_id, err = lua_redis.load_redis_script_from_file("fuzzy_count_scan.lua",
      redis_params)

  if not script_id then
    logger.errx(rspamd_config, '%s: cannot load fuzzy_count_scan.lua: %s', N,
        err or "unknown error")
    return false
  end

  local stats_script

  if settings.stats_sample > 0 then
    stats_script, err = read_script_body('fuzzy_stats_scan.lua')

    if not stats_script then
      logger.errx(rspamd_config, '%s: cannot load fuzzy_stats_scan.lua: %s; ' ..
          'storage statistics disabled', N, err)
      settings.stats_sample = 0
    end
  end

  local keys = {
    prefix .. '_count_scan_lock',
    prefix .. '_count_scan',
    prefix .. '_count',
    prefix .. '_stats',
  }
  local pattern = glob_escape(prefix) .. string.rep('?', 64)
  -- Stable per host, so a restarted worker takes its own lock over
  local token = rspamd_util.get_hostname()
  -- Progress that has not been checkpointed for so long is abandoned
  local stale_age = math.max(settings.interval, settings.lock_ttl * 3)
  local request_timeout = math.max(60.0, (redis_params.timeout or 1.0) * 10)

  local st = {
    phase = 'idle', -- idle or scanning
    gen = 0, -- identifies the outstanding request, late replies are dropped
    busy_since = nil,
    wake_at = 0,
    stats = new_stats(),
    script_known = false, -- whether the stats script is known to be cached by the server
  }
  count_scanners[scan_id] = st

  local function wait(delay)
    st.wake_at = rspamd_util.get_ticks() + delay
  end

  local function calendar_now()
    return string.format('%.3f', rspamd_util.get_time())
  end

  -- Wraps a reply handler of a new request
  local function new_request(f)
    st.gen = st.gen + 1
    st.busy_since = rspamd_util.get_ticks()
    local gen = st.gen

    return function(req_err, data)
      if gen ~= st.gen or not st.busy_since then
        return
      end

      st.busy_since = nil
      local ok, res = pcall(f, req_err, data)

      if not ok then
        logger.errx(rspamd_config, '%s: count scan for prefix %s failed: %s', N, prefix, res)
        st.phase = 'idle'
        wait(settings.error_backoff)
      end
    end
  end

  local function exec_script(args, f)
    local cb = new_request(f)

    if not lua_redis.exec_redis_script(script_id,
        { ev_base = ev_base, is_write = true, key = keys[2] },
        cb, keys, args) then
      cb('cannot execute count scan script', nil)
    end
  end

  local function script_args(op, ...)
    return { op, token, tostring(settings.lock_ttl), calendar_now(), ... }
  end

  local function suspend_pass(reason)
    logger.infox(rspamd_config, '%s: suspending count scan for prefix %s on %s ' ..
        'after %s batches: %s', N, prefix, st.server, st.batches, reason)
    st.phase = 'idle'

    exec_script(script_args('release'), function(req_err)
      if req_err then
        logger.warnx(rspamd_config, '%s: cannot release count scan lock for prefix %s: %s',
            N, prefix, req_err)
      end
      wait(settings.error_backoff)
    end)
  end

  local function checkpoint()
    st.last_checkpoint = rspamd_util.get_ticks()

    exec_script(script_args('checkpoint', st.upstream:get_name(), st.server,
        st.cursor, tostring(st.found), tostring(st.batches), st.started,
        stats_script and ucl.to_format(st.stats, 'json-compact') or ''),
        function(req_err, data)
          if req_err then
            -- Not fatal: the lock is renewed by the next checkpoint
            logger.warnx(rspamd_config, '%s: cannot checkpoint count scan for prefix %s: %s',
                N, prefix, req_err)
          elseif tonumber(data) ~= 1 then
            logger.warnx(rspamd_config, '%s: count scan lock for prefix %s is lost, ' ..
                'stopping the pass', N, prefix)
            st.phase = 'idle'
            wait(settings.lock_ttl)
          end
        end)
  end

  local function finish()
    local duration = rspamd_util.get_time() - (tonumber(st.started) or rspamd_util.get_time())
    local stats = ''

    if stats_script then
      stats = published_stats(st.stats, st.found, settings.stats_sample, {
        started = tonumber(st.started) or 0,
        duration = math.floor(duration),
        server = st.server,
      })
    end

    exec_script(script_args('finish', st.upstream:get_name(), st.server,
        tostring(st.found), tostring(st.batches), string.format('%.0f', duration), stats),
        function(req_err, data)
          st.phase = 'idle'

          if req_err then
            -- The last checkpoint is kept, so the next pass rescans the tail only
            logger.errx(rspamd_config, '%s: cannot publish fuzzy hashes count for prefix %s: %s',
                N, prefix, req_err)
            wait(settings.error_backoff)
          elseif tonumber(data) ~= 1 then
            logger.warnx(rspamd_config, '%s: count scan lock for prefix %s is lost, ' ..
                'discarding the result', N, prefix)
            wait(settings.lock_ttl)
          else
            logger.infox(rspamd_config, '%s: counted %s fuzzy hashes for prefix %s on %s ' ..
                'in %s batches, %s seconds%s', N, st.found, prefix, st.server, st.batches,
                string.format('%.0f', duration),
                stats_script and string.format(', %s sampled for statistics', st.stats.sampled) or '')
            wait(settings.interval)
          end
        end)
  end

  local function scan_step()
    local sent_at = rspamd_util.get_ticks()

    local cb = new_request(function(req_err, data)
      local now = rspamd_util.get_ticks()

      if stats_script and req_err and string.find(req_err, 'NOSCRIPT', 1, true) then
        -- The pinned server has lost the script: resend it with EVAL
        st.script_known = false
        wait(0)
        return
      end

      local nfound = type(data) == 'table' and
          (stats_script and tonumber(data[2]) or (type(data[2]) == 'table' and #data[2]))

      if req_err or not nfound then
        st.errors = st.errors + 1
        logger.warnx(rspamd_config, '%s: SCAN on %s failed (%s of %s): %s', N, st.server,
            st.errors, settings.max_errors, req_err or 'invalid reply')

        if st.errors >= settings.max_errors then
          suspend_pass('too many errors')
        else
          wait(math.min(settings.error_backoff, settings.max_delay * st.errors))
        end

        return
      end

      st.errors = 0
      st.cursor = tostring(data[1])
      st.found = st.found + nfound
      st.batches = st.batches + 1

      if stats_script then
        st.script_known = true
        merge_stats_reply(st.stats, data)
      end

      local rtt = now - sent_at
      local delay = rtt * (1.0 - settings.duty_cycle) / settings.duty_cycle
      delay = math.min(math.max(delay, settings.min_delay), settings.max_delay)
      wait(delay)

      lua_util.debugm(N, rspamd_config, 'count scan batch %s for prefix %s: cursor %s, ' ..
          '%s found, rtt %s, next in %s', st.batches, prefix, st.cursor, st.found, rtt, delay)

      if st.cursor == '0' then
        finish()
      elseif now - st.last_checkpoint >= settings.checkpoint_interval then
        checkpoint()
      end
    end)

    local req

    if stats_script then
      req = {
        st.script_known and 'EVALSHA' or 'EVAL',
        st.script_known and stats_script.sha or stats_script.body,
        '0', st.cursor, pattern, tostring(settings.batch),
        tostring(settings.stats_sample), calendar_now(),
      }
    else
      req = { 'SCAN', st.cursor, 'MATCH', pattern, 'COUNT', tostring(settings.batch) }
    end

    if not lua_redis.request(redis_params, {
      ev_base = ev_base,
      config = rspamd_config,
      callback = cb,
      upstream = st.upstream,
      host = st.server,
    }, req) then
      cb('cannot send SCAN request', nil)
    end
  end

  local function find_read_upstream(name)
    for _, up in ipairs(redis_params.read_servers:all_upstreams()) do
      if up:get_name() == name then
        return up
      end
    end

    return nil
  end

  local function begin_pass(res, data)
    local up, server

    if res == 'resume' and data[3] ~= '' then
      up, server = find_read_upstream(data[2]), data[3]
    end

    if up then
      st.cursor, st.found, st.batches, st.started = data[4],
      tonumber(data[5]) or 0, tonumber(data[6]) or 0, data[7]
      st.stats = decode_stats(data[8]) or new_stats()
    else
      up = redis_params.read_servers:get_upstream_round_robin()
      local addr = up and up:get_addr()

      if not addr then
        st.server, st.batches = 'none', 0
        suspend_pass('no redis server available')
        return
      end

      server = addr:to_string(true)
      st.cursor, st.found, st.batches, st.started = '0', 0, 0, calendar_now()
      st.stats = new_stats()
    end

    st.script_known = false

    st.upstream, st.server, st.errors = up, server, 0
    st.phase = 'scanning'
    st.last_checkpoint = rspamd_util.get_ticks()
    wait(0)

    logger.infox(rspamd_config, '%s: %s count scan for prefix %s on %s (%s hashes found so far)',
        N, st.cursor == '0' and 'starting' or 'resuming', prefix, server, st.found)
  end

  local function start_pass()
    exec_script(script_args('start', tostring(settings.interval), tostring(stale_age)),
        function(req_err, data)
          if req_err or type(data) ~= 'table' then
            logger.warnx(rspamd_config, '%s: cannot start count scan for prefix %s: %s',
                N, prefix, req_err or 'invalid reply')
            wait(settings.error_backoff)
            return
          end

          local res = data[1]

          if res == 'wait' then
            local remain = math.min(tonumber(data[2]) or settings.interval, settings.interval)
            wait(remain + math.random() * math.min(60.0, settings.interval * 0.05))
          elseif res == 'locked' then
            local ttl = tonumber(data[2]) or 0
            wait(ttl > 0 and ttl or settings.lock_ttl)
          elseif res == 'resume' or res == 'fresh' then
            begin_pass(res, data)
          else
            logger.warnx(rspamd_config, '%s: unexpected count scan reply for prefix %s: %s',
                N, prefix, res)
            wait(settings.error_backoff)
          end
        end)
  end

  local function tick()
    local now = rspamd_util.get_ticks()

    if st.busy_since then
      if now - st.busy_since < request_timeout then
        return settings.min_delay
      end

      logger.warnx(rspamd_config, '%s: count scan request for prefix %s got no reply ' ..
          'in %s seconds', N, prefix, request_timeout)
      st.busy_since = nil
      st.gen = st.gen + 1
      st.phase = 'idle'
      wait(settings.error_backoff)
    end

    if now < st.wake_at then
      return math.max(st.wake_at - now, settings.min_delay)
    end

    if st.phase == 'scanning' then
      scan_step()
    else
      start_pass()
    end

    return settings.min_delay
  end

  rspamd_config:add_periodic(ev_base, settings.initial_delay * (1.0 + math.random()),
      function()
        local ok, res = pcall(tick)

        if ok then
          return res
        end

        logger.errx(rspamd_config, '%s: count scan for prefix %s failed: %s', N, prefix, res)
        st.busy_since = nil
        st.gen = st.gen + 1
        st.phase = 'idle'
        wait(settings.error_backoff)

        return settings.error_backoff
      end)

  return true
end

return exports
