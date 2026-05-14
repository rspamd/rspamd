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
]] --

if confighelp then
  return
end

-- MX check plugin — Phase A rewrite (issue #6032 step 2)
--
-- Three-layer Redis cache (d:/m:/i:) under <key_prefix>:; probe shapes split
-- via lua_tcp's on_error + phased timeouts (PR #6034); multi-line SMTP banner
-- parsing under verify_greeting/send_quit (wait_for_greeting deprecated).
-- Finer outcome symbols (MX_REFUSED, MX_TIMEOUT_*, MX_ERROR, MX_NULL,
-- MX_BROKEN, MX_NXDOMAIN) emit at score 0 for tuning data; primary symbols
-- (MX_GOOD/MX_INVALID/MX_MISSING/MX_WHITE) preserve today's behaviour.

local rspamd_logger = require "rspamd_logger"
local rspamd_tcp = require "rspamd_tcp"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"

local N = "mx_check"
local CRLF = '\r\n'
local E = {}

-- librdns strerror strings we care about (see contrib/librdns/dns_private.h)
local DNS_ERR_NXDOMAIN = 'no records with this name'
local DNS_ERR_NOREC = 'requested record is not found'

local settings = {
  -- timeouts (phased; legacy `timeout` parsed at config load as a fallback)
  connect_timeout = 1.0,
  read_timeout = 5.0,

  -- greeting controls
  verify_greeting = false,
  send_quit = false,

  -- cache TTLs
  expire = 86400, -- successful outcomes
  expire_novalid = 7200, -- hard failures
  expire_timeout = 1800, -- transient timeouts (so recovery surfaces quickly)

  -- behaviour
  reject_nxdomain = false,
  reject_null_mx = false,
  greylist_invalid = true,

  -- maps / cache
  key_prefix = 'rmx',
  max_mx_a_records = 5,

  -- SMTP port (configurable so the module is testable on unprivileged ports;
  -- production should leave this at 25).
  port = 25,

  -- primary symbols (today's surface)
  symbol_bad_mx = 'MX_INVALID',
  symbol_no_mx = 'MX_MISSING',
  symbol_good_mx = 'MX_GOOD',
  symbol_white_mx = 'MX_WHITE',

  -- finer symbols (Phase A: score 0, informational)
  symbol_mx_refused = 'MX_REFUSED',
  symbol_mx_timeout_connect = 'MX_TIMEOUT_CONNECT',
  symbol_mx_timeout_read = 'MX_TIMEOUT_READ',
  symbol_mx_error = 'MX_ERROR',
  symbol_mx_nxdomain = 'MX_NXDOMAIN',
  symbol_mx_null = 'MX_NULL',
  symbol_mx_broken = 'MX_BROKEN',
}

local redis_params
local exclude_domains

-- ---------------------------------------------------------------------------
-- Cache layer (Redis-backed; falls back gracefully if Redis is unavailable
-- mid-task — we still complete the probe, we just skip the write).
-- ---------------------------------------------------------------------------

local function cache_key(layer, value)
  return string.format('%s:%s:%s', settings.key_prefix, layer, value)
end

local function cache_get(task, layer, value, cb)
  local key = cache_key(layer, value)
  local function on_reply(err, data)
    cb(err, data, key)
  end
  local ok = rspamd_redis_make_request(task, redis_params, key, false,
      on_reply, 'GET', { key })
  if not ok then
    -- Synthesise a miss so the caller proceeds with DNS/probe.
    cb('redis dispatch failed', nil, key)
  end
end

local function cache_set(task, layer, value, payload, ttl)
  local key = cache_key(layer, value)
  local function on_reply(err)
    if err then
      rspamd_logger.errx(task, 'mx_check cache write %s: %s', key, err)
    end
  end
  local ok = rspamd_redis_make_request(task, redis_params, key, true,
      on_reply, 'SETEX', { key, tostring(ttl), payload })
  if not ok then
    rspamd_logger.errx(task, 'mx_check cache write failed (no redis): %s', key)
  end
  lua_util.debugm(N, task, 'cache write %s ttl=%s value=%s', key, ttl, payload)
end

-- Choose the TTL class for an i-layer verdict.
local function ttl_for_verdict(verdict)
  if verdict == 'good' then
    return settings.expire
  elseif verdict == 'timeout_connect' or verdict == 'timeout_read' then
    return settings.expire_timeout
  else
    -- refused / invalid / error:<code>
    return settings.expire_novalid
  end
end

-- ---------------------------------------------------------------------------
-- Encoding helpers for d-layer and m-layer values.
-- d-layer:  "mx:host1:prio1,host2:prio2,..."  | "mx_miss:ip1,ip2,..."  | "nxd" | "null"
-- m-layer:  "ip1,ip2,..."                     | "nxd"
-- i-layer:  "good" | "refused" | "timeout_connect" | "timeout_read"
--           | "invalid" | "error:<code>"
-- ---------------------------------------------------------------------------

local function encode_mx_list(results)
  local parts = {}
  for _, mx in ipairs(results) do
    parts[#parts + 1] = string.format('%s:%d', mx.name, mx.priority)
  end
  return 'mx:' .. table.concat(parts, ',')
end

local function decode_mx_list(value)
  -- value already stripped of "mx:" prefix
  local out = {}
  for entry in string.gmatch(value, '[^,]+') do
    local host, prio = string.match(entry, '^(.-):(%-?%d+)$')
    if host then
      out[#out + 1] = { name = host, priority = tonumber(prio) }
    end
  end
  return out
end

local function encode_ip_list(ips)
  local parts = {}
  for _, ip in ipairs(ips) do
    parts[#parts + 1] = (type(ip) == 'string') and ip or ip:to_string()
  end
  return table.concat(parts, ',')
end

local function decode_ip_list(value)
  return lua_util.str_split(value, ',')
end

-- Detect RFC 7505 Null MX: a single MX RR with priority 0 and root target.
local function is_null_mx(results)
  if #results ~= 1 then
    return false
  end
  local r = results[1]
  if r.priority ~= 0 then
    return false
  end
  return r.name == '' or r.name == '.'
end

-- ---------------------------------------------------------------------------
-- SMTP banner parsing.
-- Returns {code = "220", sep = ' '|'-', rest = "<text>"} or nil for non-SMTP.
-- ---------------------------------------------------------------------------

local function parse_greeting_line(data)
  if type(data) ~= 'string' then
    data = tostring(data or '')
  end
  local code, sep = string.match(data, '^(%d%d%d)([ %-])')
  if not code then
    return nil
  end
  return { code = code, sep = sep }
end

-- ---------------------------------------------------------------------------
-- Probe shapes.
--
-- probe_connect_only:  open TCP, success on connect, close.  Distinguishes
--   connect errors (refused vs timeout) via on_error.
--
-- probe_with_greeting: open TCP, read banner line-by-line, validate the
--   3-digit reply code, optionally send QUIT after the final line of a 220
--   banner, then close.  Connect-phase errors via on_error; read-phase
--   outcomes via the read callback.
--
-- Both invoke `cb(verdict, extra)` where verdict is one of:
--   good | refused | timeout_connect | timeout_read | invalid | error:<code>
-- ---------------------------------------------------------------------------

local function classify_connect_error(err)
  local e = tostring(err or ''):lower()
  if e:find('refused', 1, true)
      or e:find('reset', 1, true)
      or e:find('econnrefused', 1, true) then
    return 'refused'
  end
  if e:find('timeout', 1, true)
      or e:find('timed out', 1, true)
      or e:find('unreachable', 1, true)
      or e:find('no route', 1, true) then
    return 'timeout_connect'
  end
  return nil -- local-side: EPERM, EADDRNOTAVAIL, etc. — caller logs only.
end

local function probe_connect_only(task, ip, cb)
  -- One-shot wrapper: on_error may fire synchronously (refused on localhost)
  -- before rspamd_tcp.new returns, then the function returns false, then our
  -- !ok fallback below would fire cb again with a worse verdict.  Guard it.
  local fired = false
  local function finish(verdict)
    if fired then
      return
    end
    fired = true
    cb(verdict)
  end

  local function on_connect(conn)
    conn:close()
    finish('good')
  end
  local function on_error(err)
    local v = classify_connect_error(err)
    if not v then
      rspamd_logger.infox(task, 'mx probe local error for %s: %s', ip, err)
      v = 'timeout_connect'
    end
    finish(v)
  end

  -- lua_tcp_request requires `callback` even with read=false; it is a no-op
  -- in the pure connect-only shape because no read handler is queued.
  local function stub_cb() end

  local ok = rspamd_tcp.new({
    task = task,
    callback = stub_cb,
    host = ip,
    port = settings.port,
    read = false,
    connect_timeout = settings.connect_timeout,
    on_connect = on_connect,
    on_error = on_error,
  })

  if not ok then
    finish('timeout_connect')
  end
end

local function probe_with_greeting(task, ip, cb)
  local fired = false
  local function finish(verdict, extra)
    if fired then
      return
    end
    fired = true
    cb(verdict, extra)
  end

  local function on_error(err)
    -- Connect-phase only (lua_tcp guarantees the gate via LUA_TCP_FLAG_CONNECTED).
    local v = classify_connect_error(err)
    if not v then
      rspamd_logger.infox(task, 'mx probe local error for %s: %s', ip, err)
      v = 'timeout_connect'
    end
    finish(v)
  end

  -- Forward declaration so the read callback can re-queue itself for
  -- multi-line banner draining.
  local read_line

  local function send_quit_and_close(conn)
    conn:add_write(function(_)
      conn:close()
    end, 'QUIT' .. CRLF)
  end

  read_line = function(io_err, data, conn)
    if io_err then
      local e = tostring(io_err or ''):lower()
      if e:find('timeout', 1, true) then
        finish('timeout_read')
      else
        -- EOF before CRLF, or anything not a timeout, is non-SMTP behaviour.
        finish('invalid')
      end
      if conn then
        conn:close()
      end
      return
    end

    local parsed = parse_greeting_line(data)
    if not parsed then
      finish('invalid')
      conn:close()
      return
    end

    local family = string.sub(parsed.code, 1, 1)
    if family == '2' then
      -- 220 (or other 2xx) — successful greeting. If send_quit, drain any
      -- continuation lines before issuing QUIT so we don't talk mid-banner.
      if settings.send_quit then
        if parsed.sep == '-' then
          -- More banner lines to come; keep reading until the final line.
          conn:add_read(read_line, CRLF)
          return
        end
        finish('good')
        send_quit_and_close(conn)
      else
        finish('good')
        conn:close()
      end
      return
    end

    if family == '4' or family == '5' then
      finish('error:' .. parsed.code)
      conn:close()
      return
    end

    -- 1xx, 3xx, or anything else with the right shape but the wrong class —
    -- treat as non-SMTP.
    finish('invalid')
    conn:close()
  end

  local ok = rspamd_tcp.new({
    task = task,
    host = ip,
    port = settings.port,
    callback = read_line,
    stop_pattern = CRLF,
    connect_timeout = settings.connect_timeout,
    read_timeout = settings.read_timeout,
    on_error = on_error,
  })

  if not ok then
    rspamd_logger.errx(task, 'mx_check: failed to dispatch TCP probe to %s', ip)
    finish('timeout_connect')
  end
end

-- ---------------------------------------------------------------------------
-- Outcome → symbol emission.  Phase A: emit existing primary symbols at
-- today's scores plus finer symbols at score 0 for tuning data.
-- ---------------------------------------------------------------------------

local function emit_outcome(task, mx_domain, outcome, info)
  -- info table: { mx_missing = bool, host = string, code = string (for error), key = string (for white) }
  info = info or {}

  if outcome == 'white' then
    task:insert_result(settings.symbol_white_mx, 1.0, info.key or mx_domain)
    return
  end

  -- A-fallback path: today's module fires MX_MISSING whenever the MX RR is
  -- absent and we fell back to A, independent of the probe outcome.  Match
  -- that behaviour: emit MX_MISSING first, then fall through to the regular
  -- outcome emission below.
  if info.mx_missing then
    task:insert_result(settings.symbol_no_mx, 1.0, info.host or mx_domain)
  end

  if outcome == 'good' then
    task:insert_result(settings.symbol_good_mx, 1.0, info.host or mx_domain)
    return
  end

  -- DNS-level outcomes: emit the finer symbol AND fall through to the
  -- MX_INVALID emission path below so the primary skip-mail signal still
  -- fires (matches today's behaviour: anything not connectable = MX_INVALID).
  local invalid_reason
  if outcome == 'null' then
    task:insert_result(settings.symbol_mx_null, 1.0, mx_domain)
    invalid_reason = 'null mx'
    if settings.reject_null_mx then
      invalid_reason = 'null mx: rejected'
    end
  elseif outcome == 'nxdomain' then
    task:insert_result(settings.symbol_mx_nxdomain, 1.0, mx_domain)
    invalid_reason = 'nxdomain'
    if settings.reject_nxdomain then
      invalid_reason = 'nxdomain: rejected'
    end
  elseif outcome == 'broken' then
    task:insert_result(settings.symbol_mx_broken, 1.0, mx_domain)
    invalid_reason = 'broken mx'
  end

  if invalid_reason then
    -- DNS failures: emit MX_INVALID with a descriptive reason.  We bypass
    -- greylisting here because there is no transient signal — DNS results
    -- already include their own caching/retry semantics.
    task:insert_result(settings.symbol_bad_mx, 1.0, invalid_reason)
    return
  end

  -- Finer probe outcomes.
  local finer
  local code_param
  if outcome == 'refused' then
    finer = settings.symbol_mx_refused
  elseif outcome == 'timeout_connect' then
    finer = settings.symbol_mx_timeout_connect
  elseif outcome == 'timeout_read' then
    finer = settings.symbol_mx_timeout_read
  elseif outcome == 'invalid' then
    finer = nil -- MX_INVALID is the primary; no finer symbol
  else
    -- "error:<code>"
    local code = string.match(outcome, '^error:(%d+)$')
    if code then
      finer = settings.symbol_mx_error
      code_param = code
    end
  end

  if finer then
    if code_param then
      task:insert_result(finer, 1.0, code_param)
    else
      task:insert_result(finer, 1.0, info.host or mx_domain)
    end
  end

  -- Special case: a 4xx/5xx greeting means the MX is a real SMTP server —
  -- map to MX_GOOD for the primary symbol (today's behaviour too).
  if string.find(outcome, '^error:', 1) then
    if info.mx_missing then
      task:insert_result(settings.symbol_no_mx, 1.0, info.host or mx_domain)
    end
    task:insert_result(settings.symbol_good_mx, 1.0, info.host or mx_domain)
    return
  end

  -- All remaining outcomes are MX_INVALID territory.
  if settings.greylist_invalid then
    task:get_mempool():set_variable('grey_greylisted_required', '1')
    lua_util.debugm(N, task, 'advice to greylist a message')
    task:insert_result(settings.symbol_bad_mx, 1.0, 'greylisted')
  else
    task:insert_result(settings.symbol_bad_mx, 1.0)
  end
end

-- ---------------------------------------------------------------------------
-- Lookup orchestrator: step1 (d:) → step2 (m:) → step3 (i:).
-- Stateful via small closure-captured tables; each cache GET is its own
-- continuation.
-- ---------------------------------------------------------------------------

local function lookup(task, mx_domain, done)
  local ctx = { mx_domain = mx_domain, mx_missing = false }

  -- step 3: walk IP list, take first cached verdict, else probe the first one.
  local function step3(ips)
    if #ips == 0 then
      -- Should not happen — defensive.
      done('invalid', ctx)
      return
    end

    local i = 1
    local function try_next()
      if i > #ips then
        -- All uncached; probe the first IP.
        local ip = ips[1]
        local function on_probe(verdict, extra)
          cache_set(task, 'i', ip, verdict, ttl_for_verdict(verdict))
          ctx.host = ip
          done(verdict, ctx)
        end
        if settings.verify_greeting then
          probe_with_greeting(task, ip, on_probe)
        else
          probe_connect_only(task, ip, on_probe)
        end
        return
      end

      local ip = ips[i]
      cache_get(task, 'i', ip, function(err, data)
        if not err and type(data) == 'string' and #data > 0 then
          ctx.host = ip
          ctx.from_cache = true
          done(data, ctx)
          return
        end
        i = i + 1
        try_next()
      end)
    end

    try_next()
  end

  -- step 2: walk MX list, take first cached IP list; if every entry is broken,
  -- emit MX_BROKEN.  If none cached, resolve A for the highest-priority MX.
  local function step2(mx_list)
    table.sort(mx_list, function(a, b)
      return a.priority < b.priority -- RFC 5321: lowest preference first
    end)
    local limit = math.min(#mx_list, settings.max_mx_a_records)
    if limit < #mx_list then
      local trimmed = {}
      for k = 1, limit do
        trimmed[k] = mx_list[k]
      end
      mx_list = trimmed
    end

    local i = 1
    local broken_count = 0

    local function resolve_uncached()
      -- Find the highest-priority MX without a cache entry; resolve A for it.
      local target
      for _, mx in ipairs(mx_list) do
        if not mx._cache_checked or mx._cache_value == nil then
          target = mx.name
          break
        end
      end
      if not target then
        -- Everything was cache-broken.
        cache_set(task, 'd', mx_domain, 'nxd', settings.expire_novalid)
        done('broken', ctx)
        return
      end

      local r = task:get_resolver()
      r:resolve('a', {
        name = target,
        task = task,
        forced = true,
        callback = function(_, _, results, err)
          if err and err ~= DNS_ERR_NOREC and err ~= DNS_ERR_NXDOMAIN then
            -- Soft DNS failure; treat as broken-reference for this host.
            cache_set(task, 'm', target, 'nxd', settings.expire_novalid)
            broken_count = broken_count + 1
            if broken_count >= #mx_list then
              done('broken', ctx)
              return
            end
            -- Try next uncached MX.
            for _, mx in ipairs(mx_list) do
              if mx.name == target then
                mx._cache_checked = true
                mx._cache_value = 'nxd'
              end
            end
            resolve_uncached()
            return
          end

          if not results or #results == 0 then
            cache_set(task, 'm', target, 'nxd', settings.expire_novalid)
            broken_count = broken_count + 1
            for _, mx in ipairs(mx_list) do
              if mx.name == target then
                mx._cache_checked = true
                mx._cache_value = 'nxd'
              end
            end
            if broken_count >= #mx_list then
              done('broken', ctx)
              return
            end
            resolve_uncached()
            return
          end

          lua_util.shuffle(results) -- match today's per-IP picking behaviour
          local ip_strs = {}
          for _, addr in ipairs(results) do
            ip_strs[#ip_strs + 1] = addr:to_string()
          end
          cache_set(task, 'm', target, encode_ip_list(ip_strs), settings.expire)
          step3(ip_strs)
        end,
      })
    end

    local function step()
      if i > #mx_list then
        if broken_count >= #mx_list then
          -- Every cached entry says the MX target doesn't resolve.
          done('broken', ctx)
          return
        end
        resolve_uncached()
        return
      end
      local mx = mx_list[i]
      cache_get(task, 'm', mx.name, function(err, data)
        i = i + 1
        if err or type(data) ~= 'string' or #data == 0 then
          mx._cache_checked = true
          mx._cache_value = nil
          step()
          return
        end
        if data == 'nxd' or data == 'none' then
          mx._cache_checked = true
          mx._cache_value = 'nxd'
          broken_count = broken_count + 1
          step()
          return
        end
        -- Got a cached IP list; go to step 3.
        local ips = decode_ip_list(data)
        if #ips == 0 then
          broken_count = broken_count + 1
          step()
          return
        end
        step3(ips)
      end)
    end

    step()
  end

  -- step 1.5: A-fallback (no MX RR found at domain).
  local function fallback_a()
    ctx.mx_missing = true
    local r = task:get_resolver()
    r:resolve('a', {
      name = mx_domain,
      task = task,
      forced = true,
      callback = function(_, _, results, err)
        if (err and err ~= DNS_ERR_NOREC) or not results or #results == 0 then
          if err == DNS_ERR_NXDOMAIN then
            -- Drop one level deeper: check eTLD via NS.  For Phase A simplicity
            -- we treat eTLD NXDOMAIN as MX_NXDOMAIN; resolver returning
            -- NXDOMAIN at this stage already means the domain doesn't exist.
            cache_set(task, 'd', mx_domain, 'nxd', settings.expire_novalid)
            done('nxdomain', ctx)
            return
          end
          cache_set(task, 'd', mx_domain, 'nxd', settings.expire_novalid)
          done('nxdomain', ctx)
          return
        end
        lua_util.shuffle(results)
        local ip_strs = {}
        for _, addr in ipairs(results) do
          ip_strs[#ip_strs + 1] = addr:to_string()
        end
        cache_set(task, 'd', mx_domain,
          'mx_miss:' .. encode_ip_list(ip_strs), settings.expire)
        step3(ip_strs)
      end,
    })
  end

  -- step 1: d-layer cache, else MX resolution.
  local function step1_resolve_mx()
    local r = task:get_resolver()
    r:resolve('mx', {
      name = mx_domain,
      task = task,
      forced = true,
      callback = function(_, _, results, err)
        if results and #results > 0 then
          if is_null_mx(results) then
            cache_set(task, 'd', mx_domain, 'null', settings.expire_novalid)
            done('null', ctx)
            return
          end
          cache_set(task, 'd', mx_domain, encode_mx_list(results), settings.expire)
          step2(results)
          return
        end
        -- No MX → A-fallback per RFC 5321 §5.1
        fallback_a()
      end,
    })
  end

  cache_get(task, 'd', mx_domain, function(err, data)
    if err or type(data) ~= 'string' or #data == 0 then
      step1_resolve_mx()
      return
    end
    if data == 'nxd' then
      done('nxdomain', ctx)
      return
    end
    if data == 'null' then
      done('null', ctx)
      return
    end
    if lua_util.str_startswith(data, 'mx:') then
      local mx_list = decode_mx_list(string.sub(data, 4))
      if #mx_list == 0 then
        step1_resolve_mx()
        return
      end
      step2(mx_list)
      return
    end
    if lua_util.str_startswith(data, 'mx_miss:') then
      ctx.mx_missing = true
      local ips = decode_ip_list(string.sub(data, 9))
      if #ips == 0 then
        step1_resolve_mx()
        return
      end
      step3(ips)
      return
    end
    -- Unknown value; treat as miss.
    step1_resolve_mx()
  end)
end

-- ---------------------------------------------------------------------------
-- Module entry.
-- ---------------------------------------------------------------------------

local function mx_check(task)
  local ip_addr = task:get_ip()
  if task:get_user() or (ip_addr and ip_addr:is_local()) then
    return
  end

  local from = task:get_from('smtp')
  local mx_domain
  if ((from or E)[1] or E).domain and not from[2] then
    mx_domain = from[1]['domain']
  else
    mx_domain = task:get_helo()
    if mx_domain then
      mx_domain = rspamd_util.get_tld(mx_domain)
    end
  end

  if not mx_domain then
    return
  end

  if exclude_domains then
    if exclude_domains:get_key(mx_domain) then
      rspamd_logger.infox(task, 'skip mx check for %s, excluded', mx_domain)
      emit_outcome(task, mx_domain, 'white', { key = mx_domain })
      return
    end
  end

  lookup(task, mx_domain, function(outcome, info)
    -- `outcome` is one of:
    --   good | refused | timeout_connect | timeout_read | invalid
    --   error:<code> | nxdomain | null | broken | white
    lua_util.debugm(N, task, 'mx_check verdict for %s: %s', mx_domain, outcome)
    emit_outcome(task, mx_domain, outcome, info)
  end)
end

-- ---------------------------------------------------------------------------
-- Module setup.
-- ---------------------------------------------------------------------------

local opts = rspamd_config:get_all_opt('mx_check')
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'module is unconfigured')
  return
end

redis_params = lua_redis.parse_redis_server('mx_check')
if not redis_params then
  rspamd_logger.errx(rspamd_config, 'no redis servers are specified, disabling module')
  lua_util.disable_module(N, "redis")
  return
end

-- Honour deprecated keys: legacy `timeout` and `wait_for_greeting`.
do
  local legacy_timeout = opts.timeout
  local legacy_wfg = opts.wait_for_greeting
  if legacy_timeout ~= nil and opts.connect_timeout == nil then
    opts.connect_timeout = legacy_timeout
    rspamd_logger.warnx(rspamd_config,
      'mx_check: `timeout` is deprecated; use `connect_timeout` (mapped automatically)')
  end
  if legacy_wfg ~= nil and opts.verify_greeting == nil then
    opts.verify_greeting = legacy_wfg
    rspamd_logger.warnx(rspamd_config,
      'mx_check: `wait_for_greeting` is deprecated; use `verify_greeting` (mapped automatically). '
        .. 'Note: the new flag also adds multi-line banner parsing and reply-code validation.')
  end
  opts.timeout = nil
  opts.wait_for_greeting = nil
end

settings = lua_util.override_defaults(settings, opts)

lua_redis.register_prefix(settings.key_prefix .. ':*', N,
  'MX check cache (three-layer: d:/m:/i:)', { type = 'string' })

-- Augmentation budget: worst case is one DNS round + connect + read.
local dns_to = rspamd_config:get_dns_timeout() or 0.0
local budget = settings.connect_timeout + settings.read_timeout + dns_to

local id = rspamd_config:register_symbol({
  name = settings.symbol_bad_mx,
  type = 'normal',
  callback = mx_check,
  flags = 'empty',
  augmentations = { string.format("timeout=%f", budget) },
})

local function register_virtual(name)
  rspamd_config:register_symbol({
    name = name,
    type = 'virtual',
    parent = id,
  })
end

register_virtual(settings.symbol_no_mx)
register_virtual(settings.symbol_good_mx)
register_virtual(settings.symbol_white_mx)
register_virtual(settings.symbol_mx_refused)
register_virtual(settings.symbol_mx_timeout_connect)
register_virtual(settings.symbol_mx_timeout_read)
register_virtual(settings.symbol_mx_error)
register_virtual(settings.symbol_mx_nxdomain)
register_virtual(settings.symbol_mx_null)
register_virtual(settings.symbol_mx_broken)

-- Primary metric symbols (today's scores).
rspamd_config:set_metric_symbol({
  name = settings.symbol_bad_mx,
  score = 0.5,
  description = 'Domain has no working MX',
  group = 'MX',
  one_shot = true,
  one_param = true,
})
rspamd_config:set_metric_symbol({
  name = settings.symbol_good_mx,
  score = -0.01,
  description = 'Domain has working MX',
  group = 'MX',
  one_shot = true,
  one_param = true,
})
rspamd_config:set_metric_symbol({
  name = settings.symbol_white_mx,
  score = 0.0,
  description = 'Domain is whitelisted from MX check',
  group = 'MX',
  one_shot = true,
  one_param = true,
})
rspamd_config:set_metric_symbol({
  name = settings.symbol_no_mx,
  score = 3.5,
  description = 'Domain has no resolvable MX',
  group = 'MX',
  one_shot = true,
  one_param = true,
})

-- Finer symbols: registered at score 0 in Phase A.  Phase B flips them on
-- with real defaults; operators can override scores today.
local function set_finer(name, description)
  rspamd_config:set_metric_symbol({
    name = name,
    score = 0.0,
    description = description,
    group = 'MX',
    one_shot = true,
    one_param = true,
  })
end

set_finer(settings.symbol_mx_refused, 'MX target sent TCP RST (port 25 closed)')
set_finer(settings.symbol_mx_timeout_connect, 'MX target did not respond to connect attempt')
set_finer(settings.symbol_mx_timeout_read, 'MX target accepted TCP but did not send greeting')
set_finer(settings.symbol_mx_error, 'MX target greeted with 4xx/5xx (real SMTP, rejected probe)')
set_finer(settings.symbol_mx_nxdomain, 'Domain itself does not exist (NXDOMAIN)')
set_finer(settings.symbol_mx_null, 'Domain published RFC 7505 Null MX')
set_finer(settings.symbol_mx_broken, 'All MX RRs point at hostnames that do not resolve')

if settings.exclude_domains then
  exclude_domains = rspamd_config:add_map {
    type = 'set',
    description = 'Exclude specific domains from MX checks',
    url = settings.exclude_domains,
  }
end
