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

-- MX check plugin.
--
-- Three-layer Redis cache (d:<domain> / m:<mxhost> / i:<ip>) under
-- <key_prefix>:. Two TCP probe shapes: plain connect-only, or connect +
-- multi-line SMTP banner validation (verify_greeting / send_quit). Resolved
-- IPs are classified into PUBLIC / LOCAL (RFC1918, CGNAT, ULA) / BOGON
-- (loopback, TEST-NET, multicast, link-local, etc.) before any probe runs.
-- Optional trust/skip maps at each cache layer (exclude_domains, exclude_mxs,
-- exclude_ips). Symbols at any cache layer can short-circuit further work.

local rspamd_logger = require "rspamd_logger"
local rspamd_tcp = require "rspamd_tcp"
local rspamd_util = require "rspamd_util"
local rspamd_ip = require "rspamd_ip"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local lua_maps = require "lua_maps"

local N = "mx_check"
local CRLF = '\r\n'
local E = {}

-- librdns strerror strings we care about (see contrib/librdns/dns_private.h)
local DNS_ERR_NXDOMAIN = 'no records with this name'
local DNS_ERR_NOREC = 'requested record is not found'

-- Source-dedup priority (lower wins)
local SOURCE_PRIORITY = { from = 1, reply_to = 2, mime_from = 3 }

-- Anything that isn't NXDOMAIN/NOREC is a real DNS path problem (SERVFAIL,
-- timeout, unreachable resolver) -- don't blame the sender.
local function is_dns_real_failure(err)
  return err and err ~= DNS_ERR_NXDOMAIN and err ~= DNS_ERR_NOREC
end

-- Lowercase DNS names so byte-exact Redis keys don't miss on case variance
-- (RFC 1035 §2.3.3). Returns nil for non-string/empty input.
local function norm_name(name)
  if type(name) ~= 'string' or #name == 0 then return nil end
  return string.lower(name)
end


local settings = {
  -- Per-phase TCP timeouts. read_timeout is only used with verify_greeting.
  connect_timeout = 2.0,
  read_timeout = 5.0,

  -- SMTP banner validation. verify_greeting reads and code-checks the banner;
  -- send_quit issues QUIT after the final banner line on success.
  verify_greeting = false,
  send_quit = false,

  -- Cache TTLs. expire_dns = 0 disables d:/m: caching entirely.
  expire = 86400,         -- i: good probe verdict + SMTP-error code + read timeout (1d)
  expire_dns = 1800,      -- d:/m: DNS results (30m; 0 = disable)
  expire_novalid = 14400, -- i: hard failures (refused / invalid) (4h)
  expire_timeout = 7200,  -- i: connect timeout (2h)

  reject_null_mx = false,
  reject_null_mx_message = 'Domain published RFC 7505 Null MX',

  -- Never force-reject authenticated / locally-originated traffic.
  reject_authorized = false,
  reject_local = false,

  -- Greylist advice on recoverable failures.
  greylist_invalid = true,
  greylist_none = true,
  greylist_broken = true,
  greylist_refused = true,
  greylist_null = true,
  greylist_timeout_connect = true,
  greylist_timeout_read = true,

  -- Never greylist authenticated / locally-originated traffic.
  greylist_authorized = false,
  greylist_local = false,

  -- Opt back into checking authenticated / locally-originated traffic.
  check_authorized = false,
  check_local = false,

  -- Testing only. When true, loopback (127/8, ::1) is treated as a normal
  -- probeable address instead of a bogon, so the probe path can be exercised
  -- against a local listener. NEVER enable this in production.
  test_mode = false,

  -- Source domains. One probe + one symbol per unique domain;
  -- envelope > reply-to > mime-from picks the symbol prefix.
  check_from = true,
  check_mime_from = true,
  check_reply_to = true,

  -- Address-family controls. Both off disables the module at config-load.
  probe_ipv4 = true,
  probe_ipv6 = false,
  prefer_ipv6 = true,

  key_prefix = 'rmx',
  -- Cap MX list (step 2) and A/AAAA fan-out (step 3).
  max_mx_a_records = 3,

  port = 25,

  -- Per-source symbol prefixes. Envelope-from is unprefixed.
  symbol_prefix_from = '',
  symbol_prefix_mime_from = 'MIME_FROM_',
  symbol_prefix_reply_to = 'REPLYTO_',

  -- Primary symbols.
  symbol_bad_mx = 'MX_INVALID',
  symbol_good_mx = 'MX_GOOD',
  symbol_white_mx = 'MX_WHITE',

  -- Finer outcome symbols (MX-RR path).
  symbol_mx_refused = 'MX_REFUSED',
  symbol_mx_timeout_connect = 'MX_TIMEOUT_CONNECT',
  symbol_mx_timeout_read = 'MX_TIMEOUT_READ',
  symbol_mx_error = 'MX_ERROR',
  symbol_mx_none = 'MX_NONE',
  symbol_mx_null = 'MX_NULL',
  symbol_mx_broken = 'MX_BROKEN',
  symbol_mx_dns_fail = 'MX_DNS_FAIL',

  -- A-fallback path symbols (RFC 5321 §5.1: no MX RR, A used as implicit MX).
  symbol_mx_a_good = 'MX_A_GOOD',
  symbol_mx_a_refused = 'MX_A_REFUSED',
  symbol_mx_a_timeout_connect = 'MX_A_TIMEOUT_CONNECT',
  symbol_mx_a_timeout_read = 'MX_A_TIMEOUT_READ',
  symbol_mx_a_error = 'MX_A_ERROR',
  symbol_mx_a_invalid = 'MX_A_INVALID',

  -- IP-class symbols.
  symbol_mx_local_only = 'MX_LOCAL_ONLY',
  symbol_mx_local_mix = 'MX_LOCAL_MIX',
  symbol_mx_bogon_only = 'MX_BOGON_ONLY',
  symbol_mx_bogon_mix = 'MX_BOGON_MIX',

  -- Per-layer trust/skip maps. exclude_domains and exclude_mxs are trust
  -- statements (hit -> MX_WHITE, short-circuit). exclude_ips is a probe-set
  -- filter (hit -> drop IP; full match -> MX_SKIP).
  symbol_mx_skip = 'MX_SKIP',

  -- Punishment maps (mirror exclude_mxs / exclude_ips). bad_mxs is glob on
  -- MX hostnames; bad_ips is radix on resolved IPs. Any hit short-circuits
  -- the lookup with the corresponding symbol; no further probing happens.
  symbol_mx_bad = 'MX_BAD',
  symbol_mx_ip_bad = 'MX_IP_BAD',

  -- Another worker holds the i-layer probe lock.
  symbol_mx_inflight = 'MX_INFLIGHT',

  -- Redis error during lock claim; probe skipped.
  symbol_mx_redis_error = 'MX_REDIS_ERROR',
}

-- Static IP-class ranges; module-private radix maps built at config-load.
local LOCAL_CIDRS = {
  -- IPv4 RFC 1918
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  -- IPv4 CGNAT (RFC 6598)
  '100.64.0.0/10',
  -- IPv6 unique-local (RFC 4193)
  'fc00::/7',
}

-- Loopback prefixes lifted out of BOGON_CIDRS at config-load when test_mode
-- is on, so the probe path can be exercised against a local listener.
local LOOPBACK_CIDRS = { ['127.0.0.0/8'] = true, ['::1/128'] = true }

local BOGON_CIDRS = {
  -- Loopback (dropped under test_mode)
  '127.0.0.0/8',
  '::1/128',
  -- Link-local (APIPA / IPv6 link-local)
  '169.254.0.0/16',
  'fe80::/10',
  -- "This network" (RFC 1122; source-only)
  '0.0.0.0/8',
  -- IETF protocol assignments
  '192.0.0.0/24',
  -- TEST-NET-1/2/3 (documentation)
  '192.0.2.0/24',
  '198.51.100.0/24',
  '203.0.113.0/24',
  -- 6to4 anycast (deprecated)
  '192.88.99.0/24',
  -- Benchmarking
  '198.18.0.0/15',
  -- IPv4 multicast
  '224.0.0.0/4',
  -- IPv4 reserved / "Class E" (includes 255.255.255.255 broadcast)
  '240.0.0.0/4',
  -- IPv6 unspecified
  '::/128',
  -- NAT64 (RFC 6052)
  '64:ff9b::/96',
  -- IPv6 discard prefix (RFC 6666)
  '100::/64',
  -- IPv6 documentation
  '2001:db8::/32',
  -- IPv6 multicast
  'ff00::/8',
}

local redis_params
local exclude_domains
local exclude_mxs
local exclude_ips
local bad_mxs
local bad_ips
local local_ip_map
local bogon_ip_map

-- Drop IPs whose family is currently disabled; applied at every cache read.
local function filter_by_family(ips)
  if settings.probe_ipv4 and settings.probe_ipv6 then
    return ips
  end
  local out = {}
  for _, ip_str in ipairs(ips) do
    local ip = rspamd_ip.from_string(ip_str)
    if ip and ip:is_valid() then
      local v = ip:get_version()
      if (v == 6 and settings.probe_ipv6) or (v == 4 and settings.probe_ipv4) then
        out[#out + 1] = ip_str
      end
    end
  end
  return out
end

-- Classify into 'public' / 'local' / 'bogon'. Not rspamd_inet_addr:is_local
-- -- that misses RFC1918 / CGNAT / ULA.
local function classify_ip(ip_str)
  if bogon_ip_map and bogon_ip_map:get_key(ip_str) then
    return 'bogon'
  end
  if local_ip_map and local_ip_map:get_key(ip_str) then
    return 'local'
  end
  return 'public'
end

local function source_prefix(src)
  if src == 'reply_to' then return settings.symbol_prefix_reply_to end
  if src == 'mime_from' then return settings.symbol_prefix_mime_from end
  return settings.symbol_prefix_from
end

-- Pre-emit IP-class symbols alongside whatever the probe produces. The
-- offending IPs are passed as symbol options (one option per IP) so
-- operators can see exactly which addresses tripped the class without
-- digging into the resolver logs.
local function emit_ip_class_symbols(task, mx_domain, locals, bogons, has_public, src)
  local p = source_prefix(src or 'from')
  if #locals > 0 then
    local sym = p .. (has_public and settings.symbol_mx_local_mix
                                   or settings.symbol_mx_local_only)
    task:insert_result(sym, 1.0, locals)
    lua_util.debugm(N, task, '%s for %s: %s', sym, mx_domain, table.concat(locals, ','))
  end
  if #bogons > 0 then
    local sym = p .. (has_public and settings.symbol_mx_bogon_mix
                                   or settings.symbol_mx_bogon_only)
    task:insert_result(sym, 1.0, bogons)
    lua_util.debugm(N, task, '%s for %s: %s', sym, mx_domain, table.concat(bogons, ','))
  end
end

-- Cache layer (Redis-backed; degrades gracefully on Redis loss).

local function cache_key(layer, value)
  return string.format('%s:%s:%s', settings.key_prefix, layer, value)
end

-- d:/m: caching disabled when expire_dns = 0; reads synthesise a miss.
local function dns_cache_disabled(layer)
  return (layer == 'd' or layer == 'm') and settings.expire_dns == 0
end

local function cache_get(task, layer, value, cb)
  if dns_cache_disabled(layer) then
    cb(nil, nil, '')
    return
  end
  local key = cache_key(layer, value)
  local function on_reply(err, data)
    cb(err, data, key)
  end
  local ok = lua_redis.rspamd_redis_make_request(task, redis_params, key, false,
      on_reply, 'GET', { key })
  if not ok then
    -- Synthesise a miss so the caller proceeds with DNS/probe.
    cb('redis dispatch failed', nil, key)
  end
end

local function cache_set(task, layer, value, payload, ttl)
  if ttl == 0 or dns_cache_disabled(layer) then
    return
  end
  local key = cache_key(layer, value)
  local function on_reply(err)
    if err then
      rspamd_logger.errx(task, 'mx_check cache write %s: %s', key, err)
    end
  end
  local ok = lua_redis.rspamd_redis_make_request(task, redis_params, key, true,
      on_reply, 'SETEX', { key, tostring(ttl), payload })
  if ok then
    lua_util.debugm(N, task, 'cache write %s ttl=%s value=%s', key, ttl, payload)
  else
    rspamd_logger.errx(task, 'mx_check cache write failed (no redis): %s', key)
  end
end

-- Recognised cache value shapes per layer. Unknown values are treated as a
-- miss by callers; the natural resolve / probe path then issues cache_set,
-- which overwrites the bad entry in place (no DEL needed -- DEL would just
-- add a write op and a blocking Redis operation for no behavioural gain).
--   i: 'gd' | 'rf' | 'tc' | 'tr' | 'inv' | 'err:NNN'
--      (the lock value 'l' is handled separately by callers)
--   d: 'no' | 'bkn' | 'null' | 'df'
--      | 'mx:<host:prio,...>'
--      | 'a:v4:<ip,...>' | 'a:v6:<ip,...>' | 'a:v64:<ip,...>'
--   m: 'no' | 'df'
--      | 'v4:<ip,...>' | 'v6:<ip,...>' | 'v64:<ip,...>'
-- Prefix match only; empty / malformed payloads degrade gracefully via the
-- downstream decode (empty list -> re-resolve), and validating each entry
-- would just duplicate that parse logic.
local function is_valid_cache_value(layer, v)
  if type(v) ~= 'string' or #v == 0 then return false end
  if layer == 'i' then
    if v == 'gd' or v == 'rf' or v == 'tc' or v == 'tr' or v == 'inv' then
      return true
    end
    return v:match('^err:%d%d%d$') ~= nil
  elseif layer == 'd' then
    if v == 'no' or v == 'bkn' or v == 'null' or v == 'df' then return true end
    if v:match('^mx:') then return true end
    return v:match('^a:v4:') ~= nil
        or v:match('^a:v6:') ~= nil
        or v:match('^a:v64:') ~= nil
  elseif layer == 'm' then
    if v == 'no' or v == 'df' then return true end
    return v:match('^v4:') ~= nil
        or v:match('^v6:') ~= nil
        or v:match('^v64:') ~= nil
  end
  return false
end

local function lock_ttl_seconds()
  return settings.connect_timeout
      + (settings.verify_greeting and settings.read_timeout or 0)
      + 1.0
end

-- Forcefully write 'l' at i:<ip> overwriting whatever's there. Used on the
-- recovery path when the key holds invalid data (SET NX would loop on it).
-- Other workers reading cache_get afterwards see 'l' and defer via
-- MX_INFLIGHT, so only this worker probes.
local function force_claim_probe_lock(task, ip, on_ok, on_error)
  local key = cache_key('i', ip)
  local lock_ttl = lock_ttl_seconds()
  local function on_reply(err)
    if err then
      rspamd_logger.errx(task, 'mx_check force-claim %s: redis error %s', key, err)
      on_error()
      return
    end
    lua_util.debugm(N, task, 'force-claimed probe lock %s (ttl=%ss)', key, lock_ttl)
    on_ok()
  end
  local ok = lua_redis.rspamd_redis_make_request(task, redis_params, key, true,
      on_reply, 'SET',
      { key, 'l', 'EX', tostring(math.ceil(lock_ttl)) })
  if not ok then
    rspamd_logger.errx(task, 'mx_check force-claim dispatch failed: %s', key)
    on_error()
  end
end

-- SET NX EX "lock" at i:<ip> to coordinate parallel workers. Redis failures
-- fail-closed (on_error -> skip probe) so a dead cache layer can't drive an
-- uncoordinated herd. The eventual cache_set overwrites the lock value with
-- the real verdict.
--
-- Callback dispatch from the post-claim GET when SET NX fails:
--   on_won()           the key holds an unrecognised value; force-claim
--                      first to actually hold the lock, then probe.
--   on_lost(nil)       the key holds 'l' or is gone -- another worker owns
--                      the probe; caller defers via MX_INFLIGHT.
--   on_lost(verdict)   the key holds a valid verdict (a worker raced ahead
--                      between our cache_get and SET NX); caller uses it.
--   on_error()         Redis dispatch / I/O error.
local function try_claim_probe_lock(task, ip, on_won, on_lost, on_error)
  local key = cache_key('i', ip)
  local lock_ttl = lock_ttl_seconds()
  local function on_set_reply(err, data)
    if err then
      rspamd_logger.errx(task, 'mx_check probe lock %s: redis error %s', key, err)
      on_error()
      return
    end
    -- Redis SET NX returns "OK" on success and nil otherwise; rspamd_redis
    -- surfaces nil as false. Be defensive on both shapes.
    if data == 'OK' or data == true then
      lua_util.debugm(N, task, 'probe lock %s: claimed (ttl=%ss)', key, lock_ttl)
      on_won()
      return
    end
    -- SET NX failed: the key existed. GET it to tell a held lock ('l') from a
    -- published verdict (race window between our cache_get miss and this
    -- SET NX).
    lua_redis.rspamd_redis_make_request(task, redis_params, key, false,
        function(get_err, get_data)
          if get_err then
            rspamd_logger.errx(task, 'mx_check probe lock %s: post-claim GET error %s',
              key, get_err)
            on_error()
            return
          end
          if type(get_data) ~= 'string' or #get_data == 0 or get_data == 'l' then
            lua_util.debugm(N, task, 'probe lock %s: held by another worker', key)
            on_lost(nil)
            return
          end
          if is_valid_cache_value('i', get_data) then
            lua_util.debugm(N, task, 'probe lock %s: verdict already published (%s)',
              key, get_data)
            on_lost(get_data)
            return
          end
          -- Non-'l', non-verdict value at i:<ip>. Force-claim to actually
          -- hold the lock (plain on_won() without writing 'l' would let
          -- every parallel worker probe in lockstep) then dispatch to on_won.
          lua_util.debugm(N, task,
            "probe lock %s: bad cache value '%s', force-claiming to overwrite",
            key, get_data)
          force_claim_probe_lock(task, ip, on_won, on_error)
        end, 'GET', { key })
  end
  local ok = lua_redis.rspamd_redis_make_request(task, redis_params, key, true,
      on_set_reply, 'SET',
      { key, 'l', 'EX', tostring(math.ceil(lock_ttl)), 'NX' })
  if not ok then
    rspamd_logger.errx(task, 'mx_check probe lock dispatch failed: %s', key)
    on_error()
  end
end

-- TTL class for an i-layer verdict. 4xx/5xx are 'gd' (real SMTP that just
-- declined our probe) and cache at the long expire TTL. 'tr' (read timeout)
-- also rides the long TTL: TCP connected, listener is alive -- the read
-- timeout is almost always a long greeting delay (Postfix postscreen,
-- tarpit, big provider rate-limit), not a dead host.
local function ttl_for_verdict(verdict)
  if verdict == 'gd' or verdict == 'tr' or string.find(verdict, '^err:') then
    return settings.expire
  elseif verdict == 'tc' then
    return settings.expire_timeout
  else
    -- 'rf' / 'inv'
    return settings.expire_novalid
  end
end

-- Cache value formats (short codes minimise Redis footprint):
--   d:<domain>  "mx:host:prio,..." | "a:<v>:ip,..." | "no" | "null" |
--               "bkn" | "df"
--   m:<host>    "<v>:ip,..." | "no" | "df"
--   i:<ip>      "gd" | "rf" | "tc" | "tr" |
--               "inv" | "err:<code>" | "l" (probe in flight)
-- <v> ∈ {v4, v6, v64} encodes which DNS families were queried at write
-- time; readers re-resolve when current flags need a family not in <v>.

local function encode_mx_list(results)
  local parts = {}
  for _, mx in ipairs(results) do
    parts[#parts + 1] = string.format('%s:%d', mx.name, mx.priority)
  end
  return 'mx:' .. table.concat(parts, ',')
end

local function decode_mx_list(value)
  -- value already stripped of "mx:" prefix.
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

-- Family-tag prefix for IP-list cache values. Encodes which DNS families
-- were queried at write time so readers can tell "cache covers current
-- flags" (use it) from "cache was partial, current needs more" (re-resolve).
-- Without this distinction every filter-to-empty would force a re-resolve
-- even when the cache definitively says "no IPs in that family".
local function family_prefix()
  if settings.probe_ipv4 and settings.probe_ipv6 then return 'v64' end
  if settings.probe_ipv4 then return 'v4' end
  return 'v6'
end

-- Returns {v4, v6} booleans (which families the cache entry queried) and
-- the IP list table. Returns nil on unrecognised / legacy formats so the
-- caller can treat them as cache misses.
local function decode_ip_list_with_family(value)
  local prefix, body
  if value:sub(1, 4) == 'v64:' then
    prefix, body = { v4 = true, v6 = true }, value:sub(5)
  elseif value:sub(1, 3) == 'v4:' then
    prefix, body = { v4 = true }, value:sub(4)
  elseif value:sub(1, 3) == 'v6:' then
    prefix, body = { v6 = true }, value:sub(4)
  else
    return nil, nil
  end
  return prefix, lua_util.str_split(body, ',')
end

-- True iff the cached queried-families set covers every currently-enabled
-- probe family (cache was at least as informed as we need now).
local function family_coverage_ok(queried)
  if not queried then return false end
  if settings.probe_ipv4 and not queried.v4 then return false end
  if settings.probe_ipv6 and not queried.v6 then return false end
  return true
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

-- SMTP banner line -> {code, sep} or nil for non-SMTP.
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

-- Probe shapes. Both invoke cb(verdict) where verdict is one of:
--   good | refused | timeout_connect | timeout_read | invalid | error:<code>
-- probe_connect_only:  open TCP, success-on-connect, close.
-- probe_with_greeting: open TCP, read+validate SMTP banner, optional QUIT.

local function classify_connect_error(err)
  local e = tostring(err or ''):lower()
  if e:find('refused', 1, true)
      or e:find('reset', 1, true)
      or e:find('econnrefused', 1, true) then
    return 'rf'
  end
  if e:find('timeout', 1, true)
      or e:find('timed out', 1, true)
      or e:find('unreachable', 1, true)
      or e:find('no route', 1, true) then
    return 'tc'
  end
  return nil -- local-side: EPERM, EADDRNOTAVAIL, etc. — caller logs only.
end

local function probe_connect_only(task, ip, cb)
  -- on_error may fire synchronously (refused on localhost) before rspamd_tcp.new
  -- returns; the !ok fallback would then double-fire cb. Guard with `fired`.
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
    finish('gd')
  end
  local function on_error(err)
    local v = classify_connect_error(err)
    if not v then
      rspamd_logger.infox(task, 'mx probe local error for %s: %s', ip, err)
      v = 'tc'
    end
    finish(v)
  end

  -- lua_tcp_request requires `callback` even with read=false; no-op here.
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
    finish('tc')
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
    -- Connect-phase only (gated by LUA_TCP_FLAG_CONNECTED in lua_tcp).
    local v = classify_connect_error(err)
    if not v then
      rspamd_logger.infox(task, 'mx probe local error for %s: %s', ip, err)
      v = 'tc'
    end
    finish(v)
  end

  -- Forward decl: read callback re-queues itself for multi-line banners.
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
        finish('tr')
      else
        -- EOF before CRLF, or anything not a timeout, is non-SMTP behaviour.
        finish('inv')
      end
      if conn then
        conn:close()
      end
      return
    end

    local parsed = parse_greeting_line(data)
    if not parsed then
      finish('inv')
      conn:close()
      return
    end

    -- 220: valid SMTP greeting. Disconnect on the first 220 unless
    -- send_quit is on with a continuation banner (drain until sep == ' ').
    if parsed.code == '220' then
      if settings.send_quit and parsed.sep == '-' then
        conn:add_read(read_line, CRLF)
        return
      end
      finish('gd')
      if settings.send_quit then
        send_quit_and_close(conn)
      else
        conn:close()
      end
      return
    end

    -- 4xx/5xx: real SMTP rejected our probe; drop silently (421/554 close
    -- the channel anyway per RFC 5321 §3.5, so QUIT is wasted).
    local family = string.sub(parsed.code, 1, 1)
    if family == '4' or family == '5' then
      finish('err:' .. parsed.code)
      conn:close()
      return
    end

    -- 1xx/3xx/non-220 2xx: 3-digit shape but wrong class for a banner.
    finish('inv')
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
    finish('tc')
  end
end

-- Force-reject gate. Authenticated / local traffic never rejected.
local function should_reject(task, kind)
  if task:get_user() and not settings.reject_authorized then
    return false
  end
  local ip = task:get_ip()
  if ip and ip:is_local() and not settings.reject_local then
    return false
  end
  if kind == 'null' then return settings.reject_null_mx end
  return false
end

-- Greylist gate. Authenticated / local never greylisted; suppressed when
-- the same outcome is force-rejected (pre-result reject lands first).
local function should_greylist(task, kind)
  if task:get_user() and not settings.greylist_authorized then
    return false
  end
  local ip = task:get_ip()
  if ip and ip:is_local() and not settings.greylist_local then
    return false
  end
  if should_reject(task, kind) then return false end
  if kind == 'inv' then return settings.greylist_invalid end
  if kind == 'no' then return settings.greylist_none end
  if kind == 'bkn' then return settings.greylist_broken end
  if kind == 'rf' then return settings.greylist_refused end
  if kind == 'null' then return settings.greylist_null end
  if kind == 'tc' then return settings.greylist_timeout_connect end
  if kind == 'tr' then return settings.greylist_timeout_read end
  return false
end

local function advise_greylist(task, reason)
  task:get_mempool():set_variable('grey_greylisted_required', '1')
  lua_util.debugm(N, task, 'advice to greylist: %s', reason)
end

-- Map lookup verdict -> result symbols. src picks the prefix from settings
-- (symbol_prefix_{from,mime_from,reply_to}). When info.mx_missing is true
-- (A-fallback path), probe outcomes fire MX_A_*.
local function emit_outcome(task, mx_domain, outcome, info, src)
  info = info or {}
  local p = source_prefix(src or 'from')
  local host = info.host or mx_domain
  local function sym(mx_key, mx_a_key)
    return p .. settings[info.mx_missing and mx_a_key or mx_key]
  end

  if outcome == 'white' then
    task:insert_result(p .. settings.symbol_white_mx, 1.0, info.key or mx_domain)
    return
  end

  if outcome == 'ip_class_skipped' then
    -- IP-class symbols already fired at the classification step.
    return
  end

  if outcome == 'skip' then
    task:insert_result(p .. settings.symbol_mx_skip, 1.0, info.key or mx_domain)
    return
  end

  if outcome == 'bad_mx' then
    task:insert_result(p .. settings.symbol_mx_bad,
      info.weight_mult or 1.0, info.key or mx_domain)
    return
  end

  if outcome == 'bad_ip' then
    task:insert_result(p .. settings.symbol_mx_ip_bad,
      info.weight_mult or 1.0, info.key or mx_domain)
    return
  end

  if outcome == 'inflight' then
    task:insert_result(p .. settings.symbol_mx_inflight, 1.0,
      info.host or mx_domain)
    return
  end

  if outcome == 'df' then
    task:insert_result(p .. settings.symbol_mx_dns_fail, 1.0, host)
    return
  end

  if outcome == 'gd' then
    task:insert_result(sym('symbol_good_mx', 'symbol_mx_a_good'), 1.0, host)
    return
  end

  -- DNS-level outcomes (no MX_A_* split — these are name-level facts).
  if outcome == 'null' then
    task:insert_result(p .. settings.symbol_mx_null, 1.0, mx_domain)
    if should_reject(task, 'null') then
      task:set_pre_result('reject', settings.reject_null_mx_message, N)
    elseif should_greylist(task, 'null') then
      advise_greylist(task, 'mx_null')
    end
    return
  end
  if outcome == 'no' then
    task:insert_result(p .. settings.symbol_mx_none, 1.0, mx_domain)
    if should_greylist(task, 'no') then
      advise_greylist(task, 'mx_none')
    end
    return
  end
  if outcome == 'bkn' then
    -- MX_BROKEN is MX-RR-only by construction; no A-fallback variant.
    task:insert_result(p .. settings.symbol_mx_broken, 1.0, mx_domain)
    if should_greylist(task, 'bkn') then
      advise_greylist(task, 'mx_broken')
    end
    return
  end

  -- TCP-probe finer outcomes — split by path.
  if outcome == 'rf' then
    task:insert_result(sym('symbol_mx_refused', 'symbol_mx_a_refused'), 1.0, host)
    if should_greylist(task, 'rf') then
      advise_greylist(task, 'mx_refused')
    end
    return
  end
  if outcome == 'tc' then
    task:insert_result(sym('symbol_mx_timeout_connect', 'symbol_mx_a_timeout_connect'), 1.0, host)
    if should_greylist(task, 'tc') then
      advise_greylist(task, 'mx_timeout_connect')
    end
    return
  end
  if outcome == 'tr' then
    task:insert_result(sym('symbol_mx_timeout_read', 'symbol_mx_a_timeout_read'), 1.0, host)
    if should_greylist(task, 'tr') then
      advise_greylist(task, 'mx_timeout_read')
    end
    return
  end

  -- 4xx/5xx: real SMTP rejected our probe. Fire GOOD + ERROR with code.
  local code = string.match(outcome, '^err:(%d+)$')
  if code then
    task:insert_result(sym('symbol_mx_error', 'symbol_mx_a_error'), 1.0, {host, code})
    task:insert_result(sym('symbol_good_mx', 'symbol_mx_a_good'), 1.0, host)
    return
  end

  -- MX_INVALID / MX_A_INVALID: TCP up, banner not valid SMTP.
  if outcome == 'inv' then
    local invalid_sym = sym('symbol_bad_mx', 'symbol_mx_a_invalid')
    if should_greylist(task, 'inv') then
      advise_greylist(task, 'mx_invalid')
      task:insert_result(invalid_sym, 1.0, 'greylisted')
    else
      task:insert_result(invalid_sym, 1.0)
    end
    return
  end

  -- Module-internal failure: Redis was unreachable mid-claim.
  if outcome == 'redis_error' then
    task:insert_result(p .. settings.symbol_mx_redis_error, 1.0)
    return
  end
end

-- Parallel A/AAAA resolution. Callback: done(ip_strs, err_code) with
-- err_code in {nil, 'no_records', 'df'}. dns_fail only when every
-- queried family had a real network-level error.
local function resolve_addresses(task, name, done)
  local r = task:get_resolver()
  local pending = 0
  local v4_ips, v6_ips
  local v4_err, v6_err
  local cap = settings.max_mx_a_records

  local function maybe_done()
    if pending > 0 then
      return
    end
    local combined = {}
    -- Interleave 1:1 from each family so the cap doesn't starve one side.
    -- prefer_ipv6 only picks which family lands first at each index.
    local first, second
    if settings.prefer_ipv6 then
      first, second = v6_ips, v4_ips
    else
      first, second = v4_ips, v6_ips
    end
    local idx = 1
    while not cap or #combined < cap do
      local took = false
      if first and first[idx] then
        combined[#combined + 1] = first[idx]
        took = true
        if cap and #combined >= cap then break end
      end
      if second and second[idx] then
        combined[#combined + 1] = second[idx]
        took = true
      end
      if not took then break end
      idx = idx + 1
    end

    if #combined > 0 then
      done(combined, nil)
      return
    end
    -- dns_fail only if every queried family had a real failure; an
    -- authoritative NXDOMAIN/NOREC from any family is collapsed into
    -- 'no_records' (operationally equivalent without eTLD+1 verification).
    local v4_real_fail = settings.probe_ipv4 and is_dns_real_failure(v4_err)
    local v6_real_fail = settings.probe_ipv6 and is_dns_real_failure(v6_err)
    local v4_clean = settings.probe_ipv4 and not is_dns_real_failure(v4_err)
    local v6_clean = settings.probe_ipv6 and not is_dns_real_failure(v6_err)
    if (v4_real_fail or v6_real_fail) and not (v4_clean or v6_clean) then
      done({}, 'df')
      return
    end
    done({}, 'no_records')
  end

  if settings.probe_ipv4 then
    pending = pending + 1
    r:resolve('a', {
      name = name,
      task = task,
      forced = true,
      callback = function(_, _, addrs, err)
        pending = pending - 1
        v4_err = err
        if addrs and #addrs > 0 then
          local v = {}
          for _, addr in ipairs(addrs) do
            v[#v + 1] = addr:to_string()
          end
          lua_util.shuffle(v)
          v4_ips = v
        end
        maybe_done()
      end,
    })
  end

  if settings.probe_ipv6 then
    pending = pending + 1
    r:resolve('aaaa', {
      name = name,
      task = task,
      forced = true,
      callback = function(_, _, addrs, err)
        pending = pending - 1
        v6_err = err
        if addrs and #addrs > 0 then
          local v = {}
          for _, addr in ipairs(addrs) do
            v[#v + 1] = addr:to_string()
          end
          lua_util.shuffle(v)
          v6_ips = v
        end
        maybe_done()
      end,
    })
  end
end

-- Lookup orchestrator: step1 (d:) -> step2 (m:) -> step3 (i:).
local function lookup(task, mx_domain, src, done)
  local ctx = { mx_domain = mx_domain, mx_missing = false }

  -- step 3: walk IP list, take first cached verdict, else probe the first one.
  -- mx_host is the MX RR target (or the from-domain on the A-fallback path);
  -- it surfaces in probe-outcome symbol options so operators see a name, not
  -- a raw IP. IP-class symbols (MX_LOCAL_*, MX_BOGON_*) still report IPs --
  -- that's where IP information is the point.
  local function step3(ips, mx_host)
    if #ips == 0 then
      -- Should not happen — defensive.
      ctx.host = mx_host
      done('inv', ctx)
      return
    end

    -- Partition into PUBLIC / LOCAL / BOGON. Only PUBLIC gets probed;
    -- per-class symbol fires regardless so operators can score the shape.
    local public_ips = {}
    local local_ips = {}
    local bogon_ips = {}
    for _, ip in ipairs(ips) do
      local class = classify_ip(ip)
      if class == 'bogon' then
        bogon_ips[#bogon_ips + 1] = ip
      elseif class == 'local' then
        local_ips[#local_ips + 1] = ip
      else
        public_ips[#public_ips + 1] = ip
      end
    end

    local has_local = #local_ips > 0
    local has_bogon = #bogon_ips > 0
    local has_public = #public_ips > 0

    if has_local or has_bogon then
      emit_ip_class_symbols(task, mx_domain, local_ips, bogon_ips, has_public, src)
    end

    if not has_public then
      -- LOCAL/BOGON symbols already emitted; nothing routable to probe.
      done('ip_class_skipped', ctx)
      return
    end

    -- bad_ips: any public IP matching short-circuits with MX_IP_BAD. Checked
    -- before exclude_ips so an IP in both is treated as bad (punish wins
    -- over skip). The matched IP is reported as the symbol option; an
    -- optional numeric token after the entry ("1.2.3.4 5", "1.2.3.0/24 0.5")
    -- becomes a weight multiplier on top of the group score, default 1.0.
    if bad_ips then
      for _, ip in ipairs(public_ips) do
        local m = bad_ips:get_key(ip)
        if m then
          local mult = (type(m) == 'string') and tonumber(m) or nil
          done('bad_ip', { key = ip, weight_mult = mult })
          return
        end
      end
    end

    -- exclude_ips drops matched IPs; full match -> MX_SKIP, partial silent.
    if exclude_ips then
      local kept = {}
      local matched_cidrs = {}
      for _, ip in ipairs(public_ips) do
        local m = exclude_ips:get_key(ip)
        if m then
          matched_cidrs[#matched_cidrs + 1] = (type(m) == 'string' and #m > 0) and m or ip
        else
          kept[#kept + 1] = ip
        end
      end
      if #kept == 0 then
        done('skip', { key = table.concat(matched_cidrs, ',') })
        return
      end
      public_ips = kept
    end

    -- Continue with only the public subset.
    ips = public_ips

    local i = 1

    local function do_probe(ip)
      local function on_probe(verdict, _extra)
        cache_set(task, 'i', ip, verdict, ttl_for_verdict(verdict))
        ctx.host = mx_host
        done(verdict, ctx)
      end
      if settings.verify_greeting then
        probe_with_greeting(task, ip, on_probe)
      else
        probe_connect_only(task, ip, on_probe)
      end
    end

    -- Claim the lock for `ip` and probe; on race-loss the post-claim GET
    -- decides between inheriting a freshly-published verdict and deferring
    -- via MX_INFLIGHT.
    local function probe_with_lock(ip)
      try_claim_probe_lock(task, ip,
        function() do_probe(ip) end,
        function(verdict)
          ctx.host = mx_host
          if verdict then
            ctx.from_cache = true
            done(verdict, ctx)
          else
            done('inflight', ctx)
          end
        end,
        function()
          ctx.host = mx_host
          done('redis_error', ctx)
        end)
    end

    -- Heal an invalid cache entry at `ip`: force-claim the lock (overwrite
    -- the bad value with 'l' so parallel workers see the in-flight state)
    -- then probe. Bypasses SET NX because the bad value would fail it.
    local function heal_and_probe(ip)
      force_claim_probe_lock(task, ip,
        function() do_probe(ip) end,
        function()
          ctx.host = mx_host
          done('redis_error', ctx)
        end)
    end

    local function try_next()
      if i > #ips then
        -- Every IP missed cache; probe the highest-priority one.
        probe_with_lock(ips[1])
        return
      end

      local ip = ips[i]
      cache_get(task, 'i', ip, function(err, data)
        if not err and type(data) == 'string' and #data > 0 then
          if data == 'l' then
            -- Another worker is probing this IP; defer via MX_INFLIGHT.
            ctx.host = mx_host
            done('inflight', ctx)
            return
          end
          if is_valid_cache_value('i', data) then
            ctx.host = mx_host
            ctx.from_cache = true
            done(data, ctx)
            return
          end
          lua_util.debugm(N, task,
            "unexpected i: cache value at %s: '%s', force-claiming to overwrite",
            ip, data)
          heal_and_probe(ip)
          return
        end
        i = i + 1
        try_next()
      end)
    end

    try_next()
  end

  -- step 2: walk MX list for cached IPs; resolve A for the top MX otherwise.
  local function step2(mx_list)
    -- bad_mxs: any matching MX hostname short-circuits with MX_BAD. Checked
    -- before exclude_mxs so a hostname listed in both is treated as bad
    -- (punish wins over trust); operators shouldn't list the same name in
    -- both anyway. An optional numeric token after the glob entry
    -- ("trapmx.example.com 3", "*.bad.example 0.5") becomes a weight
    -- multiplier on top of the group score; default 1.0.
    if bad_mxs then
      for _, mx in ipairs(mx_list) do
        local m = bad_mxs:get_key(mx.name)
        if m then
          local mult = (type(m) == 'string') and tonumber(m) or nil
          done('bad_mx', { key = mx.name, weight_mult = mult })
          return
        end
      end
    end

    -- exclude_mxs: any matching MX hostname short-circuits with MX_WHITE.
    if exclude_mxs then
      for _, mx in ipairs(mx_list) do
        if exclude_mxs:get_key(mx.name) then
          done('white', { key = mx.name })
          return
        end
      end
    end

    local i = 1
    local broken_count = 0  -- targets that returned 'no' or 'df'
    local df_count = 0      -- subset of broken_count: targets that returned 'df'

    local function resolve_uncached()
      -- Resolve A for the highest-priority MX without a cache entry.
      local target
      for _, mx in ipairs(mx_list) do
        if not mx._cache_checked or mx._cache_value == nil then
          target = mx.name
          break
        end
      end
      if not target then
        -- Every target was already cache-broken (m-layer 'no' or 'df').
        done(df_count > 0 and 'df' or 'bkn', ctx)
        return
      end

      resolve_addresses(task, target, function(ip_strs, err_code)
        if not ip_strs or #ip_strs == 0 then
          local m_value, is_df
          if err_code == 'df' then
            -- Transient DNS path failure for THIS target; cache at m-layer
            -- (cache_set no-ops when expire_dns = 0) and iterate.
            m_value, is_df = 'df', true
            cache_set(task, 'm', target, 'df', settings.expire_dns)
          else
            -- MX target has no usable address (NXDOMAIN/NOREC).
            m_value, is_df = 'no', false
            cache_set(task, 'm', target, 'no', settings.expire_dns)
          end
          if is_df then df_count = df_count + 1 end
          broken_count = broken_count + 1
          for _, mx in ipairs(mx_list) do
            if mx.name == target then
              mx._cache_checked = true
              mx._cache_value = m_value
            end
          end
          if broken_count >= #mx_list then
            done(df_count > 0 and 'df' or 'bkn', ctx)
            return
          end
          resolve_uncached()
          return
        end

        cache_set(task, 'm', target,
          family_prefix() .. ':' .. encode_ip_list(ip_strs), settings.expire_dns)
        step3(ip_strs, target)
      end)
    end

    local function step()
      if i > #mx_list then
        if broken_count >= #mx_list then
          done(df_count > 0 and 'df' or 'bkn', ctx)
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
        if not is_valid_cache_value('m', data) then
          lua_util.debugm(N, task,
            "unexpected m: cache value at %s: '%s', treating as miss", mx.name, data)
          -- resolve_uncached will cache_set a fresh value over the bad entry.
          mx._cache_checked = true
          mx._cache_value = nil
          step()
          return
        end
        if data == 'no' then
          mx._cache_checked = true
          mx._cache_value = data
          broken_count = broken_count + 1
          step()
          return
        end
        if data == 'df' then
          mx._cache_checked = true
          mx._cache_value = data
          df_count = df_count + 1
          broken_count = broken_count + 1
          step()
          return
        end
        local queried, all_ips = decode_ip_list_with_family(data)
        if not queried then
          -- Unrecognised / legacy IP list; treat as miss so resolve_uncached
          -- re-queries under current flags.
          mx._cache_checked = true
          mx._cache_value = nil
          step()
          return
        end
        if not family_coverage_ok(queried) then
          -- Cache was written under a partial family set that doesn't cover
          -- current flags; re-resolve to fill the missing family.
          mx._cache_checked = true
          mx._cache_value = nil
          step()
          return
        end
        local ips = filter_by_family(all_ips)
        if #ips == 0 then
          -- Cache covers current flags but has no IPs in them -- definitive
          -- "broken" for THIS target (DNS authoritatively says so).
          mx._cache_checked = true
          mx._cache_value = data
          broken_count = broken_count + 1
          step()
          return
        end
        step3(ips, mx.name)
      end)
    end

    step()
  end

  -- step 1.5: A-fallback (no MX RR found at domain).
  local function fallback_a()
    ctx.mx_missing = true
    resolve_addresses(task, mx_domain, function(ip_strs, err_code)
      if not ip_strs or #ip_strs == 0 then
        if err_code == 'df' then
          cache_set(task, 'd', mx_domain, 'df', settings.expire_dns)
          done('df', ctx)
          return
        end
        cache_set(task, 'd', mx_domain, 'no', settings.expire_dns)
        done('no', ctx)
        return
      end
      cache_set(task, 'd', mx_domain,
        'a:' .. family_prefix() .. ':' .. encode_ip_list(ip_strs),
        settings.expire_dns)
      step3(ip_strs, mx_domain)
    end)
  end

  -- step 1: d-layer cache, else MX resolution.
  local function step1_resolve_mx()
    local r = task:get_resolver()
    r:resolve('mx', {
      name = mx_domain,
      task = task,
      forced = true,
      callback = function(_, _, results, err)
        if not results or #results == 0 then
          if is_dns_real_failure(err) then
            -- DNS-path failure on MX -- don't A-fallback (could produce a
            -- misleading verdict via a different resolver path).
            cache_set(task, 'd', mx_domain, 'df', settings.expire_dns)
            done('df', ctx)
            return
          end
          -- NXDOMAIN/NOREC at MX -> legitimate "no MX", A-fallback per §5.1.
          fallback_a()
          return
        end

        if is_null_mx(results) then
          cache_set(task, 'd', mx_domain, 'null', settings.expire_dns)
          done('null', ctx)
          return
        end

        -- Drop MX targets with labels starting with '_' (RFC 952/1123:
        -- invalid as hostnames; covers Domain Connect placeholders
        -- like _dc-mx.*). Publisher published MX records, so this is
        -- not the no-MX case -- all-malformed surfaces as 'bkn'.
        -- This is THE canonical normalisation point: encode_mx_list,
        -- exclude_mxs glob match, and m-layer cache keys all trust the
        -- names to be lowercase from here on.
        local valid = {}
        for _, mx in ipairs(results) do
          local name = norm_name(mx.name)
          if name and not name:match('^_') then
            mx.name = name
            valid[#valid + 1] = mx
          end
        end
        if #valid == 0 then
          cache_set(task, 'd', mx_domain, 'bkn', settings.expire_dns)
          done('bkn', ctx)
          return
        end
        -- Sort by RFC 5321 preference (lowest first) and cap before caching:
        -- canonical encoding makes Redis entries debuggable in priority order
        -- and saves bytes on records with many MX entries.
        table.sort(valid, function(a, b) return a.priority < b.priority end)
        if #valid > settings.max_mx_a_records then
          local trimmed = {}
          for k = 1, settings.max_mx_a_records do trimmed[k] = valid[k] end
          valid = trimmed
        end
        cache_set(task, 'd', mx_domain, encode_mx_list(valid), settings.expire_dns)
        step2(valid)
      end,
    })
  end

  cache_get(task, 'd', mx_domain, function(err, data)
    if err or type(data) ~= 'string' or #data == 0 then
      step1_resolve_mx()
      return
    end
    if not is_valid_cache_value('d', data) then
      lua_util.debugm(N, task,
        "unexpected d: cache value at %s: '%s', treating as miss", mx_domain, data)
      -- step1_resolve_mx will cache_set a fresh value over the bad entry.
      step1_resolve_mx()
      return
    end
    if data == 'no' then
      done('no', ctx)
      return
    end
    if data == 'bkn' then
      done('bkn', ctx)
      return
    end
    if data == 'null' then
      done('null', ctx)
      return
    end
    if data == 'df' then
      done('df', ctx)
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
    if lua_util.str_startswith(data, 'a:') then
      ctx.mx_missing = true
      local queried, all_ips = decode_ip_list_with_family(string.sub(data, 3)) -- #'a:' == 3
      if not queried then
        -- Unrecognised body; re-resolve from scratch.
        fallback_a()
        return
      end
      if not family_coverage_ok(queried) then
        -- Cache didn't query a currently-enabled family; re-resolve.
        fallback_a()
        return
      end
      local ips = filter_by_family(all_ips)
      if #ips == 0 then
        -- Cache covers current flags and authoritatively has no IPs -> MX_NONE.
        done('no', ctx)
        return
      end
      step3(ips, mx_domain)
      return
    end
    step1_resolve_mx()
  end)
end

local function mx_check(task)
  -- Skip authenticated / locally-originated traffic unless explicitly opted in.
  if task:get_user() and not settings.check_authorized then
    return
  end
  local ip_addr = task:get_ip()
  if ip_addr and ip_addr:is_local() and not settings.check_local then
    return
  end

  -- Collect candidate domains; dedup by normalised domain, keeping the
  -- highest-priority source (envelope > reply-to > mime-from).
  local domains = {}
  local function record(domain, source)
    domain = norm_name(domain)
    if not domain then return end
    local current = domains[domain]
    if not current or SOURCE_PRIORITY[source] < SOURCE_PRIORITY[current] then
      domains[domain] = source
    end
  end

  if settings.check_from then
    local from = task:get_from('smtp')
    if ((from or E)[1] or E).domain and not from[2] then
      record(from[1].domain, 'from')
    else
      record(task:get_helo(), 'from')
    end
  end
  if settings.check_mime_from then
    local mime_from = task:get_from('mime')
    if mime_from then
      for _, m in ipairs(mime_from) do
        record(m.domain, 'mime_from')
      end
    end
  end
  if settings.check_reply_to then
    local rt_hdr = task:get_header('Reply-To')
    if rt_hdr then
      local addrs = rspamd_util.parse_mail_address(rt_hdr, task:get_mempool())
      if addrs then
        for _, a in ipairs(addrs) do
          record(a.domain, 'reply_to')
        end
      end
    end
  end

  -- One probe + one symbol per unique domain. Pipelines run concurrently
  -- via rspamd's event loop.
  for mx_domain, src in pairs(domains) do
    if exclude_domains and exclude_domains:get_key(mx_domain) then
      rspamd_logger.infox(task, 'skip mx check for %s, excluded (%s)', mx_domain, src)
      emit_outcome(task, mx_domain, 'white', { key = mx_domain }, src)
    else
      lookup(task, mx_domain, src, function(outcome, info)
        lua_util.debugm(N, task, 'verdict for %s (%s): %s', mx_domain, src, outcome)
        emit_outcome(task, mx_domain, outcome, info, src)
      end)
    end
  end
end

-- Module setup.

local opts = rspamd_config:get_all_opt('mx_check')
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'module is unconfigured')
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

redis_params = lua_redis.parse_redis_server('mx_check')
if not redis_params then
  rspamd_logger.errx(rspamd_config, 'no redis servers are specified, disabling module')
  lua_util.disable_module(N, "redis")
  return
end

if not settings.probe_ipv4 and not settings.probe_ipv6 then
  rspamd_logger.errx(rspamd_config,
    'mx_check: both probe_ipv4 and probe_ipv6 are disabled — nothing to probe; disabling module')
  lua_util.disable_module(N, 'config')
  return
end

if not settings.check_from and not settings.check_mime_from and not settings.check_reply_to then
  rspamd_logger.errx(rspamd_config,
    'mx_check: check_from / check_mime_from / check_reply_to are all disabled — no source to check; disabling module')
  lua_util.disable_module(N, 'config')
  return
end

-- i-layer TTLs must be positive (zero would mean every task re-probes
-- every IP). expire_dns = 0 is allowed (disables d:/m: caching only);
-- negative rejected (Redis would refuse a negative TTL).
for _, k in ipairs({ 'expire', 'expire_novalid', 'expire_timeout' }) do
  if not (settings[k] and settings[k] > 0) then
    rspamd_logger.errx(rspamd_config,
      'mx_check: %s must be > 0 (got %s); disabling module', k, settings[k])
    lua_util.disable_module(N, 'config')
    return
  end
end
if not (settings.expire_dns and settings.expire_dns >= 0) then
  rspamd_logger.errx(rspamd_config,
    'mx_check: expire_dns must be >= 0 (got %s); disabling module', settings.expire_dns)
  lua_util.disable_module(N, 'config')
  return
end

-- max_mx_a_records caps both the MX list and the per-MX A/AAAA fan-out. Must
-- be >= 1 always, and >= 2 when both probe families are on (otherwise we
-- couldn't fit at least one A and one AAAA in the combined list).
if not (settings.max_mx_a_records and settings.max_mx_a_records >= 1) then
  rspamd_logger.errx(rspamd_config,
    'mx_check: max_mx_a_records must be >= 1 (got %s); disabling module',
    settings.max_mx_a_records)
  lua_util.disable_module(N, 'config')
  return
end
if settings.probe_ipv4 and settings.probe_ipv6 and settings.max_mx_a_records < 2 then
  rspamd_logger.errx(rspamd_config,
    'mx_check: max_mx_a_records must be >= 2 when both probe_ipv4 and probe_ipv6 are enabled (got %s); disabling module',
    settings.max_mx_a_records)
  lua_util.disable_module(N, 'config')
  return
end

lua_redis.register_prefix(settings.key_prefix .. ':*', N,
  'MX check cache (three-layer: d:/m:/i:)', { type = 'string' })

-- Augmentation budget: DNS + Redis + connect + read (worst case). Redis
-- timeout sourced from parse_redis_server's resolved value (nested redis{}
-- > global redis.conf > 1.0 default).
local dns_to = rspamd_config:get_dns_timeout() or 0.0
local redis_to = (redis_params and redis_params.timeout) or 0.0
local budget = settings.connect_timeout + settings.read_timeout
    + dns_to + redis_to

-- Stable callback parent. All per-source variants (envelope-from, MIME From,
-- Reply-To) register as virtual children of MX_CHECK so symbols_enabled or
-- disabled toggles and group / dependency declarations operate on a single
-- name that doesn't shift with symbols renames via settings.
local id = rspamd_config:register_symbol({
  name = 'MX_CHECK',
  group = 'mx',
  type = 'callback',
  callback = mx_check,
  flags = 'empty',
  augmentations = { string.format("timeout=%f", budget) },
})

local function register_all_sources(base_name)
  local prefixes = {
    settings.symbol_prefix_from,
    settings.symbol_prefix_mime_from,
    settings.symbol_prefix_reply_to,
  }
  for _, prefix in ipairs(prefixes) do
    rspamd_config:register_symbol({ name = prefix .. base_name, type = 'virtual', parent = id })
  end
end

register_all_sources(settings.symbol_bad_mx)
register_all_sources(settings.symbol_good_mx)
register_all_sources(settings.symbol_white_mx)
register_all_sources(settings.symbol_mx_refused)
register_all_sources(settings.symbol_mx_timeout_connect)
register_all_sources(settings.symbol_mx_timeout_read)
register_all_sources(settings.symbol_mx_error)
register_all_sources(settings.symbol_mx_none)
register_all_sources(settings.symbol_mx_null)
register_all_sources(settings.symbol_mx_broken)
register_all_sources(settings.symbol_mx_dns_fail)
register_all_sources(settings.symbol_mx_local_only)
register_all_sources(settings.symbol_mx_local_mix)
register_all_sources(settings.symbol_mx_bogon_only)
register_all_sources(settings.symbol_mx_bogon_mix)
register_all_sources(settings.symbol_mx_skip)
register_all_sources(settings.symbol_mx_bad)
register_all_sources(settings.symbol_mx_ip_bad)
register_all_sources(settings.symbol_mx_inflight)
register_all_sources(settings.symbol_mx_redis_error)
register_all_sources(settings.symbol_mx_a_good)
register_all_sources(settings.symbol_mx_a_refused)
register_all_sources(settings.symbol_mx_a_timeout_connect)
register_all_sources(settings.symbol_mx_a_timeout_read)
register_all_sources(settings.symbol_mx_a_error)
register_all_sources(settings.symbol_mx_a_invalid)

-- Metric defaults fan out across the 3 source prefixes with equal weight.
local function set_metric_all_sources(base_name, score, description)
  local prefixes = {
    settings.symbol_prefix_from,
    settings.symbol_prefix_mime_from,
    settings.symbol_prefix_reply_to,
  }
  for _, prefix in ipairs(prefixes) do
    rspamd_config:set_metric_symbol({
      name = prefix .. base_name,
      score = score,
      description = description,
      group = 'mx',
      one_shot = true,
    })
  end
end

set_metric_all_sources(settings.symbol_bad_mx, 3.0,
  'MX target accepted TCP but listener does not speak SMTP')
set_metric_all_sources(settings.symbol_good_mx, -0.1,
  'Domain has working MX')
set_metric_all_sources(settings.symbol_white_mx, -0.1,
  'Domain is whitelisted from MX check')

-- Default symbol weights. Operators can override any per-deployment via
-- local.d/mx_group.conf or override.d/mx_group.conf.
set_metric_all_sources(settings.symbol_mx_refused, 3.0,
  'MX target sent TCP RST (port 25 closed)')
set_metric_all_sources(settings.symbol_mx_timeout_connect, 2.0,
  'MX target did not respond to connect attempt')
set_metric_all_sources(settings.symbol_mx_timeout_read, 0.1,
  'MX target accepted TCP but did not send greeting')
set_metric_all_sources(settings.symbol_mx_error, 0.0,
  'MX target greeted with 4xx/5xx (real SMTP, rejected probe)')
set_metric_all_sources(settings.symbol_mx_none, 4.0,
  'From domain has no MX/A/AAAA records (covers NXDOMAIN and NOREC)')
set_metric_all_sources(settings.symbol_mx_null, 6.0,
  'Domain published RFC 7505 Null MX')
set_metric_all_sources(settings.symbol_mx_broken, 4.0,
  'All MX RRs point at hostnames that do not resolve')
set_metric_all_sources(settings.symbol_mx_dns_fail, 0.0,
  'Transient DNS path failure (SERVFAIL/REFUSED/timeout); sender not at fault')
set_metric_all_sources(settings.symbol_mx_local_only, 3.0,
  'All resolved MX IPs are in private ranges (RFC1918 / CGNAT / ULA); no probe run')
set_metric_all_sources(settings.symbol_mx_local_mix, 3.0,
  'Some resolved MX IPs are in private ranges; public subset probed')
set_metric_all_sources(settings.symbol_mx_bogon_only, 8.0,
  'All resolved MX IPs are bogon / non-routable (loopback, TEST-NET, multicast, etc.); no probe run')
set_metric_all_sources(settings.symbol_mx_bogon_mix, 5.0,
  'Some resolved MX IPs are bogon / non-routable; public subset probed')
set_metric_all_sources(settings.symbol_mx_skip, 0.0,
  'exclude_ips filtered every routable MX IP away; no probe run')
set_metric_all_sources(settings.symbol_mx_bad, 6.0,
  'MX hostname listed in bad_mxs (operator-defined punishment glob)')
set_metric_all_sources(settings.symbol_mx_ip_bad, 6.0,
  'Resolved MX IP listed in bad_ips (operator-defined punishment radix)')
set_metric_all_sources(settings.symbol_mx_inflight, 0.0,
  'Another rspamd worker holds the i-layer probe lock; verdict will land via that worker')
set_metric_all_sources(settings.symbol_mx_redis_error, 0.0,
  'Redis error during probe-lock claim; probe skipped (module cache layer degraded)')

-- A-fallback path. Failure shapes are stronger than MX-RR equivalents (no
-- published mail intent + no working A listener = textbook forgery / parked
-- domain). MX_A_GOOD stays neutral (legitimate RFC 5321 §5.1 deployment).
set_metric_all_sources(settings.symbol_mx_a_good, 0.0,
  'A-fallback target accepted SMTP (no MX RR; RFC 5321 §5.1 compliant)')
set_metric_all_sources(settings.symbol_mx_a_refused, 3.0,
  'A-fallback target sent TCP RST (port 25 closed)')
set_metric_all_sources(settings.symbol_mx_a_timeout_connect, 2.5,
  'A-fallback target did not respond to connect attempt')
set_metric_all_sources(settings.symbol_mx_a_timeout_read, 0.1,
  'A-fallback target accepted TCP but did not send SMTP greeting')
set_metric_all_sources(settings.symbol_mx_a_error, 0.0,
  'A-fallback target greeted with 4xx/5xx (real SMTP, rejected probe)')
set_metric_all_sources(settings.symbol_mx_a_invalid, 3.0,
  'A-fallback target accepted TCP but listener does not speak SMTP')

-- Static radix maps for IP-class classification. test_mode lifts loopback
-- out of the bogon set so the probe path stays exercisable against a local
-- listener; production must NEVER enable this.
local bogon_cidrs = BOGON_CIDRS
if settings.test_mode then
  rspamd_logger.warnx(rspamd_config,
    'mx_check: test_mode is ON, loopback is treated as probeable; '
      .. 'do NOT use this in production')
  bogon_cidrs = {}
  for _, r in ipairs(BOGON_CIDRS) do
    if not LOOPBACK_CIDRS[r] then
      bogon_cidrs[#bogon_cidrs + 1] = r
    end
  end
end
local_ip_map = lua_maps.map_add_from_ucl(LOCAL_CIDRS, 'radix',
  'mx_check LOCAL ranges (RFC1918, CGNAT, ULA)')
bogon_ip_map = lua_maps.map_add_from_ucl(bogon_cidrs, 'radix',
  'mx_check BOGON ranges (loopback, link-local, TEST-NET, multicast, etc.)')

if settings.exclude_domains then
  exclude_domains = rspamd_config:add_map {
    type = 'glob',
    description = 'Exclude specific domains from MX checks',
    url = settings.exclude_domains,
  }
end

if settings.exclude_mxs then
  exclude_mxs = rspamd_config:add_map {
    type = 'glob',
    description = 'Exclude specific MX hostnames from MX checks (m-layer trust)',
    url = settings.exclude_mxs,
  }
end

if settings.exclude_ips then
  exclude_ips = rspamd_config:add_map {
    type = 'radix',
    description = 'Exclude specific IPs/CIDRs from MX probing (i-layer skip)',
    url = settings.exclude_ips,
  }
end

if settings.bad_mxs then
  bad_mxs = rspamd_config:add_map {
    type = 'glob',
    description = 'Punish specific MX hostnames (short-circuits with MX_BAD)',
    url = settings.bad_mxs,
  }
end

if settings.bad_ips then
  bad_ips = rspamd_config:add_map {
    type = 'radix',
    description = 'Punish specific IPs/CIDRs (short-circuits with MX_IP_BAD)',
    url = settings.bad_ips,
  }
end
