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
  return
end

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local hash = require "rspamd_cryptobox_hash"
local rspamd_url = require "rspamd_url"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local N = "url_redirector"

-- Coherent browser fingerprint profiles.
--
-- The url_redirector resolves shortened/redirector URLs by issuing HTTP
-- requests. Sites that cloak (serve different content to bots) commonly
-- key on a missing or inconsistent header set, so a lone User-Agent
-- string is the weakest possible disguise. Each profile instead bundles
-- a User-Agent with the exact header set, values and order that the
-- matching real browser sends, keeping the request internally consistent
-- (e.g. Chrome carries `sec-ch-ua` client hints; Firefox and Safari do
-- not).
--
-- `headers` is an ordered list of {name, value} pairs. rspamd_http keeps
-- this order on the wire (RSPAMD_HTTP_FLAG_ORDERED_HEADERS); the Host
-- header and request line are emitted by the HTTP client itself. One
-- profile is picked per task so every hop of every chain shares a single
-- identity, the way a real browser would.

-- The Accept header all Chromium-based browsers send on a navigation.
local chromium_accept = 'text/html,application/xhtml+xml,' ..
    'application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,' ..
    'application/signed-exchange;v=b3;q=0.7'

local default_profiles = {
  {
    name = 'chrome_win',
    headers = {
      { 'Connection', 'keep-alive' },
      { 'sec-ch-ua', '"Not)A;Brand";v="8", "Chromium";v="148", "Google Chrome";v="148"' },
      { 'sec-ch-ua-mobile', '?0' },
      { 'sec-ch-ua-platform', '"Windows"' },
      { 'Upgrade-Insecure-Requests', '1' },
      { 'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36' },
      { 'Accept', chromium_accept },
      { 'Sec-Fetch-Site', 'none' },
      { 'Sec-Fetch-Mode', 'navigate' },
      { 'Sec-Fetch-User', '?1' },
      { 'Sec-Fetch-Dest', 'document' },
      { 'Accept-Encoding', 'gzip, deflate, br, zstd' },
      { 'Accept-Language', 'en-US,en;q=0.9' },
    },
  },
  {
    name = 'chrome_mac',
    headers = {
      { 'Connection', 'keep-alive' },
      { 'sec-ch-ua', '"Not)A;Brand";v="8", "Chromium";v="148", "Google Chrome";v="148"' },
      { 'sec-ch-ua-mobile', '?0' },
      { 'sec-ch-ua-platform', '"macOS"' },
      { 'Upgrade-Insecure-Requests', '1' },
      { 'User-Agent',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36' },
      { 'Accept', chromium_accept },
      { 'Sec-Fetch-Site', 'none' },
      { 'Sec-Fetch-Mode', 'navigate' },
      { 'Sec-Fetch-User', '?1' },
      { 'Sec-Fetch-Dest', 'document' },
      { 'Accept-Encoding', 'gzip, deflate, br, zstd' },
      { 'Accept-Language', 'en-US,en;q=0.9' },
    },
  },
  {
    name = 'edge_win',
    headers = {
      { 'Connection', 'keep-alive' },
      { 'sec-ch-ua', '"Not)A;Brand";v="8", "Chromium";v="148", "Microsoft Edge";v="148"' },
      { 'sec-ch-ua-mobile', '?0' },
      { 'sec-ch-ua-platform', '"Windows"' },
      { 'Upgrade-Insecure-Requests', '1' },
      { 'User-Agent',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0' },
      { 'Accept', chromium_accept },
      { 'Sec-Fetch-Site', 'none' },
      { 'Sec-Fetch-Mode', 'navigate' },
      { 'Sec-Fetch-User', '?1' },
      { 'Sec-Fetch-Dest', 'document' },
      { 'Accept-Encoding', 'gzip, deflate, br, zstd' },
      { 'Accept-Language', 'en-US,en;q=0.9' },
    },
  },
  {
    -- Firefox sends no sec-ch-ua client hints and uses a different
    -- header order and Accept set than Chromium.
    name = 'firefox_win',
    headers = {
      { 'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0' },
      { 'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
      { 'Accept-Language', 'en-US,en;q=0.5' },
      { 'Accept-Encoding', 'gzip, deflate, br, zstd' },
      { 'Connection', 'keep-alive' },
      { 'Upgrade-Insecure-Requests', '1' },
      { 'Sec-Fetch-Dest', 'document' },
      { 'Sec-Fetch-Mode', 'navigate' },
      { 'Sec-Fetch-Site', 'none' },
      { 'Sec-Fetch-User', '?1' },
      { 'Priority', 'u=0, i' },
    },
  },
  {
    -- Safari also omits sec-ch-ua and sends a leaner header set.
    name = 'safari_mac',
    headers = {
      { 'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
      { 'Accept-Encoding', 'gzip, deflate, br' },
      { 'Connection', 'keep-alive' },
      { 'User-Agent',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15' },
      { 'Accept-Language', 'en-US,en;q=0.9' },
      { 'Sec-Fetch-Site', 'none' },
      { 'Sec-Fetch-Mode', 'navigate' },
      { 'Sec-Fetch-Dest', 'document' },
    },
  },
}

local redis_params

local settings = {
  expire = 86400, -- 1 day by default
  timeout = 8, -- total timeout of module
  -- HTTP HEAD timeout per redirect hop. Either a number (whole-request
  -- duration) or a table with .connect_timeout, .ssl_timeout,
  -- .write_timeout, .read_timeout for granular control.
  http_timeout = 4,
  redis_timeout = 2, -- redis timeout for cache operations  (redis.conf module has higher priority)
  nested_limit = 2, -- how many redirects to follow
  --proxy = "http://example.com:3128", -- send request through proxy, not yet implemented
  key_prefix = 'rdr:', -- default hash name
  check_ssl = false, -- check ssl certificates
  max_urls = 5, -- how many urls to check (CTA checked in first place)
  max_size = 10 * 1024, -- maximum body to process
  -- Optional operator override. When set (a string, or a list of
  -- strings picked at random) the module sends a single User-Agent
  -- header and skips fingerprint profiles entirely. Leave unset to use
  -- the coherent browser profiles below.
  user_agent = nil,
  -- Browser fingerprint profiles used when user_agent is not set.
  fingerprint_profiles = default_profiles,
  redirector_symbol = nil, -- insert symbol if redirected url has been found
  redirector_symbol_nested = "URL_REDIRECTOR_NESTED", -- insert symbol if nested limit has been reached
  redirector_symbol_non_http = "URL_REDIRECTOR_NON_HTTP", -- HTTP -> non-HTTP(S) redirect detected
  redirectors_only = true, -- follow merely redirectors
  top_urls_key = 'rdr:top_urls', -- key for top urls
  top_urls_count = 200, -- how many top urls to save
  redirector_hosts_map = nil, -- check only those redirectors
  redirector_get_urls_map = nil, -- list of regex patterns for which GET should be used instead of HEAD
  -- inject intermediate redirect hops into the task
  save_intermediate_redirs = {
    redirectors = false,
    non_redirectors = true, -- inject non-redirector hops by default since they can hide cloaker phishing urls
  }
}

-- Spread http_timeout into the kwargs of an rspamd_http.request{} call:
-- 'timeout' for the number form, individual fields for the table form.
local function apply_http_timeout(http_params)
  local t = settings.http_timeout
  if type(t) == 'table' then
    http_params.connect_timeout = t.connect_timeout
    http_params.ssl_timeout = t.ssl_timeout
    http_params.write_timeout = t.write_timeout
    http_params.read_timeout = t.read_timeout
  else
    http_params.timeout = t
  end
end

--[[
Encode characters that are not allowed in URLs according to RFC 3986
This is needed because redirect Location headers sometimes contain unencoded spaces
and other special characters that http_parser_parse_url() doesn't accept.
Only encodes the truly problematic characters (space, control chars, etc.)
]]
local function encode_url_for_redirect(url_str)
  if not url_str then
    return nil
  end

  -- Encode space and other problematic characters that are common in redirect URLs
  -- We're conservative - only encode what http_parser_parse_url actually rejects
  -- Don't encode already-encoded sequences (%XX)
  -- Use explicit ASCII ranges instead of %w which is locale-dependent
  local encoded = url_str:gsub("([^A-Za-z0-9%-%._~:/?#%[%]@!$&'()*+,;=%%])", function(c)
    -- Don't double-encode already encoded characters
    if c == '%' then
      return c
    end
    return string.format("%%%02X", string.byte(c))
  end)

  return encoded
end

-- Build a 'host1->host2->...' string from a chain of URL objects.
-- Includes scheme for non-HTTP(S) URLs to distinguish them.
local function chain_hosts_string(chain)
  local hosts = {}
  for i = 1, #chain do
    local proto = chain[i]:get_protocol()
    if proto ~= 'http' and proto ~= 'https' then
      hosts[i] = chain[i]:get_text()
    else
      hosts[i] = chain[i]:get_host()
    end
  end
  return table.concat(hosts, '->')
end

-- Compute the per-URL Redis cache key. Hashing the URL string keeps keys
-- fixed-length and free of URL-unsafe characters; using tostring() (rather
-- than :get_raw()) keeps the hash stable across the write-then-read cycle
-- when chain values are roundtripped through rspamd_url.create.
local function cache_key_for_url(url_str)
  return settings.key_prefix .. hash.create(url_str):base32():sub(1, 32)
end

-- Whether an intermediate hop should be saved (in cache and task URL set)
-- given the per-class gates in settings.save_intermediate_redirs. Hops on
-- redirector_hosts_map are gated by .redirectors; everything else by
-- .non_redirectors -- the latter is where rotator/cloaker hosts surface.
local function should_save_hop(hop_url)
  if not hop_url then
    return false
  end
  local host = hop_url:get_host()
  local is_redirector = false
  if host and settings.redirector_hosts_map
      and settings.redirector_hosts_map:get_key(host) then
    is_redirector = true
  end
  local cfg = settings.save_intermediate_redirs
  if is_redirector then
    return cfg.redirectors and true or false
  end
  return cfg.non_redirectors and true or false
end

-- Append hop to chain unless it equals the current tail. String
-- comparison (not identity): on cache-hit walks the parsed URL is a
-- fresh Lua object for the same string, and identity (==) would
-- falsely register a self-loop as two distinct hops.
local function chain_append(chain, hop_url)
  if not hop_url then
    return
  end
  local tail = chain[#chain]
  if tail == nil or tostring(hop_url) ~= tostring(tail) then
    table.insert(chain, hop_url)
  end
end

-- Apply a finalized chain to the task: link adjacent pairs via
-- set_redirected, inject every non-orig hop as a task URL, and emit
-- redirector_symbol with hosts joined by '->'. Length-1 chain (no
-- redirect happened) is a no-op.
local function apply_redirect_chain(task, chain)
  if #chain < 2 then
    return
  end
  local mempool = task:get_mempool()
  for i = 1, #chain - 1 do
    chain[i]:set_redirected(chain[i + 1], mempool)
  end
  for i = 2, #chain do
    local proto = chain[i]:get_protocol()
    if proto == 'http' or proto == 'https' then
      task:inject_url(chain[i])
    end
  end
  if settings.redirector_symbol then
    task:insert_result(settings.redirector_symbol, 1.0,
        chain_hosts_string(chain))
  end
end

-- Persist a finalized chain to Redis as one SETEX per adjacent pair where
-- the value is the next hop. Non-terminal links carry a '^hop:' marker so
-- the reader keeps walking; the terminal link carries terminal_prefix
-- (currently 'nested') if the chain didn't fully resolve, otherwise no
-- marker. ZINCRBY counts the canonical URL string with no marker so the
-- top_urls zset stays a meaningful popularity counter.
-- A length-1 chain caches a self-loop so future scans of a direct-200
-- URL fast-path through the cache walk instead of re-issuing HEAD.
local function cache_chain_to_redis(task, chain, terminal_prefix)
  if #chain == 0 then
    return
  end

  local function trim_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'got error trimming top urls set: %s', err)
    else
      rspamd_logger.infox(task, 'trimmed top urls set to %s elements',
          settings.top_urls_count)
    end
  end

  local function card_cb(err, data)
    if err then
      rspamd_logger.errx(task, 'got error reading top urls cardinality: %s', err)
      return
    end
    if data and tonumber(data) and tonumber(data) > settings.top_urls_count * 2 then
      local ret = lua_redis.redis_make_request(task,
          redis_params, settings.top_urls_key, true, trim_cb,
          'ZREMRANGEBYRANK',
          { settings.top_urls_key, '0',
            tostring(-(settings.top_urls_count + 1)) })
      if not ret then
        rspamd_logger.errx(task, 'cannot trim top urls set')
      end
    end
  end

  local function set_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'got error caching redirect link: %s', err)
    end
  end

  local function write_link(prev_url, next_url, marker)
    local link_key = cache_key_for_url(tostring(prev_url))
    local next_str = encode_url_for_redirect(next_url:get_text())
    local cache_value
    if marker then
      cache_value = string.format('^%s:%s', marker, next_str)
    else
      cache_value = next_str
    end
    local ret, conn, _ = lua_redis.redis_make_request(task,
        redis_params, link_key, true, set_cb,
        'SETEX', { link_key, tostring(settings.expire), cache_value })
    if not ret then
      rspamd_logger.errx(task, 'cannot cache redirect link for %s', prev_url)
    elseif conn then
      conn:add_cmd('ZINCRBY', { settings.top_urls_key, '1', next_str })
    end
  end

  if #chain == 1 then
    write_link(chain[1], chain[1], terminal_prefix)
  else
    for i = 1, #chain - 1 do
      local marker
      if i == #chain - 1 then
        marker = terminal_prefix
      else
        marker = 'hop'
      end
      write_link(chain[i], chain[i + 1], marker)
    end
  end

  -- One trim probe per finalized chain rather than per link.
  local ret = lua_redis.redis_make_request(task,
      redis_params, settings.top_urls_key, false, card_cb,
      'ZCARD', { settings.top_urls_key })
  if not ret then
    rspamd_logger.errx(task, 'cannot probe top urls cardinality')
  end
end

-- Apply chain to task and persist it to Redis.
local function finalize_chain(task, chain, terminal_prefix)
  apply_redirect_chain(task, chain)
  cache_chain_to_redis(task, chain, terminal_prefix)
end

-- HTTP redirect status codes that we follow.
local redirection_codes = {
  [301] = true, -- moved permanently
  [302] = true, -- found
  [303] = true, -- see other
  [307] = true, -- temporary redirect
  [308] = true, -- permanent redirect
}

-- step (cache walk) and http_walk (live HEAD) are mutually recursive:
-- step bridges to http_walk on '^nested' to extend a partially-resolved
-- chain; http_walk splices into step on a 30x whose redirect target has
-- a cached chain (saves redundant HEADs across emails that share an
-- intermediate). Forward-declare so each can name the other.
local step
local http_walk

-- Terminal exit for step(): write back if we extended via HTTP this scan,
-- else just apply. Hoisted as a free function so step()'s recursive cache
-- hops don't allocate a fresh closure per call.
local function step_finish(task, chain, http_extended, terminal_prefix)
  if http_extended then
    finalize_chain(task, chain, terminal_prefix)
  else
    apply_redirect_chain(task, chain)
  end
end

-- Walk a cached redirect chain. data is the Redis value for
-- hash(chain[#chain]); pass nil to issue the GET. seen is the shared
-- per-scan URL-string set (cache walk and http_walk write to it so
-- cycles crossing both layers are caught with one extra Redis GET at
-- worst). ntries is the count of HTTP HEADs already issued in this
-- scan -- threaded through cache hops without change so the
-- ^nested-bridge below hands http_walk the correct remaining budget,
-- not a fresh nested_limit. Defaults to 0 for top-level cache walks.
--
-- http_extended (default false): set to true when step() was entered
-- via an http_walk splice (the chain has live-resolved entries that
-- aren't in cache yet). At terminal/exit paths we then call
-- finalize_chain (which writes back via cache_chain_to_redis) instead
-- of just apply_redirect_chain, so the new chain links get persisted.
-- For top-level cache walks (no HTTP this scan) we keep the cheap
-- apply-only path to avoid redundant SETEX traffic.
step = function(task, orig_url, chain, seen, data, ntries, http_extended)
  ntries = ntries or 0
  http_extended = http_extended or false

  if data == nil then
    local last = chain[#chain]
    local last_str = tostring(last)
    local next_key = cache_key_for_url(last_str)
    local ret = lua_redis.redis_make_request(task,
        redis_params, next_key, false,
        function(e, d)
          if e then
            rspamd_logger.errx(task,
                'redis error during chain walk at %s: %s', last_str, e)
            step_finish(task, chain, http_extended)
          elseif d == 'processing' then
            -- Another worker is currently resolving this hop; their write
            -- will populate the cache when they finish. Apply what we have
            -- and don't duplicate their HTTP work.
            lua_util.debugm(N, task,
                'cache lock at %s mid-walk, applying partial chain', last_str)
            step_finish(task, chain, http_extended)
          elseif type(d) ~= 'string' then
            -- True cache miss mid-walk: a previous chain link points to a
            -- URL whose own cache entry is gone (TTL expired or evicted).
            -- Resume live HTTP from this dead end so the chain rebuilds and
            -- gets re-cached, instead of giving up with a truncated chain.
            lua_util.debugm(N, task,
                'cache miss for %s mid-walk, extending with live HTTP', last_str)
            -- The prior ^hop iteration that appended `last` to the chain
            -- set seen[last_str]=true; http_walk re-marks it on entry, so
            -- clear here to avoid false-firing http_walk's cycle guard on
            -- the very URL we're bridging to.
            seen[last_str] = nil
            http_walk(task, orig_url, last, ntries + 1, chain, seen)
          else
            step(task, orig_url, chain, seen, d, ntries, http_extended)
          end
        end,
        'GET', { next_key })
    if not ret then
      rspamd_logger.errx(task, 'cannot make redis request to walk chain')
      step_finish(task, chain, http_extended)
    end
    return
  end

  local prefix, val = nil, data
  if data:sub(1, 1) == '^' then
    local p, v = data:match('^%^([%w_]+):(.+)$')
    if p then
      prefix, val = p, v
    end
  end

  if seen[val] then
    lua_util.debugm(N, task, 'cycle in cached chain at %s', val)
    step_finish(task, chain, http_extended)
    return
  end

  local hop = rspamd_url.create(task:get_mempool(), val,
      { 'redirect_target' })
  if not hop then
    step_finish(task, chain, http_extended)
    return
  end
  chain_append(chain, hop)
  seen[val] = true

  if prefix == 'hop' then
    step(task, orig_url, chain, seen, nil, ntries, http_extended)
    return
  end

  if prefix == 'nested' then
    -- Cached walk ended on "we ran out of HTTP budget last time".
    -- Hand off to http_walk for a live extension. ntries+1 is the
    -- index of the next HEAD in this scan -- not 1 -- so any HEADs
    -- already done before the cache splice still count toward
    -- nested_limit. If the extension finalizes successfully, the
    -- upstream ^nested marker is rewritten as ^hop and the chain
    -- grows in cache.
    lua_util.debugm(N, task,
        'extending past cached ^nested:%s with live HTTP', val)
    http_walk(task, orig_url, hop, ntries + 1, chain, seen)
    return
  end

  if prefix == 'non_http' then
    local rscheme = hop:get_protocol() or val:match('^([^:]+)')
    -- chain already includes hop (appended via chain_append above)
    task:insert_result(settings.redirector_symbol_non_http, 1.0,
        string.format('%s=%s', rscheme, chain_hosts_string(chain)))
    step_finish(task, chain, http_extended, 'non_http')
    return
  end

  -- Plain terminal: chain fully resolved, apply (and persist if extended).
  step_finish(task, chain, http_extended)
end

-- Live HTTP HEAD walk. ntries counts only HTTP requests; the cache walk
-- (step()) does not consume this budget. Bounded by settings.nested_limit.
-- On any terminal -- 200, network error, non-redirector under
-- redirectors_only=true, non-30x non-200, or failed Location parse --
-- finalize the chain. On nested_limit exhaustion, finalize with
-- terminal_prefix='nested' so the cache marks the tail with ^nested and
-- a future scan can pick up from there with a fresh HTTP budget.
--
-- Before recursing on a 30x's redirect target, probe the cache: shared
-- intermediates (e.g. multiple shortlinks all funneling through one
-- redirector host) get walked via step() instead of duplicate HEADs.
http_walk = function(task, orig_url, url, ntries, chain, seen)
  if ntries > settings.nested_limit then
    lua_util.debugm(N, task,
        'cannot get more http requests to resolve %s, stop on %s after %s attempts',
        orig_url, url, ntries)
    chain_append(chain, url)
    finalize_chain(task, chain, 'nested')
    task:insert_result(settings.redirector_symbol_nested, 1.0,
        string.format('%s:%d', chain_hosts_string(chain), ntries))
    return
  end

  -- Mirror the cache walk's cycle guard: a redirector loop A->B->A->B
  -- (e.g. login redirector flapping between two hosts) would otherwise
  -- chew through nested_limit and bloat the chain with alternating
  -- entries.
  local url_str = tostring(url)
  if seen[url_str] then
    lua_util.debugm(N, task, 'cycle in http walk at %s', url_str)
    finalize_chain(task, chain, nil)
    return
  end
  seen[url_str] = true

  local function http_callback(err, code, _, headers)
    if err then
      rspamd_logger.infox(task,
          'found redirect error from %s to %s, err message: %s',
          orig_url, url, err)
      chain_append(chain, url)
      finalize_chain(task, chain, nil)
      return
    end

    if code == 200 then
      if orig_url == url then
        rspamd_logger.infox(task, 'direct url %s, err code 200', url)
      else
        rspamd_logger.infox(task,
            'found redirect from %s to %s, err code 200', orig_url, url)
      end
      chain_append(chain, url)
      finalize_chain(task, chain, nil)
      return
    end

    if redirection_codes[code] then
      local loc = headers['location']
      local redir_url
      if loc then
        -- Encode problematic characters (spaces, etc.) that
        -- http_parser doesn't accept. Fixes issue #5525.
        local encoded_loc = encode_url_for_redirect(loc)
        redir_url = rspamd_url.create(task:get_mempool(), encoded_loc)
        if not redir_url and encoded_loc ~= loc then
          rspamd_logger.infox(task,
              'failed to parse redirect location even after encoding: %s', loc)
        end
      end
      lua_util.debugm(N, task, 'found redirect from %s to %s, err code %s',
          orig_url, loc, code)

      -- 'url' just returned 30x, so it's an intermediate. Save it
      -- only when gating allows. When extending past a cached
      -- ^nested marker, url is the cached terminal that step() just
      -- appended to chain -- in both cases it's already the tail.
      if should_save_hop(url) then
        chain_append(chain, url)
      end

      if redir_url then
        local rscheme = redir_url:get_protocol()
        if rscheme ~= 'http' and rscheme ~= 'https' then
          lua_util.debugm(N, task, 'stop resolving redirects: %s has non-http(s) scheme %s', loc, rscheme)
          chain_append(chain, redir_url)
          task:insert_result(settings.redirector_symbol_non_http, 1.0,
              string.format('%s=%s', rscheme, chain_hosts_string(chain)))
          finalize_chain(task, chain, 'non_http')
          return
        end

        local should_follow
        if settings.redirectors_only then
          should_follow = settings.redirector_hosts_map:get_key(redir_url:get_host()) ~= nil
        else
          should_follow = true
        end

        if should_follow then
          -- Probe cache for redir_url before HEADing it. If a chain is
          -- already cached at hash(redir_url) (typical when many
          -- shortlinks share a redirector intermediate, or when a prior
          -- scan resolved redir_url as its own orig), splice into step
          -- and let the cache walk continue from there. Cache miss/lock:
          -- fall back to live HEAD as before.
          local k = cache_key_for_url(tostring(redir_url))
          local ret = lua_redis.redis_make_request(task,
              redis_params, k, false,
              function(probe_err, probe_data)
                if not probe_err
                    and type(probe_data) == 'string'
                    and probe_data ~= 'processing' then
                  lua_util.debugm(N, task,
                      'cache hit on redirect target %s, splicing into cache walk',
                      redir_url)
                  chain_append(chain, redir_url)
                  seen[tostring(redir_url)] = true
                  -- Pass current ntries so any onward ^nested-bridge
                  -- inside step counts HEADs already done in this
                  -- scan toward nested_limit, instead of resetting.
                  -- http_extended=true so step's terminal path will
                  -- finalize_chain (cache the newly-resolved live link
                  -- from this http_walk to redir_url, otherwise the
                  -- 'processing' marker at hash(orig_url) is never
                  -- replaced with the actual chain).
                  step(task, orig_url, chain, seen, probe_data, ntries, true)
                else
                  http_walk(task, orig_url, redir_url, ntries + 1, chain, seen)
                end
              end,
              'GET', { k })
          if not ret then
            rspamd_logger.errx(task,
                'cannot probe cache for redirect target, falling through to HEAD')
            http_walk(task, orig_url, redir_url, ntries + 1, chain, seen)
          end
        else
          lua_util.debugm(N, task,
              'stop resolving redirects as %s is not a redirector', loc)
          chain_append(chain, redir_url)
          finalize_chain(task, chain, nil)
        end
      elseif loc then
        local raw_scheme = loc:match('^([A-Za-z][A-Za-z0-9+%-.]*):')
        if raw_scheme and raw_scheme ~= 'http' and raw_scheme ~= 'https' then
          lua_util.debugm(N, task, 'stop resolving redirects: %s has non-http(s) scheme %s (unparseable url)', loc, raw_scheme)
          -- loc cannot be parsed into a URL object, so it cannot be appended to
          -- chain or cached with a ^non_http marker. Emit the symbol now and cache
          -- as a normal terminal; future scans within the TTL won't re-emit it.
          task:insert_result(settings.redirector_symbol_non_http, 1.0,
              string.format('%s=%s->%s', raw_scheme, chain_hosts_string(chain), loc))
          finalize_chain(task, chain, nil)
        else
          lua_util.debugm(N, task, 'failed to parse location %s, headers: %s', loc, headers)
          chain_append(chain, url)
          finalize_chain(task, chain, nil)
        end
      else
        lua_util.debugm(N, task, 'no location, headers: %s', headers)
        chain_append(chain, url)
        finalize_chain(task, chain, nil)
      end
      return
    end

    -- Other non-30x non-200 status: treat current url as terminal.
    lua_util.debugm(N, task,
        'found redirect error from %s to %s, err code: %s',
        orig_url, url, code)
    chain_append(chain, url)
    finalize_chain(task, chain, nil)
  end

  local method = 'head'
  if settings.redirector_get_urls_map
      and settings.redirector_get_urls_map:get_key(url_str) then
    method = 'get'
  end

  local http_params = {
    url = url_str,
    task = task,
    method = method,
    max_size = settings.max_size,
    opaque_body = true,
    no_ssl_verify = not settings.check_ssl,
    callback = http_callback,
  }

  if settings.user_agent then
    -- Operator override: a single User-Agent header, no fingerprint.
    local ua = settings.user_agent
    if type(ua) ~= 'string' then
      ua = ua[math.random(#ua)]
    end
    http_params.headers = { ['User-Agent'] = ua }
    lua_util.debugm(N, task, 'query %s %s with user agent %s',
        method, url_str, ua)
  else
    -- Stealth: one coherent browser fingerprint per task, reused by
    -- every hop of every chain so the identity stays consistent.
    local profile = task:cache_get('url_redirector_profile')
    if not profile then
      local profiles = settings.fingerprint_profiles
      if profiles and #profiles > 0 then
        profile = profiles[math.random(#profiles)]
        task:cache_set('url_redirector_profile', profile)
      end
    end
    if profile then
      http_params.headers = profile.headers
      lua_util.debugm(N, task, 'query %s %s with %s fingerprint',
          method, url_str, profile.name)
    else
      lua_util.debugm(N, task, 'query %s %s (no fingerprint profile)',
          method, url_str)
    end
  end

  apply_http_timeout(http_params)
  rspamd_http.request(http_params)
end

-- Top-level entry: walk the cached chain from orig_url, then either
-- apply a fully-resolved chain to the task or hand off to http_walk
-- on cache miss / lock / partial walk.
--
-- Cache walks (step) are unbounded; only HTTP consumes nested_limit.
-- Cycle protection is a per-walk seen-set keyed by URL string that
-- both step and http_walk share, so cycles spanning the two are caught.
local function resolve_cached(task, orig_url)
  local key = cache_key_for_url(tostring(orig_url))
  local chain = { orig_url }
  -- seen grows as we walk forward; we do not pre-seed it with orig_url
  -- because the writer caches direct-200 URLs as a length-1 self-loop
  -- (hash(orig) = tostring(orig)), and a pre-seed would false-fire the
  -- cycle check on legitimate terminals. chain_append's tostring-eq
  -- dedup keeps us from double-appending orig in that case.
  local seen = {}

  local function redis_get_cb(err, data)
    if not err and type(data) == 'string' and data ~= 'processing' then
      lua_util.debugm(N, task, 'found cached redirect from %s to %s',
          orig_url, data)
      -- Top-level cache hit: no HEADs done yet, so ntries=0 means a
      -- ^nested-bridge later gets the full nested_limit budget.
      step(task, orig_url, chain, seen, data, 0)
      return
    end

    -- Cache miss or 'processing': try to claim the lock and live-resolve.
    -- If SET NX fails (another scan holds the lock or a stale 'processing'
    -- marker survives a crash), ndata != 'OK' and we drop this scan -- the
    -- other holder will populate the cache, or the stale lock will expire
    -- (EX = timeout + 1s) and the next scan will claim it.
    local function redis_reserve_cb(nerr, ndata)
      if nerr then
        rspamd_logger.errx(task,
            'got error while setting redirect keys: %s', nerr)
      elseif ndata == 'OK' then
        http_walk(task, orig_url, orig_url, 1, chain, seen)
      else
        lua_util.debugm(N, task,
            'failed to claim lock for %s (held by another worker or stale processing marker, ndata=%s); skipping this scan',
            orig_url, ndata)
      end
    end

    local ret = lua_redis.redis_make_request(task,
        redis_params, key, true, redis_reserve_cb,
        'SET',
        { key, 'processing', 'EX',
          tostring(math.floor(settings.timeout) + 1), 'NX' })
    if not ret then
      rspamd_logger.errx(task, "Couldn't schedule SET")
    end
  end

  local ret = lua_redis.redis_make_request(task,
      redis_params, key, false, redis_get_cb,
      'GET', { key })
  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to check results')
  end
end

local function url_redirector_process_url(task, url)
  resolve_cached(task, url)
end

local function url_redirector_handler(task)
  -- task:has_urls returns (bool, count) without materialising the URL
  -- table; bail out cheaply when the message has no URLs at all so we
  -- skip the CTA scan and extract_specific_urls call entirely.
  local has_urls, n_urls = task:has_urls()
  if not has_urls then
    lua_util.debugm(N, task, 'no URLs in task, skipping redirector resolution')
    return
  end

  local selected = {}
  local seen = {}

  for _, part in ipairs(task:get_text_parts()) do
    if part:is_html() then
      for _, url in ipairs(part:get_cta_urls(settings.max_urls, true)) do
        local host = url:get_host()
        if host and settings.redirector_hosts_map:get_key(host) then
          local key = tostring(url)
          if not seen[key] then
            lua_util.debugm(N, task, 'prefer CTA url %s for redirector', key)
            table.insert(selected, url)
            seen[key] = true
            if #selected >= settings.max_urls then
              break
            end
          end
        end
      end
    end

    if #selected >= settings.max_urls then
      break
    end
  end

  local remaining = settings.max_urls - #selected

  if remaining > 0 then
    local sp_urls = lua_util.extract_specific_urls({
      task = task,
      limit = remaining,
      filter = function(url)
        -- task:get_urls()'s default protocol mask is HTTP|HTTPS|FILE|FTP.
        -- We only follow HTTP(S); silently drop the rest at selection
        -- rather than letting them reach http_walk and waste a HEAD
        -- timeout. URL_REDIRECTOR_NON_HTTP is reserved for the case
        -- where an HTTP redirect points at a non-HTTP scheme.
        local proto = url:get_protocol()
        if proto ~= 'http' and proto ~= 'https' then
          return false
        end
        local host = url:get_host()
        if host and settings.redirector_hosts_map:get_key(host) then
          local key = tostring(url)
          if not seen[key] then
            lua_util.debugm(N, task, 'consider redirector url %s', key)
            return true
          end
        end
        return false
      end,
      no_cache = true,
      need_content = true,
    })

    if sp_urls then
      for _, u in ipairs(sp_urls) do
        local key = tostring(u)
        if not seen[key] then
          table.insert(selected, u)
          seen[key] = true
          if #selected >= settings.max_urls then
            break
          end
        end
      end
    end
  end

  if #selected == 0 then
    lua_util.debugm(N, task,
        'no URLs matched redirector_hosts_map (out of %d task URLs)',
        n_urls)
  end

  for _, u in ipairs(selected) do
    url_redirector_process_url(task, u)
  end
end

local opts = rspamd_config:get_all_opt('url_redirector')
if opts then
  settings = lua_util.override_defaults(settings, opts)

  -- Pass redis_timeout to lua_redis instead of the symbol budget.
  -- Nested redis{} block needs the override too -- parse_redis_server
  -- reads opts.redis directly when present and never falls back to
  -- opts.timeout.
  local redis_opts = lua_util.shallowcopy(opts)
  redis_opts.timeout = settings.redis_timeout
  if redis_opts.redis then
    redis_opts.redis = lua_util.shallowcopy(redis_opts.redis)
    if not redis_opts.redis.timeout then
      redis_opts.redis.timeout = settings.redis_timeout
    end
  end
  redis_params = lua_redis.parse_redis_server('url_redirector', redis_opts)

  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "redis")
  else

    if not settings.redirector_hosts_map then
      rspamd_logger.infox(rspamd_config, 'no redirector_hosts_map option is specified, disabling module')
      lua_util.disable_module(N, "config")
    else
      local lua_maps = require "lua_maps"
      settings.redirector_hosts_map = lua_maps.map_add_from_ucl(settings.redirector_hosts_map,
          'glob', 'Redirectors definitions (glob: bare names match exactly, *.foo matches subs)')

      if settings.redirector_get_urls_map then
        settings.redirector_get_urls_map = lua_maps.map_add_from_ucl(
            settings.redirector_get_urls_map, 'regexp',
            'URL redirector: URLs to fetch with GET instead of HEAD')
      end

      lua_redis.register_prefix(settings.key_prefix .. '[a-z0-9]{32}', N,
          'URL redirector hashes', {
            type = 'string',
          })
      if settings.top_urls_key then
        lua_redis.register_prefix(settings.top_urls_key, N,
            'URL redirector top urls', {
              type = 'zlist',
            })
      end
      local id = rspamd_config:register_symbol {
        name = 'URL_REDIRECTOR_CHECK',
        type = 'callback,prefilter',
        priority = lua_util.symbols_priorities.medium,
        callback = url_redirector_handler,
        augmentations = { string.format("timeout=%f", settings.timeout) }
      }

      rspamd_config:register_symbol {
        name = settings.redirector_symbol_nested,
        type = 'virtual',
        parent = id,
        score = 0,
      }

      rspamd_config:register_symbol {
        name = settings.redirector_symbol_non_http,
        type = 'virtual',
        parent = id,
        score = 0,
      }

      if settings.redirector_symbol then
        rspamd_config:register_symbol {
          name = settings.redirector_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
        }
      end
    end
  end
end
