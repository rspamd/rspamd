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
]] --

--[[[
-- @module lua_dynconf.redis
-- Redis backend for lua_dynconf.
--
-- Storage layout: one hash `<key>` (default `rspamd_dynconf`):
--   * field `v`: global integer version, incremented by every write;
--   * field `m:<module>`: JSON `{"v": <module version>, "o": { ...override table... }}`.
--
-- Reads are cheap: a check is one `HGET <key> v`; the whole hash is fetched only when the version has
-- changed. All requests use the callback API and never block.
--]]

local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local logger = require "rspamd_logger"
local json = require "lua_dynconf.json"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"

local N = "dynconf"
local FIELD_PREFIX = 'm:'

local exports = {}

local redis_params
local redis_key = 'rspamd_dynconf'
local set_script_id

-- Last seen global version (as a string, compared with `~=`) and the blobs of the modules we applied
local last_version = '0'
local applied = {}

-- Atomic write: bump the global version and store the module blob with it. ARGV[1] is the module field
-- name, ARGV[2] is the pre-encoded override JSON object (empty string removes the override), ARGV[3] is
-- the first version of a hash that does not exist yet. A hash that was deleted and written again starts
-- from a different number, so a repeated version never hides new content.
-- If ARGV[4] is given it is the blob that the writer has based the new one on (empty string: there was
-- none): when the field holds something else the script changes nothing and returns -1, so that the writer
-- can merge its change into the current content and try again.
local set_script = [[
if ARGV[4] then
  local cur = redis.call('HGET', KEYS[1], ARGV[1])
  if cur == false then
    cur = ''
  end
  if cur ~= ARGV[4] then
    return -1
  end
end
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('HSET', KEYS[1], 'v', ARGV[3])
end
local v = redis.call('HINCRBY', KEYS[1], 'v', 1)
if ARGV[2] == '' then
  redis.call('HDEL', KEYS[1], ARGV[1])
else
  redis.call('HSET', KEYS[1], ARGV[1], '{"v":' .. v .. ',"o":' .. ARGV[2] .. '}')
end
return v
]]

-- How many times an update is merged again when somebody else has changed the module in between
local UPDATE_ATTEMPTS = 5

local function decode_json(str)
  local parser = ucl.parser()
  local ok, err = parser:parse_text(str)
  if not ok then
    return nil, err
  end
  return parser:get_object()
end

-- HGETALL replies are either a flat array (RESP2) or a map (RESP3)
local function reply_pairs(data)
  local res = {}
  if type(data) ~= 'table' then
    return res
  end
  if data[1] ~= nil then
    for i = 1, #data - 1, 2 do
      res[#res + 1] = { tostring(data[i]), data[i + 1] }
    end
  else
    for k, v in pairs(data) do
      res[#res + 1] = { tostring(k), v }
    end
  end
  return res
end

--[[[
-- @function lua_dynconf.redis.configure(section)
-- Parses Redis parameters (the `dynconf` section with a fallback to the global `redis` one) and
-- registers the write script. Must be called at configuration load time.
--]]
function exports.configure(section)
  section = section or {}
  redis_params = lua_redis.parse_redis_server('dynconf', section)
  if not redis_params then
    return false, 'no redis servers are defined for dynconf'
  end
  if section.key then
    redis_key = tostring(section.key)
  end
  set_script_id = lua_redis.add_redis_script(set_script, redis_params)
  return true
end

--[[[
-- @function lua_dynconf.redis.start(cfg, ev_base, worker)
-- Called in every worker after fork; the backend is stateless apart from the last seen version
--]]
function exports.start(_, _, _)
  last_version = '0'
  applied = {}
end

--[[[
-- @function lua_dynconf.redis.version()
-- Returns the last seen global version
--]]
function exports.version()
  return tonumber(last_version) or 0
end

--[[[
-- @function lua_dynconf.redis.holds(module)
-- Returns true if the last hash delivered to the registry holds an override for the module (whether or
-- not the registry has accepted it)
--]]
function exports.holds(module)
  return applied[module] ~= nil
end

--[[[
-- @function lua_dynconf.redis.invalidate()
-- Makes the next check fetch the whole hash even if its version has not changed
--]]
function exports.invalidate()
  last_version = '0'
end

--[[[
-- @function lua_dynconf.redis.encode_json(value)
-- Compact JSON encoder that keeps the full precision of numbers (the UCL emitter does not)
-- @return {string} JSON or `nil, error`
--]]
exports.encode_json = json.encode

-- Builds the new state without touching the real one: it is committed once the registry has accepted
-- the check result. Returns `updates` (or nil) and the new `applied` map
local function process_hash(data)
  local updates = {}
  local seen = {}
  local new_applied = {}
  local any = false

  for _, pair in ipairs(reply_pairs(data)) do
    local field, blob = pair[1], tostring(pair[2])
    if field:sub(1, #FIELD_PREFIX) == FIELD_PREFIX then
      local module = field:sub(#FIELD_PREFIX + 1)
      -- A broken blob must not look like a removed override
      seen[module] = true
      local decoded, err = decode_json(blob)
      if type(decoded) ~= 'table' or type(decoded.o) ~= 'table' then
        logger.warnx(rspamd_config, 'dynconf: invalid override for module %s in redis: %s', module,
            err or 'no override table')
        new_applied[module] = applied[module]
      else
        new_applied[module] = blob
        -- Compare the whole blob, not only the version: the content may differ at the same version
        if applied[module] ~= blob then
          updates[module] = { version = tonumber(decoded.v) or 0, values = decoded.o }
          any = true
        end
      end
    end
  end

  -- Overrides that vanished from redis must be removed
  for module in pairs(applied) do
    if not seen[module] then
      updates[module] = false
      any = true
    end
  end

  return any and updates or nil, new_applied
end

--[[[
-- @function lua_dynconf.redis.check(ev_base, cb)
-- Asynchronously compares the stored version with the last seen one; `cb(err, updates, commit)`.
-- `commit()` records the new state, the registry calls it for a result that it has accepted
--]]
function exports.check(ev_base, cb)
  if not redis_params then
    cb('redis backend is not configured')
    return
  end

  local function hget_cb(err, data, _)
    if err then
      cb(string.format('redis HGET failed: %s', err))
      return
    end

    -- A missing key is version 0, so key deletion is noticed too. The reply for a missing key is the
    -- `redis.null` sentinel, which cannot be converted to a string
    local version = '0'
    if not lua_redis.is_null(data) and data ~= '' then
      version = tostring(data)
    end

    if version == last_version then
      cb(nil, nil)
      return
    end

    lua_util.debugm(N, rspamd_config, 'redis version changed from %s to %s', last_version, version)
    local function after_fetch(ferr, fdata)
      if ferr then
        cb(string.format('redis HGETALL failed: %s', ferr))
        return
      end
      local updates, new_applied = process_hash(fdata)
      -- The registry calls this when it has accepted the result (a stale result is dropped)
      cb(nil, updates, function()
        last_version = version
        applied = new_applied
      end)
    end

    local ret = lua_redis.redis_make_request_taskless(ev_base, rspamd_config, redis_params,
        redis_key, false, after_fetch, 'HGETALL', { redis_key })
    if not ret then
      cb('cannot send redis HGETALL')
    end
  end

  local ret = lua_redis.redis_make_request_taskless(ev_base, rspamd_config, redis_params,
      redis_key, false, hget_cb, 'HGET', { redis_key, 'v' })
  if not ret then
    cb('cannot send redis HGET')
  end
end

-- Runs the write script. `expected` is the blob that the new one is based on (nil: unconditional write).
-- `cb(err, version, conflict)`
local function write_blob(ctx, module, values, expected, cb)
  local blob = ''
  if values ~= nil then
    local eerr
    blob, eerr = exports.encode_json(next(values) == nil and {} or values)
    if not blob then
      cb(string.format('cannot encode the override: %s', eerr))
      return
    end
  end

  local params = {
    is_write = true,
    key = redis_key,
  }
  if ctx and ctx.task then
    params.task = ctx.task
  else
    params.ev_base = ctx and ctx.ev_base
  end

  local function script_cb(err, data)
    if err then
      cb(string.format('redis script failed: %s', err))
      return
    end
    local version = tonumber(data)
    if version and version < 0 then
      cb(nil, nil, true)
      return
    end
    -- Remember what was written (the script builds the field in exactly this way), so that a later
    -- removal by someone else is noticed by this worker too
    if values ~= nil and version then
      applied[module] = string.format('{"v":%.0f,"o":%s}', version, blob)
    else
      applied[module] = nil
    end
    cb(nil, version)
  end

  local args = { FIELD_PREFIX .. module, blob, string.format('%.0f', math.floor(rspamd_util.get_time() * 1000)) }
  if expected ~= nil then
    args[4] = expected
  end
  lua_redis.exec_redis_script(set_script_id, params, script_cb, { redis_key }, args)
end

--[[[
-- @function lua_dynconf.redis.set(ctx, module, values, cb)
-- Atomically stores (or removes, when `values` is nil) the override of a module; `ctx` is `{ task = t }`
-- or `{ ev_base = e }`. `cb(err, version)` receives the new global version.
--]]
function exports.set(ctx, module, values, cb)
  if not redis_params or not set_script_id then
    cb('redis backend is not configured')
    return
  end

  write_blob(ctx, module, values, nil, function(err, version, conflict)
    if conflict then
      -- Cannot happen without an expected blob
      cb('unexpected conflict')
    else
      cb(err, version)
    end
  end)
end

--[[[
-- @function lua_dynconf.redis.update(ctx, module, patch, prepare, cb)
-- Changes some top-level keys of the override of a module: `patch` maps a key to its new value, or to
-- `false` to remove the key. The patch is merged with the blob that redis holds right now, not with what
-- this worker has applied, and the write succeeds only if the blob has not changed since it was read
-- (otherwise the merge is repeated, a few times). `prepare(merged)` is called with the result (nil when
-- no key is left) before every write attempt and returns `ok, error`: a refusal stops the update.
-- `cb(err, version, rejected)`; `rejected` is true if `prepare` refused.
--]]
function exports.update(ctx, module, patch, prepare, cb)
  if not redis_params or not set_script_id then
    cb('redis backend is not configured')
    return
  end

  local field = FIELD_PREFIX .. module

  local function hget(callback)
    if ctx and ctx.task then
      return lua_redis.redis_make_request(ctx.task, redis_params, redis_key, false, callback,
          'HGET', { redis_key, field })
    end
    return lua_redis.redis_make_request_taskless(ctx and ctx.ev_base, rspamd_config, redis_params,
        redis_key, false, callback, 'HGET', { redis_key, field })
  end

  local function attempt(n)
    local function hget_cb(err, data)
      if err then
        cb(string.format('redis HGET failed: %s', err))
        return
      end

      local expected = ''
      local values = {}
      if not lua_redis.is_null(data) and data ~= '' then
        expected = tostring(data)
        local decoded = decode_json(expected)
        if type(decoded) == 'table' and type(decoded.o) == 'table' then
          values = decoded.o
        end
      end
      for k, v in pairs(patch) do
        if v == false then
          values[k] = nil
        else
          values[k] = v
        end
      end
      if next(values) == nil then
        values = nil
      end

      local called, pok, perr = pcall(prepare, values)
      if not called or not pok then
        cb(called and tostring(perr or 'rejected') or tostring(pok), nil, true)
        return
      end

      write_blob(ctx, module, values, expected, function(werr, version, conflict)
        if conflict then
          if n >= UPDATE_ATTEMPTS then
            cb('the override is changed by somebody else too often')
          else
            attempt(n + 1)
          end
        else
          cb(werr, version)
        end
      end)
    end

    if not hget(hget_cb) then
      cb('cannot send redis HGET')
    end
  end

  attempt(1)
end

return exports
