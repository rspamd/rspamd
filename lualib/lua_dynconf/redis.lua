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
local set_script = [[
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

local JSON_ESCAPES = {
  ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t',
  ['\b'] = '\\b', ['\f'] = '\\f',
}

local function json_escape(c)
  return JSON_ESCAPES[c] or string.format('\\u%04x', c:byte())
end

local function encode_value(v, depth)
  local tv = type(v)
  if tv == 'string' then
    if not rspamd_util.is_valid_utf8(v) then
      error('string is not valid UTF-8')
    end
    return '"' .. (v:gsub('[%c"\\]', json_escape)) .. '"'
  elseif tv == 'number' then
    if v ~= v or v == math.huge or v == -math.huge then
      error('number is not finite')
    end
    if v == math.floor(v) and math.abs(v) < 1e15 then
      return string.format('%.0f', v)
    end
    -- ucl prints floats with 6 digits only: the shortest exact form is encoded here
    local str = string.format('%.14g', v)
    if tonumber(str) ~= v then
      str = string.format('%.17g', v)
    end
    return str
  elseif tv == 'boolean' then
    return v and 'true' or 'false'
  elseif tv ~= 'table' then
    error(string.format('values of type %s cannot be encoded', tv))
  end

  if depth > 64 then
    error('value is nested too deeply')
  end

  local n, count = #v, 0
  for _ in pairs(v) do
    count = count + 1
  end
  local parts = {}
  if n > 0 and n == count then
    for i = 1, n do
      parts[i] = encode_value(v[i], depth + 1)
    end
    return '[' .. table.concat(parts, ',') .. ']'
  end

  local keys = {}
  for k in pairs(v) do
    keys[#keys + 1] = tostring(k)
  end
  table.sort(keys)
  for _, k in ipairs(keys) do
    local val = v[k]
    if val == nil then
      val = v[tonumber(k)]
    end
    parts[#parts + 1] = encode_value(k, depth + 1) .. ':' .. encode_value(val, depth + 1)
  end
  return '{' .. table.concat(parts, ',') .. '}'
end

--[[[
-- @function lua_dynconf.redis.encode_json(value)
-- Compact JSON encoder that keeps the full precision of numbers (the UCL emitter does not)
-- @return {string} JSON or `nil, error`
--]]
function exports.encode_json(value)
  local ok, res = pcall(encode_value, value, 1)
  if not ok then
    return nil, tostring(res)
  end
  return res
end

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
    -- Remember what was written (the script builds the field in exactly this way), so that a later
    -- removal by someone else is noticed by this worker too
    if values ~= nil and version then
      applied[module] = string.format('{"v":%.0f,"o":%s}', version, blob)
    else
      applied[module] = nil
    end
    cb(nil, version)
  end

  lua_redis.exec_redis_script(set_script_id, params, script_cb, { redis_key },
      { FIELD_PREFIX .. module, blob, string.format('%.0f', math.floor(rspamd_util.get_time() * 1000)) })
end

return exports
