--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2026, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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

--[[[
-- @module lua_greylist
-- Lets other modules ask the greylist plugin to delay the current message
-- and encodes the greylist records stored in Redis.
--]]

local exports = {}
local cache_key = 'lua_greylist_requests'

local function requests(task)
  local pending = task:cache_get(cache_key)
  if not pending then
    pending = {}
    task:cache_set(cache_key, pending)
  end
  return pending
end

--[[[
-- @function lua_greylist.request(task, options)
-- Request a delay of at least `options.body` and/or `options.meta` seconds for the
-- message body / envelope, attributed to `options.module`. Applies regardless of
-- the score, but whitelists, authed/local senders and pre-results still skip it.
-- Raises an error on invalid options. The longest request per scope wins.
--]]
function exports.request(task, options)
  assert(type(options) == 'table', 'greylist request must be a table')
  assert(type(options.module) == 'string' and options.module ~= '', 'greylist module is required')
  assert(options.body ~= nil or options.meta ~= nil, 'greylist scope is required')
  for _, scope in ipairs({ 'body', 'meta' }) do
    local duration = options[scope]
    if duration ~= nil then
      assert(type(duration) == 'number' and duration > 0 and duration < math.huge,
          'greylist duration must be finite and positive')
    end
  end
  local pending = requests(task)
  for _, scope in ipairs({ 'body', 'meta' }) do
    local duration = options[scope]
    if duration then
      local current = pending[scope]
      if not current or duration > current.timeout then
        pending[scope] = { timeout = duration, module = options.module }
      elseif duration == current.timeout and options.module < current.module then
        current.module = options.module
      end
    end
  end
end

--[[[
-- @function lua_greylist.request_classic(task)
-- Force classic greylisting (global timeout), still subject to the score gate
--]]
function exports.request_classic(task)
  requests(task).classic = true
end

--[[[
-- @function lua_greylist.get_requests(task)
-- @return {table} requests of the task: `body`, `meta` ({timeout, module}) and `classic`
--]]
function exports.get_requests(task)
  return task:cache_get(cache_key) or {}
end

-- Records are either a plain timestamp (classic) or `timestamp:timeout:!module` (explicit)
function exports.decode_record(value, default_timeout)
  local text = tostring(value)
  local timestamp, duration, module = text:match('^(%-?%d+):(%d+):!(.*)$')
  local explicit = timestamp ~= nil
  timestamp = tonumber(timestamp or text)
  if not timestamp then
    return nil
  end
  return {
    timestamp = timestamp,
    timeout = math.max(default_timeout, tonumber(duration) or 0),
    module = module,
    explicit = explicit,
  }
end

function exports.encode_record(record)
  local value = tostring(record.timestamp)
  if record.explicit then
    local module = (record.module or ''):gsub('[^%w_%.%-]', '')
    value = value .. ':' .. tostring(record.timeout) .. ':!' .. module
  end
  return value
end

local function requested_timeout(record, request, default_timeout)
  return math.ceil(math.max(default_timeout, request.timeout, record and record.timeout or 0))
end

function exports.record_pending(record, now)
  return record ~= nil and now < record.timestamp + record.timeout
end

function exports.request_satisfied(record, request, default_timeout, now)
  if not request then
    return true
  end
  return record ~= nil and now >= record.timestamp + requested_timeout(record, request, default_timeout)
end

function exports.plan_record(record, request, default_timeout, expire, now)
  local timestamp = record and record.timestamp or math.floor(now)
  local timeout = request and requested_timeout(record, request, default_timeout) or default_timeout
  local ttl = math.floor(expire)
  -- keep the record past its deadline so the retry can still be matched
  if timeout >= ttl then
    ttl = timeout + ttl
  end
  return {
    timestamp = timestamp,
    timeout = timeout,
    module = request and request.module or nil,
    explicit = request ~= nil,
    expire = ttl,
    deadline = timestamp + timeout,
  }
end

return exports
