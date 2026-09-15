-- Copyright 2026 Vsevolod Stakhov
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Coordination of the periodic fuzzy hashes count scan (see lua_fuzzy_redis.lua)
-- The keyspace itself is scanned by the client, possibly on a replica; this
-- script only owns the lock, the resumable progress and the published count
--
-- KEYS[1] = lock key (prefix .. "_count_scan_lock")
-- KEYS[2] = state hash (prefix .. "_count_scan")
-- KEYS[3] = count key (prefix .. "_count")
-- ARGV[1] = operation: "start", "checkpoint", "finish", "release"
-- ARGV[2] = owner token
-- ARGV[3] = lock ttl (seconds)
-- ARGV[4] = now (calendar seconds)
--
-- start:      ARGV[5] = interval between passes, ARGV[6] = progress stale age
-- checkpoint: ARGV[5] = upstream, ARGV[6] = server, ARGV[7] = cursor,
--             ARGV[8] = found, ARGV[9] = batches, ARGV[10] = started
-- finish:     ARGV[5] = upstream, ARGV[6] = server, ARGV[7] = found,
--             ARGV[8] = batches, ARGV[9] = duration

local lock_key = KEYS[1]
local state_key = KEYS[2]
local count_key = KEYS[3]
local op = ARGV[1]
local token = ARGV[2]
local lock_ttl = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local progress_fields = { 'upstream', 'server', 'cursor', 'found', 'batches', 'started', 'updated' }

local function owns_lock()
  return redis.call('GET', lock_key) == token
end

if op == 'start' then
  local interval = tonumber(ARGV[5])
  local stale_age = tonumber(ARGV[6])
  local data = redis.call('HGETALL', state_key)
  local st = {}
  for i = 1, #data, 2 do
    st[data[i]] = data[i + 1]
  end

  local updated = tonumber(st['updated'])
  local in_progress = st['cursor'] ~= nil and updated ~= nil and (now - updated) <= stale_age

  if not in_progress then
    local remain = (tonumber(st['last_done']) or 0) + interval - now
    if remain > 0 then
      return { 'wait', tostring(remain) }
    end
  end

  -- The owner token is stable per host, so a restarted worker takes its
  -- own lock over without waiting for it to expire
  local holder = redis.call('GET', lock_key)
  if holder and holder ~= token then
    return { 'locked', tostring(redis.call('TTL', lock_key)) }
  end

  redis.call('SET', lock_key, token, 'EX', lock_ttl)

  if in_progress then
    return { 'resume', st['upstream'] or '', st['server'] or '', st['cursor'],
             st['found'] or '0', st['batches'] or '0', st['started'] or tostring(now) }
  end

  redis.call('HDEL', state_key, unpack(progress_fields))

  return { 'fresh' }
elseif op == 'checkpoint' then
  if not owns_lock() then
    return 0
  end

  redis.call('EXPIRE', lock_key, lock_ttl)
  redis.call('HSET', state_key,
      'upstream', ARGV[5],
      'server', ARGV[6],
      'cursor', ARGV[7],
      'found', ARGV[8],
      'batches', ARGV[9],
      'started', ARGV[10],
      'updated', ARGV[4])

  return 1
elseif op == 'finish' then
  if not owns_lock() then
    return 0
  end

  redis.call('SET', count_key, ARGV[7])
  redis.call('HDEL', state_key, unpack(progress_fields))
  redis.call('HSET', state_key,
      'last_done', ARGV[4],
      'last_upstream', ARGV[5],
      'last_server', ARGV[6],
      'last_count', ARGV[7],
      'last_batches', ARGV[8],
      'last_duration', ARGV[9])
  redis.call('DEL', lock_key)

  return 1
elseif op == 'release' then
  -- Progress is kept, so the next pass resumes from the last checkpoint
  if owns_lock() then
    redis.call('DEL', lock_key)
  end

  return 1
end

return redis.error_reply('invalid operation: ' .. tostring(op))
