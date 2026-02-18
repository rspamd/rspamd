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

-- Fuzzy hash update script (per-hash, atomic)
-- Handles ADD, DEL, and REFRESH operations including multi-flag merge and shingles
--
-- KEYS[1] = hash_key (prefix + digest)
-- KEYS[2] = operation: "add", "del", "refresh"
-- KEYS[3] = flag (string number)
-- KEYS[4] = value (string number)
-- KEYS[5] = expire (string number, seconds)
-- KEYS[6] = timestamp (string number, calendar seconds)
-- KEYS[7] = is_weak ("0" or "1")
-- KEYS[8] = count_key (prefix .. "_count")
-- KEYS[9] = digest (raw bytes, used as value for shingle SETEX)
-- KEYS[10..] = shingle keys (0 or 32 of them)

local key = KEYS[1]
local op = KEYS[2]
local new_flag = tonumber(KEYS[3])
local new_value = tonumber(KEYS[4])
local expire = tonumber(KEYS[5])
local timestamp = KEYS[6]
local is_weak = tonumber(KEYS[7])
local count_key = KEYS[8]
local digest = KEYS[9]

if op == "add" then
  -- Multi-flag merge logic: up to 8 flag slots (primary '' + extra '1'..'7')
  local data = redis.call('HGETALL', key)
  local fields = {}
  for i = 1, #data, 2 do
    fields[data[i]] = data[i+1]
  end

  local slots = {}
  local n_slots = 0

  -- Check primary slot
  if fields['V'] and fields['F'] then
    slots[''] = {flag=tonumber(fields['F']), value=tonumber(fields['V'])}
    n_slots = n_slots + 1
  end
  -- Check extra slots 1..7
  for i = 1, 7 do
    local si = tostring(i)
    if fields['V'..si] and fields['F'..si] then
      slots[si] = {flag=tonumber(fields['F'..si]), value=tonumber(fields['V'..si])}
      n_slots = n_slots + 1
    end
  end

  -- Try to find existing slot with same flag
  local found_slot = nil
  for slot, entry in pairs(slots) do
    if entry.flag == new_flag then
      found_slot = slot
      break
    end
  end

  if found_slot then
    -- Increment existing slot value
    redis.call('HINCRBY', key, 'V'..found_slot, new_value)
  elseif n_slots == 0 then
    -- Empty hash: create primary slot
    if is_weak == 1 then
      redis.call('HSETNX', key, 'F', new_flag)
      redis.call('HSETNX', key, 'V', new_value)
    else
      redis.call('HSET', key, 'F', new_flag, 'V', new_value)
    end
    slots[''] = {flag=new_flag, value=new_value}
    n_slots = 1
  elseif n_slots < 8 then
    -- Find an empty slot and use it
    local empty_slot = nil
    if not slots[''] then
      empty_slot = ''
    else
      for i = 1, 7 do
        if not slots[tostring(i)] then
          empty_slot = tostring(i)
          break
        end
      end
    end
    if empty_slot then
      redis.call('HSET', key, 'F'..empty_slot, new_flag, 'V'..empty_slot, new_value)
      slots[empty_slot] = {flag=new_flag, value=new_value}
      n_slots = n_slots + 1
    end
  else
    -- All 8 slots full: replace the minimum-value slot if new_value is larger
    if is_weak == 0 then
      local min_slot = nil
      local min_val = nil
      for slot, entry in pairs(slots) do
        if min_val == nil or entry.value < min_val then
          min_val = entry.value
          min_slot = slot
        end
      end
      if min_val ~= nil and new_value > min_val then
        redis.call('HSET', key, 'F'..min_slot, new_flag, 'V'..min_slot, new_value)
        slots[min_slot] = {flag=new_flag, value=new_value}
      end
    end
  end

  -- Ensure primary slot has the highest value (swap if needed)
  if n_slots > 1 then
    local max_val = nil
    local max_slot = nil
    for slot, _ in pairs(slots) do
      local v = tonumber(redis.call('HGET', key, 'V'..slot) or '0')
      if max_val == nil or v > max_val then
        max_val = v
        max_slot = slot
      end
    end
    if max_slot ~= nil and max_slot ~= '' and slots[''] then
      local pv = redis.call('HGET', key, 'V')
      local pf = redis.call('HGET', key, 'F')
      local bv = redis.call('HGET', key, 'V'..max_slot)
      local bf = redis.call('HGET', key, 'F'..max_slot)
      redis.call('HSET', key, 'V', bv, 'F', bf)
      redis.call('HSET', key, 'V'..max_slot, pv, 'F'..max_slot, pf)
    end
  end

  redis.call('HSETNX', key, 'C', timestamp)
  redis.call('EXPIRE', key, expire)
  redis.call('INCR', count_key)

  -- Handle shingles: SETEX each shingle key with expire and digest as value
  for i = 10, #KEYS do
    redis.call('SETEX', KEYS[i], expire, digest)
  end

elseif op == "del" then
  redis.call('DEL', key)
  redis.call('DECR', count_key)

  for i = 10, #KEYS do
    redis.call('DEL', KEYS[i])
  end

elseif op == "refresh" then
  redis.call('EXPIRE', key, expire)

  for i = 10, #KEYS do
    redis.call('EXPIRE', KEYS[i], expire)
  end
end

return 1
