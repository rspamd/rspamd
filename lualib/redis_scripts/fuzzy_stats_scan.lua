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

-- One batch of the fuzzy hashes count scan with sampled content statistics
-- (see lua_fuzzy_redis.lua). Read-only: no shebang on purpose, so the script
-- also runs on replicas of any Redis version.
--
-- Digests matched by the SCAN are counted; every N-th of them (chosen by the
-- last two digest bytes, so the sample is stable across resumed passes) is
-- read and aggregated, and only the aggregates are returned.
--
-- ARGV[1] = cursor
-- ARGV[2] = MATCH pattern (digest keys only)
-- ARGV[3] = COUNT hint
-- ARGV[4] = sample every N-th digest (1 = every one)
-- ARGV[5] = now (calendar seconds), for age buckets
--
-- Reply: { cursor, found, sampled, multi_flag, shingled, shingle_slots,
--          age_1d, age_7d, age_30d, age_older, flag, count, sum, max, ... }

local cursor = ARGV[1]
local pattern = ARGV[2]
local count = ARGV[3]
local sample = tonumber(ARGV[4]) or 1
local now = tonumber(ARGV[5]) or 0

local fields = { 'F', 'V', 'C', 'S' }
for i = 1, 7 do
  fields[#fields + 1] = 'F' .. i
  fields[#fields + 1] = 'V' .. i
end

local res = redis.call('SCAN', cursor, 'MATCH', pattern, 'COUNT', count)
local keys = res[2]

local sampled, multi_flag, shingled, shingle_slots = 0, 0, 0, 0
local ages = { 0, 0, 0, 0 }
local flags = {}
local flags_order = {}

for _, key in ipairs(keys) do
  local b1, b2 = string.byte(key, -2, -1)
  local selected = sample <= 1 or (b1 and ((b1 * 256 + b2) % sample == 0))

  if selected then
    local data = redis.call('HMGET', key, unpack(fields))

    if data[1] then
      sampled = sampled + 1
      local nflags = 0

      for slot = 0, 7 do
        local f, v
        if slot == 0 then
          f, v = data[1], data[2]
        else
          f, v = data[3 + slot * 2], data[4 + slot * 2]
        end

        if f and v then
          nflags = nflags + 1
          local fl = flags[f]
          v = tonumber(v) or 0

          if not fl then
            fl = { count = 0, sum = 0, max = v }
            flags[f] = fl
            flags_order[#flags_order + 1] = f
          end

          fl.count = fl.count + 1
          fl.sum = fl.sum + v
          if v > fl.max then
            fl.max = v
          end
        end
      end

      if nflags > 1 then
        multi_flag = multi_flag + 1
      end

      if data[4] then
        shingled = shingled + 1
        local _, n = string.gsub(data[4], ',', '')
        shingle_slots = shingle_slots + n + 1
      end

      local created = tonumber(data[3])
      if created and now > 0 then
        local age = now - created
        if age < 86400 then
          ages[1] = ages[1] + 1
        elseif age < 7 * 86400 then
          ages[2] = ages[2] + 1
        elseif age < 30 * 86400 then
          ages[3] = ages[3] + 1
        else
          ages[4] = ages[4] + 1
        end
      end
    end
  end
end

local reply = { res[1], #keys, sampled, multi_flag, shingled, shingle_slots,
                ages[1], ages[2], ages[3], ages[4] }

for _, f in ipairs(flags_order) do
  local fl = flags[f]
  reply[#reply + 1] = f
  reply[#reply + 1] = fl.count
  reply[#reply + 1] = fl.sum
  reply[#reply + 1] = fl.max
end

return reply
