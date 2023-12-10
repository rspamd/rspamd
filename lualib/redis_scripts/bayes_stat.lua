-- Lua script to perform bayes stats
-- This script accepts the following parameters:
-- key1 - current cursor
-- key2 - symbol to examine
-- key3 - learn key (e.g. learns_ham or learns_spam)
-- key4 - max users

local cursor = tonumber(KEYS[1])

local ret = redis.call('SSCAN', KEYS[2] .. '_keys', cursor, 'COUNT', tonumber(KEYS[4]))

local new_cursor = tonumber(ret[1])
local nkeys = #ret[2]
local learns = 0
for _, key in ipairs(ret[2]) do
  learns = learns + (tonumber(redis.call('HGET', key, KEYS[3])) or 0)
end

return { new_cursor, nkeys, learns }