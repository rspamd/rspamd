-- Lua script to perform bayes stats
-- This script accepts the following parameters:
-- key1 - current cursor
-- key2 - symbol to examine
-- key3 - learn key (e.g. learns_ham or learns_spam)
-- key4 - max users
-- key5 - (optional) category

local cursor = tonumber(KEYS[1])
local category = KEYS[5]

local ret = redis.call('SSCAN', KEYS[2] .. '_keys', cursor, 'COUNT', tonumber(KEYS[4]))

local new_cursor = tonumber(ret[1])
local nkeys = #ret[2]
local learns = 0
local learns_cat = 0
for _, key in ipairs(ret[2]) do
  learns = learns + (tonumber(redis.call('HGET', key, KEYS[3])) or 0)
  if category then
    learns_cat = learns_cat + (tonumber(redis.call('HGET', key, 'learns_' .. category)) or 0)
  end
end

return { new_cursor, nkeys, learns }