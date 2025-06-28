-- Lua script to perform bayes stats
-- This script accepts the following parameters:
-- key1 - current cursor
-- key2 - symbol to examine
-- key3 - learn key (e.g. learns_ham or learns_spam)
-- key4 - max users
-- key5 - (optional) category table in message pack

local cursor = tonumber(KEYS[1])
local learn_key = KEYS[3]
local category = KEYS[5]

local category = nil

if KEYS[5] then
  category = cmsgpack.unpack(KEYS[5])
end

local symbol_keys = symbol .. '_keys'
if category then
  -- Compose deterministic suffix from the entire table (sorted keys)
  local cat_parts = {}
  for k, v in pairs(category) do
    table.insert(cat_parts, tostring(k) .. '=' .. tostring(v))
  end
  table.sort(cat_parts)
  symbol_keys = symbol_keys .. "_cat_" .. table.concat(cat_parts, "_")
end

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