-- Lua script to perform cache checking for bayes classification
-- This script accepts the following parameters:
-- key1 - cache id
-- key2 - configuration table in message pack
-- key3 - (optional) category table in message pack

local cache_id = KEYS[1]
local conf = cmsgpack.unpack(KEYS[2])
local category = KEYS[3] and cmsgpack.unpack(KEYS[3]) or nil
cache_id = string.sub(cache_id, 1, conf.cache_elt_len)

-- Try each prefix that is in Redis
for i = 0, conf.cache_max_keys do
  local prefix
  if category then
    prefix = 'cat_' .. category.id .. '_' .. conf.cache_prefix .. string.rep("X", i)
  else
    prefix = conf.cache_prefix .. string.rep("X", i)
  end
  local have = redis.call('HGET', prefix, cache_id)

  if have then
    return tonumber(have)
  end
end

return nil
