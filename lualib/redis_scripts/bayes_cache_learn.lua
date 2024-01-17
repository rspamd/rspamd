-- Lua script to perform cache checking for bayes classification
-- This script accepts the following parameters:
-- key1 - cache id
-- key3 - is spam
-- key3 - configuration table in message pack

local cache_id = KEYS[1]
local is_spam = KEYS[2]
local conf = cmsgpack.unpack(KEYS[3])
cache_id = string.sub(cache_id, 1, conf.cache_prefix_len)

-- Try each prefix that is in Redis (as some other instance might have set it)
for i = 0, conf.cache_max_keys do
  local prefix = conf.cache_prefix .. string.rep("X", i)
  local have = redis.call('HGET', prefix, cache_id)

  if have then
    -- Already in cache
    return false
  end
end

local added = false
for i = 0, conf.cache_max_keys do
  if not added then
    local prefix = conf.cache_prefix .. string.rep("X", i)
    local count = redis.call('HLEN', prefix)

    if count < conf.cache_max_elt then
      -- We can add it to this prefix
      redis.call('HSET', prefix, cache_id, is_spam)
      added = true
    end
  end
end

if not added then
  -- Need to expire some keys
  for i = 0, conf.cache_max_keys do
    local prefix = conf.cache_prefix .. string.rep("X", i)
    local exists = redis.call('EXISTS', prefix)

    if exists then
      redis.call('DEL', prefix)
      redis.call('HSET', prefix, cache_id, is_spam)

      -- Do not expire anything else
      return true
    end
  end
end

return true