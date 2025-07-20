-- Lua script to perform cache checking for bayes classification (multi-class)
-- This script accepts the following parameters:
-- key1 - cache id
-- key2 - class name (e.g. "spam", "ham", "transactional")
-- key3 - configuration table in message pack

local cache_id = KEYS[1]
local class_name = KEYS[2]
local conf = cmsgpack.unpack(KEYS[3])

-- Handle backward compatibility for binary values
if class_name == "1" then
  class_name = "spam"
elseif class_name == "0" then
  class_name = "ham"
end
cache_id = string.sub(cache_id, 1, conf.cache_elt_len)

-- Try each prefix that is in Redis (as some other instance might have set it)
for i = 0, conf.cache_max_keys do
  local prefix = conf.cache_prefix .. string.rep("X", i)
  local have = redis.call('HGET', prefix, cache_id)

  if have then
    -- Already in cache, but class_name changes when relearning
    redis.call('HSET', prefix, cache_id, class_name)
    return false
  end
end

local added = false
local lim = conf.cache_max_elt
for i = 0, conf.cache_max_keys do
  if not added then
    local prefix = conf.cache_prefix .. string.rep("X", i)
    local count = redis.call('HLEN', prefix)

    if count < lim then
      -- We can add it to this prefix
      redis.call('HSET', prefix, cache_id, class_name)
      added = true
    end
  end
end

if not added then
  -- Need to expire some keys
  local expired = false
  for i = 0, conf.cache_max_keys do
    local prefix = conf.cache_prefix .. string.rep("X", i)
    local exists = redis.call('EXISTS', prefix)

    if exists then
      if not expired then
        redis.call('DEL', prefix)
        redis.call('HSET', prefix, cache_id, class_name)

        -- Do not expire anything else
        expired = true
      elseif i > 0 then
        -- Move key to a shorter prefix, so we will rotate them eventually from lower to upper
        local new_prefix = conf.cache_prefix .. string.rep("X", i - 1)
        redis.call('RENAME', prefix, new_prefix)
      end
    end
  end
end

return true
