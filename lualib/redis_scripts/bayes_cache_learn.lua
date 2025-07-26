-- Lua script to perform cache checking for bayes classification (multi-class)
-- This script accepts the following parameters:
-- key1 - cache id
-- key2 - class name (e.g. "spam", "ham", "transactional")
-- key3 - configuration table in message pack

local cache_id = KEYS[1]
local class_name = KEYS[2]
local conf = cmsgpack.unpack(KEYS[3])

-- Convert class names to numeric cache values for consistency
local cache_value
if class_name == "1" or class_name == "spam" or class_name == "S" then
  cache_value = "1" -- spam
elseif class_name == "0" or class_name == "ham" or class_name == "H" then
  cache_value = "0" -- ham
else
  -- For other classes, use a simple hash to get a consistent numeric value
  -- This ensures cache check can return a number while preserving class info
  local hash = 0
  for i = 1, #class_name do
    hash = hash + string.byte(class_name, i)
  end
  cache_value = tostring(2 + (hash % 1000)) -- Start from 2, avoid 0/1
end
cache_id = string.sub(cache_id, 1, conf.cache_elt_len)

-- Try each prefix that is in Redis (as some other instance might have set it)
for i = 0, conf.cache_max_keys do
  local prefix = conf.cache_prefix .. string.rep("X", i)
  local have = redis.call('HGET', prefix, cache_id)

  if have then
    -- Already in cache, but cache_value changes when relearning
    redis.call('HSET', prefix, cache_id, cache_value)
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
      redis.call('HSET', prefix, cache_id, cache_value)
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
        redis.call('HSET', prefix, cache_id, cache_value)

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
