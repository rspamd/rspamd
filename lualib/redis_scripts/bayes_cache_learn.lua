-- Lua script to perform cache learning for bayes classification (multi-class)
-- This script accepts the following parameters:
-- key1 - cache id
-- argv1 - class name string (e.g. "spam", "ham", "transactional")
-- argv2 - configuration table in message pack
--
-- The cache value stored in Redis is the class name string.  A numeric class_id
-- hash was used previously, but uint64_t values > 2^53 lose precision when
-- round-tripped through Lua doubles, so the equality check on retrieval was
-- unreliable for arbitrary multiclass names.

local cache_id = KEYS[1]
local class_name = ARGV[1]
local conf = cmsgpack.unpack(ARGV[2])

-- Store the class name directly as the cache value
local cache_value = class_name
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
