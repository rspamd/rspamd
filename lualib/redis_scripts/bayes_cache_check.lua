-- Lua script to perform cache checking for bayes classification
-- This script accepts the following parameters:
-- key1 - cache id
-- key2 - configuration table in message pack
-- key3 - (optional) category table in message pack

local cache_id = KEYS[1]
local conf = cmsgpack.unpack(KEYS[2])
local category = nil
if KEYS[3] then
  category = cmsgpack.unpack(KEYS[3])
end
cache_id = string.sub(cache_id, 1, conf.cache_elt_len)

local prefix_base = conf.cache_prefix

if category then
  -- Compose a deterministic string from the category table
  local cat_parts = {}
  for k, v in pairs(category) do
    table.insert(cat_parts, tostring(k) .. '=' .. tostring(v))
  end
  table.sort(cat_parts)
  prefix_base = prefix_base .. "_cat_" .. table.concat(cat_parts, "_")
end

-- Try each prefix that is in Redis
for i = 0, conf.cache_max_keys do
  local prefix = conf.cache_prefix .. string.rep("X", i)
  local have = redis.call('HGET', prefix, cache_id)

  if have then
    return tonumber(have)
  end
end

return nil
