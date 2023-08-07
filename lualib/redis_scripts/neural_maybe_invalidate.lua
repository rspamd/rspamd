-- Lua script to invalidate ANNs by rank
-- Uses the following keys
-- key1 - prefix for keys
-- key2 - number of elements to leave

local card = redis.call('ZCARD', KEYS[1])
local lim = tonumber(KEYS[2])
if card > lim then
  local to_delete = redis.call('ZRANGE', KEYS[1], 0, card - lim - 1)
  if to_delete then
    for _, k in ipairs(to_delete) do
      local tb = cjson.decode(k)
      if type(tb) == 'table' and type(tb.redis_key) == 'string' then
        redis.call('DEL', tb.redis_key)
        -- Also train vectors
        redis.call('DEL', tb.redis_key .. '_spam_set')
        redis.call('DEL', tb.redis_key .. '_ham_set')
      end
    end
  end
  redis.call('ZREMRANGEBYRANK', KEYS[1], 0, card - lim - 1)
  return to_delete
else
  return {}
end