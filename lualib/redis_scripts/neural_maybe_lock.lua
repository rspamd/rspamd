-- Lua script lock ANN for learning
-- Uses the following keys
-- key1 - prefix for keys
-- key2 - current time
-- key3 - key expire
-- key4 - hostname

local locked = redis.call('HGET', KEYS[1], 'lock')
local now = tonumber(KEYS[2])
if locked then
  locked = tonumber(locked)
  local expire = tonumber(KEYS[3])
  if now > locked and (now - locked) < expire then
    return { tostring(locked), redis.call('HGET', KEYS[1], 'hostname') or 'unknown' }
  end
end
redis.call('HSET', KEYS[1], 'lock', tostring(now))
redis.call('HSET', KEYS[1], 'hostname', KEYS[4])
return 1