-- Checks bucket, updating it if needed
-- KEYS[1] - prefix to update, e.g. RL_<triplet>_<seconds>
-- KEYS[2] - current time in milliseconds
-- KEYS[3] - bucket leak rate (messages per millisecond)
-- KEYS[4] - bucket burst
-- KEYS[5] - expire for a bucket
-- KEYS[6] - number of recipients
-- return 1 if message should be ratelimited and 0 if not
-- Redis keys used:
--   l - last hit
--   b - current burst
--   p - pending messages (those that are currently processing)
--   dr - current dynamic rate multiplier (*10000)
--   db - current dynamic burst multiplier (*10000)

local last = redis.call('HGET', KEYS[1], 'l')
local now = tonumber(KEYS[2])
local nrcpt = tonumber(KEYS[6])
local dynr, dynb, leaked = 0, 0, 0
if not last then
  -- New bucket
  redis.call('HMSET', KEYS[1], 'l', KEYS[2], 'b', '0', 'dr', '10000', 'db', '10000', 'p', tostring(nrcpt))
  redis.call('EXPIRE', KEYS[1], KEYS[5])
  return {0, '0', '1', '1', '0'}
end

last = tonumber(last)
local burst,pending = unpack(redis.call('HMGET', KEYS[1], 'b', 'p'))
burst,pending = tonumber(burst or '0'),tonumber(pending or '0')
-- Sanity to avoid races
if burst < 0 then burst = 0 end
if pending < 0 then pending = 0 end
pending = pending + nrcpt -- this message
-- Perform leak
if burst + pending > 0 then
  if burst > 0 and last < tonumber(KEYS[2]) then
    local rate = tonumber(KEYS[3])
    dynr = tonumber(redis.call('HGET', KEYS[1], 'dr')) / 10000.0
    if dynr == 0 then dynr = 0.0001 end
    rate = rate * dynr
    leaked = ((now - last) * rate)
    if leaked > burst then leaked = burst end
    burst = burst - leaked
    redis.call('HINCRBYFLOAT', KEYS[1], 'b', -(leaked))
    redis.call('HSET', KEYS[1], 'l', KEYS[2])
  end

  dynb = tonumber(redis.call('HGET', KEYS[1], 'db')) / 10000.0
  if dynb == 0 then dynb = 0.0001 end

  burst = burst + pending
  if burst > 0 and (burst + tonumber(KEYS[6])) > tonumber(KEYS[4]) * dynb then
    return {1, tostring(burst - pending), tostring(dynr), tostring(dynb), tostring(leaked)}
  end
  -- Increase pending if we allow ratelimit
  redis.call('HINCRBY', KEYS[1], 'p', nrcpt)
else
  burst = 0
  redis.call('HMSET', KEYS[1], 'b', '0', 'p', tostring(nrcpt))
end

return {0, tostring(burst), tostring(dynr), tostring(dynb), tostring(leaked)}