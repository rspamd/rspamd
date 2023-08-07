-- This script updates a token bucket rate limiter with dynamic rate and burst multipliers in Redis.

-- KEYS: Input parameters
-- KEYS[1] - prefix: The Redis key prefix used to store the bucket information.
-- KEYS[2] - now: The current time in milliseconds.
-- KEYS[3] - dynamic_rate_multiplier: A multiplier to adjust the rate limit dynamically.
-- KEYS[4] - dynamic_burst_multiplier: A multiplier to adjust the burst limit dynamically.
-- KEYS[5] - max_dyn_rate: The maximum allowed value for the dynamic rate multiplier.
-- KEYS[6] - max_burst_rate: The maximum allowed value for the dynamic burst multiplier.
-- KEYS[7] - expire: The expiration time for the Redis key storing the bucket information, in seconds.
-- KEYS[8] - number_of_recipients: The number of requests to be allowed (or the increase rate).

-- 1. Retrieve the last hit time and initialize variables
local prefix = KEYS[1]
local last = redis.call('HGET', prefix, 'l')
local now = tonumber(KEYS[2])
local nrcpt = tonumber(KEYS[8])
if not last then
  -- 2. Initialize a new bucket if the last hit time is not found (must not happen)
  redis.call('HMSET', prefix, 'l', tostring(now), 'b', tostring(nrcpt), 'dr', '10000', 'db', '10000', 'p', '0')
  redis.call('EXPIRE', prefix, KEYS[7])
  return { 1, 1, 1 }
end

-- 3. Update the dynamic rate multiplier based on input parameters
local dr, db = 1.0, 1.0

local max_dr = tonumber(KEYS[5])

if max_dr > 1 then
  local rate_mult = tonumber(KEYS[3])
  dr = tonumber(redis.call('HGET', prefix, 'dr')) / 10000

  if rate_mult > 1.0 and dr < max_dr then
    dr = dr * rate_mult
    if dr > 0.0001 then
      redis.call('HSET', prefix, 'dr', tostring(math.floor(dr * 10000)))
    else
      redis.call('HSET', prefix, 'dr', '1')
    end
  elseif rate_mult < 1.0 and dr > (1.0 / max_dr) then
    dr = dr * rate_mult
    if dr > 0.0001 then
      redis.call('HSET', prefix, 'dr', tostring(math.floor(dr * 10000)))
    else
      redis.call('HSET', prefix, 'dr', '1')
    end
  end
end

-- 4. Update the dynamic burst multiplier based on input parameters
local max_db = tonumber(KEYS[6])
if max_db > 1 then
  local rate_mult = tonumber(KEYS[4])
  db = tonumber(redis.call('HGET', prefix, 'db')) / 10000

  if rate_mult > 1.0 and db < max_db then
    db = db * rate_mult
    if db > 0.0001 then
      redis.call('HSET', prefix, 'db', tostring(math.floor(db * 10000)))
    else
      redis.call('HSET', prefix, 'db', '1')
    end
  elseif rate_mult < 1.0 and db > (1.0 / max_db) then
    db = db * rate_mult
    if db > 0.0001 then
      redis.call('HSET', prefix, 'db', tostring(math.floor(db * 10000)))
    else
      redis.call('HSET', prefix, 'db', '1')
    end
  end
end

-- 5. Update the burst and pending values based on the number of recipients (requests)
local burst, pending = unpack(redis.call('HMGET', prefix, 'b', 'p'))
burst, pending = tonumber(burst or '0'), tonumber(pending or '0')
if burst < 0 then
  burst = nrcpt
else
  burst = burst + nrcpt
end
if pending < nrcpt then
  pending = 0
else
  pending = pending - nrcpt
end

-- 6. Set the updated values back to Redis and update the expiration time for the bucket
redis.call('HMSET', prefix, 'b', tostring(burst), 'p', tostring(pending), 'l', KEYS[2])
redis.call('EXPIRE', prefix, KEYS[7])

-- 7. Return the updated burst value, dynamic rate multiplier, and dynamic burst multiplier
return { tostring(burst), tostring(dr), tostring(db) }