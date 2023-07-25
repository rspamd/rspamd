-- This script cleans up the pending requests in Redis.

-- KEYS: Input parameters
-- KEYS[1] - prefix: The Redis key prefix used to store the bucket information.
-- KEYS[2] - now: The current time in milliseconds.
-- KEYS[3] - expire: The expiration time for the Redis key storing the bucket information, in seconds.
-- KEYS[4] - number_of_recipients: The number of requests to be allowed (or the increase rate).

-- 1. Retrieve the last hit time and initialize variables
local prefix = KEYS[1]
local last = redis.call('HGET', prefix, 'l')
local nrcpt = tonumber(KEYS[4])
if not last then
  -- No bucket, no cleanup
  return 0
end


-- 2. Update the pending values based on the number of recipients (requests)
local pending = redis.call('HGET', prefix, 'p')
pending = tonumber(pending or '0')
if pending < nrcpt then pending = 0 else pending = pending - nrcpt end

-- 3. Set the updated values back to Redis and update the expiration time for the bucket
redis.call('HMSET', prefix, 'p', tostring(pending), 'l', KEYS[2])
redis.call('EXPIRE', prefix, KEYS[3])

-- 4. Return the updated pending value
return pending