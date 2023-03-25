-- Updates a bucket
-- KEYS[1] - prefix to update, e.g. RL_<triplet>_<seconds>
-- KEYS[2] - current time in milliseconds
-- KEYS[3] - dynamic rate multiplier
-- KEYS[4] - dynamic burst multiplier
-- KEYS[5] - max dyn rate (min: 1/x)
-- KEYS[6] - max burst rate (min: 1/x)
-- KEYS[7] - expire for a bucket
-- KEYS[8] - number of recipients (or increase rate)
-- Redis keys used:
--   l - last hit
--   b - current burst
--   p - messages pending (must be decreased by 1)
--   dr - current dynamic rate multiplier
--   db - current dynamic burst multiplier
local prefix = KEYS[1]
local last = redis.call('HGET', prefix, 'l')
local now = tonumber(KEYS[2])
local nrcpt = tonumber(KEYS[8])
if not last then
  -- New bucket (why??)
  redis.call('HMSET', prefix, 'l', tostring(now), 'b', tostring(nrcpt), 'dr', '10000', 'db', '10000', 'p', '0')
  redis.call('EXPIRE', prefix, KEYS[7])
  return {1, 1, 1}
end

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

local burst,pending = unpack(redis.call('HMGET', prefix, 'b', 'p'))
burst,pending = tonumber(burst or '0'),tonumber(pending or '0')
if burst < 0 then burst = nrcpt else burst = burst + nrcpt end
if pending < nrcpt then pending = 0 else pending = pending - nrcpt end

redis.call('HMSET', prefix, 'b', tostring(burst), 'p', tostring(pending), 'l', KEYS[2])
redis.call('EXPIRE', prefix, KEYS[7])

return {tostring(burst), tostring(dr), tostring(db)}