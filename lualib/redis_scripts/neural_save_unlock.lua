-- Lua script to save and unlock ANN in redis
-- Uses the following keys
-- key1 - prefix for ANN
-- key2 - prefix for profile
-- key3 - compressed ANN
-- key4 - profile as JSON
-- key5 - expire in seconds
-- key6 - current time
-- key7 - old key
-- key8 - ROC Thresholds
-- key9 - optional PCA
local now = tonumber(KEYS[6])
redis.call('ZADD', KEYS[2], now, KEYS[4])
redis.call('HSET', KEYS[1], 'ann', KEYS[3])
redis.call('DEL', KEYS[1] .. '_spam_set')
redis.call('DEL', KEYS[1] .. '_ham_set')
redis.call('HDEL', KEYS[1], 'lock')
redis.call('HDEL', KEYS[7], 'lock')
redis.call('EXPIRE', KEYS[1], tonumber(KEYS[5]))
redis.call('HSET', KEYS[1], 'roc_thresholds', KEYS[8])
if KEYS[9] then
  redis.call('HSET', KEYS[1], 'pca', KEYS[9])
end
return 1