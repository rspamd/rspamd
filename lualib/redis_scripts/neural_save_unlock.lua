-- Lua script to save and unlock ANN in redis
-- Uses the following keys and argv
-- key1 - prefix for ANN
-- key2 - prefix for profile
-- key3 - old key
-- argv1 - compressed ANN
-- argv2 - profile as JSON
-- argv3 - expire in seconds
-- argv4 - current time
-- argv5 - ROC Thresholds
-- argv6 - optional PCA
-- argv7 - optional providers_meta (JSON)
-- argv8 - optional norm_stats (JSON)
local now = tonumber(ARGV[4])
redis.call('ZADD', KEYS[2], now, ARGV[2])
redis.call('HSET', KEYS[1], 'ann', ARGV[1])
redis.call('HSET', KEYS[1], 'roc_thresholds', ARGV[5])
if ARGV[6] and ARGV[6] ~= '' then
  redis.call('HSET', KEYS[1], 'pca', ARGV[6])
end
if ARGV[7] and ARGV[7] ~= '' then
  redis.call('HSET', KEYS[1], 'providers_meta', ARGV[7])
end
if ARGV[8] and ARGV[8] ~= '' then
  redis.call('HSET', KEYS[1], 'norm_stats', ARGV[8])
end
redis.call('HDEL', KEYS[1], 'lock')
redis.call('HDEL', KEYS[3], 'lock')
redis.call('HSET', KEYS[3], 'obsolete', '1')
redis.call('EXPIRE', KEYS[3], 600)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
-- expire in 10m, to not face race condition with other rspamd replicas refill deleted keys
redis.call('EXPIRE', KEYS[3] .. '_spam_set', 600)
redis.call('EXPIRE', KEYS[3] .. '_ham_set', 600)
return 1
