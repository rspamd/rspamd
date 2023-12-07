-- Lua script to perform bayes learning
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- key2 - boolean is_spam
-- key3 - string symbol
-- key4 - boolean is_unlearn
-- key5 - set of tokens encoded in messagepack array of int64_t

local prefix = KEYS[1]
local is_spam = KEYS[2] == 'true' and true or false
local symbol = KEYS[3]
local is_unlearn = KEYS[4] == 'true' and true or false
local input_tokens = cmsgpack.unpack(KEYS[5])

local prefix_underscore = prefix .. '_'
local hash_key = is_spam and 'S' or 'H'
local learned_key = is_spam and 'learns_spam' or 'learns_ham'

redis.call('SADD', symbol .. '_keys', prefix)
redis.call('HSET', prefix, 'version', '2') -- new schema
redis.call('HINCRBY', prefix, learned_key, is_unlearn and -1 or 1) -- increase or decrease learned count

for _, token in ipairs(input_tokens) do
  redis.call('HINCRBY', prefix_underscore .. tostring(token), hash_key, 1)
end