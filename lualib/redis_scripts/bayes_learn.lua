-- Lua script to perform bayes learning
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- key2 - boolean is_spam
-- key3 - string symbol
-- key4 - boolean is_unlearn
-- key5 - set of tokens encoded in messagepack array of strings
-- key6 - set of text tokens (if any) encoded in messagepack array of strings (size must be twice of `KEYS[5]`)

local prefix = KEYS[1]
local is_spam = KEYS[2] == 'true' and true or false
local symbol = KEYS[3]
local is_unlearn = KEYS[4] == 'true' and true or false
local input_tokens = cmsgpack.unpack(KEYS[5])
local text_tokens

if KEYS[6] then
  text_tokens = cmsgpack.unpack(KEYS[6])
end

local hash_key = is_spam and 'S' or 'H'
local learned_key = is_spam and 'learns_spam' or 'learns_ham'

redis.call('SADD', symbol .. '_keys', prefix)
redis.call('HSET', prefix, 'version', '2') -- new schema
redis.call('HINCRBY', prefix, learned_key, is_unlearn and -1 or 1) -- increase or decrease learned count

for i, token in ipairs(input_tokens) do
  redis.call('HINCRBY', token, hash_key, 1)
  if text_tokens then
    local tok1 = text_tokens[i * 2 - 1]
    local tok2 = text_tokens[i * 2]

    if tok1 then
      if tok2 then
        redis.call('HSET', token, 'tokens', string.format('%s:%s', tok1, tok2))
      else
        redis.call('HSET', token, 'tokens', tok1)
      end

      redis.call('ZINCRBY', prefix .. '_z', token, is_unlearn and -1 or 1)
    end
  end
end