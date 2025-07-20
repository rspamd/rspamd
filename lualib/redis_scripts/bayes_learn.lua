-- Lua script to perform bayes learning (multi-class)
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- key2 - class label string (e.g. "S", "H", "T")
-- key3 - string symbol
-- key4 - boolean is_unlearn
-- key5 - set of tokens encoded in messagepack array of strings
-- key6 - set of text tokens (if any) encoded in messagepack array of strings (size must be twice of `KEYS[5]`)

local prefix = KEYS[1]
local class_label = KEYS[2]
local symbol = KEYS[3]
local is_unlearn = KEYS[4] == 'true' and true or false
local input_tokens = cmsgpack.unpack(KEYS[5])
local text_tokens

if KEYS[6] then
  text_tokens = cmsgpack.unpack(KEYS[6])
end

-- Handle backward compatibility for boolean values
if class_label == 'true' then
  class_label = 'S' -- spam
elseif class_label == 'false' then
  class_label = 'H' -- ham
end

local hash_key = class_label
local learned_key = 'learns_' .. string.lower(class_label)

-- Handle legacy keys for backward compatibility
if class_label == 'S' then
  learned_key = 'learns_spam'
elseif class_label == 'H' then
  learned_key = 'learns_ham'
end

redis.call('SADD', symbol .. '_keys', prefix)
redis.call('HSET', prefix, 'version', '2')                         -- new schema
redis.call('HINCRBY', prefix, learned_key, is_unlearn and -1 or 1) -- increase or decrease learned count

for i, token in ipairs(input_tokens) do
  redis.call('HINCRBY', token, hash_key, is_unlearn and -1 or 1)
  if text_tokens then
    local tok1 = text_tokens[i * 2 - 1]
    local tok2 = text_tokens[i * 2]

    if tok1 then
      if tok2 then
        redis.call('HSET', token, 'tokens', string.format('%s:%s', tok1, tok2))
      else
        redis.call('HSET', token, 'tokens', tok1)
      end

      redis.call('ZINCRBY', prefix .. '_z', is_unlearn and -1 or 1, token)
    end
  end
end
