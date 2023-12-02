-- Lua script to perform bayes classification
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- key2 - set of tokens encoded in messagepack array of int64_t

local prefix = KEYS[1]
local input_tokens = cmsgpack.unpack(KEYS[2])
local output_spam = {}
local output_ham = {}

for i, token in ipairs(input_tokens) do
  local token_data = redis.call('HMGET', prefix .. tostring(token), 'H', 'S')

  if token_data then
    local ham_count = tonumber(token_data[1]) or 0
    local spam_count = tonumber(token_data[2]) or 0

    output_ham[i] = ham_count
    output_spam[i] = spam_count
  else
    output_ham[i] = 0
    output_spam[i] = 0
  end
end

return cmsgpack.pack({ output_ham, output_spam })