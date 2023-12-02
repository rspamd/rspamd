-- Lua script to perform bayes classification
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- key2 - set of tokens encoded in messagepack array of int64_t

local prefix = KEYS[1]
local input_tokens = cmsgpack.unpack(KEYS[2])
local output_spam = {}
local output_ham = {}

local learned_ham = redis.call('HGET', prefix, 'learned_ham') or 0
local learned_spam = redis.call('HGET', prefix, 'learned_spam') or 0
local prefix_underscore = prefix .. '_'

-- Output is a set of pairs (token_index, token_count), tokens that are not
-- found are not filled.
-- This optimisation will save a lot of space for sparse tokens, and in Bayes that assumption is normally held

if learned_ham > 0 and learned_spam > 0 then
  for i, token in ipairs(input_tokens) do
    local token_data = redis.call('HMGET', prefix_underscore .. tostring(token), 'H', 'S')

    if token_data then
      local ham_count = token_data[1]
      local spam_count = tonumber(token_data[2]) or 0

      if ham_count then
        table.insert(output_ham, { i, tonumber(ham_count) })
      end

      if spam_count then
        table.insert(output_spam, { i, tonumber(spam_count) })
      end
    end
  end
end

return { learned_ham, learned_spam, output_ham, output_spam }