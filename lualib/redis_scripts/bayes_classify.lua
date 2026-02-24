-- Lua script to perform bayes classification (multi-class)
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- argv1 - class labels: table of all class labels as "TABLE:label1,label2,..."
-- argv2 - set of tokens encoded in messagepack array of strings

local prefix = KEYS[1]
local class_labels_arg = ARGV[1]
local input_tokens = cmsgpack.unpack(ARGV[2])

-- Parse class labels (always expect TABLE: format)
local class_labels = {}
if string.match(class_labels_arg, "^TABLE:") then
  local labels_str = string.sub(class_labels_arg, 7) -- Remove "TABLE:" prefix
  for label in string.gmatch(labels_str, "([^,]+)") do
    table.insert(class_labels, label)
  end
else
  -- Legacy single class - convert to array
  class_labels = { class_labels_arg }
end

-- Get learned counts for all classes (ordered)
local learned_counts = {}
for _, label in ipairs(class_labels) do
  local key = 'learns_' .. string.lower(label)
  -- Handle legacy keys for backward compatibility
  if label == 'H' then
    key = 'learns_ham'
  elseif label == 'S' then
    key = 'learns_spam'
  end
  table.insert(learned_counts, tonumber(redis.call('HGET', prefix, key)) or 0)
end

-- Get token data for all classes (ordered)
local token_results = {}
for i, _ in ipairs(class_labels) do
  token_results[i] = {}
end

-- Check if we have any learning data
local has_learns = false
for _, count in ipairs(learned_counts) do
  if count > 0 then
    has_learns = true
    break
  end
end

if has_learns then
  -- Process each token
  for i, token in ipairs(input_tokens) do
    local token_data = redis.call('HMGET', token, unpack(class_labels))

    if token_data then
      for j, _ in ipairs(class_labels) do
        local count = token_data[j]
        if count and tonumber(count) > 0 then
          table.insert(token_results[j], { i, tonumber(count) })
        end
      end
    end
  end
end

-- Always return ordered arrays: [learned_counts_array, token_results_array]
return { learned_counts, token_results }
