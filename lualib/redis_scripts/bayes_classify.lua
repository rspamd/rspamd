-- Lua script to perform bayes classification (multi-class)
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- key2 - class labels: either table of all class labels (multi-class) or single string (binary)
-- key3 - set of tokens encoded in messagepack array of strings

local prefix = KEYS[1]
local class_labels_arg = KEYS[2]
local input_tokens = cmsgpack.unpack(KEYS[3])

-- Determine if this is multi-class (table) or binary (string)
local class_labels = {}
if type(class_labels_arg) == "table" then
  class_labels = class_labels_arg
else
  -- Binary compatibility: handle old boolean or single string format
  if class_labels_arg == "true" then
    class_labels = { "S" }            -- spam
  elseif class_labels_arg == "false" then
    class_labels = { "H" }            -- ham
  else
    class_labels = { class_labels_arg } -- single class label
  end
end

-- Get learned counts for all classes
local learned_counts = {}
for _, label in ipairs(class_labels) do
  local key = 'learns_' .. string.lower(label)
  -- Also try legacy keys for backward compatibility
  if label == 'H' then
    key = 'learns_ham'
  elseif label == 'S' then
    key = 'learns_spam'
  end
  learned_counts[label] = tonumber(redis.call('HGET', prefix, key)) or 0
end

-- Get token data for all classes (only if we have learns for any class)
local outputs = {}
local has_learns = false
for _, count in pairs(learned_counts) do
  if count > 0 then
    has_learns = true
    break
  end
end

if has_learns then
  -- Initialize outputs for each class
  for _, label in ipairs(class_labels) do
    outputs[label] = {}
  end

  -- Process each token
  for i, token in ipairs(input_tokens) do
    local token_data = redis.call('HMGET', token, unpack(class_labels))

    if token_data then
      for j, label in ipairs(class_labels) do
        local count = token_data[j]
        if count then
          table.insert(outputs[label], { i, tonumber(count) })
        end
      end
    end
  end
end

-- Format output for backward compatibility
if #class_labels == 2 and class_labels[1] == 'H' and class_labels[2] == 'S' then
  -- Binary format: [learned_ham, learned_spam, output_ham, output_spam]
  return {
    learned_counts['H'] or 0,
    learned_counts['S'] or 0,
    outputs['H'] or {},
    outputs['S'] or {}
  }
elseif #class_labels == 2 and class_labels[1] == 'S' and class_labels[2] == 'H' then
  -- Binary format: [learned_ham, learned_spam, output_ham, output_spam]
  return {
    learned_counts['H'] or 0,
    learned_counts['S'] or 0,
    outputs['H'] or {},
    outputs['S'] or {}
  }
else
  -- Multi-class format: [learned_counts_table, outputs_table]
  return { learned_counts, outputs }
end
