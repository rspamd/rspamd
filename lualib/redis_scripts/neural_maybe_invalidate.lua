-- Lua script to invalidate ANNs
-- Uses the following keys and argv
-- key1 - prefix for keys (profile zset)
-- key2 - number of elements to leave
-- argv1 - tombstone cutoff timestamp (optional): profile entries older than this
--         whose ANN blob no longer exists and that hold no training data are
--         removed.  This clears stale entries left behind when a blob expires or
--         a profile was registered but never trained, which would otherwise keep
--         shadowing freshly trained (lower-versioned) ANNs in version selection.

local removed = {}

-- 1) Rank-based pruning: keep the `lim` newest entries by score (timestamp)
local card = redis.call('ZCARD', KEYS[1])
local lim = tonumber(KEYS[2])
if card > lim then
  local to_delete = redis.call('ZRANGE', KEYS[1], 0, card - lim - 1)
  if to_delete then
    for _, k in ipairs(to_delete) do
      local tb = cjson.decode(k)
      if type(tb) == 'table' and type(tb.redis_key) == 'string' then
        redis.call('DEL', tb.redis_key)
        -- Also train vectors
        redis.call('DEL', tb.redis_key .. '_spam_set')
        redis.call('DEL', tb.redis_key .. '_ham_set')
      end
      removed[#removed + 1] = k
    end
  end
  redis.call('ZREMRANGEBYRANK', KEYS[1], 0, card - lim - 1)
end

-- 2) Tombstone GC: drop entries with no trained blob and no training data that
--    are older than the cutoff.  Entries still accumulating vectors, or younger
--    than the cutoff (freshly registered profiles awaiting their first train),
--    are spared regardless of blob presence.
local cutoff = tonumber(ARGV[1])
if cutoff then
  local survivors = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
  local i = 1
  while i <= #survivors do
    local member = survivors[i]
    local score = tonumber(survivors[i + 1])
    i = i + 2
    if score and score < cutoff then
      local ok, tb = pcall(cjson.decode, member)
      if ok and type(tb) == 'table' and type(tb.redis_key) == 'string' then
        local has_blob = redis.call('HEXISTS', tb.redis_key, 'ann') == 1
        local has_spam = redis.call('EXISTS', tb.redis_key .. '_spam_set') == 1
        local has_ham = redis.call('EXISTS', tb.redis_key .. '_ham_set') == 1
        if not has_blob and not has_spam and not has_ham then
          redis.call('ZREM', KEYS[1], member)
          removed[#removed + 1] = member
        end
      end
    end
  end
end

return removed
