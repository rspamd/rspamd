-- Lua script that checks if we can store a new training vector
-- Uses the following keys:
-- key1 - ann key
-- returns nspam,nham (or nil if locked)

local prefix = KEYS[1]
local locked = redis.call('HGET', prefix, 'lock')
if locked then
  local host = redis.call('HGET', prefix, 'hostname') or 'unknown'
  return string.format('%s:%s', host, locked)
end
local nspam = 0
local nham = 0

local ret = redis.call('SCARD', prefix .. '_spam_set')
if ret then nspam = tonumber(ret) end
ret = redis.call('SCARD', prefix .. '_ham_set')
if ret then nham = tonumber(ret) end

return {nspam,nham}