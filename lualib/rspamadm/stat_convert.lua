local sqlite3 = require "rspamd_sqlite3"
local redis = require "rspamd_redis"
local util = require "rspamd_util"

local function send_redis(server, symbol, tokens, password, db, cmd)
  local ret = true
  local conn,err = redis.connect_sync({
    host = server,
  })

  local err_str

  if not conn then
    print('Cannot connect to ' .. server .. ' error: ' .. err)
    return false, err
  end

  if password then
    conn:add_cmd('AUTH', {password})
  end
  if db then
    conn:add_cmd('SELECT', {db})
  end

  for _,t in ipairs(tokens) do
    if not conn:add_cmd(cmd, {symbol .. t[3], t[1], t[2]}) then
      ret = false
      err_str = 'add command failure' .. string.format('%s %s',
        cmd, table.concat({symbol .. t[3], t[1], t[2]}, ' '))
    end
  end

  if ret then
    ret,err_str = conn:exec()
  end

  return ret,err_str
end

local function convert_learned(cache, server, password, redis_db)
  local converted = 0
  local db = sqlite3.open(cache)
  local ret = true
  local err_str

  if not db then
    print('Cannot open cache database: ' .. cache)
    return false
  end

  db:sql('BEGIN;')

  local conn,err = redis.connect_sync({
    host = server,
  })

  if not conn then
    print('Cannot connect to ' .. server .. ' error: ' .. err)
    return false
  end

  if password then
    conn:add_cmd('AUTH', {password})
  end
  if redis_db then
    conn:add_cmd('SELECT', {redis_db})
  end

  for row in db:rows('SELECT * FROM learns;') do
    local is_spam
    local digest = tostring(util.encode_base32(row.digest))

    if row.flag == '0' then
      is_spam = '-1'
    else
      is_spam = '1'
    end

    if not conn:add_cmd('HSET', {'learned_ids', digest, is_spam}) then
      print('Cannot add hash: ' .. digest)
      ret = false
    else
      converted = converted + 1
    end
  end
  db:sql('COMMIT;')

  if ret then
    ret,err_str = conn:exec()
  end

  if ret then
    print(string.format('Converted %d cached items from sqlite3 learned cache to redis',
      converted))
  else
    print('Error occurred during sending data to redis: ' .. err_str)
  end

  return ret
end

return function (_, res)

end
