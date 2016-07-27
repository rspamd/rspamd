local sqlite3 = require "rspamd_sqlite3"
local redis = require "rspamd_redis"
local util = require "rspamd_util"

local function send_redis(server, symbol, tokens, password, db, cmd)
  local ret = true
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
  if db then
    conn:add_cmd('SELECT', {db})
  end

  for _,t in ipairs(tokens) do
    if not conn:add_cmd(cmd, {symbol .. t[3], t[1], t[2]}) then
      ret = false
    end
  end

  if ret then
    ret = conn:exec()
  end

  return ret
end

local function convert_learned(cache, server, password, db)
  local converted = 0
  local db = sqlite3.open(cache)
  local ret = true

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
  if db then
    conn:add_cmd('SELECT', {db})
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
    ret = conn:exec()
  end

  if ret then
    print(string.format('Converted %d cached items from sqlite3 learned cache to redis',
      converted))
  else
    print('Error occurred during sending data to redis')
  end

  return ret
end

return function (args, res)
  local db = sqlite3.open(res['source_db'])
  local tokens = {}
  local num = 0
  local total = 0
  local nusers = 0
  local lim = 1000 -- Update each 1000 tokens
  local users_map = {}
  local learns = {}
  local redis_password = res['redis_password']
  local redis_db = res['redis_db']
  local ret = false
  local cmd = 'HINCRBY'

  if res['reset_previous'] then
    cmd = 'HSET'
  end

  if res['cache_db'] then
    if not convert_learned(res['cache_db'], res['redis_host']) then
      print('Cannot convert learned cache to redis')
      return
    end
  end

  if not db then
    print('Cannot open source db: ' .. res['source_db'])
    return
  end

  db:sql('BEGIN;')
  -- Fill users mapping
  for row in db:rows('SELECT * FROM users;') do
    if row.id == '0' then
      users_map[row.id] = ''
    else
      users_map[row.id] = row.name
    end
    learns[row.id] = row.learns
    nusers = nusers + 1
  end

  -- Workaround for old databases
  for row in db:rows('SELECT * FROM languages WHERE id=0;') do
    if learns[row.id] then
      learns[row.id] = learns[row.id] + row.learns
    else
      learns[row.id] = row.learns
    end
  end

  -- Fill tokens, sending data to redis each `lim` records
  for row in db:rows('SELECT token,value,user FROM tokens;') do
    local user = ''
    if row.user ~= 0 and users_map[row.user] then
      user = users_map[row.user]
    end

    table.insert(tokens, {row.token, row.value, user})

    num = num + 1
    total = total + 1
    if num > lim then
      if not send_redis(res['redis_host'], res['symbol'],
        tokens, redis_password, redis_db, cmd) then

        print('Cannot send tokens to the redis server')
        return
      end

      num = 0
      tokens = {}
    end
  end
  if #tokens > 0 and
    not send_redis(res['redis_host'], res['symbol'], tokens,
      redis_password, redis_db, cmd) then

    print('Cannot send tokens to the redis server')
    return
  end
  -- Now update all users
  local conn,err = redis.connect_sync({
    host = res['redis_host'],
  })

  if not conn then
    print('Cannot connect to ' .. res['redis_host'] .. ' error: ' .. err)
    return false
  end

  if redis_password then
    conn:add_cmd('AUTH', {redis_password})
  end
  if redis_db then
    conn:add_cmd('SELECT', {redis_db})
  end

  for id,learned in pairs(learns) do
    local user = users_map[id]
    if not conn:add_cmd(cmd, {res['symbol'] .. user, 'learns', learned}) then
      print('Cannot update learns for user: ' .. user)
    end
  end
  db:sql('COMMIT;')

  ret = conn:exec()

  if ret then
    print(string.format('Migrated %d tokens for %d users for symbol %s',
     total, nusers, res['symbol']))
  else
    print('Error occurred during sending data to redis')
  end
end
