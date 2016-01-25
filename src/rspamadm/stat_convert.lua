local sqlite3 = require "rspamd_sqlite3"
local redis = require "rspamd_redis"
local _ = require "fun"

local function send_redis(server, symbol, tokens)
  local ret = true
  local args = {}
  
  _.each(function(t)
    if not args[t[3]] then
      args[t[3]] = {symbol .. t[3]}
    end
    table.insert(args[t[3]], t[1])
    table.insert(args[t[3]], t[2])
  end, tokens)
  
  _.each(function(k, argv)
    if not redis.make_request_sync({
        host = server,
        cmd = 'HMSET',
        args = argv
      }) then
      ret = false
    end
  end, args)
  
  return ret
end

return function (args, res)
  local db = sqlite3.open(res['source_db'])
  local tokens = {}
  local num = 0
  local lim = 100 -- Update each 100 tokens
  local users_map = {}
  local learns = {}

  if not db then
    print('Cannot open source db: ' .. res['source_db'])
    return
  end

  db:sql('BEGIN;')
  -- Fill users mapping
  for row in db:rows('SELECT * FROM users;') do
    users_map[row.id] = row.name
    learns[row.id] = row.learned
  end
  -- Fill tokens, sending data to redis each `lim` records
  for row in db:rows('SELECT token,value,user FROM tokens;') do
    local user = ''
    if row.user ~= 0 and users_map[row.user] then
      user = users_map[row.user]
    end
    
    table.insert(tokens, {row.token, row.value, user})
    
    num = num + 1
    if num > lim then
      if not send_redis(res['redis_host'], res['symbol'], tokens, users_map) then
        print('Cannot send tokens to the redis server')
        return
      end
      
      num = 0
      tokens = {}
    end
  end
  db:sql('COMMIT;')
end