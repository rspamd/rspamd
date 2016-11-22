local sqlite3 = require "rspamd_sqlite3"
local redis = require "rspamd_redis"
local util = require "rspamd_util"

local function connect_redis(server, password, db)
  local ret
  local conn, err = redis.connect_sync({
    host = server,
  })

  if not conn then
    return nil, 'Cannot connect: ' .. err
  end

  if password then
    ret = conn:add_cmd('AUTH', {password})
    if not ret then
      return nil, 'Cannot queue command'
    end
  end
  if db then
    ret = conn:add_cmd('SELECT', {db})
    if not ret then
      return nil, 'Cannot queue command'
    end
  end

  return conn, nil
end

local function send_digests(digests, redis_host, redis_password, redis_db)
  local conn, err = connect_redis(redis_host, redis_password, redis_db)
  if err then
    print(err)
    return false
  end
  local ret
  for _, v in ipairs(digests) do
    ret = conn:add_cmd('HMSET', {
      'fuzzy' .. v[1],
      'F', v[2],
      'V', v[3],
    })
    if not ret then
      print('Cannot batch command')
      return false
    end
    ret = conn:add_cmd('EXPIRE', {
      'fuzzy' .. v[1],
      tostring(v[4]),
    })
    if not ret then
      print('Cannot batch command')
      return false
    end
  end
  ret, err = conn:exec()
  if not ret then
    print('Cannot execute batched commands: ' .. err)
    return false
  end
  return true
end

local function send_shingles(shingles, redis_host, redis_password, redis_db)
  local conn, err = connect_redis(redis_host, redis_password, redis_db)
  if err then
    print("Redis error: " .. err)
    return false
  end
  local ret
  for _, v in ipairs(shingles) do
    ret = conn:add_cmd('SET', {
      'fuzzy_' .. v[2] .. '_' .. v[1],
      v[4],
    })
    if not ret then
      print('Cannot batch SET command: ' .. err)
      return false
    end
    ret = conn:add_cmd('EXPIRE', {
      'fuzzy_' .. v[2] .. '_' .. v[1],
      tostring(v[3]),
    })
    if not ret then
      print('Cannot batch command')
      return false
    end
  end
  ret, err = conn:exec()
  if not ret then
    print('Cannot execute batched commands: ' .. err)
    return false
  end
  return true
end

local function update_counters(total, redis_host, redis_password, redis_db)
  local conn, err = connect_redis(redis_host, redis_password, redis_db)
  if err then
    print(err)
    return false
  end
  local ret
  ret = conn:add_cmd('SET', {
    'fuzzylocal',
    total,
  })
  if not ret then
    print('Cannot batch command')
    return false
  end
  ret = conn:add_cmd('SET', {
    'fuzzy_count',
    total,
  })
  if not ret then
    print('Cannot batch command')
    return false
  end
  ret, err = conn:exec()
  if not ret then
    print('Cannot execute batched commands: ' .. err)
    return false
  end
  return true
end

return function (_, res)
  local db = sqlite3.open(res['source_db'])
  local shingles = {}
  local digests = {}
  local num_batch_digests = 0
  local num_batch_shingles = 0
  local total_digests = 0
  local total_shingles = 0
  local lim_batch = 1000 -- Update each 1000 entries
  local redis_password = res['redis_password']
  local redis_db = nil

  if res['redis_db'] then
    redis_db = tostring(res['redis_db'])
  end

  if not db then
    print('Cannot open source db: ' .. res['source_db'])
    return
  end

  local now = util.get_time()
  for row in db:rows('SELECT id, flag, digest, value, time FROM digests') do

    local expire_in = math.floor(now - row.time + res['expiry'])
    if expire_in >= 1 then
      table.insert(digests, {row.digest, row.flag, row.value, expire_in})
      num_batch_digests = num_batch_digests + 1
      total_digests = total_digests + 1
      for srow in db:rows('SELECT value, number FROM shingles WHERE digest_id = ' .. row.id) do
        table.insert(shingles, {srow.value, srow.number, expire_in, row.digest})
        total_shingles = total_shingles + 1
        num_batch_shingles = num_batch_shingles + 1
      end
    end
    if num_batch_digests >= lim_batch then
      if not send_digests(digests, res['redis_host'], redis_password, redis_db) then
        return
      end
      num_batch_digests = 0
      digests = {}
    end
    if num_batch_shingles >= lim_batch then
      if not send_shingles(shingles, res['redis_host'], redis_password, redis_db) then
        return
      end
      num_batch_shingles = 0
      shingles = {}
    end
  end
  if digests[1] then
    if not send_digests(digests, res['redis_host'], redis_password, redis_db) then
      return
    end
  end
  if shingles[1] then
    if not send_shingles(shingles, res['redis_host'], redis_password, redis_db) then
      return
    end
  end

  local message = string.format(
    'Migrated %d digests and %d shingles',
    total_digests, total_shingles
  )
  if not update_counters(total_digests, res['redis_host'], redis_password, redis_db) then
    message = message .. ' but failed to update counters'
  end
  print(message)
end
