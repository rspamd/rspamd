local sqlite3 = require "rspamd_sqlite3"
local redis = require "rspamd_redis"
local util = require "rspamd_util"

-- Checks the values returned by exec(): a pair (ok, reply) per command, or a
-- single (false, error) when the replies cannot be returned. Returns true or
-- false and the first error
local function check_replies(...)
  local nres = select('#', ...)

  if nres == 0 then
    return false, 'no replies from redis'
  end

  local replies = { ... }

  for i = 1, nres, 2 do
    if not replies[i] then
      return false, tostring(replies[i + 1])
    end
  end

  return true
end

local function connect_redis(server, username, password, db)
  if username and not password then
    return nil, 'Redis requires a password when username is supplied'
  end

  -- The connection pool sends AUTH and SELECT before the commands
  local ok, conn = redis.connect_sync({
    host = server,
    username = username,
    password = password,
    db = db,
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
  })

  if not ok then
    return nil, 'Cannot connect: ' .. tostring(conn)
  end

  return conn, nil
end

local function send_digests(conn, digests)
  local ret, err
  for _, v in ipairs(digests) do
    ret, err = conn:add_cmd('HMSET', {
      'fuzzy' .. v[1],
      'F', v[2],
      'V', v[3],
    })
    if not ret then
      print('Cannot batch command: ' .. tostring(err))
      return false
    end
    ret, err = conn:add_cmd('EXPIRE', {
      'fuzzy' .. v[1],
      tostring(v[4]),
    })
    if not ret then
      print('Cannot batch command: ' .. tostring(err))
      return false
    end
  end
  ret, err = check_replies(conn:exec())
  if not ret then
    print('Cannot execute batched commands: ' .. err)
    return false
  end
  return true
end

local function send_shingles(conn, shingles)
  local ret, err
  for _, v in ipairs(shingles) do
    ret, err = conn:add_cmd('SET', {
      'fuzzy_' .. v[2] .. '_' .. v[1],
      v[4],
    })
    if not ret then
      print('Cannot batch SET command: ' .. tostring(err))
      return false
    end
    ret, err = conn:add_cmd('EXPIRE', {
      'fuzzy_' .. v[2] .. '_' .. v[1],
      tostring(v[3]),
    })
    if not ret then
      print('Cannot batch command: ' .. tostring(err))
      return false
    end
  end
  ret, err = check_replies(conn:exec())
  if not ret then
    print('Cannot execute batched commands: ' .. err)
    return false
  end
  return true
end

local function update_counters(conn, total)
  local ret, err
  ret, err = conn:add_cmd('SET', {
    'fuzzylocal',
    total,
  })
  if not ret then
    print('Cannot batch command: ' .. tostring(err))
    return false
  end
  ret, err = conn:add_cmd('SET', {
    'fuzzy_count',
    total,
  })
  if not ret then
    print('Cannot batch command: ' .. tostring(err))
    return false
  end
  ret, err = check_replies(conn:exec())
  if not ret then
    print('Cannot execute batched commands: ' .. err)
    return false
  end
  return true
end

return function(_, res)
  local db = sqlite3.open(res['source_db'])
  local shingles = {}
  local digests = {}
  local num_batch_digests = 0
  local num_batch_shingles = 0
  local total_digests = 0
  local total_shingles = 0
  local lim_batch = 1000 -- Update each 1000 entries
  local redis_username = res['redis_username']
  local redis_password = res['redis_password']
  local redis_db = nil

  if res['redis_db'] then
    redis_db = tostring(res['redis_db'])
  end

  if not db then
    print('Cannot open source db: ' .. res['source_db'])
    return
  end

  -- One connection serves all batches: each connection object holds a pooled
  -- connection until it is collected
  local conn, err = connect_redis(res['redis_host'], redis_username, redis_password, redis_db)
  if not conn then
    print(err)
    return
  end

  local now = util.get_time()
  for row in db:rows('SELECT id, flag, digest, value, time FROM digests') do

    local expire_in = math.floor(now - row.time + res['expiry'])
    if expire_in >= 1 then
      table.insert(digests, { row.digest, row.flag, row.value, expire_in })
      num_batch_digests = num_batch_digests + 1
      total_digests = total_digests + 1
      for srow in db:rows('SELECT value, number FROM shingles WHERE digest_id = ' .. row.id) do
        table.insert(shingles, { srow.value, srow.number, expire_in, row.digest })
        total_shingles = total_shingles + 1
        num_batch_shingles = num_batch_shingles + 1
      end
    end
    if num_batch_digests >= lim_batch then
      if not send_digests(conn, digests) then
        return
      end
      num_batch_digests = 0
      digests = {}
    end
    if num_batch_shingles >= lim_batch then
      if not send_shingles(conn, shingles) then
        return
      end
      num_batch_shingles = 0
      shingles = {}
    end
  end
  if digests[1] then
    if not send_digests(conn, digests) then
      return
    end
  end
  if shingles[1] then
    if not send_shingles(conn, shingles) then
      return
    end
  end

  local message = string.format(
      'Migrated %d digests and %d shingles',
      total_digests, total_shingles
  )
  if not update_counters(conn, total_digests) then
    message = message .. ' but failed to update counters'
  end
  print(message)
end
