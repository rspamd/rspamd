--[[[
-- Just a test for Redis API
--]]

local logger = require "rspamd_logger"
local redis_lua = require "lua_redis"

local redis_params
local N = 'redis_test'

local lua_script = [[
local f = function() end
return "hello from lua on redis"
]]

local function redis_simple_async_symbol(task)
  local function redis_cb(err, data)
    if err then
      task:insert_result('REDIS_ASYNC_ERROR', 1.0, err)
    else
      task:insert_result('REDIS_ASYNC', 1.0, data)
    end
  end

  redis_lua.rspamd_redis_make_request(
    task,
    redis_params,
    "test_key",
    false,
    redis_cb,
    'GET',
    {'test_key'}
  )
end

local function redis_simple_async_api201809(task)
  local function redis_cb(err, data)
    if err then
      task:insert_result('REDIS_ASYNC201809_ERROR', 1.0, err)
    else
      task:insert_result('REDIS_ASYNC201809', 1.0, data)
    end
  end

  local attrs = {
    task = task,
    callback = redis_cb
  }
  local request = {
    'GET',
    'test_key'
  }
  redis_lua.request(redis_params, attrs, request)
end

local function redis_symbol(task)

  local attrs = {task = task}
  local is_ok, connection = redis_lua.connect(redis_params, attrs)

  logger.infox(task, "connect: %1, %2", is_ok, connection)

  if not is_ok then
    task:insert_result('REDIS_ERROR', 1.0, connection)
    return
  end

  local err, data

  is_ok, err = connection:add_cmd('EVAL', {lua_script, 0})
  logger.infox(task, "add_cmd: %1, %2", is_ok, err)

  if not is_ok then
    task:insert_result('REDIS_ERROR_2', 1.0, err)
    return
  end

  is_ok,data = connection:exec()

  logger.infox(task, "exec: %1, %2", is_ok, data)

  if not is_ok then
    task:insert_result('REDIS_ERROR_3', 1.0, data)
    return
  end

  task:insert_result('REDIS', 1.0, data)

end

-- What a pooled connection must not carry from one request to another, and
-- what a failed setup of a connection must tell
local function redis_pool_symbol(task)
  local lua_util = require "lua_util"
  local failures = {}
  local attrs = { task = task }

  local function check(what, cond, got)
    if not cond then
      failures[#failures + 1] = string.format('%s: %s', what, tostring(got))
    end
  end

  -- A database that does not exist: the request fails, it does not run in
  -- the database 0
  local bad_db = lua_util.shallowcopy(redis_params)
  bad_db.db = '9999'
  local ok, data = redis_lua.request(bad_db, attrs, { 'GET', 'test_key' })
  check('database out of range', not ok or data ~= 'test value', data)

  -- A database chosen by a command does not stay on the connection
  redis_lua.request(redis_params, attrs, { 'SELECT', '5' })
  ok, data = redis_lua.request(redis_params, attrs, { 'GET', 'test_key' })
  check('after SELECT', ok and data == 'test value', data)

  -- Nor does an open transaction
  redis_lua.request(redis_params, attrs, { 'MULTI' })
  ok, data = redis_lua.request(redis_params, attrs, { 'GET', 'test_key' })
  check('after MULTI', ok and data == 'test value', data)

  -- Replies of the newer protocol are tables and numbers, with every value
  -- at its place
  local is_ok, connection = redis_lua.connect(redis_params, attrs)
  if is_ok then
    connection:add_cmd('HELLO', { '3' })
    connection:add_cmd('HSET', { 'redis_pool_test_hash', 'field', 'value' })
    connection:add_cmd('HGETALL', { 'redis_pool_test_hash' })
    connection:add_cmd('GET', { 'test_key' })
    -- A status and a value for each command
    local res = { connection:exec() }
    local hello, hash, value = res[2], res[6], res[8]

    if res[1] and type(hello) == 'table' then
      check('map reply', type(hash) == 'table' and hash[1] == 'field' and hash[2] == 'value',
          type(hash) == 'table' and table.concat(hash, ',') or hash)
      check('reply after a map', value == 'test value', value)
    end
    -- Else the server has no HELLO: nothing to check
  else
    check('connect', false, connection)
  end

  if #failures == 0 then
    task:insert_result('REDIS_POOL_OK', 1.0)
  else
    task:insert_result('REDIS_POOL_FAIL', 1.0, failures)
  end
end

redis_params = rspamd_parse_redis_server(N)

rspamd_config:register_symbol({
  name = 'REDIS_POOL_TEST',
  score = 1.0,
  callback = redis_pool_symbol,
  flags = 'coro',
})

rspamd_config:register_symbol({
  name = 'SIMPLE_REDIS_ASYNC_TEST',
  score = 1.0,
  callback = redis_simple_async_symbol,
  no_squeeze = true
})

rspamd_config:register_symbol({
  name = 'SIMPLE_REDIS_ASYNC201809_TEST',
  score = 1.0,
  callback = redis_simple_async_api201809,
  no_squeeze = true
})

rspamd_config:register_symbol({
  name = 'REDIS_TEST',
  score = 1.0,
  callback = redis_symbol,
  flags = 'coro',
})
-- ]]
