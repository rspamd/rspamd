--[[[
-- Just a test for Redis API
--]]

local logger = require "rspamd_logger"
local redis_lua = require "lua_redis"
local lua_util = require "lua_util"

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

local function redis_symbol(task)

  local params = lua_util.deepcopy(redis_params)
  params.task = task
  local is_ok, connection = redis_lua.redis_connect_sync(params)

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

redis_params = rspamd_parse_redis_server(N)

rspamd_config:register_symbol({
  name = 'SIMPLE_REDIS_ASYNC_TEST',
  score = 1.0,
  callback = redis_simple_async_symbol,
  no_squeeze = true
})

rspamd_config:register_symbol({
  name = 'REDIS_TEST',
  score = 1.0,
  callback = redis_symbol,
  no_squeeze = true
})
-- ]]
