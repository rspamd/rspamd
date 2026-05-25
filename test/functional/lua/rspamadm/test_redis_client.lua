local logger = require "rspamd_logger"
local redis = require "lua_redis"
local upstream_list = require "rspamd_upstream_list"

-- redis port comes from the test harness; under parallel pabot each
-- worker has its own redis instance on a different port. rspamadm
-- (unlike rspamd) does NOT populate the rspamd_env global, so read
-- the RSPAMD_ env var directly. Fall back to the historical literal
-- for standalone invocations.
local redis_port = tonumber(os.getenv("RSPAMD_REDIS_PORT")) or 56379
local upstreams_write = upstream_list.create('127.0.0.1', redis_port)
local upstreams_read = upstream_list.create('127.0.0.1', redis_port)

local is_ok, connection = redis.redis_connect_sync({
  write_servers = upstreams_write,
  read_servers = upstreams_read,
--  config = rspamd_config,
--  ev_base = rspamadm_ev_base,
--  session = rspamadm_session,
  timeout = 2
})


local lua_script = [[
local f = function() end
--for k = 1,100000000 do
--  for i=1,100000000 do
--    f()
--  end
--end
return "hello from lua on redis"
]]

local a,b = connection:add_cmd('EVAL', {lua_script, 0})
local is_ok,ver = connection:exec()

print(is_ok, ver)

--[[
a,b = connection:add_cmd('EVAL', {lua_script, 0})
print(a,b)

is_ok,ver = connection:exec()

print(is_ok, ver)
]]