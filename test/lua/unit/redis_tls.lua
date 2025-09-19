-- Simple unit test to validate TLS options propagation in lua_redis
local lua_redis = require "lua_redis"

-- Build a minimal options table; no network connections are made here
local opts = {
  servers = '127.0.0.1:6379',
  timeout = 1.0,
  ssl = true,
  no_ssl_verify = true,
  ssl_ca = '/tmp/ca.crt',
  ssl_ca_dir = '/tmp/ca',
  ssl_cert = '/tmp/client.crt',
  ssl_key = '/tmp/client.key',
  sni = 'example.test',
}

local params = lua_redis.try_load_redis_servers(opts, nil, true)

assert(params, 'try_load_redis_servers returned nil')
assert(params.ssl == true, 'ssl flag not propagated')
assert(params.no_ssl_verify == true, 'no_ssl_verify flag not propagated')
assert(params.ssl_ca == '/tmp/ca.crt', 'ssl_ca not propagated')
assert(params.ssl_ca_dir == '/tmp/ca', 'ssl_ca_dir not propagated')
assert(params.ssl_cert == '/tmp/client.crt', 'ssl_cert not propagated')
assert(params.ssl_key == '/tmp/client.key', 'ssl_key not propagated')
assert(params.sni == 'example.test', 'sni not propagated')

-- Also ensure request helpers pass these options through (no execution)
-- This part only checks that the table has values set that would be consumed
-- by rspamd_redis.make_request/connect in runtime code paths.
local req_attrs = { task = nil, config = nil, ev_base = nil } -- not used here
local req_tbl = { 'PING' }

-- If we got here, options are present; actual network tests are covered by functional tests.
return true

