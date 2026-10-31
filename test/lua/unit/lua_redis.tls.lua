-- Unit tests for TLS settings propagation in lua_redis
--
-- Connections are not established here: rspamd_redis is replaced with a stub
-- that records the options lua_redis passes to it.

context("lua_redis TLS options", function()
  local lua_redis = require "lua_redis"
  local rspamd_ip = require "rspamd_ip"

  local tls = {
    ssl = true,
    no_ssl_verify = false,
    ssl_ca = '/etc/rspamd/redis-ca.pem',
    ssl_ca_dir = '/etc/ssl/certs',
    ssl_cert = '/etc/rspamd/redis-client.pem',
    ssl_key = '/etc/rspamd/redis-client.key',
    sni = 'redis.example',
  }

  test("copy_tls_options copies only TLS settings that are set", function()
    local options = lua_redis.copy_tls_options({
      ssl = false,
      ssl_ca = 'ca.pem',
      password = 'secret',
    }, { host = 'redis.example' })

    assert_equal(options.ssl, false)
    assert_equal(options.ssl_ca, 'ca.pem')
    assert_nil(options.ssl_key)
    assert_nil(options.password)
    assert_equal(options.host, 'redis.example')
  end)

  test("SCRIPT LOAD connections carry TLS settings", function()
    local addr = rspamd_ip.from_string('127.0.0.1')
    local upstream = {
      get_name = function() return 'redis.example' end,
      get_addr = function() return addr end,
      ok = function() end,
      fail = function() end,
    }
    local redis_params = {
      timeout = 1.0,
      read_servers = {
        all_upstreams = function() return { upstream } end,
      },
    }
    for k, v in pairs(tls) do
      redis_params[k] = v
    end

    lua_redis.add_redis_script('return 1', redis_params)

    local captured
    local saved = package.loaded.rspamd_redis
    package.loaded.rspamd_redis = {
      connect_sync = function(options)
        captured = options
        return false, 'stub'
      end,
    }
    local ok, err = pcall(lua_redis.prepare_redis_setup, redis_params, {
      ev_base = 'fake_ev_base',
      session = 'fake_session',
    }, function() end)
    package.loaded.rspamd_redis = saved

    assert_true(ok, tostring(err))
    assert_not_nil(captured)
    for k, v in pairs(tls) do
      assert_equal(captured[k], v, 'TLS option ' .. k)
    end
  end)
end)
