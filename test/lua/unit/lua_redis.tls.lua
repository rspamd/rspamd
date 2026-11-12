-- Connection configuration must cross request builders as one object, so new
-- connection settings do not need forwarding code in every command path.
context("lua_redis connection options", function()
  local lua_redis = require "lua_redis"
  local rspamd_ip = require "rspamd_ip"

  local function with_connection(f, check)
    local saved_config = rspamd_config
    _G.rspamd_config = { add_on_load = function() end, add_periodic = function() end }
    local addr = rspamd_ip.from_string('127.0.0.1:6379')
    local upstream = {
      get_name = function() return 'redis.example' end,
      get_addr = function() return addr end,
      ok = function() end,
      fail = function() end,
    }
    local servers = {
      all_upstreams = function() return { upstream } end,
      get_upstream_round_robin = function() return upstream end,
      get_upstream_master_slave = function() return upstream end,
    }
    local params = {
      timeout = 1.0,
      read_servers = servers,
      write_servers = servers,
      username = 'redis-user',
      password = 'redis-password',
      db = '3',
      ssl = true,
      no_ssl_verify = false,
      ssl_ca = 'ca.pem',
      ssl_ca_dir = '/etc/ssl/certs',
      ssl_cert = 'client.pem',
      ssl_key = 'client.key',
      sni = 'redis.example',
      session = 'fake_session',
    }
    local captured
    local saved = package.loaded.rspamd_redis
    local function capture(options)
      captured = options
      return false, 'stub'
    end
    package.loaded.rspamd_redis = {
      make_request = capture,
      connect = capture,
      connect_sync = capture,
    }
    local ok, err = pcall(f, params, addr)
    package.loaded.rspamd_redis = saved
    _G.rspamd_config = saved_config

    assert(ok, tostring(err))
    assert(captured)
    assert(rawequal(params, captured.connection), 'connection configuration was copied or lost')
    assert(captured.host == addr)
    assert(captured.timeout == params.timeout)
    assert(captured.ssl == nil)
    assert(captured.password == nil)
    assert(captured.dbname == nil)
    check(true)
  end

  test("task requests retain connection configuration", function()
    with_connection(function(params)
      lua_redis.redis_make_request({}, params, nil, false, function() end, 'PING', {})
    end, assert_true)
  end)

  test("taskless requests retain connection configuration", function()
    with_connection(function(params)
      lua_redis.redis_make_request_taskless('fake_ev_base', rspamd_config, params,
          nil, false, function() end, 'PING', {})
    end, assert_true)
  end)

  for _, method in ipairs({ 'request', 'connect' }) do
    for _, async in ipairs({ false, true }) do
      test(method .. (async and ' async' or ' sync') .. " retains connection configuration", function()
        with_connection(function(params)
          local attrs = {
            config = rspamd_config,
            ev_base = 'fake_ev_base',
          }
          if async then attrs.callback = function() end end
          lua_redis[method](params, attrs, { 'PING' })
        end, assert_true)
      end)
    end
  end

  test("legacy synchronous helper retains connection configuration", function()
    with_connection(function(params)
      lua_redis.redis_connect_sync(params, false, nil, rspamd_config, 'fake_ev_base')
    end, assert_true)
  end)

  test("synchronous SCRIPT LOAD retains connection configuration", function()
    with_connection(function(params)
      lua_redis.add_redis_script('return 1', params)
      lua_redis.prepare_redis_setup(params, {
        ev_base = 'fake_ev_base',
        session = 'fake_session',
      }, function() end)
    end, assert_true)
  end)

  test("asynchronous SCRIPT LOAD retains connection configuration", function()
    with_connection(function(params)
      local id = lua_redis.add_redis_script('return 1', params)
      lua_redis.exec_redis_script(id, { ev_base = 'fake_ev_base' }, function() end, {}, {})
    end, assert_true)
  end)
end)
