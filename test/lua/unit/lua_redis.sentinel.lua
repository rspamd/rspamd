context('Redis Sentinel connections', function()
  local lua_util = require 'lua_util'
  local rspamd_ip = require 'rspamd_ip'

  local function with_sentinel(options, f)
    local saved_config = rspamd_config
    local names = { 'rspamd_redis', 'rspamd_upstream_list', 'rspamd_logger', 'rspamd_util' }
    local saved = {}
    for _, name in ipairs(names) do saved[name] = package.loaded[name] end
    local state = { requests = {}, connects = {}, loads = {}, ticks = {}, timers = {},
      failures = 0, successes = 0, now = 100 }
    state.task = {
      add_timer = function(_, _, cb) state.timers[#state.timers + 1] = cb end,
      get_ev_base = function() return 'event-base' end,
    }
    package.loaded.rspamd_util = setmetatable({ get_ticks = function() return state.now end },
        { __index = saved.rspamd_util })
    local address = rspamd_ip.from_string('127.0.0.1:26379')
    local upstream = {
      get_addr = function() if not state.unresolved then return address end end,
      get_name = function() return 'sentinel' end,
      fail = function() state.failures = state.failures + 1 end,
      ok = function() state.successes = state.successes + 1 end,
    }
    local config = {
      add_on_load = function(_, cb) state.loads[#state.loads + 1] = cb end,
      add_periodic = function(_, _, _, cb) state.ticks[#state.ticks + 1] = cb end,
      get_all_opt = function() return state.defaults end,
    }
    package.loaded.rspamd_upstream_list = {
      create = function()
        return {
          get_upstream_round_robin = function() return upstream end,
          all_upstreams = function() return { upstream } end,
          add_watcher = function() end,
        }
      end,
    }
    package.loaded.rspamd_logger = {
      errx = function() end, infox = function() end, warnx = function() end,
    }
    local masters = {{ 'name', 'mymaster', 'ip', '127.0.0.1', 'port', '6379' }}
    local slaves = {{ 'ip', '127.0.0.2', 'port', '6379', 'master-link-status', 'ok' }}
    state.masters, state.slaves = masters, slaves
    package.loaded.rspamd_redis = {
      make_request = function(opts)
        state.requests[#state.requests + 1] = opts
        return not ((state.reject_slaves and opts.args[1] == 'slaves') or
            (state.reject_scripts and opts.cmd == 'SCRIPT'))
      end,
      connect_sync = function(opts)
        state.connects[#state.connects + 1] = opts
        local command
        return true, {
          add_cmd = function(_, _, args) command = args[1] end,
          exec = function()
            if state.sync_error then return false, 'test failure' end
            return true, command == 'masters' and state.masters or state.slaves
          end,
        }
      end,
    }
    _G.rspamd_config = config
    local ok, err = pcall(function()
      local redis = dofile(lua_util.join_path(rspamd_paths.LUALIBDIR, 'lua_redis.lua'))
      options.servers = options.servers or '127.0.0.9:6379'
      options.sentinels = options.sentinels or '127.0.0.1:26379'
      local params = assert(redis.try_load_redis_servers(options, config, true))
      state.sync = function()
        local result = 'not called'
        redis.prepare_redis_setup(params, {
          config = config, ev_base = 'event-base', session = 'session', scripts = false,
        }, function(e) result = e end)
        return result
      end
      state.tick = function()
        state.loads[1](config, 'event-base', { is_scanner = function() return true end })
        state.ticks[1]()
      end
      f(redis, params, state)
    end)
    _G.rspamd_config = saved_config
    for _, name in ipairs(names) do package.loaded[name] = saved[name] end
    assert(ok, err)
  end

  for _, async in ipairs({ false, true }) do
    test((async and 'async' or 'sync') .. ' uses separate Sentinel connection settings', function()
      with_sentinel({
        username = 'data-user', password = 'data-password', ssl = false, db = '3',
        sentinel = { username = 'sentinel-user', password = 'sentinel-password',
          ssl = true, no_ssl_verify = false, ssl_ca = 'sentinel-ca', ssl_cert = 'cert',
          ssl_key = 'key', ssl_ca_dir = 'ca-dir', sni = 'sentinel.example', timeout = 2 },
      }, function(_, params, state)
        if async then
          state.tick()
          state.requests[1].callback(nil, state.masters)
          state.requests[2].callback(nil, state.slaves)
        else
          assert(state.sync() == nil)
        end
        local requests = async and state.requests or state.connects
        assert(#requests == 2)
        for _, opts in ipairs(requests) do
          assert(rawequal(opts.connection, params.sentinel))
          assert(opts.connection.username == 'sentinel-user')
          assert(opts.connection.password == 'sentinel-password')
          assert(opts.connection.db == nil)
          assert(opts.timeout == 2)
          assert(opts.no_pool)
        end
        assert(params.ssl == false and params.db == '3')
        assert(params.write_servers_str == '127.0.0.1:6379')
        assert(params.read_servers_str == '127.0.0.1:6379,127.0.0.2:6379')
      end)
      assert_true(true)
    end)
  end

  test('legacy credentials retain plaintext Sentinel with TLS data nodes', function()
    with_sentinel({ ssl = true, username = 'data', password = 'data',
      sentinel_username = 'legacy-user', sentinel_password = 'legacy-password' },
    function(_, _, state)
      assert(state.sync() == nil)
      local connection = state.connects[1].connection
      assert(connection.username == 'legacy-user' and connection.password == 'legacy-password')
      assert(not connection.ssl and connection.ssl_ca == nil)
    end)
    assert_true(true)
  end)

  test('local Sentinel settings inherit defaults without losing explicit false', function()
    with_sentinel({}, function(redis, _, state)
      state.defaults = { sentinel = { ssl = true, no_ssl_verify = true,
        username = 'global', ssl_ca = 'global-ca' } }
      local params = redis.try_load_redis_servers({ servers = '127.0.0.9:6380',
        sentinel = { ssl = false, no_ssl_verify = false, username = 'local' } }, rspamd_config)
      assert(params.sentinel.ssl == false and params.sentinel.no_ssl_verify == false)
      assert(params.sentinel.username == 'local' and params.sentinel.ssl_ca == 'global-ca')
    end)
    assert_true(true)
  end)

  test('connection cache distinguishes TLS flags and connection namespaces', function()
    with_sentinel({}, function(redis)
      local function parse(opts) opts.servers = '127.0.0.9:6381'; return redis.try_load_redis_servers(opts, rspamd_config, true) end
      assert(not rawequal(parse({ ssl = true }), parse({ ssl = false })))
      assert(not rawequal(parse({ sentinel = { ssl = true } }), parse({ sentinel = { ssl = false } })))
      assert(not rawequal(parse({ sentinel = { no_ssl_verify = true } }), parse({ sentinel = { no_ssl_verify = false } })))
      assert(not rawequal(parse({ sni = 'host' }), parse({ sentinel = { sni = 'host' } })))
      assert(rawequal(parse({ sentinel = { ssl = true, sni = 'host' } }), parse({ sentinel = { sni = 'host', ssl = true } })))
    end)
    assert_true(true)
  end)

  for _, failure in ipairs({ 'reply', 'schedule', 'empty', 'unresolved', 'malformed-master', 'malformed-slave' }) do
    test('async discovery preserves topology on ' .. failure .. ' failure', function()
      with_sentinel({ sentinel = { ssl = true } }, function(_, params, state)
        local original = params.write_servers
        state.reject_slaves = failure == 'schedule'
        state.unresolved = failure == 'unresolved'
        state.tick()
        if failure == 'unresolved' then
          assert(#state.requests == 0)
        else
          local masters = failure == 'empty' and {} or state.masters
          if failure == 'malformed-master' then masters = {{ 'name', 'broken' }} end
          state.requests[1].callback(nil, masters)
          if failure == 'reply' then state.requests[2].callback('failure', nil) end
          if failure == 'malformed-slave' then state.requests[2].callback(nil, {{ 'port', '6379' }}) end
        end
        assert(rawequal(params.write_servers, original))
        assert(state.successes == 0 and state.failures > 0)
      end)
      assert_true(true)
    end)
  end

  test('Sentinel schema rejects invalid TLS configuration', function()
    with_sentinel({}, function(redis)
      local schema = require('lua_shape.registry').global():resolve_schema(redis.enrich_schema())
      assert(not schema:check({ servers = 'localhost', sentinel = { ssl = 'yes' } }))
      assert(schema:check({ servers = 'localhost', sentinel = { ssl = true, no_ssl_verify = false } }))
      assert(not pcall(redis.try_load_redis_servers,
          { servers = 'localhost', sentinel = { ssl = 'yes' } }, rspamd_config, true))
    end)
    assert_true(true)
  end)

  test('synchronous discovery tries each Sentinel after an unresolved endpoint', function()
    with_sentinel({}, function(_, params, state)
      local good = params.sentinels:all_upstreams()[1]
      local bad = { get_addr = function() end, fail = function() end }
      params.sentinels = {
        all_upstreams = function() return { bad, good } end,
        get_upstream_round_robin = function() return bad end,
      }
      assert(state.sync() == nil)
      assert(#state.connects == 2)
      assert(params.write_servers_str == '127.0.0.1:6379')
    end)
    assert_true(true)
  end)

  for _, task in ipairs({ false, true }) do
    test((task and 'task' or 'taskless') .. ' script upload retries a stale bootstrap connection', function()
      with_sentinel({}, function(redis, params, state)
        local id = redis.add_redis_script('return 1', params)
        state.reject_scripts = true
        local attrs = task and { task = state.task } or { ev_base = 'event-base' }
        redis.exec_redis_script(id, attrs, function() end, {}, {})
        assert(#state.requests == 2)
        state.reject_scripts = false
        state.loads[2](rspamd_config, 'event-base', {})
        state.ticks[#state.ticks]()
        assert(#state.requests == 4, 'connection initiation failure became permanent')
      end)
      assert_true(true)
    end)
  end

  test('background upload never executes a cancelled task waiter', function()
    with_sentinel({}, function(redis, params, state)
      local id = redis.add_redis_script('return 1', params)
      redis.exec_redis_script(id, { task = state.task }, function() error('cancelled task called') end, {}, {})
      assert(#state.timers == 1 and #state.requests == 2)
      assert(state.requests[1].task == nil and state.requests[1].ev_base == 'event-base')
      -- Cancellation removes the task timer. Completing a shared upload must
      -- not retain the scan in the global script wait queue.
      state.timers = {}
      state.requests[1].callback(nil, 'sha')
      state.requests[2].callback(nil, 'sha')
      assert(#state.requests == 2)
    end)
    assert_true(true)
  end)

  test('task script waiter times out without executing a later upload', function()
    with_sentinel({}, function(redis, params, state)
      local id = redis.add_redis_script('return 1', params)
      local calls, result = 0
      redis.exec_redis_script(id, { task = state.task }, function(err) calls = calls + 1; result = err end, {}, {})
      state.now = state.now + 2
      assert(state.timers[1]() == nil)
      assert(calls == 1 and result:match('Timeout'))
      state.requests[1].callback(nil, 'sha')
      assert(calls == 1 and #state.requests == 2)
    end)
    assert_true(true)
  end)

  test('task waiter retries a transport failure and executes after upload', function()
    with_sentinel({}, function(redis, params, state)
      local id = redis.add_redis_script('return 1', params)
      state.reject_scripts = true
      redis.exec_redis_script(id, { task = state.task }, function() end, {}, {})
      state.reject_scripts = false
      assert(state.timers[1]() > 0)
      assert(#state.requests == 4)
      state.requests[3].callback(nil, 'sha')
      state.requests[4].callback(nil, 'sha')
      assert(state.timers[1]() == nil)
      assert(state.requests[5].cmd == 'EVALSHA')
    end)
    assert_true(true)
  end)
end)
