-- Unit tests for lua_redis.prepare_redis_setup
--
-- The actual sentinel resolution and SCRIPT LOAD paths require a running
-- Redis Sentinel cluster, which is out of scope for unit tests. These tests
-- exercise the public surface: argument validation, callback semantics, and
-- the no-op success path (no sentinels configured, no scripts registered for
-- the supplied redis_params).

context("lua_redis.prepare_redis_setup", function()
  local lua_redis = require "lua_redis"

  test("errors when redis_params is missing", function()
    local captured
    lua_redis.prepare_redis_setup(nil, { ev_base = 'x', session = 'x' },
        function(err) captured = err end)
    assert_not_nil(captured)
  end)

  test("errors when redis_params is wrong type", function()
    local captured
    lua_redis.prepare_redis_setup('not a table', { ev_base = 'x', session = 'x' },
        function(err) captured = err end)
    assert_not_nil(captured)
  end)

  test("errors when ev_base is unavailable", function()
    local captured
    lua_redis.prepare_redis_setup({}, { session = 'x' },
        function(err) captured = err end)
    assert_not_nil(captured)
  end)

  test("errors when session is unavailable", function()
    local captured
    lua_redis.prepare_redis_setup({}, { ev_base = 'x' },
        function(err) captured = err end)
    assert_not_nil(captured)
  end)

  test("opts argument is optional (callback in 2nd slot)", function()
    -- Without rspamadm globals the validation path should still fire and
    -- return an error string via the callback rather than throwing.
    local called = false
    local captured
    lua_redis.prepare_redis_setup({}, function(err)
      called = true
      captured = err
    end)
    assert_true(called)
    -- ev_base global is absent in rspamd-test → expect error string.
    assert_not_nil(captured)
  end)

  test("callback receives nil on no-op success path", function()
    -- redis_params with no sentinels and no registered scripts → both setup
    -- branches short-circuit; ev_base/session never get dereferenced so we
    -- can pass placeholder truthy values through opts.
    local called = false
    local captured = 'sentinel'
    lua_redis.prepare_redis_setup({}, {
      ev_base = 'fake_ev_base',
      session = 'fake_session',
    }, function(err)
      called = true
      captured = err
    end)
    assert_true(called)
    assert_nil(captured)
  end)

  test("opts.scripts = false skips script loading", function()
    -- Same no-op shape but explicitly disable scripts; should still succeed.
    local captured = 'sentinel'
    lua_redis.prepare_redis_setup({}, {
      ev_base = 'fake_ev_base',
      session = 'fake_session',
      scripts = false,
    }, function(err) captured = err end)
    assert_nil(captured)
  end)

  test("opts.sentinels = false skips sentinel resolution", function()
    -- Even if redis_params.sentinels were truthy, opts.sentinels=false should
    -- bypass that branch. Use a marker that would otherwise crash the sync
    -- resolver (no all_upstreams() method on a string) to prove the bypass.
    local captured = 'sentinel'
    lua_redis.prepare_redis_setup({ sentinels = 'definitely-not-an-upstream-list' }, {
      ev_base = 'fake_ev_base',
      session = 'fake_session',
      sentinels = false,
    }, function(err) captured = err end)
    assert_nil(captured)
  end)

  test("non-function callback raises", function()
    local ok = pcall(lua_redis.prepare_redis_setup, {}, {}, 'not a function')
    assert_false(ok)
  end)
end)
