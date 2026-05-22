-- Upstream list / upstream object tests

context("Upstream lua API", function()
  local upstream_list = require "rspamd_upstream_list"

  test("create from comma-separated string", function()
    local ups = upstream_list.create('127.0.0.1,127.0.0.2,127.0.0.3', 11333)
    assert_not_nil(ups)
    local all = ups:all_upstreams()
    assert_equal(#all, 3)
  end)

  test("get_upstream_round_robin returns a usable upstream", function()
    local ups = upstream_list.create('127.0.0.1,127.0.0.2', 11333)
    assert_not_nil(ups)
    local up = ups:get_upstream_round_robin()
    assert_not_nil(up)
    assert_not_nil(up:get_name())
    assert_not_nil(up:get_port())
    up:ok()
  end)

  test("get_upstream_by_hash with the same key is stable", function()
    local ups = upstream_list.create('127.0.0.1,127.0.0.2,127.0.0.3', 11333)
    local first = ups:get_upstream_by_hash('hello')
    local second = ups:get_upstream_by_hash('hello')
    assert_not_nil(first)
    assert_not_nil(second)
    assert_equal(first:get_name(), second:get_name())
    first:ok()
    second:ok()
  end)

  test("dropping a wrapper without ok/fail does not crash", function()
    -- Smoke test for the __gc retire-on-drop fallback. Repeatedly acquire
    -- and immediately abandon wrappers; the destructor must release the
    -- inflight reference without blowing up. We then verify we can still
    -- get usable wrappers from the same list.
    local ups = upstream_list.create('127.0.0.1,127.0.0.2,127.0.0.3', 11333)
    for _ = 1, 50 do
      local up = ups:get_upstream_round_robin()
      assert_not_nil(up)
      up = nil
    end
    collectgarbage('collect')

    local survivor = ups:get_upstream_round_robin()
    assert_not_nil(survivor)
    survivor:ok()
  end)

  test("all_upstreams() wrappers are safe to drop", function()
    -- all_upstreams() is a view, not an acquisition: dropping the table
    -- must not retire any inflight reference (there is none to retire).
    local ups = upstream_list.create('127.0.0.1,127.0.0.2', 11333)
    for _ = 1, 20 do
      local all = ups:all_upstreams()
      assert_equal(#all, 2)
      all = nil
    end
    collectgarbage('collect')

    -- Subsequent operations still work.
    local up = ups:get_upstream_round_robin()
    assert_not_nil(up)
    up:ok()
  end)

  test("calling :ok then :fail on the same wrapper is safe", function()
    -- The retired flag prevents the __gc from also retiring; explicit
    -- pairs of ok/fail still drive the underlying upstream, but the
    -- per-wrapper inflight is decremented only once.
    local ups = upstream_list.create('127.0.0.1', 11333)
    local up = ups:get_upstream_round_robin()
    assert_not_nil(up)
    up:ok()
    up:fail('test')
    up:ok()
    up = nil
    collectgarbage('collect')
  end)
end)
