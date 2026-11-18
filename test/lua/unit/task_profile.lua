-- lua_task_profile: option validation and sampling decisions with stub objects

context("lua_task_profile", function()
  local lua_task_profile = require "lua_task_profile"

  local function stub_cfg()
    local cfg = { calls = {} }
    function cfg:register_profiled_symbols(tbl)
      table.insert(self.calls, tbl)
      return true
    end
    return cfg
  end

  local function stub_task(prof)
    local task = { calls = {} }
    function task:get_symbols_profile(opts)
      table.insert(self.calls, opts or false)
      return prof
    end
    return task
  end

  local function seq(values)
    local i = 0
    return function()
      i = i + 1
      return values[i]
    end
  end

  local PROF = { names = { 'A' }, times = { 1.0 }, sync_times = { 1.0 }, flags = { 0 } }

  test("reason names", function()
    assert_equal(lua_task_profile.reason_names[0], 'none')
    assert_equal(lua_task_profile.reason_names[1], 'sampled')
    assert_equal(lua_task_profile.reason_names[2], 'slow')
  end)

  test("feature off returns nil, nil", function()
    local cfg = stub_cfg()
    local p, err = lua_task_profile.new(cfg, {})
    assert_nil(p)
    assert_nil(err)
    p, err = lua_task_profile.new(cfg, { sample_rate = 0, slow_time = 0, symbols = { 'A' } })
    assert_nil(p)
    assert_nil(err)
    p, err = lua_task_profile.new(cfg, nil)
    assert_nil(p)
    assert_nil(err)
    assert_equal(#cfg.calls, 0)
  end)

  test("invalid options", function()
    local cases = {
      { sample_rate = 'x', symbols = { 'A' } },
      { sample_rate = -0.1, symbols = { 'A' } },
      { sample_rate = 1.5, symbols = { 'A' } },
      { sample_rate = 0 / 0, symbols = { 'A' } },
      { slow_time = -1, symbols = { 'A' } },
      { slow_time = 'garbage', symbols = { 'A' } },
      { slow_time = '1x', symbols = { 'A' } },
      { slow_time = '5 parsecs', symbols = { 'A' } },
      { slow_time = {}, symbols = { 'A' } },
      { sample_rate = 0.1, max_slow_rate = -1, symbols = { 'A' } },
      { sample_rate = 0.1, max_slow_rate = 'x', symbols = { 'A' } },
      { sample_rate = 0.1, symbols = { '' } },
      { sample_rate = 0.1, symbols = { 1 } },
      { sample_rate = 0.1, symbols = 'A' },
      { sample_rate = 0.1, groups = { {} } },
      { sample_rate = 0.1 },
      { sample_rate = 0.1, groups = {}, symbols = {} },
      { slow_time = 1 },
    }
    for i, opts in ipairs(cases) do
      local cfg = stub_cfg()
      local p, err = lua_task_profile.new(cfg, opts)
      assert_nil(p, 'case ' .. i)
      assert_equal(type(err), 'string', 'case ' .. i)
      assert_equal(#cfg.calls, 0, 'case ' .. i)
    end
  end)

  test("sample_rate error mentions 0.1", function()
    local _, err = lua_task_profile.new(stub_cfg(), { sample_rate = 10, symbols = { 'A' } })
    assert_not_nil(err:find('0.1', 1, true))
  end)

  test("registration is called once with the right tables", function()
    local cfg = stub_cfg()
    local p, err = lua_task_profile.new(cfg, {
      sample_rate = 0.5, groups = { 'g1', 'g2' }, symbols = { 'S1' } })
    assert_nil(err)
    assert_not_nil(p)
    assert_equal(#cfg.calls, 1)
    assert_equal(#cfg.calls[1].groups, 2)
    assert_equal(cfg.calls[1].groups[1], 'g1')
    assert_equal(cfg.calls[1].groups[2], 'g2')
    assert_equal(#cfg.calls[1].symbols, 1)
    assert_equal(cfg.calls[1].symbols[1], 'S1')
    -- only groups
    cfg = stub_cfg()
    p = lua_task_profile.new(cfg, { sample_rate = 0.5, groups = { 'g' } })
    assert_not_nil(p)
    assert_equal(#cfg.calls[1].symbols, 0)
  end)

  test("defaults and string slow_time", function()
    local p = lua_task_profile.new(stub_cfg(), { sample_rate = 0.25, symbols = { 'A' } })
    assert_equal(p.sample_rate, 0.25)
    assert_equal(p.slow_time, 0)
    assert_equal(p.max_slow_rate, 1)
    p = lua_task_profile.new(stub_cfg(), { slow_time = '500', symbols = { 'A' } })
    assert_equal(p.slow_time, 500)
    p = lua_task_profile.new(stub_cfg(), { slow_time = '2s', symbols = { 'A' } })
    assert_equal(p.slow_time, 2)
    p = lua_task_profile.new(stub_cfg(), { slow_time = '500ms', symbols = { 'A' } })
    assert_equal(p.slow_time, 0.5)
    p = lua_task_profile.new(stub_cfg(), { slow_time = '100 ms', symbols = { 'A' } })
    assert_equal(p.slow_time, 0.1)
    p = lua_task_profile.new(stub_cfg(), { slow_time = '0.5', symbols = { 'A' } })
    assert_equal(p.slow_time, 0.5)
    p = lua_task_profile.new(stub_cfg(), { slow_time = 0.25, symbols = { 'A' } })
    assert_equal(p.slow_time, 0.25)
  end)

  test("rate 0 never samples, rate 1 always samples", function()
    local p = lua_task_profile.new(stub_cfg(), {
      sample_rate = 0, slow_time = 1, symbols = { 'A' }, rng = seq({ 0, 0, 0 }) })
    local task = stub_task(nil)
    for _ = 1, 3 do
      local reason, prof = p:collect(task)
      assert_equal(reason, 0)
      assert_nil(prof)
    end
    p = lua_task_profile.new(stub_cfg(), {
      sample_rate = 1, symbols = { 'A' }, rng = seq({ 0.999999, 0.5, 0 }) })
    for _ = 1, 3 do
      local reason, prof = p:collect(stub_task(PROF))
      assert_equal(reason, 1)
      assert_equal(prof, PROF)
    end
  end)

  test("coin on both sides of the rate", function()
    local p = lua_task_profile.new(stub_cfg(), {
      sample_rate = 0.3, symbols = { 'A' }, rng = seq({ 0.29, 0.3, 0.31 }) })
    local task = stub_task(PROF)
    assert_equal((p:collect(task)), 1)
    assert_equal((p:collect(task)), 0)
    assert_equal((p:collect(task)), 0)
  end)

  test("sampled wins over slow", function()
    local p = lua_task_profile.new(stub_cfg(), {
      sample_rate = 0.5, slow_time = 1, symbols = { 'A' }, rng = seq({ 0.1 }) })
    local task = stub_task(PROF)
    local reason = p:collect(task)
    assert_equal(reason, 1)
    assert_equal(#task.calls, 1)
    assert_equal(task.calls[1], false)
  end)

  test("nil profile on the sample path gives 0", function()
    local p = lua_task_profile.new(stub_cfg(), {
      sample_rate = 0.5, slow_time = 1, symbols = { 'A' }, rng = seq({ 0.1 }) })
    local task = stub_task(nil)
    local reason, prof = p:collect(task)
    assert_equal(reason, 0)
    assert_nil(prof)
    -- the slow path is not tried after a sampled coin
    assert_equal(#task.calls, 1)
  end)

  test("slow path passes min_time in milliseconds", function()
    local p = lua_task_profile.new(stub_cfg(), {
      slow_time = 0.5, symbols = { 'A' }, rng = seq({ 0.9, 0.9 }), now = function() return 0 end })
    local task = stub_task(nil)
    local reason, prof = p:collect(task)
    assert_equal(reason, 0)
    assert_nil(prof)
    assert_equal(#task.calls, 1)
    assert_equal(task.calls[1].min_time, 500)
    task = stub_task(PROF)
    reason, prof = p:collect(task)
    assert_equal(reason, 2)
    assert_equal(prof, PROF)
    assert_equal(task.calls[1].min_time, 500)
  end)

  test("token bucket: burst, refusal, refill", function()
    local now = 100
    local p = lua_task_profile.new(stub_cfg(), {
      slow_time = 0.1, max_slow_rate = 2, symbols = { 'A' },
      rng = function() return 0.9 end, now = function() return now end })
    local task = stub_task(PROF)
    assert_equal((p:collect(task)), 2)
    assert_equal((p:collect(task)), 2)
    assert_equal((p:collect(task)), 0)
    now = now + 0.25 -- half a token
    assert_equal((p:collect(task)), 0)
    now = now + 0.25 -- a whole one
    assert_equal((p:collect(task)), 2)
    assert_equal((p:collect(task)), 0)
    now = now + 1000 -- capped at capacity
    assert_equal((p:collect(task)), 2)
    assert_equal((p:collect(task)), 2)
    assert_equal((p:collect(task)), 0)
  end)

  test("token bucket: capacity is at least 1", function()
    local now = 0
    local p = lua_task_profile.new(stub_cfg(), {
      slow_time = 0.1, max_slow_rate = 0.5, symbols = { 'A' },
      rng = function() return 0.9 end, now = function() return now end })
    local task = stub_task(PROF)
    assert_equal((p:collect(task)), 2)
    assert_equal((p:collect(task)), 0)
    now = now + 2
    assert_equal((p:collect(task)), 2)
  end)

  test("max_slow_rate 0 is unlimited and rate never limits samples", function()
    local p = lua_task_profile.new(stub_cfg(), {
      slow_time = 0.1, max_slow_rate = 0, symbols = { 'A' },
      rng = function() return 0.9 end, now = function() return 0 end })
    local task = stub_task(PROF)
    for _ = 1, 50 do
      assert_equal((p:collect(task)), 2)
    end
    p = lua_task_profile.new(stub_cfg(), {
      sample_rate = 1, slow_time = 0.1, max_slow_rate = 1, symbols = { 'A' },
      rng = function() return 0 end, now = function() return 0 end })
    for _ = 1, 10 do
      assert_equal((p:collect(task)), 1)
    end
  end)

  test("different seeds give different coin sequences", function()
    local function coins(seed)
      local p = lua_task_profile.new(stub_cfg(), {
        sample_rate = 0.5, symbols = { 'A' }, seed = seed })
      local task = stub_task(PROF)
      local res = {}
      -- observe the coins through the decisions
      for _ = 1, 64 do
        res[#res + 1] = (p:collect(task)) == 1 and '1' or '0'
      end
      return table.concat(res)
    end
    assert_equal(coins(12345), coins(12345))
    assert_not_equal(coins(12345), coins(987654321))
  end)

  test("default generator is seeded randomly per profiler", function()
    local function first_values()
      local p = lua_task_profile.new(stub_cfg(), { sample_rate = 0.5, symbols = { 'A' } })
      p:collect(stub_task(PROF))
      local res = {}
      for i = 1, 32 do
        res[i] = string.format('%.12f', p.rng())
      end
      return table.concat(res, ',')
    end
    assert_not_equal(first_values(), first_values())
  end)

  test("the generator is created lazily, after fork", function()
    local p = lua_task_profile.new(stub_cfg(), { sample_rate = 0.5, symbols = { 'A' } })
    assert_nil(p.rng)
    p:collect(stub_task(PROF))
    assert_equal(type(p.rng), 'function')
  end)

  test("default generator stays within [0, 1)", function()
    local p = lua_task_profile.new(stub_cfg(), { sample_rate = 0.5, symbols = { 'A' } })
    -- the first collect seeds the generator lazily
    p:collect(stub_task(PROF))
    assert_equal(type(p.rng), 'function')
    local lo, hi = 1, 0
    for _ = 1, 10000 do
      local c = p.rng()
      assert_true(c >= 0 and c < 1)
      lo = math.min(lo, c)
      hi = math.max(hi, c)
    end
    assert_true(lo < 0.05 and hi > 0.95)
  end)
end)
