local lua_greylist = require "lua_greylist"

local function new_task()
  local cache = {}
  return {
    cache_get = function(_, key) return cache[key] end,
    cache_set = function(_, key, value) cache[key] = value end,
  }
end

context("Greylist requests", function()
  test("Scopes aggregate independently in either order", function()
    for _, reverse in ipairs({ false, true }) do
      local task = new_task()
      local first = { module = 'first', body = 600, meta = 837 }
      local second = { module = 'second', body = 1800, meta = 700 }
      lua_greylist.request(task, reverse and second or first)
      lua_greylist.request(task, reverse and first or second)
      local requests = lua_greylist.get_requests(task)
      assert_equal(requests.body.timeout, 1800)
      assert_equal(requests.body.module, 'second')
      assert_equal(requests.meta.timeout, 837)
      assert_equal(requests.meta.module, 'first')
    end
  end)

  test("Requests are isolated per task", function()
    local first, second = new_task(), new_task()
    lua_greylist.request(first, { module = 'test', meta = 837 })
    assert_nil(lua_greylist.get_requests(first).body)
    assert_nil(lua_greylist.get_requests(second).meta)
  end)

  test("Classic requests do not replace explicit requests", function()
    local task = new_task()
    lua_greylist.request(task, { module = 'test', body = 600 })
    lua_greylist.request_classic(task)
    local requests = lua_greylist.get_requests(task)
    assert_true(requests.classic)
    assert_equal(requests.body.timeout, 600)
    assert_nil(requests.meta)
  end)

  test("Equal durations have deterministic attribution", function()
    local task = new_task()
    lua_greylist.request(task, { module = 'zeta', body = 600 })
    lua_greylist.request(task, { module = 'alpha', body = 600 })
    assert_equal(lua_greylist.get_requests(task).body.module, 'alpha')
  end)

  test("Invalid requests do not partially mutate state", function()
    local task = new_task()
    local invalid = {
      {}, { module = 'test' }, { module = '', body = 600 },
      { module = 'test', body = 0 }, { module = 'test', body = -1 },
      { module = 'test', body = math.huge }, { module = 'test', body = 0 / 0 },
      { module = 'test', body = '600' }, { module = 'test', body = 600, meta = false },
    }
    for _, options in ipairs(invalid) do
      assert_false(pcall(lua_greylist.request, task, options))
      assert_nil(lua_greylist.get_requests(task).body)
      assert_nil(lua_greylist.get_requests(task).meta)
    end
  end)
end)

context("Greylist records", function()
  test("Classic and explicit records round trip", function()
    local classic = lua_greylist.decode_record('1000', 300)
    assert_equal(classic.timestamp, 1000)
    assert_equal(classic.timeout, 300)
    assert_false(classic.explicit)
    assert_equal(lua_greylist.encode_record(classic), '1000')
    local explicit = lua_greylist.decode_record('1000:837:!testmod', 300)
    assert_equal(explicit.timeout, 837)
    assert_equal(explicit.module, 'testmod')
    assert_true(explicit.explicit)
    assert_equal(lua_greylist.encode_record(explicit), '1000:837:!testmod')
  end)

  test("Invalid records are rejected", function()
    assert_nil(lua_greylist.decode_record('1000:600', 300))
    assert_nil(lua_greylist.decode_record('1000:600:testmod', 300))
    assert_nil(lua_greylist.decode_record('invalid', 300))
    assert_nil(lua_greylist.decode_record('1000:bad:!testmod', 300))
  end)

  test("Encoding sanitises attribution including an empty module", function()
    local record = { timestamp = 1000, timeout = 600, explicit = true, module = 'test module!' }
    assert_equal(lua_greylist.encode_record(record), '1000:600:!testmodule')
    record.module = '!!!'
    local decoded = lua_greylist.decode_record(lua_greylist.encode_record(record), 300)
    assert_equal(decoded.module, '')
    assert_equal(decoded.timeout, 600)
  end)

  test("A record matures exactly at its deadline", function()
    local record = lua_greylist.decode_record('1000:600:!testmod', 300)
    assert_true(lua_greylist.record_pending(record, 1599.9))
    assert_false(lua_greylist.record_pending(record, 1600))
    assert_false(lua_greylist.record_pending(nil, 1600))
    assert_equal(lua_greylist.decode_record('1000:100:!testmod', 300).timeout, 300)
  end)

  test("Planning credits elapsed time and cannot shorten a request", function()
    local request = { timeout = 837, module = 'testmod' }
    local record = lua_greylist.decode_record('1000', 300)
    local plan = lua_greylist.plan_record(record, request, 300, 86400, 1400)
    assert_equal(plan.timestamp, 1000)
    assert_equal(plan.deadline, 1837)
    assert_equal(plan.expire, 86400)
    assert_equal(lua_greylist.encode_record(plan), '1000:837:!testmod')
    local longer = lua_greylist.decode_record('1000:1800:!original', 300)
    assert_equal(lua_greylist.plan_record(longer, request, 300, 86400, 1400).timeout, 1800)
  end)

  test("Planning and satisfaction use the same rounded deadline", function()
    local record = lua_greylist.decode_record('1000', 300)
    local request = { timeout = 600.5, module = 'testmod' }
    local plan = lua_greylist.plan_record(record, request, 300, 600, 1400)
    assert_equal(plan.timeout, 601)
    assert_equal(plan.expire, 1201)
    assert_false(lua_greylist.request_satisfied(record, request, 300, plan.deadline - 0.1))
    assert_true(lua_greylist.request_satisfied(record, request, 300, plan.deadline))
    assert_false(lua_greylist.request_satisfied(nil, request, 300, plan.deadline))
    assert_true(lua_greylist.request_satisfied(nil, nil, 300, plan.deadline))
  end)

  test("Classic planning keeps the global delay without explicit metadata", function()
    local plan = lua_greylist.plan_record(nil, nil, 300, 86400, 1000.9)
    assert_equal(plan.timestamp, 1000)
    assert_equal(plan.deadline, 1300)
    assert_false(plan.explicit)
    assert_nil(plan.module)
    assert_equal(lua_greylist.encode_record(plan), '1000')
    assert_equal(lua_greylist.plan_record(nil, { timeout = 100, module = 'test' }, 300, 300, 1000).expire, 600)
  end)
end)
