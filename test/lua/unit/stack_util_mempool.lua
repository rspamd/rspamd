context("Lua stack discipline: mempool", function()
  local mempool = require "rspamd_mempool"

  test("suggest_size returns a number", function()
    local pool = mempool.create()
    local sz = pool:suggest_size()
    assert_equal(type(sz), 'number')
    assert_true(sz >= 0)
    pool:destroy()
  end)

  test("set_bucket with varargs stores exactly num_values numbers", function()
    local pool = mempool.create()
    pool:set_bucket('b', 3, 1, 2, 3)
    local bucket = pool:get_variable('b', 'bucket')
    assert_rspamd_table_eq({
      expect = { 1, 2, 3 },
      actual = bucket
    })
    pool:destroy()
  end)
end)
