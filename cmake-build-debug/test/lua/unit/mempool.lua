context("Memory pool unit tests", function()
  test("Mempool variables", function()
    local mempool = require "rspamd_mempool"

    local pool = mempool.create()

    assert_not_nil(pool)

    -- string
    pool:set_variable('a', 'bcd')
    local var = pool:get_variable('a')
    assert_equal(var, 'bcd')

    -- integer
    pool:set_variable('a', 1)
    var = pool:get_variable('a', 'double')
    assert_equal(var, 1)

    -- float
    pool:set_variable('a', 1.01)
    var = pool:get_variable('a', 'double')
    assert_equal(var, 1.01)

    -- boolean
    pool:set_variable('a', false)
    var = pool:get_variable('a', 'bool')
    assert_equal(var, false)

    -- multiple
    pool:set_variable('a', 'bcd', 1, 1.01, false)
    local v1, v2, v3, v4 = pool:get_variable('a', 'string,double,double,bool')
    assert_equal(v1, 'bcd')
    assert_equal(v2, 1)
    assert_equal(v3, 1.01)
    assert_equal(v4, false)

    local t = {1,2,3,4,5}
    pool:set_variable('a', t)
    local bucket = pool:get_variable('a', 'bucket')
    assert_rspamd_table_eq({
      expect = t,
      actual = bucket
    })

    pool:destroy()
  end)
end)