context("Lua stack discipline: UCL iteration", function()
  local ucl = require "ucl"

  test("pairs() over a wrapped array yields keys 1..n and terminates", function()
    local parser = ucl.parser()
    local res = parser:parse_string('["e1","e2","e3"]')
    assert(res)
    local arr = parser:get_object_wrapped()
    assert_equal(arr:type(), 'array')

    local keys, values = {}, {}
    for k, v in arr:pairs() do
      table.insert(keys, k)
      table.insert(values, v:unwrap())
    end

    assert_rspamd_table_eq({ expect = { 1, 2, 3 }, actual = keys })
    assert_rspamd_table_eq({ expect = { 'e1', 'e2', 'e3' }, actual = values })
  end)
end)
