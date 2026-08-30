-- Test some UCL stuff

context("UCL manipulation", function()
  local ucl = require "ucl"

  local parser = ucl.parser()
  local res, err = parser:parse_string('{"key":"val"}')
  assert(res)

  local reply = parser:get_object_wrapped()
  local expected = {
    key = 'ohlol',
    ololo = 'ohlol'
  }

  test("UCL transparent test: object", function()
    assert_equal(tostring(reply), '{"key":"val"}')
    assert_equal(reply:type(), 'object')
    assert_equal(reply:at('key'):unwrap(), 'val')
    reply.ololo = 'ohlol'
    reply.ololo = 'ohlol'
    reply.key = 'ohlol'
    assert_equal(reply:at('key'):unwrap(), 'ohlol')

    for k, v in reply:pairs() do
      assert_equal(expected[k], v:unwrap())
    end
  end)

  test("UCL transparent test: array", function()
    parser = ucl.parser()
    res, err = parser:parse_string('["e1","e2"]')
    assert(res)
    local ireply = parser:get_object_wrapped()

    assert_equal(tostring(ireply), '["e1","e2"]')
    assert_equal(ireply:type(), 'array')
    ireply[1] = 1
    ireply[1] = 1
    ireply[1] = 1
    ireply[1] = 1
    ireply[1] = 1
    ireply[ireply:len() + 1] = 100500
    local iexpected = { 1, "e2", 100500 }
    for k, v in ireply:ipairs() do
      assert_equal(v:unwrap(), iexpected[k])
    end
  end)

  test("UCL transparent test: concat", function()
    reply.tbl = ireply
    expected.tbl = iexpected
    for k, v in reply:pairs() do
      if type(expected[k]) == 'table' then
        for kk, vv in v:ipairs() do
          assert_equal(expected[k][kk], vv:unwrap())
        end
      else
        assert_equal(expected[k], v:unwrap())
      end
    end
  end)

  test("UCL transparent test: implicit conversion array->object", function()
    -- Assign empty table, so it'll be an array
    reply.t = {}
    assert_equal(reply.t:type(), 'array')
    -- We can convert empty table to object
    reply.t.test = 'test'
    assert_equal(reply.t:type(), 'object')
    assert_equal(reply.t.test:unwrap(), 'test')
  end)

  test("UCL untrusted parser: defaults are applied", function()
    local p = ucl.untrusted_parser()
    local limits = p:get_limits()

    assert_equal(limits.max_depth, 64)
    assert_equal(limits.max_nodes, 1000000)
    assert_equal(limits.max_alloc, 64 * 1024 * 1024)
    assert_equal(limits.max_key_length, 1024)
    assert_equal(limits.max_string_length, 16 * 1024 * 1024)
  end)

  test("UCL untrusted parser: rejects deep nesting", function()
    local p = ucl.untrusted_parser()
    local deep = string.rep('[', 1000) .. string.rep(']', 1000)
    local ok, err = p:parse_string(deep)

    assert_false(ok)
    assert_not_nil(err)
  end)

  test("UCL untrusted parser: accepts ordinary replies", function()
    local p = ucl.untrusted_parser()
    local ok = p:parse_string('{"verdict": "clean", "scores": [1, 2, 3]}')

    assert_true(ok)

    local obj = p:get_object()
    assert_equal(obj.verdict, 'clean')
    assert_equal(#obj.scores, 3)
  end)

  test("UCL untrusted parser: msgpack is bounded too", function()
    local p = ucl.untrusted_parser({ max_depth = 8 })
    -- 9 nested fixarrays, innermost holding int 1
    local deep = string.rep('\145', 9) .. '\1'
    local ok = p:parse_text(deep, 'msgpack')

    assert_false(ok)
  end)

  test("UCL untrusted parser: limits can be overridden", function()
    local p = ucl.untrusted_parser({ max_depth = 4, max_string_length = 8 })
    local limits = p:get_limits()

    -- Overridden fields change, the rest keep the untrusted defaults
    assert_equal(limits.max_depth, 4)
    assert_equal(limits.max_string_length, 8)
    assert_equal(limits.max_nodes, 1000000)

    assert_false(p:parse_string('[[[[[1]]]]]'))
  end)

  test("UCL untrusted parser: zero means unlimited", function()
    local p = ucl.untrusted_parser({ max_depth = 0 })
    local deep = string.rep('[', 2000) .. string.rep(']', 2000)

    assert_true(p:parse_string(deep))
  end)

  test("UCL parser: set_limits overlays without dropping the rest", function()
    local p = ucl.untrusted_parser()
    p:set_limits({ max_key_length = 4 })

    local limits = p:get_limits()
    assert_equal(limits.max_key_length, 4)
    assert_equal(limits.max_depth, 64)

    assert_false(p:parse_string('{"toolongkey": 1}'))
  end)

  test("UCL parser: default parser keeps the libucl defaults", function()
    local p = ucl.parser()
    local limits = p:get_limits()

    -- Only the depth guard is on by default, so existing callers are unchanged
    assert_equal(limits.max_depth, 1024)
    assert_equal(limits.max_nodes, 0)
    assert_equal(limits.max_alloc, 0)
  end)

  test("UCL parser: bad limit names are rejected", function()
    local p = ucl.parser()

    assert_false(pcall(function()
      p:set_limits({ max_dpeth = 4 })
    end))

    assert_false(pcall(function()
      p:set_limits({ max_depth = -1 })
    end))

    assert_false(pcall(function()
      p:set_limits({ max_depth = 'lots' })
    end))
  end)

  collectgarbage() -- To ensure we don't crash with asan
end)