-- Test some UCL stuff

context("UCL manipulation", function()
  local ucl = require "ucl"

  test("UCL transparent test", function()
    local parser = ucl.parser()
    local res, err = parser:parse_string('{"key":"val"}')
    assert(res)

    local reply = parser:get_object_wrapped()

    assert_equal(tostring(reply), '{"key":"val"}')
    assert_equal(reply:type(), 'object')
    assert_equal(reply:at('key'):unwrap(), 'val')
    reply.ololo = 'ohlol'
    reply.ololo = 'ohlol'
    reply.key = 'ohlol'
    assert_equal(reply:at('key'):unwrap(), 'ohlol')
    local expected = {
      key = 'ohlol',
      ololo = 'ohlol'
    }
    for k, v in reply:pairs() do
      assert_equal(expected[k], v:unwrap())
    end

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
    ireply[#ireply + 1] = 100500
    local iexpected = { 1, 1, 1, 1, 1, "e1", "e2", 100500 }
    for k, v in ireply:ipairs() do
      assert_equal(iexpected[k], v:unwrap())
    end

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

    collectgarbage() -- To ensure we don't crash with asan
  end)
end)