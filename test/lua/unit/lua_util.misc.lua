local util  = require 'lua_util'

context("Lua util - callback_from_string", function()
  local cases = {
    {'return function', 'return function(a, b) return a + b end'},
    {'function', 'function(a, b) return a + b end'},
    {'plain ops', 'local c = select(1, ...)\nreturn c + select(2, ...)'},
  }
  -- Wrapped in {label, value} pairs: a bare nil first element would end the
  -- ipairs walk immediately and silently register none of these as tests
  local fail_cases = {
    { 'nil', nil },
    { 'empty string', '' },
    { 'return function syntax error', 'return function(a, b) ( end' },
    { 'function syntax error', 'function(a, b) ( end' },
  }

  for _,c in ipairs(cases) do
    test('Success case: ' .. c[1], function()
      local ret,f = util.callback_from_string(c[2])
      assert_true(ret, f)
      assert_equal(f(2, 2), 4)
    end)
  end
  for _,c in ipairs(fail_cases) do
    test('Failure case: ' .. c[1], function()
      local ret,err = util.callback_from_string(c[2])
      assert_false(ret)
      assert_equal(type(err), 'string')
    end)
  end

  -- A bare expression is wrapped into 'return function(...) <s>; end', so it
  -- compiles even when it references undefined globals: the error surfaces on
  -- the first call, not at load time
  test('a bare expression compiles into a callback that may fail when called', function()
    local ret, f = util.callback_from_string('return a + b')
    assert_true(ret, f)
    assert_false((pcall(f)))
  end)

  test('chunkname appears in syntax error message', function()
    local ret, err = util.callback_from_string('return function(a, b) ( end', 'my_chunk')
    assert_false(ret)
    assert_not_nil(string.find(err, 'my_chunk', 1, true), err)
  end)

  test('whole chunk may set up locals before returning a callback', function()
    local ret, callback = util.callback_from_string(
      'local offset = 3\nreturn function(value) return value + offset end',
      'setup_chunk', true)
    assert_true(ret, callback)
    assert_equal(callback(2), 5)
  end)

  test('non-string input is rejected without throwing', function()
    local ok, ret, err = pcall(util.callback_from_string, {}, 'bad_chunk', true)
    assert_true(ok)
    assert_false(ret)
    assert_equal(err, 'invalid or empty string')
  end)

  -- A valid chunk that yields no callback must report a string error: callers
  -- feed the second return value straight into string.format('%s', ...), which
  -- throws on nil or on a table under LuaJIT
  for _, c in ipairs({
    { 'nothing', 'local x = 1', 'nil' },
    { 'a table', 'return { 1, 2 }', 'table' },
    { 'a string', 'return "not a function"', 'string' },
  }) do
    test('chunk returning ' .. c[1] .. ' yields a string error', function()
      local ret, err = util.callback_from_string(c[2], 'no_callback_chunk', true)
      assert_false(ret)
      assert_equal(type(err), 'string')
      assert_not_nil(string.find(err, c[3], 1, true), err)
    end)
  end

  test('runtime error inside the chunk yields a string error', function()
    local ret, err = util.callback_from_string('error("boom")', 'boom_chunk', true)
    assert_false(ret)
    assert_equal(type(err), 'string')
    assert_not_nil(string.find(err, 'boom', 1, true), err)
  end)
end)

context("Lua util - str_endswith", function()
  local ending = {
    {'a', 'a'},
    {'ab', 'b'},
    {'ab', 'ab'},
    {'abc', 'bc'},
    {'any', ''},
  }
  local not_ending = {
    {'a', 'b'},
    {'', 'a'},
    {'ab', 'a'},
    {'ab', 'ba'},
    {'ab', 'lab'},
    {'abc', 'ab'},
    {'abcd', 'bc'},
    {'a', 'A'},
    {'aB', 'b'},
  }
  for _, c in ipairs(ending) do
    test(string.format('True case: str_endswith("%s", "%s")', c[1], c[2]), function()
      assert_true(util.str_endswith(c[1], c[2]))
    end)
  end
  for _, c in ipairs(not_ending) do
    test(string.format('False case: str_endswith("%s", "%s")', c[1], c[2]), function()
      assert_false(util.str_endswith(c[1], c[2]))
    end)
  end
end)
