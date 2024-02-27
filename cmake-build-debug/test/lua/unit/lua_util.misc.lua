local util  = require 'lua_util'

context("Lua util - callback_from_string", function()
  local cases = {
    {'return function', 'return function(a, b) return a + b end'},
    {'function', 'function(a, b) return a + b end'},
    {'plain ops', 'local c = select(1, ...)\nreturn c + select(2, ...)'},
  }
  local fail_cases = {
    nil,
    '',
    'return function(a, b) ( end',
    'function(a, b) ( end',
    'return a + b'
  }

  for _,c in ipairs(cases) do
    test('Success case: ' .. c[1], function()
      local ret,f = util.callback_from_string(c[2])
      assert_true(ret, f)
      assert_equal(f(2, 2), 4)
    end)
  end
  for i,c in ipairs(fail_cases) do
    test('Failure case: ' .. tostring(i), function()
      local ret,f = util.callback_from_string(c)
      assert_false(ret)
    end)
  end
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
