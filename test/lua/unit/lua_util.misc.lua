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