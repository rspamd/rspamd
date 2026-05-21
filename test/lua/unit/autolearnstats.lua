local m = require 'rspamadm.autolearnstats'
local pad     = m._pad
local cell    = m._cell
local MAX_COL = m._MAX_COL

context("autolearnstats - pad", function()
  test("pads short string to given width", function()
    assert_equal("hi   ", pad("hi", 5))
    assert_equal(5, #pad("hi", 5))
  end)

  test("returns string unchanged when length equals width", function()
    assert_equal("hello", pad("hello", 5))
  end)

  test("returns string unchanged when longer than width", function()
    assert_equal("toolong", pad("toolong", 4))
  end)

  test("works for width >= 100 without string.format crash", function()
    local result = pad("x", 100)
    assert_equal(100, #result)
    assert_equal("x", result:sub(1, 1))
    assert_equal(" ", result:sub(100, 100))
  end)
end)

context("autolearnstats - cell", function()
  test("pads short string to given width", function()
    local result = cell("hi", 10)
    assert_equal(10, #result)
    assert_equal("hi        ", result)
  end)

  test("returns string unchanged when length equals width", function()
    local result = cell("hello", 5)
    assert_equal("hello", result)
    assert_equal(5, #result)
  end)

  test("truncates long string and appends '..'", function()
    local result = cell("very long string here", 10)
    assert_equal(10, #result)
    assert_equal("very lon..", result)
  end)

  test("truncated suffix is always '..'", function()
    local result = cell(string.rep("a", 80), 40)
    assert_equal("..", result:sub(39, 40))
  end)

  test("result is always exactly n chars for short input", function()
    for _, n in ipairs({4, 5, 10, 40, 60, 99, 100, 150}) do
      local result = cell("x", n)
      assert_equal(n, #result,
        string.format("cell('x', %d): expected length %d, got %d", n, n, #result))
    end
  end)

  test("result is always exactly n chars for long input", function()
    local long = string.rep("a", 200)
    for _, n in ipairs({4, 5, 10, 40, 60, 99, 100, 150}) do
      local result = cell(long, n)
      assert_equal(n, #result,
        string.format("cell(200*'a', %d): expected length %d, got %d", n, n, #result))
    end
  end)

  test("no crash and correct truncation for width >= 100 (LuaJIT regression)", function()
    -- Prior to the fix, string.format("%-176s", ...) in the table header crashed
    -- because LuaJIT only parses 2-digit format widths.  cell() itself must not
    -- crash for any width and must return a string of exactly that width.
    local long = string.rep("a", 200)
    local result = cell(long, 176)
    assert_equal(176, #result)
    assert_equal("..", result:sub(175, 176))
  end)

  test("MAX_COL is 60", function()
    assert_equal(60, MAX_COL)
  end)
end)
