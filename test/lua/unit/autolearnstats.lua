local m = require 'rspamadm.autolearnstats'
local pad              = m._pad
local cell             = m._cell
local MAX_COL          = m._MAX_COL
local make_sort_key_fns = m._make_sort_key_fns

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

context("autolearnstats - sort_key_fns", function()
  local function make_entry(req_id, verdict, score, from, rcpts, ts)
    return {
      req_id = req_id,
      c = { verdict = verdict, score = score, from = from, rcpts = rcpts, ts = ts },
    }
  end

  local ips = { ['<aaa>'] = '1.2.3.4', ['<bbb>'] = '10.0.0.1' }
  local fns = make_sort_key_fns(ips)

  test("verdict key returns verdict string", function()
    local e = make_entry('<aaa>', 'spam', '8.5', 'a@b.c', 'x@y.z', '2026-01-01 00:00:00')
    assert_equal('spam', fns.verdict(e))
  end)

  test("score key returns number for positive score", function()
    local e = make_entry('<aaa>', 'spam', '8.5', 'a@b.c', 'x@y.z', '2026-01-01 00:00:00')
    assert_equal(8.5, fns.score(e))
  end)

  test("score key returns number for negative score", function()
    local e = make_entry('<aaa>', 'ham', '-4.0', 'a@b.c', 'x@y.z', '2026-01-01 00:00:00')
    assert_equal(-4.0, fns.score(e))
  end)

  test("score numeric order is correct (not lexicographic)", function()
    local e10 = make_entry('<a>', 'spam', '10.0', '', '', '2026-01-01 00:00:00')
    local e9  = make_entry('<b>', 'spam',  '9.0', '', '', '2026-01-01 00:00:01')
    assert_true(fns.score(e9) < fns.score(e10))
  end)

  test("ts key returns timestamp string", function()
    local e = make_entry('<aaa>', 'spam', '8.5', 'a@b.c', 'x@y.z', '2026-05-21 12:34:56')
    assert_equal('2026-05-21 12:34:56', fns.ts(e))
  end)

  test("tid key strips angle brackets", function()
    local e = make_entry('<abc123>', 'spam', '1.0', '', '', '')
    assert_equal('abc123', fns.tid(e))
  end)

  test("ip key returns IP from ips table", function()
    local e = make_entry('<aaa>', 'spam', '1.0', '', '', '')
    assert_equal('1.2.3.4', fns.ip(e))
  end)

  test("ip key returns '-' for unknown req_id", function()
    local e = make_entry('<zzz>', 'spam', '1.0', '', '', '')
    assert_equal('-', fns.ip(e))
  end)

  test("from key returns from field", function()
    local e = make_entry('<aaa>', 'spam', '1.0', 'sender@example.com', '', '')
    assert_equal('sender@example.com', fns.from(e))
  end)

  test("sort by verdict then ts preserves time order within group", function()
    local entries = {
      make_entry('<c>', 'spam', '8.0', '', '', '2026-01-01 00:00:03'),
      make_entry('<a>', 'ham',  '8.0', '', '', '2026-01-01 00:00:01'),
      make_entry('<b>', 'spam', '8.0', '', '', '2026-01-01 00:00:02'),
      make_entry('<d>', 'ham',  '8.0', '', '', '2026-01-01 00:00:04'),
    }
    -- Simulate pre-computed sort_key as handler does
    local key_fn = fns.verdict
    for _, e in ipairs(entries) do e.sort_key = key_fn(e) end
    table.sort(entries, function(a, b)
      if a.sort_key ~= b.sort_key then return a.sort_key < b.sort_key end
      return a.c.ts < b.c.ts
    end)
    -- 'ham' < 'spam' lexicographically; within ham: a(01) before d(04)
    assert_equal('ham',  entries[1].c.verdict)
    assert_equal('<a>',  entries[1].req_id)
    assert_equal('ham',  entries[2].c.verdict)
    assert_equal('<d>',  entries[2].req_id)
    assert_equal('spam', entries[3].c.verdict)
    assert_equal('<b>',  entries[3].req_id)
    assert_equal('spam', entries[4].c.verdict)
    assert_equal('<c>',  entries[4].req_id)
  end)

  test("ts key used as default when no sort-by specified (--group without --sort-by)", function()
    local entries = {
      make_entry('<b>', 'spam', '8.0', '', '', '2026-01-01 00:00:02'),
      make_entry('<a>', 'ham',  '8.0', '', '', '2026-01-01 00:00:01'),
      make_entry('<c>', 'spam', '8.0', '', '', '2026-01-01 00:00:02'),
    }
    local key_fn = fns.ts  -- effective_sort = 'ts' when sort_by is nil
    for _, e in ipairs(entries) do e.sort_key = key_fn(e) end
    table.sort(entries, function(a, b) return a.sort_key < b.sort_key end)
    assert_equal('<a>', entries[1].req_id)
    -- b and c share the same ts: sort_key equal, group separator fires between
    -- a unique ts and the repeated one
    assert_equal(entries[2].sort_key, entries[3].sort_key)
  end)
end)
