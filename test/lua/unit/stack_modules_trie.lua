-- Stack discipline of trie:match with a table of inputs

context("Trie match with table input", function()
  local t = require "rspamd_trie"
  local trie = t.create({'ab', 'cd'})

  local function sorted(tbl)
    local r = {}
    for _, v in ipairs(tbl) do
      table.insert(r, v)
    end
    table.sort(r)
    return r
  end

  test("no callback returns the result table, not the input", function()
    local input = {'xabx', 'cdcd'}
    local m = trie:match(input)

    assert_equal('table', type(m))
    assert_rspamd_table_eq({expect = {'xabx', 'cdcd'}, actual = input})
    -- 'ab' ends at 3 in the first string, 'cd' ends at 2 and 4 in the second
    assert_rspamd_table_eq({expect = {3}, actual = sorted(m[1])})
    assert_rspamd_table_eq({expect = {2, 4}, actual = sorted(m[2])})
  end)

  test("no callback with report_start returns {start, end} pairs", function()
    local som = t.create({'ab', 'cd'}, t.flags.som)
    local m = som:match({'xabx', 'cdcd'}, true)

    assert_equal('table', type(m))
    assert_equal(1, #m[1])
    assert_equal(2, #m[2])
    assert_equal(1, m[1][1][1])
    assert_equal(3, m[1][1][2])
  end)

  test("callback form returns boolean and sees all matches", function()
    local seen = {}
    local ret = trie:match({'xabx', 'cdcd'}, function(idx, pos)
      table.insert(seen, idx * 100 + pos)
      return 0
    end)

    assert_equal(true, ret)
    assert_rspamd_table_eq({expect = {103, 202, 204}, actual = sorted(seen)})
  end)

  test("callback form without matches returns false", function()
    local ret = trie:match({'xxx', 'yyy'}, function() return 0 end)
    assert_equal(false, ret)
  end)
end)
