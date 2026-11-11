-- Trie search tests

context("Trie search functions", function()
  local t = require "rspamd_trie"
  local logger = require "rspamd_logger"
  local patterns = {
    'test',
    'est',
    'he',
    'she',
    'str\1ing'
  }

  local trie = t.create(patterns)

  local cases = {
    {'test', true, {{4, 1}, {4, 2}}},
    {'she test test', true, {{3, 4}, {3, 3}, {8, 1}, {8, 2}, {13, 1}, {13, 2}}},
    {'non-existent', false},
    {'str\1ing test', true, {{7, 5}, {12, 1}, {12, 2}}},
  }

  local function cmp_tables(t1, t2)
    if t1[2] ~= t2[2] then
      return t1[2] < t2[2]
    else
      return t1[1] < t2[1]
    end
  end

  for i,c in ipairs(cases) do
    test("Trie search " .. i, function()
      local res = {}
      local function cb(idx, pos)
        table.insert(res, {pos, idx})

        return 0
      end

      ret = trie:match(c[1], cb)

      assert_equal(c[2], ret, tostring(c[2]) .. ' while matching ' .. c[1])

      if ret then
        table.sort(c[3], cmp_tables)
        table.sort(res, cmp_tables)
        assert_rspamd_table_eq({
          expect = c[3],
          actual = res
        })
      end
    end)
  end

  for i,c in ipairs(cases) do
    test("Trie search, table version " .. i, function()
      local match = {}

      match = trie:match(c[1])

      assert_equal(c[2], #match > 0, tostring(c[2]) .. ' while matching ' .. c[1])

      if match and #match > 0 then
        local res = {}
        -- Convert to something that this test expects
        for pat,hits in pairs(match) do
          for _,pos in ipairs(hits) do
            table.insert(res, {pos, pat})
          end
        end
        table.sort(c[3], cmp_tables)
        table.sort(res, cmp_tables)
        assert_rspamd_table_eq({
          expect = c[3],
          actual = res
        })
      end
    end)
  end

end)

context("Trie start-of-match (SOM) offsets", function()
  local t = require "rspamd_trie"
  local bit = require "bit"

  -- Offsets are byte offsets: start is 0-based inclusive, end is 0-based
  -- exclusive (one past the last matched byte), so end - start == match length.
  -- This is exactly what the YARA-style helpers need for #s / @s[i] / "$s at X".

  -- {start, end, pattern_idx} ordering helper
  local function cmp(a, b)
    if a[3] ~= b[3] then return a[3] < b[3] end
    if a[1] ~= b[1] then return a[1] < b[1] end
    return a[2] < b[2]
  end

  test("flags.som is exposed", function()
    assert_not_nil(t.flags.som, "rspamd_trie.flags.som must exist")
  end)

  test("literal patterns report every occurrence as {start, end}", function()
    -- "abcab": 'ab' (id1) at [0,2) and [3,5); 'bc' (id2) at [1,3)
    local trie = t.create({'ab', 'bc'}, t.flags.som)
    local m = trie:match('abcab', true)

    -- Count semantics (#s): two occurrences of 'ab', one of 'bc'
    assert_equal(2, #m[1])
    assert_equal(1, #m[2])

    -- @s[i]: first 'ab' starts at offset 0, second at offset 3
    assert_equal(0, m[1][1][1])
    assert_equal(3, m[1][2][1])

    local res = {}
    for idx, hits in pairs(m) do
      for _, se in ipairs(hits) do
        table.insert(res, {se[1], se[2], idx})
      end
    end
    local expect = {{0, 2, 1}, {3, 5, 1}, {1, 3, 2}}
    table.sort(res, cmp)
    table.sort(expect, cmp)
    assert_rspamd_table_eq({expect = expect, actual = res})
  end)

  test("callback form reports {start, end} when report_start is set", function()
    local trie = t.create({'ab', 'bc'}, t.flags.som)
    local res = {}
    trie:match('abcab', function(idx, se)
      table.insert(res, {se[1], se[2], idx})
      return 0
    end, true)

    local expect = {{0, 2, 1}, {3, 5, 1}, {1, 3, 2}}
    table.sort(res, cmp)
    table.sort(expect, cmp)
    assert_rspamd_table_eq({expect = expect, actual = res})
  end)

  test("regex patterns report real start offsets", function()
    -- fixed-length regex 'a.c' at [0,3) and [4,7) in "axc-ayc"
    local trie = t.create({'a.c'}, bit.bor(t.flags.re, t.flags.som))
    local m = trie:match('axc-ayc', true)

    assert_equal(2, #m[1])
    local res = {}
    for _, se in ipairs(m[1]) do
      table.insert(res, {se[1], se[2], 1})
    end
    local expect = {{0, 3, 1}, {4, 7, 1}}
    table.sort(res, cmp)
    table.sort(expect, cmp)
    assert_rspamd_table_eq({expect = expect, actual = res})
  end)

  test("no match yields an empty result table", function()
    local trie = t.create({'zzz'}, t.flags.som)
    local m = trie:match('abcdef', true)
    assert_equal(0, #m)
  end)
end)
