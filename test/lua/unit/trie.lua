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
