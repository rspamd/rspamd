context("Rspamd_text:byte() test", function()
  local rspamd_text = require "rspamd_text"

  local str = 'OMG'
  local txt = rspamd_text.fromstring(str)
  local fmt = 'case rspamd_text:byte(%s,%s)'
  local cases = {
    {'1', 'nil'},
    {'nil', '1'},
  }

  for start = -4, 4 do
    for stop = -4, 4 do
      table.insert(cases, {tostring(start), tostring(stop)})
    end
  end

  for _, case in ipairs(cases) do
    local name = string.format(fmt, case[1], case[2])
    test(name, function()
      local txt_bytes = {txt:byte(tonumber(case[1]), tonumber(case[2]))}
      local str_bytes = {str:byte(tonumber(case[1]), tonumber(case[2]))}
      assert_rspamd_table_eq({
        expect = str_bytes,
        actual = txt_bytes
      })
    end)
  end
end)

context("Rspamd_text:find() test", function()
  local rspamd_text = require "rspamd_text"

  local cases = {
    {{'foobarfoo', 'f'}, {1, 1}},
    {{'foobarfoo', 'foo'}, {1, 3}},
    {{'foobarfoo', 'bar'}, {4, 6}},
    {{'foobarfoo', 'baz'}, nil},
    {{'foobarfoo', 'rfoo'}, {6, 9}},
    {{'foo', 'bar'}, nil},
    {{'x', 'xxxx'}, nil},
    {{'', ''}, {1, 0}},
    {{'', '_'}, nil},
    {{'x', ''}, {1, 0}},
  }

  for _, case in ipairs(cases) do
    local name = string.format('case rspamd_text:find(%s,%s)', case[1][1], case[1][2])
    test(name, function()
      local t = rspamd_text.fromstring(case[1][1])
      local s,e = t:find(case[1][2])

      if case[2] then
        assert_rspamd_table_eq({
          expect = case[2],
          actual = {s, e}
        })
      else
        assert_nil(s)
      end
      local ss,ee = string.find(case[1][1], case[1][2], 1, true)
      assert_rspamd_table_eq({
        expect = { ss, ee },
        actual = { s, e }
      })
    end)
    -- Compare with vanila lua
    name = string.format('case lua string vs rspamd_text:find(%s,%s)', case[1][1], case[1][2])
    test(name, function()
      local t = rspamd_text.fromstring(case[1][1])
      local s,e = t:find(case[1][2])
      local ss,ee = string.find(case[1][1], case[1][2], 1, true)
      assert_rspamd_table_eq({
        expect = { ss, ee },
        actual = { s, e }
      })
    end)
  end
end)
