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

context("Rspamd_text:normalize_newlines() test", function()
  local rspamd_text = require "rspamd_text"

  -- No normalization needed
  test("already CRLF - no change", function()
    local t = rspamd_text.fromstring("line1\r\nline2\r\nline3\r\n")
    local orig_ptr = t:ptr()
    t:normalize_newlines("crlf")
    assert_equal(t:ptr(), orig_ptr, "should return same text when no change needed")
    assert_equal(t:str(), "line1\r\nline2\r\nline3\r\n")
  end)

  test("already LF only - no change for LF mode", function()
    local t = rspamd_text.fromstring("line1\nline2\nline3\n")
    local orig_ptr = t:ptr()
    t:normalize_newlines("lf")
    assert_equal(t:ptr(), orig_ptr, "should return same text when no change needed")
    assert_equal(t:str(), "line1\nline2\nline3\n")
  end)

  test("no newlines at all - no change", function()
    local t = rspamd_text.fromstring("just some text without newlines")
    local orig_ptr = t:ptr()
    t:normalize_newlines("crlf")
    assert_equal(t:ptr(), orig_ptr, "should return same text when no newlines")
    assert_equal(t:str(), "just some text without newlines")
  end)

  -- LF to CRLF conversion
  test("LF to CRLF: simple", function()
    local t = rspamd_text.fromstring("line1\nline2\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "line1\r\nline2\r\n")
  end)

  test("LF to CRLF: bare LF after CRLF stays CRLF", function()
    local t = rspamd_text.fromstring("line1\r\nline2\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "line1\r\nline2\r\n")
  end)

  test("LF to CRLF: multiple bare LFs", function()
    local t = rspamd_text.fromstring("a\nb\nc\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "a\r\nb\r\nc\r\n")
  end)

  test("LF to CRLF: text starting with LF", function()
    local t = rspamd_text.fromstring("\nfirst line\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "\r\nfirst line\r\n")
  end)

  test("LF to CRLF: text ending with LF", function()
    local t = rspamd_text.fromstring("last line\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "last line\r\n")
  end)

  test("LF to CRLF: consecutive LFs", function()
    local t = rspamd_text.fromstring("line1\n\nline3")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "line1\r\n\r\nline3")
  end)

  -- CRLF to LF conversion
  test("CRLF to LF: simple", function()
    local t = rspamd_text.fromstring("line1\r\nline2\r\n")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "line1\nline2\n")
  end)

  test("CRLF to LF: mixed CRLF and LF", function()
    local t = rspamd_text.fromstring("line1\r\nline2\nline3\r\n")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "line1\nline2\nline3\n")
  end)

  test("CRLF to LF: multiple consecutive CRLF", function()
    local t = rspamd_text.fromstring("a\r\n\r\nb")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "a\n\nb")
  end)

  -- Weird line endings
  test("CR only (not followed by LF) preserved in CRLF mode", function()
    local t = rspamd_text.fromstring("line1\rline2\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "line1\rline2\r\n")
  end)

  test("CR only preserved in LF mode", function()
    local t = rspamd_text.fromstring("line1\rline2\r\n")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "line1\rline2\n")
  end)

  test("multiple CRs before LF", function()
    local t = rspamd_text.fromstring("line\r\r\nline2")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "line\r\nline2")
  end)

  -- Inconsistent line endings
  test("mixed CRLF and LF to CRLF", function()
    local t = rspamd_text.fromstring("line1\r\nline2\nline3\r\nline4\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "line1\r\nline2\r\nline3\r\nline4\r\n")
  end)

  test("mixed CRLF and LF to LF", function()
    local t = rspamd_text.fromstring("line1\r\nline2\nline3\r\nline4\n")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "line1\nline2\nline3\nline4\n")
  end)

  -- Only line endings
  test("single LF to CRLF", function()
    local t = rspamd_text.fromstring("\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "\r\n")
  end)

  test("single CRLF to LF", function()
    local t = rspamd_text.fromstring("\r\n")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "\n")
  end)

  test("multiple LF only to CRLF", function()
    local t = rspamd_text.fromstring("\n\n\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "\r\n\r\n\r\n")
  end)

  test("multiple CRLF only to LF", function()
    local t = rspamd_text.fromstring("\r\n\r\n\r\n")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "\n\n\n")
  end)

  -- Edge cases
  test("empty string - no change", function()
    local t = rspamd_text.fromstring("")
    local orig_ptr = t:ptr()
    t:normalize_newlines("crlf")
    assert_equal(t:ptr(), orig_ptr)
    assert_equal(t:str(), "")
  end)

  test("single character without newline", function()
    local t = rspamd_text.fromstring("x")
    local orig_ptr = t:ptr()
    t:normalize_newlines("crlf")
    assert_equal(t:ptr(), orig_ptr)
    assert_equal(t:str(), "x")
  end)

  test("single character with newline", function()
    local t = rspamd_text.fromstring("x\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "x\r\n")
  end)

  test("large text with many newlines", function()
    local lines = {}
    for i = 1, 1000 do
      lines[i] = "line" .. i
    end
    local input = table.concat(lines, "\n")
    local expected = table.concat(lines, "\r\n")
    local t = rspamd_text.fromstring(input)
    t:normalize_newlines("crlf")
    assert_equal(t:str(), expected)
  end)

  test("text with null bytes", function()
    local t = rspamd_text.fromstring("line1\n\x00line2\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "line1\r\n\x00line2\r\n")
  end)

  -- Mode parameter variations
  test("mode 'crlf' works", function()
    local t = rspamd_text.fromstring("a\n")
    t:normalize_newlines("crlf")
    assert_equal(t:str(), "a\r\n")
  end)

  test("mode 'windows' works (alias for crlf)", function()
    local t = rspamd_text.fromstring("a\n")
    t:normalize_newlines("windows")
    assert_equal(t:str(), "a\r\n")
  end)

  test("mode 'lf' works", function()
    local t = rspamd_text.fromstring("a\r\n")
    t:normalize_newlines("lf")
    assert_equal(t:str(), "a\n")
  end)

  test("mode 'unix' works (alias for lf)", function()
    local t = rspamd_text.fromstring("a\r\n")
    t:normalize_newlines("unix")
    assert_equal(t:str(), "a\n")
  end)

  test("default mode is crlf", function()
    local t = rspamd_text.fromstring("a\n")
    t:normalize_newlines()
    assert_equal(t:str(), "a\r\n")
  end)

  test("case insensitive mode", function()
    local t = rspamd_text.fromstring("a\n")
    t:normalize_newlines("CRLF")
    assert_equal(t:str(), "a\r\n")
  end)
end)
