-- Test utf routines

context("UTF8 check functions", function()
  local ffi = require("ffi")
  ffi.cdef[[
    void rspamd_str_lc_utf8 (char *str, unsigned int size);
    void rspamd_str_lc (char *str, unsigned int size);
    char * rspamd_str_make_utf_valid (const char *src, size_t slen, size_t *dstlen);
  ]]

  local cases = {
    {"АбЫрвАлг", "абырвалг"},
    {"АAБBвc", "аaбbвc"},
    --{"STRASSE", "straße"}, XXX: NYI
    {"KEÇİ", "keçi"},
  }

  for i,c in ipairs(cases) do
    test("UTF lowercase " .. tostring(i), function()
      local buf = ffi.new("char[?]", #c[1] + 1)
      ffi.copy(buf, c[1])
      ffi.C.rspamd_str_lc_utf8(buf, #c[1])
      local s = ffi.string(buf)
      assert_equal(s, c[2])
    end)
  end

  cases = {
    {"AbCdEf", "abcdef"},
    {"A", "a"},
    {"AaAa", "aaaa"},
    {"AaAaAaAa", "aaaaaaaa"}
  }

  for i,c in ipairs(cases) do
    test("ASCII lowercase " .. tostring(i), function()
      local buf = ffi.new("char[?]", #c[1] + 1)
      ffi.copy(buf, c[1])
      ffi.C.rspamd_str_lc(buf, #c[1])
      local s = ffi.string(buf)
      assert_equal(s, c[2])
    end)
  end

  cases = {
    {'тест', 'тест'},
    {'\200\213\202', '���'},
    {'тест\200\213\202test', 'тест���test'},
    {'\200\213\202test', '���test'},
    {'\200\213\202test\200\213\202', '���test���'},
    {'тест\200\213\202test\200\213\202', 'тест���test���'},
    {'тест\200\213\202test\200\213\202тест', 'тест���test���тест'},
  }

  local NULL = ffi.new 'void*'
  for i,c in ipairs(cases) do
    test("Unicode make valid " .. tostring(i), function()
      local buf = ffi.new("char[?]", #c[1] + 1)
      ffi.copy(buf, c[1])

      local s = ffi.string(ffi.C.rspamd_str_make_utf_valid(buf, #c[1], NULL))
      local function to_hex(s)
        return (s:gsub('.', function (c)
          return string.format('%02X', string.byte(c))
        end))
      end
      print(to_hex(s))
      print(to_hex(c[2]))
      assert_equal(s, c[2])
    end)
  end
end)