-- Test utf routines

context("UTF8 check functions", function()
  local ffi = require("ffi")
  ffi.cdef[[
    void rspamd_str_lc_utf8 (char *str, unsigned int size);
    void rspamd_str_lc (char *str, unsigned int size);
  ]]

  test("UTF lowercase", function()
    local cases = {
      {"АбЫрвАлг", "абырвалг"},
      {"АAБBвc", "аaбbвc"}
    }
    
    for _,c in ipairs(cases) do
      local buf = ffi.new("char[?]", #c[1] + 1)
      ffi.copy(buf, c[1])
      ffi.C.rspamd_str_lc_utf8(buf, #c[1])
      local s = ffi.string(buf)
      assert_equal(s, c[2])
    end
  end)
  test("ASCII lowercase", function()
    local cases = {
      {"AbCdEf", "abcdef"},
      {"A", "a"},
      {"AaAa", "aaaa"},
      {"AaAaAaAa", "aaaaaaaa"}
    }
    
    for _,c in ipairs(cases) do
      local buf = ffi.new("char[?]", #c[1] + 1)
      ffi.copy(buf, c[1])
      ffi.C.rspamd_str_lc(buf, #c[1])
      local s = ffi.string(buf)
      assert_equal(s, c[2])
    end
  end)
end)