-- Test siphash routines

context("Siphash check functions", function()
  local ffi = require("ffi")
  ffi.cdef[[
    size_t siphash24_test(void);
  ]]

  test("Siphash test vectors", function()
    local res = ffi.C.siphash24_test()
    
    assert_not_equal(res, 0)
  end)
end)