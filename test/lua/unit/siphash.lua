-- Test siphash routines

context("Siphash check functions", function()
  local ffi = require("ffi")
  ffi.cdef[[
    void rspamd_cryptobox_init (void);
    size_t siphash24_test(bool generic);
    double rspamd_get_ticks (void);
  ]]
  
  ffi.C.rspamd_cryptobox_init()
  
  test("Siphash test reference vectors", function()
    local t1 = ffi.C.rspamd_get_ticks()
    local res = ffi.C.siphash24_test(true)
    local t2 = ffi.C.rspamd_get_ticks()
    
    print("Refrence siphash: " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
  test("Siphash test optimized vectors", function()
    local t1 = ffi.C.rspamd_get_ticks()
    local res = ffi.C.siphash24_test(false)
    local t2 = ffi.C.rspamd_get_ticks()
    
    print("Optimized siphash: " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
end)