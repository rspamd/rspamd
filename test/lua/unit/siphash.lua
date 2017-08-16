-- Test siphash routines

context("Siphash check functions", function()
  local ffi = require("ffi")
  ffi.cdef[[
    void rspamd_cryptobox_init (void);
    size_t siphash24_test(bool generic, size_t niters, size_t len);
    bool siphash24_fuzz (size_t cycles);
    double rspamd_get_ticks (void);
  ]]

  ffi.C.rspamd_cryptobox_init()

  test("Siphash test reference vectors (1KB)", function()
    local t1 = ffi.C.rspamd_get_ticks()
     local res = ffi.C.siphash24_test(true, 100000, 1024)
    local t2 = ffi.C.rspamd_get_ticks()

    print("Reference siphash (1KB): " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
  test("Siphash test optimized vectors (1KB)", function()
    local t1 = ffi.C.rspamd_get_ticks()
    local res = ffi.C.siphash24_test(false, 100000, 1024)
    local t2 = ffi.C.rspamd_get_ticks()

    print("Optimized siphash (1KB): " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
  test("Siphash test reference vectors (5B)", function()
    local t1 = ffi.C.rspamd_get_ticks()
     local res = ffi.C.siphash24_test(true, 1000000, 5)
    local t2 = ffi.C.rspamd_get_ticks()

    print("Reference siphash (5B): " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
  test("Siphash test optimized vectors (5B)", function()
    local t1 = ffi.C.rspamd_get_ticks()
    local res = ffi.C.siphash24_test(false, 1000000, 5)
    local t2 = ffi.C.rspamd_get_ticks()

    print("Optimized siphash (5B): " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
  test("Siphash test reference vectors (50B)", function()
    local t1 = ffi.C.rspamd_get_ticks()
    local res = ffi.C.siphash24_test(true, 1000000, 50)
    local t2 = ffi.C.rspamd_get_ticks()

    print("Reference siphash (50B): " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
  test("Siphash test optimized vectors (50B)", function()
    local t1 = ffi.C.rspamd_get_ticks()
    local res = ffi.C.siphash24_test(false, 1000000, 50)
    local t2 = ffi.C.rspamd_get_ticks()

    print("Optimized siphash (50B): " .. tostring(t2 - t1) .. " sec")
    assert_not_equal(res, 0)
  end)
  test("Siphash fuzz test (1000 iters)", function()
    local res = ffi.C.siphash24_fuzz(1000)

    assert_not_equal(res, 0)
  end)
  test("Siphash fuzz test (10000 iters)", function()
    local res = ffi.C.siphash24_fuzz(10000)

    assert_not_equal(res, 0)
  end)
end)
