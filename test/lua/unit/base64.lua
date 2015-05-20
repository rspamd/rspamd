context("Base64 encodning", function()
  local ffi = require("ffi")
  ffi.cdef[[
    void ottery_rand_bytes(void *buf, size_t n);
    unsigned ottery_rand_unsigned(void);
    unsigned char* g_base64_decode (const char *in, size_t *outlen);
    char * rspamd_encode_base64 (const unsigned char *in, size_t inlen, 
      size_t str_len, size_t *outlen);
    void g_free(void *ptr);
    int memcmp(const void *a1, const void *a2, size_t len);
  ]]
  
  local function random_buf(max_size)
    local l = ffi.C.ottery_rand_unsigned() % max_size + 1
    local buf = ffi.new("unsigned char[?]", l)
    ffi.C.ottery_rand_bytes(buf, l)
    
    return buf, l
  end
  
  test("Base64 encode test", function()
    local cases = {
      {"", ""},
      {"f", "Zg=="},
      {"fo", "Zm8="},
      {"foo", "Zm9v"},
      {"foob", "Zm9vYg=="},
      {"fooba", "Zm9vYmE="},
      {"foobar", "Zm9vYmFy"},
    }
    
    local nl = ffi.new("size_t [1]")
    for _,c in ipairs(cases) do
      local b = ffi.C.rspamd_encode_base64(c[1], #c[1], 0, nl)
      local s = ffi.string(b)
      ffi.C.g_free(b)
      assert_equal(s, c[2], s .. " not equal " .. c[2])
    end
  end)
  
  test("Base64 line split encode test", function()
    local text = [[
Man is distinguished, not only by his reason, but by this singular passion from
other animals, which is a lust of the mind, that by a perseverance of delight
in the continued and indefatigable generation of knowledge, exceeds the short
vehemence of any carnal pleasure.]]
    local b64 = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz\r\nIHNpbmd1bGFyIHBhc3Npb24gZnJvbQpvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg\r\ndGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodAppbiB0aGUgY29udGlu\r\ndWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo\r\nZSBzaG9ydAp2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="
    local nl = ffi.new("size_t [1]")
    local b = ffi.C.rspamd_encode_base64(text, #text, 76, nl)
    local cmp = ffi.C.memcmp(b, b64, nl[0])
    ffi.C.g_free(b)
    assert_equal(cmp, 0)
  end)
  
  test("Base64 fuzz test", function()
    for i = 1,1000 do
      local b, l = random_buf(4096)
      local nl = ffi.new("size_t [1]")
      local lim = ffi.C.ottery_rand_unsigned() % 64 + 10
      local ben = ffi.C.rspamd_encode_base64(b, l, lim, nl)
      local bs = ffi.string(ben)
      local ol = ffi.new("size_t [1]")
      local nb = ffi.C.g_base64_decode(ben, ol)
      
      local cmp = ffi.C.memcmp(b, nb, l)
      ffi.C.g_free(ben)
      ffi.C.g_free(nb)
      assert_equal(cmp, 0, "fuzz test failed for length: " .. tostring(l))
    end
  end)
end)