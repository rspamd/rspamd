-- Test zbase32 encoding/decoding

context("Base32 encodning", function()
  local ffi = require("ffi")
  ffi.cdef[[
    void ottery_rand_bytes(void *buf, size_t n);
    unsigned ottery_rand_unsigned(void);
    unsigned char* rspamd_decode_base32 (const char *in, size_t inlen, size_t *outlen);
    char * rspamd_encode_base32 (const unsigned char *in, size_t inlen);
    void g_free(void *ptr);
  ]]
  
  local function random_buf(max_size)
    local l = ffi.C.ottery_rand_unsigned()
    local buf = ffi.new("unsigned char[?]", l)
    ffi.C.ottery_rand_bytes(buf, l)
    
    return buf, l
  end
  
  test("Base32 exact test", function()
    local cases = {
      {'test123', 'wm3g84fg13cy'},
      {'hello', 'em3ags7p'}
    }
    
    for _,c in ipairs(cases) do
      local b = ffi.C.rspamd_encode_base32(c[1], #c[1])
      local s = ffi.string(b)
      ffi.C.g_free(b)
      assert_equal(s, c[2], s .. " not equal " .. c[2])
    end
  end)
end)