-- Test zbase32 encoding/decoding

context("Base32 encodning", function()
  local ffi = require("ffi")
  ffi.cdef[[
    void ottery_rand_bytes(void *buf, size_t n);
    unsigned ottery_rand_unsigned(void);
    unsigned char* rspamd_decode_base32 (const char *in, size_t inlen, size_t *outlen, int how);
    char * rspamd_encode_base32 (const unsigned char *in, size_t inlen, int how);
    void g_free(void *ptr);
    int memcmp(const void *a1, const void *a2, size_t len);
  ]]

  local function random_buf(max_size)
    local l = ffi.C.ottery_rand_unsigned() % max_size + 1
    local buf = ffi.new("unsigned char[?]", l)
    ffi.C.ottery_rand_bytes(buf, l)

    return buf, l
  end

  test("Base32 encode test", function()
    local cases = {
      {'test123', 'wm3g84fg13cy'},
      {'hello', 'em3ags7p'}
    }

    for _,c in ipairs(cases) do
      local b = ffi.C.rspamd_encode_base32(c[1], #c[1], 0)
      local s = ffi.string(b)
      ffi.C.g_free(b)
      assert_equal(s, c[2], s .. " not equal " .. c[2])
    end
  end)

  test("Base32 fuzz test", function()
    for i = 1,1000 do
      local b, l = random_buf(4096)
      local how = math.floor(math.random(3) - 1)
      local ben = ffi.C.rspamd_encode_base32(b, l, how)
      local bs = ffi.string(ben)
      local nl = ffi.new("size_t [1]")
      local nb = ffi.C.rspamd_decode_base32(bs, #bs, nl, how)

      local cmp = ffi.C.memcmp(b, nb, l)
      ffi.C.g_free(ben)
      ffi.C.g_free(nb)
      assert_equal(cmp, 0, "fuzz test failed for length: " .. tostring(l))
    end
  end)
end)