-- Test utf routines

context("UTF8 check functions", function()
  local ffi = require("ffi")
  ffi.cdef[[
    unsigned int rspamd_str_lc_utf8 (char *str, unsigned int size);
    unsigned int rspamd_str_lc (char *str, unsigned int size);
    void rspamd_fast_utf8_library_init (unsigned flags);
    void ottery_rand_bytes(void *buf, size_t n);
    double rspamd_get_ticks(int allow);
    size_t rspamd_fast_utf8_validate (const unsigned char *data, size_t len);
    size_t rspamd_fast_utf8_validate_ref (const unsigned char *data, size_t len);
    size_t rspamd_fast_utf8_validate_sse41 (const unsigned char *data, size_t len);
    size_t rspamd_fast_utf8_validate_avx2 (const unsigned char *data, size_t len);
    char * rspamd_str_make_utf_valid (const char *src, size_t slen, size_t *dstlen, void *);
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
      local nlen = ffi.C.rspamd_str_lc_utf8(buf, #c[1])
      local s = ffi.string(buf, nlen)
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

      local s = ffi.string(ffi.C.rspamd_str_make_utf_valid(buf, #c[1], NULL, NULL))
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

  -- Enable sse and avx2
  ffi.C.rspamd_fast_utf8_library_init(3)
  local valid_cases = {
    "a",
    "\xc3\xb1",
    "\xe2\x82\xa1",
    "\xf0\x90\x8c\xbc",
    "안녕하세요, 세상"
  }
  for i,c in ipairs(valid_cases) do
    test("Unicode validate success: " .. tostring(i), function()
      local buf = ffi.new("char[?]", #c + 1)
      ffi.copy(buf, c)

      local ret = ffi.C.rspamd_fast_utf8_validate(buf, #c)
      assert_equal(ret, 0)
    end)
  end
  local invalid_cases = {
    "\xc3\x28",
    "\xa0\xa1",
    "\xe2\x28\xa1",
    "\xe2\x82\x28",
    "\xf0\x28\x8c\xbc",
    "\xf0\x90\x28\xbc",
    "\xf0\x28\x8c\x28",
    "\xc0\x9f",
    "\xf5\xff\xff\xff",
    "\xed\xa0\x81",
    "\xf8\x90\x80\x80\x80",
    "123456789012345\xed",
    "123456789012345\xf1",
    "123456789012345\xc2",
    "\xC2\x7F"
  }
  for i,c in ipairs(invalid_cases) do
    test("Unicode validate fail: " .. tostring(i), function()
      local buf = ffi.new("char[?]", #c + 1)
      ffi.copy(buf, c)

      local ret = ffi.C.rspamd_fast_utf8_validate(buf, #c)
      assert_not_equal(ret, 0)
    end)
  end

  local speed_iters = 10000
  local function test_size(buflen, is_valid, impl)
    local logger = require "rspamd_logger"
    local test_str
    if is_valid then
      test_str = table.concat(valid_cases)
    else
      test_str = table.concat(valid_cases) .. table.concat(invalid_cases)
    end

    local buf = ffi.new("char[?]", buflen)
    if #test_str < buflen then
      local t = {}
      local len = #test_str
      while len < buflen do
        t[#t + 1] = test_str
        len = len + #test_str
      end
      test_str = table.concat(t)
    end
    ffi.copy(buf, test_str:sub(1, buflen))

    local tm = 0

    for _=1,speed_iters do
      if impl == 'ref' then
        local t1 = ffi.C.rspamd_get_ticks(1)
        ffi.C.rspamd_fast_utf8_validate_ref(buf, buflen)
        local t2 = ffi.C.rspamd_get_ticks(1)
        tm = tm + (t2 - t1)
      elseif impl == 'sse' then
        local t1 = ffi.C.rspamd_get_ticks(1)
        ffi.C.rspamd_fast_utf8_validate_sse41(buf, buflen)
        local t2 = ffi.C.rspamd_get_ticks(1)
        tm = tm + (t2 - t1)
      else
        local t1 = ffi.C.rspamd_get_ticks(1)
        ffi.C.rspamd_fast_utf8_validate_avx2(buf, buflen)
        local t2 = ffi.C.rspamd_get_ticks(1)
        tm = tm + (t2 - t1)
      end
    end

    logger.messagex("%s utf8 %s check (valid = %s): %s ticks per iter, %s ticks per byte",
        impl, buflen, is_valid,
        tm / speed_iters, tm / speed_iters / buflen)

    return 0
  end

  for _,sz in ipairs({78, 512, 65535}) do
    test(string.format("Utf8 test %s %d buffer, %s", 'ref', sz, 'valid'), function()
      local res = test_size(sz, true, 'ref')
      assert_equal(res, 0)
    end)
    test(string.format("Utf8 test %s %d buffer, %s", 'ref', sz, 'invalid'), function()
      local res = test_size(sz, false, 'ref')
      assert_equal(res, 0)
    end)

    if jit.arch == 'x64' then
      test(string.format("Utf8 test %s %d buffer, %s", 'sse', sz, 'valid'), function()
        local res = test_size(sz, true, 'sse')
        assert_equal(res, 0)
      end)
      test(string.format("Utf8 test %s %d buffer, %s", 'sse', sz, 'invalid'), function()
        local res = test_size(sz, false, 'sse')
        assert_equal(res, 0)
      end)
      test(string.format("Utf8 test %s %d buffer, %s", 'avx2', sz, 'valid'), function()
        local res = test_size(sz, true, 'avx2')
        assert_equal(res, 0)
      end)
      test(string.format("Utf8 test %s %d buffer, %s", 'avx2', sz, 'invalid'), function()
        local res = test_size(sz, false, 'avx2')
        assert_equal(res, 0)
      end)
    end
  end

end)