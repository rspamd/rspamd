--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

context("RFC2047 decoding", function()
  local ffi = require("ffi")

  ffi.cdef[[
    const char * rspamd_mime_header_decode (void *pool, const char *in, size_t inlen);
    void * rspamd_mempool_new_ (size_t sz, const char *name, int flags, const char *strloc);
    void rspamd_mempool_delete (void *pool);
  ]]

  test("Decode rfc2047 tokens", function()
    -- Test -> expected
    local cases = {
      {"=?US-ASCII*EN?Q?Keith_Moore?= <moore@cs.utk.edu>", "Keith Moore <moore@cs.utk.edu>"},
      {[[=?windows-1251?Q?=C2=FB_=F1=EC=EE=E6=E5=F2=E5_=F5=E0=F0?=
 =?windows-1251?Q?=E0=EA=F2=E5=F0=E8=E7=EE=E2=E0=F2=FC=F1?=
 =?windows-1251?Q?=FF_=E7=EE=F0=EA=E8=EC_=E7=F0=E5=ED=E8?=
 =?windows-1251?Q?=E5=EC?=]], "Вы сможете характеризоваться зорким зрением"},
      {'v=1; a=rsa-sha256; c=relaxed/relaxed; d=yoni.za.org; s=testdkim1;',
      'v=1; a=rsa-sha256; c=relaxed/relaxed; d=yoni.za.org; s=testdkim1;'},
      {"=?windows-1251?B?xO7q8+zl7fIuc2NyLnV1ZQ==?=", "Документ.scr.uue"},
      {"=?UTF-8?Q?=20wie=20ist=20es=20Ihnen=20ergangen?.pdf?=", " wie ist es Ihnen ergangen?.pdf"}, -- ? inside
      {"=?UTF-8?Q?=20wie=20ist=20es=20Ihnen=20ergangen??=", " wie ist es Ihnen ergangen?"}, -- ending ? inside
    }

    local pool = ffi.C.rspamd_mempool_new_(4096, "lua", 0, "rfc2047.lua:49")

    for _,c in ipairs(cases) do
      local res = ffi.C.rspamd_mime_header_decode(pool, c[1], #c[1])
      res = ffi.string(res)
      assert_not_nil(res, "cannot decode " .. c[1])
      assert_rspamd_eq({actual = res, expect = c[2]})

    end

    ffi.C.rspamd_mempool_delete(pool)
  end)
  test("Fuzz test for rfc2047 tokens", function()
    local util = require("rspamd_util")
    local pool = ffi.C.rspamd_mempool_new_(4096, "lua", 0, "rfc2047.lua:63")
    local str = "Тест Тест Тест Тест Тест"

    for i = 0,1000 do
      local r1 = math.random()
      local r2 = math.random()
      local sl1 = #str / 2.0 * r1
      local sl2 = #str / 2.0 * r2

      local s1 = tostring(util.encode_base64(string.sub(str, 1, sl1)))
      local s2 = tostring(util.encode_base64(string.sub(str, sl1 + 1, sl2)))
      local s3 = tostring(util.encode_base64(string.sub(str, sl2 + 1)))

      if #s1 > 0 and #s2 > 0 and #s3 > 0 then
        local s = string.format('=?UTF-8?B?%s?= =?UTF-8?B?%s?= =?UTF-8?B?%s?=',
          s1, s2, s3)
        local res = ffi.C.rspamd_mime_header_decode(pool, s, #s)
        res = ffi.string(res)
        assert_not_nil(res, "cannot decode " .. s)
        assert_rspamd_eq({actual = res, expect = str})
      end
    end

    ffi.C.rspamd_mempool_delete(pool)
  end)
end)
