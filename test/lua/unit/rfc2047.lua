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
    void * rspamd_mempool_new (size_t sz, const char *name);
    void rspamd_mempool_destroy (void *pool);
  ]]

  test("Decode rfc2047 tokens", function()
    -- Test -> expected
    local cases = {
      {"=?US-ASCII*EN?Q?Keith_Moore?= <moore@cs.utk.edu>", "Keith Moore <moore@cs.utk.edu>"},
    }

    local pool = ffi.C.rspamd_mempool_new(4096, "lua")

    for _,c in ipairs(cases) do
      local res = ffi.C.rspamd_mime_header_decode(pool, c[1], #c[1])
      res = ffi.string(res)
      assert_equal(res, c[2], res .. " not equal " .. c[2])
      assert_not_nil(res, "cannot decode " .. c[1])
    end

    ffi.C.rspamd_mempool_destroy(pool)
  end)
end)
