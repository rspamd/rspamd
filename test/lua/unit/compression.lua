-- Compression unit tests

context("Rspamd compression", function()
  local rspamd_zstd = require "rspamd_zstd"
  local rspamd_text = require "rspamd_text"

  test("Compressed can be decompressed", function()
    local str = 'test'
    local cctx = rspamd_zstd.compress_ctx()
    local dctx = rspamd_zstd.decompress_ctx()
    assert_rspamd_eq({actual = dctx:stream(cctx:stream(str, 'end')),
                      expect = rspamd_text.fromstring(str)})
  end)
  test("Compressed concatenation can be decompressed", function()
    local str = 'test'
    local cctx = rspamd_zstd.compress_ctx()
    local dctx = rspamd_zstd.decompress_ctx()
    assert_rspamd_eq({actual = dctx:stream(cctx:stream(str) .. cctx:stream(str, 'end')),
                      expect = rspamd_text.fromstring(str .. str)})
  end)

  local sizes = {10, 100, 1000, 10000}
  for _,sz in ipairs(sizes) do
    test("Compressed fuzz size: " .. tostring(sz), function()
      for _=1,1000 do
        local rnd = rspamd_text.randombytes(sz)
        local cctx = rspamd_zstd.compress_ctx()
        local dctx = rspamd_zstd.decompress_ctx()
        assert_rspamd_eq({actual = dctx:stream(cctx:stream(rnd, 'end')),
                          expect = rnd})
      end
    end)
  end

  test("Compressed chunks", function()
    local cctx = rspamd_zstd.compress_ctx()
    local tin = {}
    local tout = {}
    for i=1,1000 do
      local rnd = rspamd_text.randombytes(i)
      tin[#tin + 1] = rnd
    end
    for i=1,1000 do
      local o
      if i == 1000 then
        o = cctx:stream(tin[i], 'end')
      else
        o = cctx:stream(tin[i])
      end
      tout[#tout + 1] = o
    end
    local dctx = rspamd_zstd.decompress_ctx()
    assert_rspamd_eq({actual = dctx:stream(rspamd_text.fromtable(tout)),
                      expect = rspamd_text.fromtable(tin)})
  end)
end)