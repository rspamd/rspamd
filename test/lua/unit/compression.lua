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

  if os.getenv("RSPAMD_LUA_EXPENSIVE_TESTS") then
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

  test("Large output is decompressed in full", function()
    local str = string.rep('x', 1024 * 1024 + 1)
    local cctx = rspamd_zstd.compress_ctx()
    local dctx = rspamd_zstd.decompress_ctx()
    assert_rspamd_eq({actual = dctx:stream(cctx:stream(str, 'end')),
                      expect = rspamd_text.fromstring(str)})
  end)

  test("Corrupt input is an error and keeps the context usable", function()
    local cctx = rspamd_zstd.compress_ctx()
    local frame = cctx:stream('test', 'end')
    local dctx = rspamd_zstd.decompress_ctx()
    for _ = 1, 3 do
      local res, err = dctx:stream('this is not a zstd frame')
      assert_nil(res)
      assert_match('^zstd error', err)
    end
    assert_rspamd_eq({actual = dctx:stream(frame),
                      expect = rspamd_text.fromstring('test')})
  end)

  test("Truncated frame is an error and keeps the context usable", function()
    local str = string.rep('hello world ', 100)
    local cctx = rspamd_zstd.compress_ctx()
    local frame = tostring(cctx:stream(str, 'end'))
    local dctx = rspamd_zstd.decompress_ctx()
    -- Cut inside the frame header, then inside the block
    for _, len in ipairs({5, #frame - 3}) do
      local res, err = dctx:stream(frame:sub(1, len))
      assert_nil(res)
      assert_match('Src size is incorrect', err)
      assert_rspamd_eq({actual = dctx:stream(frame),
                        expect = rspamd_text.fromstring(str)})
    end
  end)
end)