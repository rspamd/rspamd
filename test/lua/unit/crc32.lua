-- CRC-32 tests: rspamd_text:crc32, rspamd_util.crc32 and
-- rspamd_cryptobox_hash.create_specific("crc32").
--
-- Golden values are the standard CRC-32 (zlib crc32 / YARA hash.crc32,
-- polynomial 0xEDB88320). The "real attachment buffer" values were produced
-- with Python's zlib.crc32 (identical to YARA hash.crc32) over the exact same
-- bytes constructed below.

context("CRC-32", function()
  local rspamd_text = require "rspamd_text"
  local rspamd_util = require "rspamd_util"
  local hash = require "rspamd_cryptobox_hash"

  local function T(s)
    return rspamd_text.fromstring(s)
  end

  -- A deterministic, attachment-like binary buffer:
  --   15-byte PDF-ish header + 8 copies of all 256 byte values + footer.
  local function sample_buffer()
    local bytes = {}
    for i = 0, 255 do
      bytes[#bytes + 1] = string.char(i)
    end
    local block = string.rep(table.concat(bytes), 8) -- 2048 bytes
    return "%PDF-1.7\n%\226\227\207\211\n" .. block .. "\nendstream endobj\n"
  end

  test("text:crc32 golden values", function()
    assert_equal(T(""):crc32(), 0x00000000)
    assert_equal(T("123456789"):crc32(), 0xCBF43926)
  end)

  test("util.crc32 golden values (string and text input)", function()
    assert_equal(rspamd_util.crc32(""), 0x00000000)
    assert_equal(rspamd_util.crc32("123456789"), 0xCBF43926)
    assert_equal(rspamd_util.crc32(T("123456789")), 0xCBF43926)
  end)

  test("create_specific('crc32') == zlib/YARA crc32", function()
    -- via initial data
    assert_equal(hash.create_specific("crc32", "123456789"):hex(), "cbf43926")
    -- empty input
    assert_equal(hash.create_specific("crc32"):hex(), "00000000")
  end)

  test("create_specific('crc32') streaming matches one-shot", function()
    local h = hash.create_specific("crc32")
    h:update("123")
    h:update("456")
    h:update("789")
    assert_equal(h:hex(), "cbf43926")
    -- hex form must match the integer form of the text method
    assert_equal(tonumber(h:hex(), 16), T("123456789"):crc32())
  end)

  test("create_specific('crc32'):reset re-initialises the state", function()
    local h = hash.create_specific("crc32", "123456789")
    assert_equal(h:hex(), "cbf43926")
    h:reset()
    h:update("123456789")
    assert_equal(h:hex(), "cbf43926")
  end)

  test("text:crc32 1-based start/len slicing", function()
    -- "234" is the 3-byte slice of "123456789" starting at position 2
    assert_equal(T("123456789"):crc32(2, 3), 0x0D717969)
    -- self-consistency: slice crc == crc of the same bytes on their own
    assert_equal(T("123456789"):crc32(2, 3), T("234"):crc32())
    -- default len runs to the end
    assert_equal(T("123456789"):crc32(1), 0xCBF43926)
    assert_equal(T("123456789"):crc32(1, 9), 0xCBF43926)
  end)

  test("util.crc32 1-based start/len slicing matches text method", function()
    local s = "123456789"
    assert_equal(rspamd_util.crc32(s, 2, 3), T(s):crc32(2, 3))
    assert_equal(rspamd_util.crc32(s, 4), T(s):crc32(4))
  end)

  test("real attachment buffer cross-checked against zlib/YARA crc32", function()
    local buf = sample_buffer()
    assert_equal(#buf, 2081)
    local t = T(buf)
    -- whole buffer
    assert_equal(t:crc32(), 0xD0A1329A)
    assert_equal(rspamd_util.crc32(buf), 0xD0A1329A)
    assert_equal(tonumber(hash.create_specific("crc32", t):hex(), 16), 0xD0A1329A)
    -- a 40-byte interior slice (Python buf[10:50] == 1-based start=11, len=40)
    assert_equal(t:crc32(11, 40), 0x2F95E096)
    assert_equal(rspamd_util.crc32(buf, 11, 40), 0x2F95E096)
  end)

  test("text:crc32 rejects out-of-range arguments", function()
    local t = T("123456789")
    assert_false(pcall(function() t:crc32(0) end))      -- start < 1
    assert_false(pcall(function() t:crc32(11) end))     -- start past end+1
    assert_false(pcall(function() t:crc32(1, 100) end)) -- len too large
  end)
end)
