-- Byte-distribution statistics methods on rspamd_text:
-- entropy / byte_mean / byte_deviation / serial_correlation / monte_carlo_pi.
-- Expected values are derived analytically from the statistic definitions over
-- buffers whose statistics are determined exactly.

context("Text byte-statistics", function()
  local rspamd_text = require "rspamd_text"

  local EPS = 1e-9
  local function approx(actual, expected)
    return math.abs(actual - expected) < EPS
  end

  local function T(s)
    return rspamd_text.fromstring(s)
  end

  test("entropy: empty buffer is 0", function()
    assert_equal(0.0, T(""):entropy())
  end)

  test("entropy: single symbol is 0", function()
    assert_equal(0.0, T(string.rep("\0", 256)):entropy())
    assert_equal(0.0, T(string.rep("A", 100)):entropy())
  end)

  test("entropy: two equal symbols is 1 bit/byte", function()
    assert_equal(1.0, T("aaaabbbb"):entropy())
  end)

  test("entropy: every byte value once is 8 bits/byte", function()
    local bytes = {}
    for i = 0, 255 do
      bytes[#bytes + 1] = string.char(i)
    end
    assert_equal(8.0, T(table.concat(bytes)):entropy())
  end)

  test("byte_mean: unsigned byte values", function()
    assert_equal(0.0, T(string.rep("\0", 16)):byte_mean())
    assert_equal(97.5, T("aaaabbbb"):byte_mean()) -- 'a'=97 'b'=98
    -- 0x00 and 0xFF equal counts -> 127.5 (unsigned, not -0.5)
    assert_equal(127.5, T(string.char(0, 255, 0, 255)):byte_mean())
  end)

  test("byte_mean: mean of 0..255 is 127.5", function()
    local bytes = {}
    for i = 0, 255 do
      bytes[#bytes + 1] = string.char(i)
    end
    assert_equal(127.5, T(table.concat(bytes)):byte_mean())
  end)

  test("byte_deviation: mean absolute deviation", function()
    -- |97-97.5|*4 + |98-97.5|*4 = 4, /8 = 0.5
    assert_equal(0.5, T("aaaabbbb"):byte_deviation(97.5))
    assert_equal(0.0, T(string.rep("A", 10)):byte_deviation(65.0))
  end)

  test("byte_deviation: deviation of 0..255 about 127.5 is 64", function()
    local bytes = {}
    for i = 0, 255 do
      bytes[#bytes + 1] = string.char(i)
    end
    assert_equal(64.0, T(table.concat(bytes)):byte_deviation(127.5))
  end)

  test("serial_correlation: hand-computed ramp", function()
    -- {0,1,2,3} -> -0.2
    assert_true(approx(T(string.char(0, 1, 2, 3)):serial_correlation(), -0.2))
  end)

  test("serial_correlation: identical bytes hit the sentinel", function()
    assert_equal(-100000.0, T(string.rep("\0", 64)):serial_correlation())
    -- single byte also -> sentinel
    assert_equal(-100000.0, T("A"):serial_correlation())
  end)

  test("serial_correlation: empty buffer is 0", function()
    assert_equal(0.0, T(""):serial_correlation())
  end)

  test("monte_carlo_pi: point outside the circle", function()
    -- 6x0xFF -> outside -> mpi 0 -> |0 - PI|/PI == 1
    assert_true(approx(T(string.rep(string.char(255), 6)):monte_carlo_pi(), 1.0))
  end)

  test("monte_carlo_pi: all-in-circle deviation", function()
    -- 12 zero bytes -> 2 groups in circle -> mpi 4 -> |4 - PI|/PI
    local expected = math.abs((4.0 - 3.141592653589793) / 3.141592653589793)
    assert_true(approx(T(string.rep("\0", 12)):monte_carlo_pi(), expected))
  end)

  test("monte_carlo_pi: fewer than 6 bytes is defined 0", function()
    assert_equal(0.0, T("abc"):monte_carlo_pi())
  end)

  test("start/length slicing (1-based start)", function()
    local t = T("AAAABBBB") -- 'A'=65 at [1..4], 'B'=66 at [5..8]
    -- whole buffer: two equal symbols
    assert_equal(1.0, t:entropy())
    assert_equal(65.5, t:byte_mean())
    -- slice starting at position 5, length 4 -> "BBBB"
    assert_equal(0.0, t:entropy(5, 4))
    assert_equal(66.0, t:byte_mean(5, 4))
    -- slice from start position to end
    assert_equal(0.0, t:entropy(5))
    assert_equal(66.0, t:byte_mean(5))
    -- length clamped to available bytes
    assert_equal(66.0, t:byte_mean(5, 1000))
  end)

  test("out-of-range slice is defined 0", function()
    local t = T("AAAABBBB")
    assert_equal(0.0, t:entropy(100))
    assert_equal(0.0, t:byte_mean(100))
    assert_equal(0.0, t:entropy(0))    -- start < 1 is empty
    assert_equal(0.0, t:entropy(1, 0)) -- zero length is empty
  end)
end)
