local cr = require 'rspamd_cryptobox'

context("Cryptobox - fast_hash64", function()

  test('Returns two numbers', function()
    local hi, lo = cr.fast_hash64("test")
    assert_not_nil(hi)
    assert_not_nil(lo)
    assert_equal(type(hi), "number")
    assert_equal(type(lo), "number")
  end)

  test('Same input produces same output', function()
    local hi1, lo1 = cr.fast_hash64("hello world")
    local hi2, lo2 = cr.fast_hash64("hello world")
    assert_equal(hi1, hi2)
    assert_equal(lo1, lo2)
  end)

  test('Different input produces different output', function()
    local hi1, lo1 = cr.fast_hash64("hello")
    local hi2, lo2 = cr.fast_hash64("world")
    -- At least one of hi/lo should differ
    assert_true(hi1 ~= hi2 or lo1 ~= lo2, "Different inputs should produce different hashes")
  end)

  test('Seed affects output', function()
    local hi1, lo1 = cr.fast_hash64("test", 0)
    local hi2, lo2 = cr.fast_hash64("test", 12345)
    assert_true(hi1 ~= hi2 or lo1 ~= lo2, "Different seeds should produce different hashes")
  end)

  test('Empty string is valid input', function()
    local hi, lo = cr.fast_hash64("")
    assert_not_nil(hi)
    assert_not_nil(lo)
  end)

  test('Long string is valid input', function()
    local long_str = string.rep("x", 10000)
    local hi, lo = cr.fast_hash64(long_str)
    assert_not_nil(hi)
    assert_not_nil(lo)
  end)

  test('XOR accumulation produces order-independent result', function()
    local bit = require "bit"

    local function hash_and_xor(strings)
      local acc_hi, acc_lo = 0, 0
      for _, s in ipairs(strings) do
        local hi, lo = cr.fast_hash64(s)
        acc_hi = bit.bxor(acc_hi, hi)
        acc_lo = bit.bxor(acc_lo, lo)
      end
      return acc_hi, acc_lo
    end

    -- Same strings in different order
    local hi1, lo1 = hash_and_xor({"alpha", "beta", "gamma"})
    local hi2, lo2 = hash_and_xor({"gamma", "alpha", "beta"})
    local hi3, lo3 = hash_and_xor({"beta", "gamma", "alpha"})

    assert_equal(hi1, hi2)
    assert_equal(lo1, lo2)
    assert_equal(hi1, hi3)
    assert_equal(lo1, lo3)
  end)

end)
