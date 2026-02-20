local util = require 'lua_util'

context("Lua util - unordered_table_digest", function()

  test('Simple map produces consistent digest', function()
    local t1 = { a = 1, b = 2, c = 3 }
    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t1)
    assert_equal(d1, d2)
    assert_equal(#d1, 16) -- 64 bits = 16 hex chars
  end)

  test('Order independence for maps', function()
    -- Create tables that may iterate in different orders
    local t1 = {}
    t1.alpha = "first"
    t1.beta = "second"
    t1.gamma = "third"

    local t2 = {}
    t2.gamma = "third"
    t2.alpha = "first"
    t2.beta = "second"

    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_equal(d1, d2, "Digests should be equal regardless of insertion order")
  end)

  test('Different values produce different digests', function()
    local t1 = { a = 1, b = 2 }
    local t2 = { a = 1, b = 3 }
    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_not_equal(d1, d2)
  end)

  test('Different keys produce different digests', function()
    local t1 = { a = 1, b = 2 }
    local t2 = { a = 1, c = 2 }
    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_not_equal(d1, d2)
  end)

  test('Numeric values are included in digest', function()
    local t1 = { weight = 1.0 }
    local t2 = { weight = 2.0 }
    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_not_equal(d1, d2, "Different numeric values should produce different digests")
  end)

  test('Boolean values are included in digest', function()
    local t1 = { enabled = true }
    local t2 = { enabled = false }
    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_not_equal(d1, d2, "Different boolean values should produce different digests")
  end)

  test('Nested tables are handled correctly', function()
    local t1 = { outer = { inner = "value" } }
    local t2 = { outer = { inner = "value" } }
    local t3 = { outer = { inner = "other" } }

    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    local d3 = util.unordered_table_digest(t3)

    assert_equal(d1, d2, "Same nested structure should produce same digest")
    assert_not_equal(d1, d3, "Different nested values should produce different digest")
  end)

  test('Arrays preserve order', function()
    local t1 = { "a", "b", "c" }
    local t2 = { "c", "b", "a" }
    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_not_equal(d1, d2, "Arrays with different order should have different digests")
  end)

  test('Empty table produces consistent digest', function()
    local t1 = {}
    local t2 = {}
    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_equal(d1, d2)
  end)

  test('Complex nested structure with mixed types', function()
    local t1 = {
      providers = {
        { type = "llm", model = "gpt-4", weight = 1.0 },
        { type = "symbols", weight = 0.5 },
      },
      fusion = {
        normalization = "none",
        include_meta = true,
        meta_weight = 1.0,
      },
      max_inputs = 100,
    }

    local t2 = {
      max_inputs = 100,
      fusion = {
        meta_weight = 1.0,
        include_meta = true,
        normalization = "none",
      },
      providers = {
        { type = "llm", model = "gpt-4", weight = 1.0 },
        { type = "symbols", weight = 0.5 },
      },
    }

    local d1 = util.unordered_table_digest(t1)
    local d2 = util.unordered_table_digest(t2)
    assert_equal(d1, d2, "Same structure with different key order should produce same digest")
  end)

end)
