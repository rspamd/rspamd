local hash = require 'rspamd_cryptobox_hash'

context("Cryptobox hash tests", function()

  local function hash_value(value)
    local h = hash.create()
    h:update(value)
    return h:hex()
  end

  local function compare_hashes(val1, val2)
    return hash_value(val1) == hash_value(val2)
  end

  context("Basic type hashing", function()
    test("Handles strings", function()
      local h1 = hash_value("test")
      local h2 = hash_value("test")
      assert_equal(h1, h2, "Same strings should hash to same value")

      assert_not_equal(hash_value("test"), hash_value("test2"),
          "Different strings should hash differently")
    end)

    test("Handles numbers", function()
      -- Integer tests
      assert_equal(hash_value(123), hash_value(123))
      assert_not_equal(hash_value(123), hash_value(124))

      -- Float tests
      assert_equal(hash_value(123.45), hash_value(123.45))
      assert_not_equal(hash_value(123.45), hash_value(123.46))

      -- Different number types should hash differently
      assert_not_equal(hash_value(123), hash_value(123.1))
    end)

    test("Handles booleans", function()
      assert_equal(hash_value(true), hash_value(true))
      assert_equal(hash_value(false), hash_value(false))
      assert_not_equal(hash_value(true), hash_value(false))
    end)

    test("Handles nil", function()
      local h1 = hash.create()
      local h2 = hash.create()
      h1:update(nil)
      h2:update(nil)
      assert_equal(h1:hex(), h2:hex())
    end)
  end)

  context("Table hashing", function()
    test("Handles array tables", function()
      assert_equal(hash_value({ 1, 2, 3 }), hash_value({ 1, 2, 3 }))
      assert_not_equal(hash_value({ 1, 2, 3 }), hash_value({ 1, 2, 4 }))
      assert_not_equal(hash_value({ 1, 2, 3 }), hash_value({ 1, 2 }))
    end)

    test("Handles key-value tables", function()
      assert_equal(
          hash_value({ foo = "bar", baz = 123 }),
          hash_value({ foo = "bar", baz = 123 })
      )
      assert_not_equal(
          hash_value({ foo = "bar" }),
          hash_value({ foo = "baz" })
      )
    end)

    test("Handles mixed tables", function()
      assert_equal(
          hash_value({ 1, 2, foo = "bar" }),
          hash_value({ 1, 2, foo = "bar" })
      )
      assert_not_equal(
          hash_value({ 1, 2, foo = "bar" }),
          hash_value({ 1, 2, foo = "baz" })
      )
    end)

    test("Handles nested tables", function()
      assert_equal(
          hash_value({ 1, { 2, 3 }, foo = { bar = "baz" } }),
          hash_value({ 1, { 2, 3 }, foo = { bar = "baz" } })
      )
      assert_not_equal(
          hash_value({ 1, { 2, 3 } }),
          hash_value({ 1, { 2, 4 } })
      )
    end)
  end)

  context("Complex scenarios", function()
    test("Handles multiple updates", function()
      local h1 = hash.create()
      h1:update("test")
      h1:update(123)
      h1:update({ foo = "bar" })

      local h2 = hash.create()
      h2:update("test")
      h2:update(123)
      h2:update({ foo = "bar" })

      assert_equal(h1:hex(), h2:hex())
    end)

    test("Order matters for updates", function()
      local h1 = hash.create()
      h1:update("a")
      h1:update("b")

      local h2 = hash.create()
      h2:update("b")
      h2:update("a")

      assert_not_equal(h1:hex(), h2:hex())
    end)

    test("Handles all types together", function()
      local complex = {
        str = "test",
        num = 123,
        float = 123.45,
        bool = true,
        arr = { 1, 2, 3 },
        nested = {
          foo = {
            bar = "baz"
          }
        }
      }

      assert_equal(hash_value(complex), hash_value(complex))
    end)
  end)

  context("Error conditions", function()
    test("Prevents update after finalization", function()
      local h = hash.create()
      h:update("test")
      local _ = h:hex() -- finalize
      assert_error(function()
        h:update("more")
      end)
    end)

    test("Handles function values", function()
      local h = hash.create()
      local f = function()
      end
      assert_not_error(function()
        h:update(f)
      end)
    end)
  end)

  context("Determinism tests", function()
    test("Same input always produces same hash", function()
      local inputs = {
        "test string",
        123,
        true,
        { 1, 2, 3 },
        { foo = "bar", nested = { 1, 2, 3 } },
      }

      for _, input in ipairs(inputs) do
        local h1 = hash_value(input)
        local h2 = hash_value(input)
        assert_equal(h1, h2, "Hash should be deterministic for: " .. type(input))
      end
    end)
  end)
end)