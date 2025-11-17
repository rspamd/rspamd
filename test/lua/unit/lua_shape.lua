context("Lua shape validation", function()
  local T = require "lua_shape.core"
  local Registry = require "lua_shape.registry"

  -- Scalar type tests
  context("Scalar types", function()
    test("String type - valid", function()
      local schema = T.string()
      local ok, val = schema:check("hello")
      assert_true(ok)
      assert_equal(val, "hello")
    end)

    test("String type - invalid", function()
      local schema = T.string()
      local ok, err = schema:check(123)
      assert_false(ok)
      assert_equal(err.kind, "type_mismatch")
      assert_equal(err.details.expected, "string")
      assert_equal(err.details.got, "number")
    end)

    test("String with length constraints", function()
      local schema = T.string({ min_len = 3, max_len = 10 })

      local ok, val = schema:check("hello")
      assert_true(ok)

      ok = schema:check("hi")
      assert_false(ok)

      ok = schema:check("this is too long")
      assert_false(ok)
    end)

    test("String with pattern", function()
      local schema = T.string({ pattern = "^%d+$" })

      local ok = schema:check("123")
      assert_true(ok)

      ok = schema:check("abc")
      assert_false(ok)
    end)

    test("Integer type with range", function()
      local schema = T.integer({ min = 0, max = 100 })

      local ok, val = schema:check(50)
      assert_true(ok)
      assert_equal(val, 50)

      ok = schema:check(150)
      assert_false(ok)

      ok = schema:check(-10)
      assert_false(ok)
    end)

    test("Integer rejects non-integer", function()
      local schema = T.integer()
      local ok, err = schema:check(3.14)
      assert_false(ok)
      assert_equal(err.kind, "constraint_violation")
      assert_equal(err.details.constraint, "integer")
    end)

    test("Number accepts integer and float", function()
      local schema = T.number({ min = 0, max = 10 })

      local ok = schema:check(5)
      assert_true(ok)

      ok = schema:check(5.5)
      assert_true(ok)

      ok = schema:check(15)
      assert_false(ok)
    end)

    test("Boolean type", function()
      local schema = T.boolean()

      local ok, val = schema:check(true)
      assert_true(ok)
      assert_equal(val, true)

      ok, val = schema:check(false)
      assert_true(ok)
      assert_equal(val, false)

      ok = schema:check("true")
      assert_false(ok)
    end)

    test("Enum type", function()
      local schema = T.enum({"debug", "info", "warning", "error"})

      local ok = schema:check("info")
      assert_true(ok)

      ok, err = schema:check("trace")
      assert_false(ok)
      assert_equal(err.kind, "enum_mismatch")
    end)

    test("Literal type", function()
      local schema = T.literal("exact_value")

      local ok = schema:check("exact_value")
      assert_true(ok)

      ok = schema:check("other_value")
      assert_false(ok)
    end)
  end)

  -- Array type tests
  context("Array type", function()
    test("Array of strings - valid", function()
      local schema = T.array(T.string())
      local ok, val = schema:check({"foo", "bar", "baz"})
      assert_true(ok)
      assert_rspamd_table_eq({expect = {"foo", "bar", "baz"}, actual = val})
    end)

    test("Array of strings - invalid item", function()
      local schema = T.array(T.string())
      local ok, err = schema:check({"foo", 123, "baz"})
      assert_false(ok)
      assert_equal(err.kind, "array_items_invalid")
    end)

    test("Array with size constraints", function()
      local schema = T.array(T.string(), { min_items = 2, max_items = 5 })

      local ok = schema:check({"a", "b", "c"})
      assert_true(ok)

      ok = schema:check({"a"})
      assert_false(ok)

      ok = schema:check({"a", "b", "c", "d", "e", "f"})
      assert_false(ok)
    end)

    test("Array rejects table with non-array keys", function()
      local schema = T.array(T.string())
      local ok, err = schema:check({foo = "bar"})
      assert_false(ok)
      assert_equal(err.kind, "type_mismatch")
    end)
  end)

  -- Table type tests
  context("Table type", function()
    test("Simple table - valid", function()
      local schema = T.table({
        name = T.string(),
        age = T.integer({ min = 0 })
      })

      local ok, val = schema:check({ name = "Alice", age = 30 })
      assert_true(ok)
      assert_equal(val.name, "Alice")
      assert_equal(val.age, 30)
    end)

    test("Table - missing required field", function()
      local schema = T.table({
        name = T.string(),
        age = T.integer()
      })

      local ok, err = schema:check({ name = "Bob" })
      assert_false(ok)
      assert_equal(err.kind, "table_invalid")
    end)

    test("Table - optional field", function()
      local schema = T.table({
        name = T.string(),
        email = T.string():optional()
      })

      local ok, val = schema:check({ name = "Charlie" })
      assert_true(ok)
      assert_equal(val.name, "Charlie")
      assert_nil(val.email)
    end)

    test("Table - optional field with explicit syntax", function()
      local schema = T.table({
        name = T.string(),
        email = { schema = T.string(), optional = true }
      })

      local ok = schema:check({ name = "David" })
      assert_true(ok)
    end)

    test("Table - default value in transform mode", function()
      local schema = T.table({
        name = T.string(),
        port = { schema = T.integer(), optional = true, default = 8080 }
      })

      local ok, val = schema:transform({ name = "server" })
      assert_true(ok)
      assert_equal(val.port, 8080)
    end)

    test("Table - closed table rejects unknown fields", function()
      local schema = T.table({
        name = T.string()
      }, { open = false })

      local ok, err = schema:check({ name = "Eve", extra = "field" })
      assert_false(ok)
      assert_equal(err.kind, "table_invalid")
    end)

    test("Table - open table allows unknown fields", function()
      local schema = T.table({
        name = T.string()
      }, { open = true })

      local ok, val = schema:check({ name = "Frank", extra = "field" })
      assert_true(ok)
      assert_equal(val.extra, "field")
    end)
  end)

  -- Optional and default tests
  context("Optional and default values", function()
    test("Optional wrapper", function()
      local schema = T.optional(T.string())

      local ok, val = schema:check("hello")
      assert_true(ok)
      assert_equal(val, "hello")

      ok, val = schema:check(nil)
      assert_true(ok)
      assert_nil(val)
    end)

    test("Optional with default in check mode", function()
      local schema = T.string():with_default("default")

      local ok, val = schema:check(nil)
      assert_true(ok)
      assert_nil(val) -- check mode doesn't apply defaults
    end)

    test("Optional with default in transform mode", function()
      local schema = T.string():with_default("default")

      local ok, val = schema:transform(nil)
      assert_true(ok)
      assert_equal(val, "default")
    end)
  end)

  -- Transform tests
  context("Transform support", function()
    test("Transform string to number", function()
      local schema = T.transform(T.number(), function(val)
        if type(val) == "string" then
          return tonumber(val)
        end
        return val
      end)

      local ok, val = schema:transform("42")
      assert_true(ok)
      assert_equal(val, 42)
    end)

    test("Transform with validation", function()
      local schema = T.transform(T.integer({ min = 0 }), function(val)
        if type(val) == "string" then
          return tonumber(val)
        end
        return val
      end)

      -- Valid transform
      local ok, val = schema:transform("10")
      assert_true(ok)
      assert_equal(val, 10)

      -- Transform result fails validation
      ok = schema:transform("-5")
      assert_false(ok)
    end)

    test("Transform only in transform mode", function()
      local schema = T.transform(T.number(), function(val)
        return val * 2
      end)

      -- Check mode: no transform
      local ok, val = schema:check(5)
      assert_true(ok)
      assert_equal(val, 5)

      -- Transform mode: applies transform
      ok, val = schema:transform(5)
      assert_true(ok)
      assert_equal(val, 10)
    end)

    test("Chained transform using :transform_with", function()
      local schema = T.string():transform_with(function(val)
        return val:upper()
      end)

      local ok, val = schema:transform("hello")
      assert_true(ok)
      assert_equal(val, "HELLO")
    end)
  end)

  -- one_of tests
  context("one_of type", function()
    test("one_of - first variant matches", function()
      local schema = T.one_of({
        T.string(),
        T.integer()
      })

      local ok, val = schema:check("text")
      assert_true(ok)
      assert_equal(val, "text")
    end)

    test("one_of - second variant matches", function()
      local schema = T.one_of({
        T.string(),
        T.integer()
      })

      local ok, val = schema:check(42)
      assert_true(ok)
      assert_equal(val, 42)
    end)

    test("one_of - no variant matches", function()
      local schema = T.one_of({
        T.string(),
        T.integer()
      })

      local ok, err = schema:check(true)
      assert_false(ok)
      assert_equal(err.kind, "one_of_mismatch")
      assert_equal(#err.details.variants, 2)
    end)

    test("one_of with named variants", function()
      local schema = T.one_of({
        { name = "string_variant", schema = T.string() },
        { name = "number_variant", schema = T.integer() }
      })

      local ok = schema:check("text")
      assert_true(ok)
    end)

    test("one_of with table variants shows intersection", function()
      local schema = T.one_of({
        {
          name = "adult",
          schema = T.table({
            name = T.string(),
            age = T.integer({ min = 18 })
          })
        },
        {
          name = "child",
          schema = T.table({
            name = T.string(),
            age = T.integer({ max = 17 })
          })
        }
      })

      local ok, err = schema:check({ age = 25 })
      assert_false(ok)
      assert_equal(err.kind, "one_of_mismatch")
      -- Should have intersection showing common fields
      assert_not_nil(err.details.intersection)
      assert_not_nil(err.details.intersection.required_fields.name)
      assert_not_nil(err.details.intersection.required_fields.age)
    end)
  end)

  -- Registry tests
  context("Registry", function()
    test("Define and get schema", function()
      local reg = Registry.global()

      local schema = reg:define("test.simple", T.string())
      assert_not_nil(schema)

      local retrieved = reg:get("test.simple")
      assert_not_nil(retrieved)
    end)

    test("Reference resolution", function()
      -- Use global registry but with unique schema ID
      local reg = Registry.global()
      local unique_id = "test.ref_user_" .. tostring(os.time())

      local user_schema = T.table({
        name = T.string(),
        email = T.string()
      })

      reg:define(unique_id, user_schema)

      -- Create a simple test: resolve a ref directly
      local ref_schema = T.ref(unique_id)
      local resolved = reg:resolve_schema(ref_schema)

      -- Resolved schema should now be the actual table schema
      local ok, val = resolved:check({ name = "Alice", email = "alice@example.com" })
      assert_true(ok)
      assert_equal(val.name, "Alice")
    end)

    test("List registered schemas", function()
      local reg = Registry.global()
      local ids = reg:list()
      assert_not_nil(ids)
      assert_equal(type(ids), "table")
    end)
  end)

  -- Error formatting tests
  context("Error formatting", function()
    test("Format type mismatch error", function()
      local schema = T.string()
      local ok, err = schema:check(123)
      assert_false(ok)

      local formatted = T.format_error(err)
      assert_not_nil(formatted)
      assert_true(#formatted > 0)
      assert_true(formatted:find("type mismatch") ~= nil)
    end)

    test("Format constraint violation error", function()
      local schema = T.integer({ min = 0, max = 100 })
      local ok, err = schema:check(150)
      assert_false(ok)

      local formatted = T.format_error(err)
      assert_not_nil(formatted)
      assert_true(formatted:find("constraint violation") ~= nil)
      assert_true(formatted:find("max") ~= nil)
    end)

    test("Format nested table errors", function()
      local schema = T.table({
        name = T.string(),
        config = T.table({
          port = T.integer({ min = 1, max = 65535 })
        })
      })

      local ok, err = schema:check({
        name = "server",
        config = { port = 99999 }
      })
      assert_false(ok)

      local formatted = T.format_error(err)
      assert_not_nil(formatted)
      assert_true(formatted:find("config.port") ~= nil)
    end)

    test("Format one_of error with intersection", function()
      local schema = T.one_of({
        {
          name = "config_a",
          schema = T.table({ type = T.literal("a"), value_a = T.string() })
        },
        {
          name = "config_b",
          schema = T.table({ type = T.literal("b"), value_b = T.integer() })
        }
      })

      local ok, err = schema:check({ value_a = "test" })
      assert_false(ok)

      local formatted = T.format_error(err)
      assert_not_nil(formatted)
      assert_true(formatted:find("alternative") ~= nil)
      assert_true(formatted:find("type") ~= nil)
    end)
  end)

  -- Documentation support
  context("Documentation", function()
    test("Add documentation to schema", function()
      local schema = T.string():doc({
        summary = "User name",
        description = "Full name of the user",
        examples = {"Alice", "Bob"}
      })

      assert_not_nil(schema.opts.doc)
      assert_equal(schema.opts.doc.summary, "User name")
    end)

    test("Documentation doesn't affect validation", function()
      local schema = T.integer({ min = 0 }):doc({ summary = "Age" })

      local ok = schema:check(25)
      assert_true(ok)

      ok = schema:check(-5)
      assert_false(ok)
    end)
  end)

  -- Utility functions
  context("Utility functions", function()
    test("Deep clone", function()
      local original = {
        a = 1,
        b = { c = 2, d = { e = 3 } }
      }

      local cloned = T.deep_clone(original)

      assert_rspamd_table_eq({expect = original, actual = cloned})
      assert_not_equal(cloned, original) -- different object
      assert_not_equal(cloned.b, original.b) -- nested is cloned too
    end)

    test("Deep clone handles non-tables", function()
      assert_equal(T.deep_clone("string"), "string")
      assert_equal(T.deep_clone(42), 42)
      assert_equal(T.deep_clone(true), true)
      assert_nil(T.deep_clone(nil))
    end)
  end)
end)
