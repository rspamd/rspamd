local caseless_table = require "rspamd_caseless_table"

context("Caseless table tests", function()

  context("Creation", function()
    test("create() returns empty table", function()
      local ct = caseless_table.create()
      assert_not_nil(ct)
      assert_equal(#ct, 0)
    end)

    test("from_table() converts a regular table", function()
      local ct = caseless_table.from_table({
        ["Content-Type"] = "text/html",
        ["X-Spam"] = "yes",
      })
      assert_not_nil(ct)
      assert_equal(#ct, 2)
    end)
  end)

  context("Case-insensitive lookup", function()
    test("Lookup ignores case", function()
      local ct = caseless_table.from_table({
        ["Content-Type"] = "text/html",
      })
      assert_equal(ct["Content-Type"], "text/html")
      assert_equal(ct["content-type"], "text/html")
      assert_equal(ct["CONTENT-TYPE"], "text/html")
      assert_equal(ct["Content-type"], "text/html")
    end)

    test("Missing key returns nil", function()
      local ct = caseless_table.from_table({
        ["X-Header"] = "value",
      })
      assert_nil(ct["Y-Header"])
    end)
  end)

  context("Key case preservation", function()
    test("to_table preserves original key case", function()
      local ct = caseless_table.from_table({
        ["X-Original-Case"] = "value1",
      })
      local t = ct:to_table()
      assert_not_nil(t["X-Original-Case"])
      assert_equal(t["X-Original-Case"], "value1")
    end)

    test("each() yields original key case", function()
      local ct = caseless_table.from_table({
        ["X-MyHeader"] = "val",
      })
      local found = false
      for k, v in ct:each() do
        if k == "X-MyHeader" and v == "val" then
          found = true
        end
      end
      assert_true(found)
    end)
  end)

  context("Assignment (__newindex)", function()
    test("Set new key", function()
      local ct = caseless_table.create()
      ct["X-New"] = "hello"
      assert_equal(ct["x-new"], "hello")
      assert_equal(#ct, 1)
    end)

    test("Overwrite existing key with different case", function()
      local ct = caseless_table.from_table({
        ["Content-Type"] = "text/plain",
      })
      ct["content-type"] = "text/html"
      assert_equal(ct["Content-Type"], "text/html")
      assert_equal(#ct, 1)
    end)

    test("Delete key by assigning nil", function()
      local ct = caseless_table.from_table({
        ["X-Remove"] = "bye",
        ["X-Keep"] = "stay",
      })
      assert_equal(#ct, 2)
      ct["x-remove"] = nil
      assert_nil(ct["X-Remove"])
      assert_equal(#ct, 1)
      assert_equal(ct["X-Keep"], "stay")
    end)
  end)

  context("has_key", function()
    test("Returns true for existing key", function()
      local ct = caseless_table.from_table({
        ["X-Exists"] = "yes",
      })
      assert_true(ct:has_key("X-Exists"))
      assert_true(ct:has_key("x-exists"))
      assert_true(ct:has_key("X-EXISTS"))
    end)

    test("Returns false for missing key", function()
      local ct = caseless_table.from_table({
        ["X-Exists"] = "yes",
      })
      assert_false(ct:has_key("X-Missing"))
    end)
  end)

  context("Length (__len)", function()
    test("Empty table has length 0", function()
      local ct = caseless_table.create()
      assert_equal(#ct, 0)
    end)

    test("Reflects number of keys", function()
      local ct = caseless_table.from_table({
        a = "1",
        b = "2",
        c = "3",
      })
      assert_equal(#ct, 3)
    end)
  end)

  context("Iteration with each()", function()
    test("Iterates over all keys", function()
      local src = {
        ["Alpha"] = "a",
        ["Beta"] = "b",
        ["Gamma"] = "c",
      }
      local ct = caseless_table.from_table(src)
      local collected = {}
      for k, v in ct:each() do
        collected[k] = v
      end
      assert_equal(collected["Alpha"], "a")
      assert_equal(collected["Beta"], "b")
      assert_equal(collected["Gamma"], "c")
    end)
  end)

  context("to_table()", function()
    test("Converts back to regular table", function()
      local src = {
        ["Key1"] = "val1",
        ["Key2"] = "val2",
      }
      local ct = caseless_table.from_table(src)
      local t = ct:to_table()
      assert_equal(type(t), "table")
      assert_equal(t["Key1"], "val1")
      assert_equal(t["Key2"], "val2")
    end)
  end)

  context("Tostring (__tostring)", function()
    test("Returns a descriptive string", function()
      local ct = caseless_table.from_table({
        a = "1",
        b = "2",
      })
      local s = tostring(ct)
      assert_match("caseless_table", s)
      assert_match("2", s)
    end)
  end)

  context("Multi-value entries", function()
    test("from_table with array value stores multi-value", function()
      local ct = caseless_table.from_table({
        ["Set-Cookie"] = {"cookie1", "cookie2", "cookie3"},
      })
      -- __index returns first element
      assert_equal(ct["Set-Cookie"], "cookie1")
      -- get_all returns full array
      local all = ct:get_all("set-cookie")
      assert_not_nil(all)
      assert_equal(type(all), "table")
      assert_equal(#all, 3)
      assert_equal(all[1], "cookie1")
      assert_equal(all[2], "cookie2")
      assert_equal(all[3], "cookie3")
    end)

    test("get_all wraps single value in array", function()
      local ct = caseless_table.from_table({
        ["X-Single"] = "only-one",
      })
      local all = ct:get_all("X-Single")
      assert_equal(type(all), "table")
      assert_equal(#all, 1)
      assert_equal(all[1], "only-one")
    end)

    test("get_all returns nil for missing key", function()
      local ct = caseless_table.create()
      local all = ct:get_all("missing")
      assert_nil(all)
    end)
  end)

  context("Edge cases", function()
    test("Empty string key", function()
      local ct = caseless_table.create()
      ct[""] = "empty"
      assert_equal(ct[""], "empty")
      assert_equal(#ct, 1)
    end)

    test("Numeric values", function()
      local ct = caseless_table.create()
      ct["num"] = 42
      assert_equal(ct["num"], 42)
    end)

    test("Boolean values", function()
      local ct = caseless_table.create()
      ct["flag"] = true
      assert_equal(ct["flag"], true)
    end)

    test("Long key (>256 chars)", function()
      local long_key = string.rep("x", 300)
      local ct = caseless_table.create()
      ct[long_key] = "long"
      assert_equal(ct[long_key], "long")
      assert_equal(ct[string.upper(long_key)], "long")
    end)

    test("Method names are not exposed as keys", function()
      local ct = caseless_table.from_table({
        ["normal"] = "value",
      })
      -- __gc, __tostring etc. should not leak through __index
      assert_nil(ct["__gc"])
      assert_nil(ct["__tostring"])
      assert_nil(ct["__len"])
      assert_nil(ct["__newindex"])
    end)

    test("Methods are callable via method syntax", function()
      local ct = caseless_table.from_table({
        ["key"] = "value",
      })
      -- These should work as methods
      assert_true(ct:has_key("key"))
      assert_not_nil(ct:to_table())
      assert_not_nil(ct:get_all("key"))
    end)
  end)
end)
