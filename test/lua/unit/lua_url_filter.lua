-- URL filter tests

context("URL filter functions", function()
  local lua_url_filter = require("lua_url_filter")
  local url = require("rspamd_url")
  local mpool = require("rspamd_mempool")
  local test_helper = require("rspamd_test_helper")
  local logger = require("rspamd_logger")
  local rspamd_text = require("rspamd_text")

  test_helper.init_url_parser()

  local pool = mpool.create()

  local ACCEPT = 0
  local SUSPICIOUS = 1
  local REJECT = 2

  -- Test filter_url_string basic validation
  local filter_cases = {
    -- Normal URLs - should accept
    { "http://example.com", 0, ACCEPT, "normal URL" },
    { "https://www.example.com/path", 0, ACCEPT, "normal HTTPS URL" },
    { "ftp://ftp.example.com", 0, ACCEPT, "normal FTP URL" },

    -- Long user fields - should be suspicious or rejected
    { "http://" .. string.rep("a", 100) .. "@example.com", 0, SUSPICIOUS, "100-char user (suspicious)" },
    { "http://" .. string.rep("a", 300) .. "@example.com", 0, SUSPICIOUS, "300-char user (suspicious)" },
    { "http://" .. string.rep("a", 600) .. "@example.com", 0, REJECT, "600-char user (reject)" },

    -- Multiple @ signs
    { "http://user@@example.com", 0, SUSPICIOUS, "double @ sign" },
    { "http://user@host@example.com", 0, SUSPICIOUS, "multiple @ signs" },
    { "http://" .. string.rep("@", 25) .. "example.com", 0, REJECT, ">20 @ signs (reject)" },

    -- Very long URLs
    { "http://example.com/" .. string.rep("a", 2100), 0, REJECT, ">2048 char URL (reject)" },

    -- Control characters (should reject)
    { "http://example.com/\x00test", 0, REJECT, "URL with null byte" },
    { "http://example.com/\x1ftest", 0, REJECT, "URL with control char" },
  }

  for i, c in ipairs(filter_cases) do
    test("filter_url_string: " .. c[4], function()
      local url_text = rspamd_text.fromstring(c[1])
      local result = lua_url_filter.filter_url_string(url_text, c[2])
      assert_equal(c[3], result,
          logger.slog('expected result %s, but got %s for "%s"',
              c[3], result, c[4]))
    end)
  end

  -- Test filter_url with URL objects
  local url_object_cases = {
    { "http://example.com", ACCEPT, "normal URL object" },
    { "http://" .. string.rep("a", 150) .. "@example.com", SUSPICIOUS, "long user in URL object" },
  }

  for i, c in ipairs(url_object_cases) do
    test("filter_url: " .. c[3], function()
      local parsed_url = url.create(pool, c[1])
      assert_not_nil(parsed_url, "failed to parse: " .. c[1])

      local result = lua_url_filter.filter_url(parsed_url)
      assert_equal(c[2], result,
          logger.slog('expected result %s, but got %s for "%s"',
              c[2], result, c[3]))
    end)
  end

  -- Test UTF-8 validation
  local utf8_cases = {
    { "http://example.com/valid", ACCEPT, "valid ASCII" },
    { "http://example.com/Тест", ACCEPT, "valid UTF-8 Cyrillic" },
    { "http://example.com/日本語", ACCEPT, "valid UTF-8 Japanese" },
    { "http://example.com/\xFF\xFE", REJECT, "invalid UTF-8" },
  }

  for i, c in ipairs(utf8_cases) do
    test("UTF-8 validation: " .. c[3], function()
      local url_text = rspamd_text.fromstring(c[1])
      local result = lua_url_filter.filter_url_string(url_text, 0)
      assert_equal(c[2], result,
          logger.slog('expected result %s, but got %s for "%s"',
              c[2], result, c[3]))
    end)
  end

  -- Test custom filter registration
  test("register custom filter", function()
    lua_url_filter.clear_filters() -- Clear any previously registered filters

    local called = false
    local custom_filter = function(url_text, flags)
      called = true
      -- Custom filters receive rspamd_text, use :find instead of :match
      if url_text:find("blocked") then
        return REJECT
      end
      return ACCEPT
    end

    lua_url_filter.register_filter(custom_filter)

    local url_text = rspamd_text.fromstring("http://blocked.example.com")
    local result = lua_url_filter.filter_url_string(url_text, 0)
    assert_true(called, "custom filter was not called")
    assert_equal(REJECT, result, "custom filter did not reject")

    lua_url_filter.clear_filters() -- Clean up after test
  end)

  -- Test filter chaining
  test("filter chaining stops on REJECT", function()
    lua_url_filter.clear_filters() -- Clear any previously registered filters

    local filter1_called = false
    local filter2_called = false

    lua_url_filter.register_filter(function(url_str, flags)
      filter1_called = true
      return REJECT
    end)

    lua_url_filter.register_filter(function(url_str, flags)
      filter2_called = true
      return ACCEPT
    end)

    local url_text = rspamd_text.fromstring("http://example.com")
    lua_url_filter.filter_url_string(url_text, 0)

    assert_true(filter1_called, "first filter not called")
    assert_false(filter2_called, "second filter called despite REJECT")

    lua_url_filter.clear_filters() -- Clean up after test
  end)

  -- Test oversized user field (issue #5731)
  test("issue #5731 - oversized user field parsing", function()
    local long_user = string.rep("a", 80)
    local url_str = "http://" .. long_user .. ":password@example.com/path"

    local url_text = rspamd_text.fromstring(url_str)
    local result = lua_url_filter.filter_url_string(url_text, 0)

    -- Should be SUSPICIOUS, not REJECT, allowing C parser to continue
    assert_equal(SUSPICIOUS, result,
        "80-char user should be SUSPICIOUS, allowing parsing to continue")

    -- Verify URL can still be parsed by C parser
    local parsed_url = url.create(pool, url_str)
    assert_not_nil(parsed_url, "URL with 80-char user should be parseable")

    local t = parsed_url:to_table()
    assert_equal("example.com", t.host, "host should be parsed correctly")
  end)

end)
