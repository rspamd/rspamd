context("HTML URL rewriting", function()
  local rspamd_task = require("rspamd_task")
  local logger = require("rspamd_logger")

  test("Basic URL rewriting with simple HTML", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<a href="http://example.com/test">Click here</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    -- Rewrite URL callback
    local function rewrite_callback(task, url)
      if url == "http://example.com/test" then
        return "http://safe.com/redirected"
      end
      return nil
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "rewrite should return results")

    -- Check that we got rewritten HTML
    local rewritten_found = false
    for part_id, html_text in pairs(result) do
      local html = tostring(html_text)
      assert_true(html:find("http://safe.com/redirected", 1, true) ~= nil,
        "rewritten URL not found in output")
      assert_true(html:find("http://example.com/test", 1, true) == nil,
        "original URL should be replaced")
      rewritten_found = true
    end

    assert_true(rewritten_found, "should have rewritten at least one part")

    task:destroy()
  end)

  test("Multiple URLs in same HTML part", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<a href="http://example.com/link1">Link 1</a>
<a href="http://example.com/link2">Link 2</a>
<img src="http://example.com/image.jpg">
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local rewritten_urls = {}
    local function rewrite_callback(task, url)
      table.insert(rewritten_urls, url)
      return "http://safe.com/" .. #rewritten_urls
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "rewrite should return results")
    assert_equal(#rewritten_urls, 3, "should have found 3 URLs")

    -- Check all URLs were rewritten
    for part_id, html_text in pairs(result) do
      local html = tostring(html_text)
      assert_true(html:find("http://safe.com/1", 1, true) ~= nil, "first URL not rewritten")
      assert_true(html:find("http://safe.com/2", 1, true) ~= nil, "second URL not rewritten")
      assert_true(html:find("http://safe.com/3", 1, true) ~= nil, "third URL not rewritten")
    end

    task:destroy()
  end)

  test("Callback returning nil (no rewrite)", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<a href="http://example.com/test">Click here</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    -- Callback returns nil, so no rewriting
    local function rewrite_callback(task, url)
      return nil
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    -- Should return nil when no URLs are rewritten
    assert_nil(result, "should return nil when callback returns nil for all URLs")

    task:destroy()
  end)

  test("Selective URL rewriting", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<a href="http://evil.com/phish">Bad Link</a>
<a href="http://safe.com/ok">Good Link</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local function rewrite_callback(task, url)
      -- Only rewrite evil.com URLs
      if url:find("evil.com", 1, true) then
        return "http://warning.com/blocked"
      end
      return nil
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "rewrite should return results")

    for part_id, html_text in pairs(result) do
      local html = tostring(html_text)
      assert_true(html:find("http://warning.com/blocked", 1, true) ~= nil,
        "evil URL should be rewritten")
      assert_true(html:find("http://safe.com/ok", 1, true) ~= nil,
        "safe URL should remain unchanged")
      assert_true(html:find("http://evil.com/phish", 1, true) == nil,
        "original evil URL should be replaced")
    end

    task:destroy()
  end)

  test("Non-HTML parts are skipped", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/plain

This is plain text with http://example.com/test
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local callback_called = false
    local function rewrite_callback(task, url)
      callback_called = true
      return "http://rewritten.com/"
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    -- Should return nil for plain text
    assert_nil(result, "should return nil for non-HTML parts")
    assert_false(callback_called, "callback should not be called for plain text")

    task:destroy()
  end)

  test("Quoted-printable encoded HTML", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html
Content-Transfer-Encoding: quoted-printable

<html>
<body>
<a href=3D"http://example.com/test">Link</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local function rewrite_callback(task, url)
      if url == "http://example.com/test" then
        return "http://safe.com/redirect"
      end
      return nil
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "rewrite should work on quoted-printable content")

    for part_id, html_text in pairs(result) do
      local html = tostring(html_text)
      -- The rewritten HTML should contain the new URL
      assert_true(html:find("safe.com", 1, true) ~= nil,
        "rewritten URL should be in output")
    end

    task:destroy()
  end)

  test("Empty HTML", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local function rewrite_callback(task, url)
      return "http://rewritten.com/"
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    -- Should return nil for empty HTML
    assert_nil(result, "should return nil for empty HTML")

    task:destroy()
  end)

  test("Invalid callback type", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html><body><a href="http://test.com">test</a></body></html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    -- Pass a non-function
    local success, err = pcall(function()
      task:rewrite_html_urls("not a function")
    end)

    assert_false(success, "should fail with invalid callback")
    assert_true(err:find("function expected", 1, true) ~= nil,
      "error message should mention function expected")

    task:destroy()
  end)

  test("Multipart message with multiple HTML parts", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Plain text part

--boundary123
Content-Type: text/html

<html><body><a href="http://example.com/part1">Part 1</a></body></html>

--boundary123
Content-Type: text/html

<html><body><a href="http://example.com/part2">Part 2</a></body></html>

--boundary123--
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local urls_seen = {}
    local function rewrite_callback(task, url)
      table.insert(urls_seen, url)
      return "http://safe.com/" .. #urls_seen
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "should rewrite multipart HTML")

    -- Should have processed both HTML parts
    local part_count = 0
    for part_id, html_text in pairs(result) do
      part_count = part_count + 1
    end

    assert_true(part_count >= 1, "should have rewritten at least one HTML part")
    assert_true(#urls_seen >= 1, "should have found at least one URL")

    task:destroy()
  end)

  test("URL with special characters", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<a href="http://example.com/path?param=value&other=123#anchor">Link</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local captured_url = nil
    local function rewrite_callback(task, url)
      captured_url = url
      return "http://safe.com/redirect"
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "should handle URLs with special chars")
    assert_not_nil(captured_url, "should have captured URL")

    for part_id, html_text in pairs(result) do
      local html = tostring(html_text)
      assert_true(html:find("http://safe.com/redirect", 1, true) ~= nil,
        "rewritten URL should be in output")
    end

    task:destroy()
  end)

  test("Data URI scheme is skipped", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<img src="data:image/png;base64,iVBORw0KG==">
<a href="http://example.com/test">Real link</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local urls_seen = {}
    local function rewrite_callback(task, url)
      table.insert(urls_seen, url)
      return "http://safe.com/redirect"
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "should rewrite non-data URLs")

    -- Should only see the http URL, not the data: URI
    local found_data_uri = false
    for _, url in ipairs(urls_seen) do
      if url:find("^data:", 1) then
        found_data_uri = true
      end
    end

    assert_false(found_data_uri, "data: URIs should be skipped")
    assert_true(#urls_seen >= 1, "should have found the http URL")

    task:destroy()
  end)

  test("CID scheme is skipped", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<img src="cid:image001@example.com">
<a href="http://example.com/test">Real link</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local urls_seen = {}
    local function rewrite_callback(task, url)
      table.insert(urls_seen, url)
      return "http://safe.com/redirect"
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "should rewrite non-cid URLs")

    -- Should only see the http URL, not the cid: URI
    local found_cid_uri = false
    for _, url in ipairs(urls_seen) do
      if url:find("^cid:", 1) then
        found_cid_uri = true
      end
    end

    assert_false(found_cid_uri, "cid: URIs should be skipped")
    assert_true(#urls_seen >= 1, "should have found the http URL")

    task:destroy()
  end)

  test("Edge case: bare cid: and data: schemes", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<img src="cid:">
<img src="data:">
<a href="http://example.com/test">Real link</a>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local urls_seen = {}
    local function rewrite_callback(task, url)
      table.insert(urls_seen, url)
      return "http://safe.com/redirect"
    end

    local result = task:rewrite_html_urls(rewrite_callback)

    assert_not_nil(result, "should rewrite non-special scheme URLs")

    -- Should only see the http URL, not bare cid: or data:
    assert_equal(#urls_seen, 1, "should see exactly 1 URL (the http one)")
    assert_equal(urls_seen[1], "http://example.com/test", "should see the http URL")

    task:destroy()
  end)

end)
