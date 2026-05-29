context("HTML URL extraction", function()
  local rspamd_task = require("rspamd_task")
  local logger = require("rspamd_logger")

  test("Basic URL extraction from simple HTML", function()
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

    local urls = task:get_html_urls()

    assert_not_nil(urls, "should extract URLs")

    -- Check structure
    local found_url = false
    for part_id, url_list in pairs(urls) do
      assert_true(type(url_list) == "table", "URL list should be a table")
      for i, url_info in ipairs(url_list) do
        assert_not_nil(url_info.url, "should have url field")
        assert_not_nil(url_info.attr, "should have attr field")
        assert_not_nil(url_info.tag, "should have tag field")

        if url_info.url == "http://example.com/test" then
          assert_equal(url_info.attr, "href", "should be href attribute")
          assert_equal(url_info.tag, "a", "should be <a> tag")
          found_url = true
        end
      end
    end

    assert_true(found_url, "should find the expected URL")

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

    local urls = task:get_html_urls()

    assert_not_nil(urls, "should extract URLs")

    -- Count URLs
    local url_count = 0
    local found_urls = {}
    for part_id, url_list in pairs(urls) do
      for i, url_info in ipairs(url_list) do
        url_count = url_count + 1
        found_urls[url_info.url] = url_info
      end
    end

    assert_equal(url_count, 3, "should have found 3 URLs")
    assert_not_nil(found_urls["http://example.com/link1"], "should find link1")
    assert_not_nil(found_urls["http://example.com/link2"], "should find link2")
    assert_not_nil(found_urls["http://example.com/image.jpg"], "should find image")

    -- Check attributes
    assert_equal(found_urls["http://example.com/link1"].attr, "href")
    assert_equal(found_urls["http://example.com/link1"].tag, "a")
    assert_equal(found_urls["http://example.com/image.jpg"].attr, "src")
    assert_equal(found_urls["http://example.com/image.jpg"].tag, "img")

    task:destroy()
  end)

  test("Non-HTML parts return nil", function()
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

    local urls = task:get_html_urls()

    -- Should return nil for plain text
    assert_nil(urls, "should return nil for non-HTML parts")

    task:destroy()
  end)

  test("Empty HTML returns nil", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local urls = task:get_html_urls()

    -- Should return nil for empty HTML
    assert_nil(urls, "should return nil for empty HTML")

    task:destroy()
  end)

  test("HTML without URLs returns nil", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html>
<body>
<p>Just some text without any links</p>
</body>
</html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local urls = task:get_html_urls()

    -- Should return nil when no URLs found
    assert_nil(urls, "should return nil when no URLs found")

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

    local urls = task:get_html_urls()

    assert_not_nil(urls, "should extract non-data URLs")

    -- Check that data: URIs are skipped
    local found_data_uri = false
    local found_http_url = false
    for part_id, url_list in pairs(urls) do
      for i, url_info in ipairs(url_list) do
        if url_info.url:find("^data:", 1, false) then
          found_data_uri = true
        end
        if url_info.url == "http://example.com/test" then
          found_http_url = true
        end
      end
    end

    assert_false(found_data_uri, "data: URIs should be skipped")
    assert_true(found_http_url, "should have found the http URL")

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

    local urls = task:get_html_urls()

    assert_not_nil(urls, "should extract non-cid URLs")

    -- Check that cid: URIs are skipped
    local found_cid_uri = false
    local found_http_url = false
    for part_id, url_list in pairs(urls) do
      for i, url_info in ipairs(url_list) do
        if url_info.url:find("^cid:", 1, false) then
          found_cid_uri = true
        end
        if url_info.url == "http://example.com/test" then
          found_http_url = true
        end
      end
    end

    assert_false(found_cid_uri, "cid: URIs should be skipped")
    assert_true(found_http_url, "should have found the http URL")

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

    local urls = task:get_html_urls()

    assert_not_nil(urls, "should extract URLs from multipart HTML")

    -- Should have processed at least one HTML part
    local part_count = 0
    local total_urls = 0
    for part_id, url_list in pairs(urls) do
      part_count = part_count + 1
      total_urls = total_urls + #url_list
    end

    assert_true(part_count >= 1, "should have URLs from at least one HTML part")
    assert_true(total_urls >= 1, "should have found at least one URL")

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

    local urls = task:get_html_urls()

    assert_not_nil(urls, "should handle URLs with special chars")

    local found_url = false
    for part_id, url_list in pairs(urls) do
      for i, url_info in ipairs(url_list) do
        if url_info.url:find("example.com/path", 1, true) then
          found_url = true
          -- URL should contain the query parameters
          assert_true(url_info.url:find("param=value", 1, true) ~= nil,
                     "should preserve query parameters")
        end
      end
    end

    assert_true(found_url, "should have found the URL with special chars")

    task:destroy()
  end)

  test("Query-embedded URL extraction is bounded by its parameter", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html><body>
<a href="http://wrap.com/r?u=http%3A%2F%2Fdest.com%2F&b=x&c=y">link</a>
</body></html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local found
    for _, u in ipairs(task:get_urls() or {}) do
      if u:get_host() == "dest.com" then
        found = u:get_text()
      end
    end

    assert_not_nil(found, "embedded query URL should be extracted")
    assert_equal("http://dest.com/", found,
        "embedded URL must stop at the parameter boundary, not swallow &b=x&c=y")

    task:destroy()
  end)

  test("Query-embedded URL inherits CTA from its parent href", function()
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html><body>
<a href="http://wrap.com/r?u=http%3A%2F%2Fdest.com%2F">Click here to continue</a>
</body></html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local found_cta = false
    for _, part in ipairs(task:get_text_parts() or {}) do
      if part:is_html() then
        for _, u in ipairs(part:get_cta_urls({ original = true }) or {}) do
          if u:get_host() == "dest.com" then
            found_cta = true
          end
        end
      end
    end

    assert_true(found_cta,
        "query-extracted destination should inherit CTA from its parent href")

    task:destroy()
  end)

  test("Nested query-embedded URLs are followed to the leaf", function()
    -- href wraps mid, whose (escaped) query wraps deep
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html><body>
<a href="http://wrap.com/r?u=http%3A%2F%2Fmid.com%2F%3Fv%3Dhttp%253A%252F%252Fdeep.com%252F">link</a>
</body></html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls() or {}) do
      hosts[u:get_host()] = true
    end

    assert_true(hosts["mid.com"], "first-level embedded URL should be extracted")
    assert_true(hosts["deep.com"], "nested embedded URL should be extracted")

    task:destroy()
  end)

  test("Nested query-embedded URLs stop at RSPAMD_URL_QUERY_MAX_NESTING", function()
    -- wrap?u=l1?v=l2?w=l3?x=l4?y=l5?z=l6, each level escaped one layer deeper.
    -- With the nesting cap at 5, l1..l5 are extracted but l6 (a 6th level) is not.
    local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html><body>
<a href="http://wrap.com/r?u=http%3A%2F%2Fl1.com%2F%3Fu%3Dhttp%253A%252F%252Fl2.com%252F%253Fv%253Dhttp%25253A%25252F%25252Fl3.com%25252F%25253Fw%25253Dhttp%2525253A%2525252F%2525252Fl4.com%2525252F%2525253Fx%2525253Dhttp%252525253A%252525252F%252525252Fl5.com%252525252F%252525253Fy%252525253Dhttp%25252525253A%25252525252F%25252525252Fl6.com%25252525252F">link</a>
</body></html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls() or {}) do
      hosts[u:get_host()] = true
    end

    assert_true(hosts["l1.com"], "level-1 embedded URL should be extracted")
    assert_true(hosts["l2.com"], "level-2 embedded URL should be extracted")
    assert_true(hosts["l3.com"], "level-3 embedded URL should be extracted")
    assert_true(hosts["l4.com"], "level-4 embedded URL should be extracted")
    assert_true(hosts["l5.com"], "level-5 embedded URL should be extracted")
    assert_nil(hosts["l6.com"], "level-6 URL is past the nesting cap and must not be extracted")

    task:destroy()
  end)

end)
