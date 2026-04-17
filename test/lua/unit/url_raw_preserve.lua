-- Regression test for issue #5986: url:get_raw() must return the URL text
-- as it appeared in the original message (preserving percent-encoding),
-- even when the same URL is present in both the HTML part (where href
-- values are partially percent-decoded during parsing) and the plain-text
-- part.  HTML parts are processed before plain-text parts, so before the
-- fix the HTML-sourced URL (with a partially-decoded raw buffer) would
-- win deduplication and url:get_raw() would return a mangled form.

context("URL get_raw preservation across multipart/alternative", function()
  local rspamd_task = require("rspamd_task")

  -- A long percent-encoded URL that exercises the html_process_url
  -- decoder (which decodes %40, %3A, %7C, %2F, %3F, %5C back to
  -- their literal characters).  Using characters the decoder touches
  -- so we can distinguish "raw as seen in message" from "decoded".
  local encoded_url =
    "https://safelinks.example.com/?url=https%3A%2F%2Flink.example.com%2Fpath" ..
    "&data=05%7C02%7Cmail%40example.com%7C0%7C%7C%7C&reserved=0"
  local decoded_url =
    "https://safelinks.example.com/?url=https://link.example.com/path" ..
    "&data=05|02|mail@example.com|0|||&reserved=0"

  local function find_safelinks(urls)
    for _, u in ipairs(urls) do
      if u:get_host() == "safelinks.example.com" then
        return u
      end
    end
    return nil
  end

  test("plain-text-only URL: raw is verbatim", function()
    local msg = table.concat({
      "From: test@example.com",
      "To: nobody@example.com",
      "Subject: test",
      "Content-Type: text/plain",
      "",
      "Visit " .. encoded_url,
      "",
    }, "\r\n")

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local u = find_safelinks(task:get_urls({ "https", "http" }))
    assert_not_nil(u, "safelinks URL should be extracted")
    assert_equal(u:get_raw(), encoded_url,
      "plain-text URL raw must equal the verbatim text")
    task:destroy()
  end)

  test("HTML-only URL: raw is verbatim href", function()
    local msg = table.concat({
      "From: test@example.com",
      "To: nobody@example.com",
      "Subject: test",
      "Content-Type: text/html",
      "",
      '<html><body><a href="' .. encoded_url .. '">Click</a></body></html>',
      "",
    }, "\r\n")

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local u = find_safelinks(task:get_urls({ "https", "http" }))
    assert_not_nil(u, "safelinks URL should be extracted")
    assert_equal(u:get_raw(), encoded_url,
      "HTML href raw must equal the verbatim href bytes, not the partially decoded form")
    task:destroy()
  end)

  test("same URL in HTML and plain text: raw stays verbatim (issue #5986)", function()
    local boundary = "boundary-string"
    local msg = table.concat({
      "From: test@example.com",
      "To: nobody@example.com",
      "Subject: test",
      "MIME-Version: 1.0",
      'Content-Type: multipart/alternative; boundary="' .. boundary .. '"',
      "",
      "--" .. boundary,
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Visit " .. encoded_url,
      "",
      "--" .. boundary,
      "Content-Type: text/html; charset=utf-8",
      "",
      '<html><body><a href="' .. encoded_url .. '">Click</a></body></html>',
      "",
      "--" .. boundary .. "--",
      "",
    }, "\r\n")

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local u = find_safelinks(task:get_urls({ "https", "http" }))
    assert_not_nil(u, "safelinks URL should be extracted")
    -- Before the fix this returned the decoded form.
    assert_equal(u:get_raw(), encoded_url,
      "dedup winner's raw must preserve the verbatim percent-encoded text")
    assert_not_equal(u:get_raw(), decoded_url,
      "raw must not be the partially-decoded form used internally for parsing")
    task:destroy()
  end)

  test("raw buffer outlives parse scratch (memory ownership)", function()
    -- Ensure that url:get_raw() continues to return stable bytes after
    -- processing finishes and the scratch buffers used during parsing
    -- go out of scope.  Both strings must survive a GC pass since the
    -- raw pointer lives in the task mempool.
    local msg = table.concat({
      "From: test@example.com",
      "To: nobody@example.com",
      "Subject: test",
      "Content-Type: text/html",
      "",
      '<html><body><a href="' .. encoded_url .. '">X</a></body></html>',
      "",
    }, "\r\n")

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local u = find_safelinks(task:get_urls({ "https", "http" }))
    assert_not_nil(u)
    local first = u:get_raw()
    collectgarbage("collect")
    collectgarbage("collect")
    local second = u:get_raw()
    assert_equal(first, second, "raw must remain stable across GC (mempool-backed)")
    assert_equal(first, encoded_url)
    task:destroy()
  end)
end)
