-- Behaviour of the url bindings on arguments that rules can pass

context("URL Lua bindings", function()
  local rspamd_url = require "rspamd_url"
  local rspamd_text = require "rspamd_text"
  local rspamd_task = require "rspamd_task"
  local mpool = require "rspamd_mempool"
  local pool = mpool.create()

  test("create returns nil for a text without an url", function()
    assert_nil(rspamd_url.create(pool, rspamd_text.fromstring("no url here")))
    assert_nil(rspamd_url.create(pool, "no url here"))
    assert_nil(rspamd_url.create(pool, rspamd_text.fromstring("no url here"), { "phished" }))
  end)

  test("create still finds an url in a text", function()
    local u = rspamd_url.create(pool, rspamd_text.fromstring("http://example.com/a"))
    assert_equal("http://example.com/a", tostring(u))
  end)

  test("set_redirected returns nil for a string without an url", function()
    local u = rspamd_url.create(pool, "http://example.com/a")
    assert_nil(u:set_redirected("no url here", pool))
    assert_nil(u:get_flags().redirected)
    assert_nil(u:get_redirected())
  end)

  test("a redirect target is not a phished url", function()
    local u = rspamd_url.create(pool, "http://example.com/b")
    local target = rspamd_url.create(pool, "http://target.example.net/")
    assert_nil(u:get_redirected())
    assert_nil(u:get_phished())
    u:set_redirected(target, pool)
    assert_equal("http://target.example.net/", tostring(u:get_redirected()))
    assert_nil(u:get_phished())

    local s = rspamd_url.create(pool, "http://example.com/c")
    local r = s:set_redirected("http://target.example.org/x", pool)
    assert_equal("http://target.example.org/x", tostring(r))
    assert_equal("http://target.example.org/x", tostring(s:get_redirected()))
  end)

  test("the url shown for a link is not a redirect target", function()
    local msg = "From: <a@example.com>\r\nContent-Type: text/html\r\n\r\n" ..
        '<html><body><a href="http://evil.example.net/x">http://bank.example.com/</a></body></html>\r\n'
    local ok, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(ok)
    task:process_message()
    local seen = false
    for _, u in ipairs(task:get_urls(true)) do
      if u:get_host() == "evil.example.net" then
        seen = true
        assert_true(u:is_phished())
        assert_equal("bank.example.com", u:get_phished():get_host())
        assert_nil(u:get_redirected())
        -- A redirect set later replaces the shown url
        u:set_redirected("http://final.example.org/", task:get_mempool())
        assert_equal("final.example.org", u:get_redirected():get_host())
        assert_nil(u:get_phished())
      end
    end
    assert_true(seen)
    task:destroy()
  end)

  test("to_http escapes what cannot be in a request line", function()
    local cases = {
      { "http://example.com/a%0d%0aX-Header:%20v", "http://example.com/a%0D%0AX-Header:%20v" },
      { "http://user@example.com/a%0d%0aX:1?q=%0a1", "http://example.com/a%0D%0AX:1?q=%0A1" },
      { "http://example.com/a%09b%00c%7f", "http://example.com/a%09b%00c%7F" },
      { "http://example.com/plain?q=1#frag", "http://example.com/plain?q=1" },
      { "http://user:pw@example.com:8080/p?q", "http://example.com:8080/p?q" },
      { "http://u@example.com?q", "http://example.com/?q" },
    }
    for _, c in ipairs(cases) do
      local u = rspamd_url.create(pool, c[1])
      assert_not_nil(u, c[1])
      local res = u:to_http()
      assert_equal(c[2], res)
      assert_nil(res:find("[%z\1-\32\127]"), "raw control in " .. c[1])
    end
  end)

  test("callto is a telephone url", function()
    local u = rspamd_url.create(pool, "callto:+123456")
    assert_not_nil(u)
    assert_equal("telephone", u:get_protocol())
  end)

  test("inject_url refuses a third argument that is no mime part", function()
    local ok, task = rspamd_task.load_from_string(
        "From: <a@example.com>\r\nContent-Type: text/plain\r\n\r\nhello\r\n", rspamd_config)
    assert_true(ok)
    task:process_message()
    local u = rspamd_url.create(task:get_mempool(), "http://injected.example.com/?u=http://inner.example.org/")
    assert_false(pcall(task.inject_url, task, u, u))
    assert_false(pcall(task.inject_url, task, u, task:get_mempool()))
    task:inject_url(u)
    local part = task:get_parts()[1]
    task:inject_url(rspamd_url.create(task:get_mempool(), "http://second.example.com/"), part)
    local hosts = {}
    for _, x in ipairs(task:get_urls(true)) do hosts[x:get_host()] = true end
    assert_true(hosts["injected.example.com"])
    assert_true(hosts["second.example.com"])
    task:destroy()
  end)
end)
