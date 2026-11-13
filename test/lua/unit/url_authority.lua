context("URL authority ends where browsers end it", function()
  local mpool = require("rspamd_mempool")
  local url = require("rspamd_url")
  local rspamd_task = require("rspamd_task")
  local test_helper = require("rspamd_test_helper")

  test_helper.init_url_parser()
  local pool = mpool.create()

  -- url, host, port, obscured
  local cases = {
    { "http://a.example.com\\@b.example.com/", "a.example.com", nil, true },
    { "http://U\\m@w", "u", nil, true },
    { "http://evil.com:80\\@good.com/", "evil.com", 80, true },
    { "http://evil.com:8080\\path", "evil.com", 8080, false },
    { "https://user:pw@b.example.com/", "b.example.com", nil, false },
    { "http:\\\\a.example.com\\path", "a.example.com", nil, true },
  }

  for _, c in ipairs(cases) do
    test("Backslash ends the authority: " .. c[1], function()
      local u = url.create(pool, c[1])
      assert_not_nil(u, "cannot parse " .. c[1])
      assert_equal(c[2], u:get_host())
      if c[3] then
        assert_equal(c[3], u:get_port())
      end
      assert_equal(c[4], u:get_flags().obscured or false)
      -- the normalised form must designate the same host
      local u2 = url.create(pool, tostring(u))
      assert_not_nil(u2, "cannot parse again " .. tostring(u))
      assert_equal(u:get_host(), u2:get_host())
    end)
  end

  local function hosts_of(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    local hosts = {}
    for _, u in ipairs(task:get_urls(true) or {}) do
      hosts[u:get_host()] = u
    end
    task:destroy()
    return hosts
  end

  test("A later address on the line does not drop a text url", function()
    local hosts = hosts_of(table.concat({
      "From: a@example.org",
      "To: b@example.org",
      "Subject: t",
      "Content-Type: text/plain",
      "",
      "Visit http://example.com or write to info@example.org today",
      "Also http://evil.example.com\\@good.example.org/x now",
      "",
    }, "\r\n"))
    assert_not_nil(hosts["example.com"])
    assert_not_nil(hosts["evil.example.com"])
    assert_nil(hosts["good.example.org"])
  end)

  test("Encoded separators do not end the authority of an href", function()
    local hosts = hosts_of(table.concat({
      "From: a@example.org",
      "To: b@example.org",
      "Subject: t",
      "Content-Type: text/html",
      "",
      '<a href="http://one.example.com%2F@evil1.example.net/x">a</a>',
      '<a href="http://two.example.com%3F@evil2.example.net/x">b</a>',
      '<a href="http://three.example.com%5C@evil3.example.net/x">c</a>',
      '<a href="http://evil4.example.net\\@four.example.com/x">d</a>',
      -- browsers drop the newline too
      '<a href="http:/\n/five.example.com%2F@evil5.example.net/x">e</a>',
      -- http and https take any number of slashes before the authority, none too
      '<a href="http:///six.example.com%2F@evil6.example.net/x">f</a>',
      '<a href="http:seven.example.com%2F@evil7.example.net/x">g</a>',
      '<a href="http:///eight.example.com%3F@evil8.example.net/x">h</a>',
      '<a href="https:\\\\\\nine.example.com%5C@evil9.example.net/x">i</a>',
      "",
    }, "\r\n"))
    for _, h in ipairs({ "evil1.example.net", "evil2.example.net", "evil3.example.net",
                         "evil4.example.net", "evil5.example.net", "evil6.example.net",
                         "evil7.example.net", "evil8.example.net", "evil9.example.net" }) do
      assert_not_nil(hosts[h], h .. " is not extracted")
    end
    for _, h in ipairs({ "one.example.com", "two.example.com", "three.example.com",
                         "four.example.com", "five.example.com", "six.example.com",
                         "seven.example.com", "eight.example.com", "nine.example.com" }) do
      assert_nil(hosts[h], h .. " is taken for the host")
    end
  end)

  test("An encoded separator can start the authority of an href", function()
    local hosts = hosts_of(table.concat({
      "From: a@example.org",
      "To: b@example.org",
      "Subject: t",
      "Content-Type: text/html",
      "",
      '<a href="https://%3Fwww.ten.example.com@evil10.example.net/">a</a>',
      '<a href="//%3F@evil11.example.net/">b</a>',
      '<a href="http:%3Fx@evil12.example.net/">c</a>',
      '<a href="https:///%3Fx@evil13.example.net/">d</a>',
      '<a href="https://%2F%3Fx@evil14.example.net/">e</a>',
      "",
    }, "\r\n"))
    for i = 10, 14 do
      local h = string.format("evil%d.example.net", i)
      assert_not_nil(hosts[h], h .. " is not extracted")
    end
    assert_nil(hosts["www.ten.example.com"], "the user info is taken for the host")
  end)
end)
