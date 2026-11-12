-- Hosts, userinfo and their components as seen through the message path

context("URL host parsing", function()
  local rspamd_task = require "rspamd_task"
  local test_helper = require("rspamd_test_helper")

  test_helper.init_url_parser()

  local function extract(content_type, body)
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: " .. content_type .. "\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" ..
        body .. "\r\n"
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    local res = {}
    for _, u in ipairs(task:get_urls(true) or {}) do
      table.insert(res, {
        host = u:get_host(), tld = u:get_tld(), url = tostring(u),
        user = u:get_user(), path = u:get_path(), query = u:get_query(),
        fragment = u:get_fragment(), flags = u:get_flags(),
      })
    end
    task:destroy()
    return res
  end

  -- The first url of a link in an HTML part, nil if there is none
  local function one(href)
    return extract("text/html; charset=utf-8",
        '<html><body><a href="' .. href .. '">click</a></body></html>')[1]
  end

  -- The assert functions exist only inside the test bodies, so they are passed in
  local function make_check(assert_not_nil, assert_equal)
    return function(href, host, tld, msg)
      local u = one(href)
      assert_not_nil(u, "no url for " .. (msg or href))
      assert_equal(host, u.host, "host of " .. (msg or href))
      if tld then
        assert_equal(tld, u.tld, "tld of " .. (msg or href))
      end
      return u
    end
  end

  local function find_host(urls, host)
    for _, u in ipairs(urls) do
      if u.host == host then
        return u
      end
    end
  end

  test("Hosts that grow under normalisation keep their tail", function()
    local check_host = make_check(assert_not_nil, assert_equal)
    -- U+01C6 becomes 'dz' with a caron (2 bytes -> 3 bytes) under NFKC
    local dz = "\199\134"
    local dz_nfkc = "d\197\190"
    local u = check_host("http://" .. string.rep(dz, 12) .. ".example.com/x",
        string.rep(dz_nfkc, 12) .. ".example.com", "example.com", "grown host")
    assert_equal("x", u.path)
    assert_true(u.flags.unnormalised)

    -- Path, query and fragment grow as well and keep what follows them
    u = one("http://example.com/" .. string.rep(dz, 20) .. "?q=" .. string.rep(dz, 20) ..
        "#f" .. string.rep(dz, 20) .. "end")
    assert_not_nil(u)
    assert_equal("example.com", u.host)
    assert_equal(string.rep(dz_nfkc, 20), u.path)
    assert_equal("q=" .. string.rep(dz_nfkc, 20), u.query)
    assert_equal("f" .. string.rep(dz_nfkc, 20) .. "end", u.fragment)

    -- A result that does not fit the 16 bit lengths does not overflow
    u = one("http://example.com/" .. string.rep("\239\183\186", 2400) .. "?q=1#frag")
    assert_not_nil(u)
    assert_equal("example.com", u.host)
    assert_equal("q=1", u.query)
    assert_equal("frag", u.fragment)

    -- Unchanged cases
    check_host("http://example.com/x", "example.com", "example.com")
    check_host("http://xn--strae-oqa.example.com/x", "xn--strae-oqa.example.com", "example.com")
    check_host("http://%41bc.example.com/x", "abc.example.com", "example.com")
    local long = string.rep("a", 60) .. "." .. string.rep("b", 60) .. "." .. string.rep("c", 60) .. ".example.com"
    check_host("http://" .. long .. "/x", long, "example.com", "long host")
  end)

  test("Hosts that grow under the IDN mapping are kept as browsers see them", function()
    local check_host = make_check(assert_not_nil, assert_equal)
    -- A sharp s is kept (UTS #46 non-transitional), a browser goes to xn--strae-oqa
    local u = check_host("http://stra\195\159e.example.com/x", "stra\195\159e.example.com", "example.com")
    assert_equal("x", u.path)
    check_host("http://STRA\195\159E.example.com/", "stra\195\159e.example.com", "example.com")
    -- Final sigma is kept too
    check_host("http://\206\177\207\130.example.com/", "\206\177\207\130.example.com", "example.com")
    -- Capital I with dot above grows when lowercased
    check_host("http://\196\176stanbul.example.com/", "i\204\135stanbul.example.com", "example.com")
    -- A label of many growing characters
    check_host("http://" .. string.rep("\196\176", 50) .. ".example.com/",
        string.rep("i\204\135", 50) .. ".example.com", "example.com")
    -- Unchanged cases
    check_host("http://xn--80ak6aa92e.com/", "xn--80ak6aa92e.com")
    check_host("http://example.com/", "example.com")
    check_host("http://\209\130\208\181\209\129\209\130.example.com/",
        "\209\130\208\181\209\129\209\130.example.com")
  end)

  test("Non-ASCII bytes in the userinfo do not drop the url", function()
    local check_host = make_check(assert_not_nil, assert_equal)
    local u = check_host("http://us\195\169r@example.com/x", "example.com", "example.com")
    assert_equal("us\195\169r", u.user)
    assert_equal("x", u.path)

    u = check_host("http://a:\195\188@example.com/", "example.com", "example.com")
    assert_equal("a", u.user)

    u = check_host("http://\195\188ser:pa\195\159@example.com/", "example.com", "example.com")
    assert_equal("\195\188ser", u.user)

    -- Not valid UTF-8, the userinfo is opaque
    u = check_host("http://us\255er@example.com/", "example.com", "example.com")
    assert_not_nil(u.user)
    u = check_host("http://a:\255\254@example.com/", "example.com", "example.com")
    assert_equal("a", u.user)

    -- Unchanged cases
    u = check_host("http://user:pass@example.com/", "example.com", "example.com")
    assert_equal("user", u.user)
    u = check_host("http://user@example.com:8080/x", "example.com", "example.com")
    assert_equal("user", u.user)
    u = check_host("http://\209\130\208\181\209\129\209\130.example.com/\195\169",
        "\209\130\208\181\209\129\209\130.example.com")
    assert_nil(u.user)
  end)

  test("The host is what follows the last @ of the authority", function()
    local check_host = make_check(assert_not_nil, assert_equal)
    local u = check_host("http://a@b@example.com/x", "example.com", "example.com")
    assert_equal("a@b", u.user)
    assert_true(u.flags.obscured)
    assert_equal("x", u.path)

    u = check_host("http://good.example@evil.example@x.example.com/",
        "x.example.com", "example.com")
    assert_equal("good.example@evil.example", u.user)
    assert_true(u.flags.obscured)

    u = check_host("http://a:b@c:d@example.com/x", "example.com", "example.com")
    assert_true(u.flags.obscured)
    assert_equal("a", u.user)

    u = check_host("http://a@@example.com/x", "example.com", "example.com")
    assert_true(u.flags.obscured)

    -- An @ after the end of the authority is not a part of it
    u = check_host("http://a@example.com/x@y.example.org", "example.com", "example.com")
    assert_equal("a", u.user)
    assert_equal("x@y.example.org", u.path)
    u = check_host("http://a@example.com?q=b@c.example.org", "example.com", "example.com")
    assert_equal("a", u.user)
    u = check_host("http://a@example.com#b@c.example.org", "example.com", "example.com")
    assert_equal("a", u.user)

    -- Unchanged cases
    u = check_host("http://user@example.com/", "example.com", "example.com")
    assert_equal("user", u.user)
    assert_nil(u.flags.obscured)
    u = check_host("http://user:pass@example.com/", "example.com", "example.com")
    assert_equal("user", u.user)
    assert_nil(u.flags.obscured)
  end)

  test("The host is the last @ of the authority in a text", function()
    local check_host = make_check(assert_not_nil, assert_equal)
    local function text_urls(text)
      return extract("text/plain", text)
    end

    local urls = text_urls("see http://a@b@example.com/x now")
    assert_equal(1, #urls)
    assert_equal("example.com", urls[1].host)
    assert_true(urls[1].flags.obscured)

    -- A list separator or a bracket ends the url
    urls = text_urls("see http://a@example.com,b@example.org now")
    assert_not_nil(find_host(urls, "example.com"))
    assert_equal("a", find_host(urls, "example.com").user)
    urls = text_urls("see <http://a@example.com> and b@example.org")
    assert_not_nil(find_host(urls, "example.com"))
    assert_equal("a", find_host(urls, "example.com").user)

    urls = text_urls("see http://us\195\169r@example.com/x now")
    assert_equal(1, #urls)
    assert_equal("example.com", urls[1].host)
    assert_equal("us\195\169r", urls[1].user)
  end)

  test("A decoded host is checked for forbidden characters", function()
    local check_host = make_check(assert_not_nil, assert_equal)
    local u = check_host("http://evil.example.org%2f.example.com/x", "evil.example.org", "example.org",
        "encoded slash")
    assert_true(u.flags.obscured)
    assert_true(u.flags.host_encoded)

    local encoded = { "%00", "%0a", "%0d", "%20", "%40", "%3a", "%5c", "%23", "%3f", "%7f", "%25",
      "%7c", "%5b", "%5d", "%3c", "%3e", "%5e" }

    -- The HTML path decodes a few of these before parsing, so they go through a text part
    for _, c in ipairs(encoded) do
      local href = "http://evil.example.org" .. c .. ".example.com/x"
      u = extract("text/plain", "see " .. href .. " end")[1]
      assert_not_nil(u, "no url for " .. href)
      assert_equal("evil.example.org", u.host, "host of " .. href)
      assert_equal("example.org", u.tld, "tld of " .. href)
      assert_equal("x", u.path)
      assert_true(u.flags.obscured, "no obscured flag for " .. href)
    end

    for _, c in ipairs({ "%20", "%25", "%0a", "%7f" }) do
      u = one("http://evil.example.org" .. c .. ".example.com/x")
      assert_not_nil(u, "no url for " .. c)
      assert_equal("evil.example.org", u.host, "host of " .. c)
      assert_equal("example.org", u.tld, "tld of " .. c)
      assert_true(u.flags.obscured, "no obscured flag for " .. c)
    end

    -- A full width slash is a slash after normalisation and ends the host
    u = one("http://evil.example.org\239\188\143.example.com/x")
    assert_not_nil(u)
    assert_equal("evil.example.org", u.host)
    assert_equal("example.org", u.tld)

    -- Nothing is left
    assert_nil(one("http://%2f.example.com/x"))
    assert_nil(one("http://%00example.com/x"))

    -- Unchanged cases
    u = check_host("http://%41bc.example.com/x", "abc.example.com", "example.com")
    assert_true(u.flags.host_encoded)
    assert_nil(u.flags.obscured)
    check_host("http://example.com/x", "example.com", "example.com")
    check_host("http://xn--strae-oqa.example.com/", "xn--strae-oqa.example.com", "example.com")
    check_host("http://127.0.0.1/x", "127.0.0.1")
    u = check_host("http://[::1]/x", "::1")
    assert_nil(u.flags.obscured)
    u = check_host("http://[2001:db8::1]:8080/x", "2001:db8::1")
    assert_nil(u.flags.obscured)
    u = check_host("http://user:pass@example.com:8080/x", "example.com", "example.com")
    assert_equal("user", u.user)
    local long = string.rep("a", 60) .. "." .. string.rep("b", 60) .. ".example.com"
    check_host("http://" .. long .. "/x", long, "example.com")
  end)
end)
