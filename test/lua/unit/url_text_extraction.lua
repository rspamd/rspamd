context("URL extraction from plain text", function()
  local rspamd_task = require("rspamd_task")
  local url = require("rspamd_url")
  local mpool = require("rspamd_mempool")
  local test_helper = require("rspamd_test_helper")

  test_helper.init_url_parser()
  local pool = mpool.create()

  -- Runs a body through a real task, returns a list of
  -- { str, host, proto, flags } for the web urls, emails and phones
  local function extract(body, ctype)
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: " .. (ctype or "text/plain") .. "; charset=utf-8\r\n\r\n" .. body .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    local out = {}
    local function add(list)
      for _, u in ipairs(list or {}) do
        table.insert(out, {
          str = tostring(u),
          host = u:get_host(),
          proto = u:get_protocol(),
          flags = u:get_flags(),
        })
      end
    end
    add(task:get_urls(true))
    add(task:get_urls("telephone"))
    task:destroy()
    return out
  end

  local function find(list, proto, host)
    for _, u in ipairs(list) do
      if u.proto == proto and (host == nil or u.host == host) then
        return u
      end
    end
    return nil
  end

  local function describe(list)
    local t = {}
    for _, u in ipairs(list) do
      table.insert(t, u.str)
    end
    return "[" .. table.concat(t, ", ") .. "]"
  end

  local function expect_web(body, proto, host, ctype)
    local list = extract(body, ctype)
    local u = find(list, proto, host)
    assert(u ~= nil, "no " .. proto .. " url with host " .. host .. " in '" .. body ..
        "', got " .. describe(list))
    return u, list
  end

  -- Returns true if there is nothing in the body, or false and what was found
  local function no_urls(body, ctype)
    local list = extract(body, ctype)
    return #list == 0, "unexpected urls in '" .. body .. "': " .. describe(list)
  end

  -- Task 1: tel: and callto: start at a word boundary and end with the number

  for _, c in ipairs({
    "Hotel: 1 night. See http://evil.example.com/x",
    "Intel: 5551234 http://evil.example.com/x",
    "Motel: 2 nights http://evil.example.com/x",
    "Tel: 5551234 http://evil.example.com/x",
    "tel:5551234 http://evil.example.com/x",
    "Tel: 555 1234 http://evil.example.com/x",
    "callto:5 http://evil.example.com/x",
    "tel:+1-555-123-4567 http://evil.example.com/x",
    "tel: 555 1234 x. http://evil.example.com/x",
  }) do
    test("A url after a phone-like text is found: " .. c, function()
      local u = expect_web(c, "http", "evil.example.com")
      assert_equal("http://evil.example.com/x", u.str)
    end)
  end

  for _, c in ipairs({ "Hotel: 1 night", "Intel: 5551234", "Motel: x", "Hotel: x", "tel:", "tel: x", "callto:alice" }) do
    test("No phone in: " .. c, function()
      local ok, msg = no_urls(c)
      assert_true(ok, msg)
    end)
  end

  test("tel: inside a word is not a phone", function()
    local list = extract("Hotel: 1 night. See http://evil.example.com/x")
    assert_nil(find(list, "telephone"), "phone from Hotel: " .. describe(list))
  end)

  test("A phone with separators", function()
    local list = extract("tel:+1-555-123-4567")
    local u = find(list, "telephone")
    assert_not_nil(u, "no phone, got " .. describe(list))
    assert_equal("15551234567", u.host)
    assert_equal("tel:15551234567", u.str)
  end)

  test("A phone with spaces and parentheses", function()
    local list = extract("call tel:+1 (555) 123-4567 now")
    local u = find(list, "telephone")
    assert_not_nil(u, "no phone, got " .. describe(list))
    assert_equal("15551234567", u.host)
  end)

  test("A phone with parameters", function()
    local list = extract("tel:5551234;ext=1")
    local u = find(list, "telephone")
    assert_not_nil(u, "no phone, got " .. describe(list))
    assert_equal("55512341", u.host)
    assert_equal("tel:55512341", u.str)
  end)

  test("A phone after the scheme and a space", function()
    local list = extract("Tel: 555 1234")
    local u = find(list, "telephone")
    assert_not_nil(u, "no phone, got " .. describe(list))
    assert_equal("5551234", u.host)
  end)

  test("A phone in parentheses and before a full stop", function()
    local u = find(extract("(tel:555-1234)"), "telephone")
    assert_not_nil(u)
    assert_equal("5551234", u.host)
    u = find(extract("write or tel:555-1234."), "telephone")
    assert_not_nil(u)
    assert_equal("5551234", u.host)
  end)

  test("A phone and a url on one line are both found", function()
    local list = extract("Tel: 5551234 http://evil.example.com/x")
    assert_not_nil(find(list, "telephone", "5551234"), describe(list))
    assert_not_nil(find(list, "http", "evil.example.com"), describe(list))
  end)

  test("A letter ends a phone", function()
    local list = extract("tel:5551234abc http://evil.example.com/x")
    assert_not_nil(find(list, "http", "evil.example.com"), describe(list))
  end)

  -- Task 2: a rejected candidate does not hide the ones after it

  for _, p in ipairs({
    "http://a..b/",
    "http://-a.com/",
    "http://a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p/",
    "http://a.com:99999/",
    "http://x.co:/",
  }) do
    test("A url after a rejected one: " .. p, function()
      local body = p .. "http://evil.example.com/x"
      local u, list = expect_web(body, "http", "evil.example.com")
      assert_equal("http://evil.example.com/x", u.str, describe(list))
    end)
  end

  test("Two urls with a rejected candidate between them", function()
    local list = extract("http://a.example.com/x http://a..b/http://b.example.com/y")
    assert_not_nil(find(list, "http", "a.example.com"), describe(list))
    assert_not_nil(find(list, "http", "b.example.com"), describe(list))
  end)

  -- Task 3: a scheme glued to a word

  for _, c in ipairs({
    { "Clickhttps://evil.example.com/x", "https", "https://evil.example.com/x" },
    { "1http://evil.example.com/x", "http", "http://evil.example.com/x" },
    { "a\226\128\139http://evil.example.com/x", "http", "http://evil.example.com/x" },
    { "shttp://evil.example.com/x", "http", "http://evil.example.com/x" },
    { "xhttps://evil.example.com/x", "https", "https://evil.example.com/x" },
    { "Visithttp://evil.example.com/x now", "http", "http://evil.example.com/x" },
    { "Getftp://evil.example.com/x", "ftp", "ftp://evil.example.com/x" },
    { "sftp://evil.example.com/x", "ftp", "ftp://evil.example.com/x" },
  }) do
    test("A scheme glued to a word: " .. c[1], function()
      local u = expect_web(c[1], c[2], "evil.example.com")
      assert_equal(c[3], u.str)
    end)
  end

  for _, c in ipairs({ "foohttp:bar", "hxxp://evil.example.com", "xhttp:evil", "1sip:evil.example.com" }) do
    test("Not an url: " .. c, function()
      local list = extract(c)
      assert_nil(find(list, "http"), describe(list))
      assert_nil(find(list, "https"), describe(list))
      assert_nil(find(list, "ftp"), describe(list))
    end)
  end

  test("An url after text is as before", function()
    local u = expect_web("see http://a.example.com/x", "http", "a.example.com")
    assert_equal("http://a.example.com/x", u.str)
    assert_false(u.flags.obscured or false)
  end)

  test("Two urls on a line", function()
    local list = extract("http://a.example.com/x http://b.example.com/y")
    assert_not_nil(find(list, "http", "a.example.com"), describe(list))
    assert_not_nil(find(list, "http", "b.example.com"), describe(list))
  end)

  test("An url glued to the one before it is one url", function()
    local list = extract("http://a.example.com/xhttp://b.example.com/y")
    assert_not_nil(find(list, "http", "a.example.com"), describe(list))
    assert_nil(find(list, "http", "b.example.com"), describe(list))
  end)

  test("mailto: and a bare address", function()
    local u = expect_web("mailto:user@example.com", "mailto", "example.com")
    assert_equal("user@example.com", u.str)
    u = expect_web("write to user@example.com now", "mailto", "example.com")
    assert_equal("user@example.com", u.str)
  end)

  -- Task 4: one slash or backslash after the scheme

  for _, c in ipairs({
    { "http:/evil.example.com/x", "http", "http://evil.example.com/x", true },
    { "https:/evil.example.com/x", "https", "https://evil.example.com/x", true },
    { "http:\\evil.example.com/x", "http", "http://evil.example.com/x", true },
    { "http:/\\evil.example.com/x", "http", "http://evil.example.com/x", true },
    { "ftp:/evil.example.com/x", "ftp", "ftp://evil.example.com/x", true },
    { "see https:\\evil.example.com/x now", "https", "https://evil.example.com/x", true },
    { "http://evil.example.com/x", "http", "http://evil.example.com/x", false },
  }) do
    test("Slashes after the scheme: " .. c[1], function()
      local u = expect_web(c[1], c[2], "evil.example.com")
      assert_equal(c[3], u.str)
      assert_equal(c[4], u.flags.obscured or false)
    end)
  end

  test("A single slash does not swallow the next url", function()
    local list = extract("http:/a.example.com/x http://b.example.com/y")
    assert_not_nil(find(list, "http", "a.example.com"), describe(list))
    assert_not_nil(find(list, "http", "b.example.com"), describe(list))
  end)

  test("A single slash with a user name", function()
    local u = expect_web("http:/user@evil.example.com/x", "http", "evil.example.com")
    assert_equal("user", u.str:match("//([^@]+)@"))
  end)

  test("A single slash is created as an url", function()
    local u = url.create(pool, "http:/evil.example.com/x")
    assert_not_nil(u)
    assert_equal("evil.example.com", u:get_host())
    assert_equal("http://evil.example.com/x", tostring(u))
    assert_true(u:get_flags().obscured or false)
  end)

  test("A single slash stays an error for an upstream", function()
    assert_nil(url.parse(pool, "http:/a.example.com/x", { upstream = true }))
    assert_nil(url.parse(pool, "http:\\a.example.com/x", { upstream = true }))
    assert_not_nil(url.parse(pool, "http://a.example.com/x", { upstream = true }))
  end)

  -- Task 5: www. does not depend on the regular expression engine

  test("www. in an html part", function()
    local u = expect_web("<html><body><p>see www.evil.example.com now</p></body></html>",
        "http", "www.evil.example.com", "text/html")
    assert_equal("http://www.evil.example.com", u.str)
  end)

  test("www. in a text part", function()
    local u = expect_web("see www.evil.example.com now", "http", "www.evil.example.com")
    assert_equal("http://www.evil.example.com", u.str)
    assert_true(u.flags.schemaless or false)
  end)

  test("www. at the start of a text", function()
    local u = expect_web("www.evil.example.com/x", "http", "www.evil.example.com")
    assert_equal("http://www.evil.example.com/x", u.str)
  end)

  for _, c in ipairs({ "see www. now", "see www.- now", "see awww.evil now", "see www", "see www." }) do
    test("No url from: " .. c, function()
      local ok, msg = no_urls(c)
      assert_true(ok, msg)
    end)
  end

  test("www. in an html part is not a bare domain", function()
    local ok, msg = no_urls("<html><body><p>see evil.example.com now</p></body></html>", "text/html")
    assert_true(ok, msg)
  end)

  -- Inputs that cost nothing but time

  for _, c in ipairs({
    { "sip:", 256000 }, { "http://", 150000 }, { "tel:", 256000 }, { "Hotel:", 170000 },
    { "tel:1 ", 170000 }, { "xhttps://", 110000 }, { "http:/", 170000 }, { "http:\\", 170000 },
    { "www.", 256000 }, { "www.a", 200000 }, { "h323:x@", 150000 }, { "tel:+1 555 ", 90000 },
    { "a@b.example.com ", 64000 },
  }) do
    test("Large input stays fast: " .. c[1], function()
      local function timed(n)
        local body = string.rep(c[1], n)
        local t0 = os.clock()
        extract(body)
        return os.clock() - t0
      end
      local took = timed(c[2])
      if took >= 3 then
        -- A slow build (sanitizers) is fine as long as the cost stays linear
        local quarter = timed(math.floor(c[2] / 4))
        assert_true(took < quarter * 8 + 0.5,
            string.format("%s x %d took %.2f s, a quarter of it took %.2f s",
                c[1], c[2], took, quarter))
      end
    end)
  end
end)
