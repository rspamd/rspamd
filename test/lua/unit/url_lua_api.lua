context("Url lua api: sampling, options, link vs image", function()
  local rspamd_task = require("rspamd_task")
  local test_helper = require("rspamd_test_helper")

  test_helper.init_url_parser()

  -- default max_lua_urls
  local limit = 1024

  local function load(ctype, body)
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: " .. ctype .. "; charset=utf-8\r\n\r\n" .. body .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not res then
      return nil
    end
    task:process_message()
    return task
  end

  local function texts(urls)
    local t = {}
    for i, u in ipairs(urls) do
      t[i] = u:get_text()
    end
    return t
  end

  local function set_of(list)
    local s = {}
    for _, v in ipairs(list) do
      s[v] = true
    end
    return s
  end

  local function same_list(a, b)
    if #a ~= #b then
      return false
    end
    local sb = set_of(b)
    for _, v in ipairs(a) do
      if not sb[v] then
        return false
      end
    end
    return true
  end

  local function links_and_padding(nlinks, nemails)
    local t = {}
    for i = 1, nlinks do
      t[#t + 1] = string.format("http://link%d.example.org/p", i)
    end
    for i = 1, nemails do
      t[#t + 1] = string.format("user%d@mail%d.example.net", i, i % 50)
    end
    return table.concat(t, "\r\n")
  end

  local function padding_result(nemails)
    local task = load("text/plain", links_and_padding(20, nemails))
    if not task then
      return nil
    end
    local r = { urls = texts(task:get_urls()), emails = #task:get_emails() }
    task:destroy()
    return r
  end

  for _, nemails in ipairs({ 3000, 9000 }) do
    test("20 links with " .. nemails .. " emails: all links returned", function()
      local r = padding_result(nemails)
      assert_not_nil(r, "failed to load message")
      assert_equal(20, #r.urls, "email padding hides links: " .. #r.urls .. " of 20 returned")
      for _, t in ipairs(r.urls) do
        assert_true(t:find("^http://link") ~= nil, "unexpected url " .. t)
      end
      assert_equal(math.min(nemails, limit), r.emails)
    end)
  end

  test("more urls than the limit: at most limit, stable", function()
    local task = load("text/plain", links_and_padding(3000, 0))
    assert_not_nil(task, "failed to load message")
    local a = texts(task:get_urls())
    local b = texts(task:get_urls())
    local c = texts(task:get_urls({ sort = true }))
    task:destroy()
    assert_true(#a <= limit, "returned " .. #a)
    assert_true(#a > 0)
    assert_true(same_list(a, b), "two calls return different sets")
    assert_true(same_list(a, c), "sorted call returns a different set")
  end)

  test("get_urls_filtered samples the filtered set", function()
    local task = load("text/plain", links_and_padding(20, 3000))
    assert_not_nil(task, "failed to load message")
    local urls = task:get_urls_filtered(nil, nil, { 'http' })
    local n = #urls
    task:destroy()
    assert_equal(20, n)
  end)

  test("protocol array form is honoured", function()
    local body = links_and_padding(10, 5) .. "\r\nftp://files1.example.org/a\r\n" ..
        "ftp://files2.example.org/b\r\n"
    local task = load("text/plain", body)
    assert_not_nil(task, "failed to load message")
    local ftp = texts(task:get_urls({ 'ftp' }))
    local mixed = task:get_urls({ 'mailto', 'http' })
    local nmixed = #mixed
    local all_ok = true
    for _, u in ipairs(mixed) do
      local p = u:get_protocol()
      if p ~= 'mailto' and p ~= 'http' then
        all_ok = false
      end
    end
    local by_name = texts(task:get_urls({ protocols = { 'ftp' } }))
    task:destroy()
    assert_equal(2, #ftp, "ftp only expected")
    for _, t in ipairs(ftp) do
      assert_true(t:find("^ftp://") ~= nil, "unexpected url " .. t)
    end
    assert_equal(15, nmixed)
    assert_true(all_ok, "mailto,http list returned other protocols")
    assert_true(same_list(ftp, by_name))
  end)

  test("sort option", function()
    local task = load("text/plain", links_and_padding(40, 0))
    assert_not_nil(task, "failed to load message")
    local unsorted = task:get_urls({ sort = false })
    local sorted = task:get_urls({ sort = true })
    local un_texts, so_texts = texts(unsorted), texts(sorted)
    local by_lt = {}
    for i, u in ipairs(unsorted) do
      by_lt[i] = u
    end
    local ok, err = pcall(table.sort, by_lt)
    local lt_texts = texts(by_lt)
    task:destroy()

    assert_equal(40, #so_texts)
    assert_equal(40, #un_texts)
    assert_true(same_list(un_texts, so_texts))
    local differs = false
    for i = 1, #so_texts do
      if so_texts[i] ~= un_texts[i] then
        differs = true
      end
    end
    assert_true(differs, "sort=false returned the sorted order")
    assert_true(ok, "table.sort(urls) failed: " .. tostring(err))
    for i = 1, #so_texts do
      assert_equal(so_texts[i], lt_texts[i])
    end
  end)

  test("get_emails returns all emails among many http urls", function()
    local task = load("text/plain", links_and_padding(3000, 5))
    assert_not_nil(task, "failed to load message")
    local emails = task:get_emails()
    local n = #emails
    local all_mail = true
    for _, u in ipairs(emails) do
      if u:get_protocol() ~= 'mailto' then
        all_mail = false
      end
    end
    task:destroy()
    assert_equal(5, n)
    assert_true(all_mail)
  end)

  -- link vs image
  local function html_msg(prefix, body)
    return "<html><body>" .. prefix .. body .. "</body></html>"
  end

  local function find_in(urls, needle)
    for _, u in ipairs(urls) do
      if u:get_text():find(needle, 1, true) then
        return true
      end
    end
    return false
  end

  local function html_case(prefix, host, body)
    local task = load("text/html", html_msg(prefix, body))
    if not task then
      return nil
    end
    local r = {
      default = find_in(task:get_urls(), host),
      images = find_in(task:get_urls({ images = true }), host),
    }
    task:destroy()
    return r
  end

  local function link_image_case(prefix, host, link_first)
    local u = "http://" .. host .. "/p"
    local a = '<a href="' .. u .. '">x</a>'
    local img = '<img src="' .. u .. '">'
    return html_case(prefix, host, link_first and (a .. img) or (img .. a))
  end

  local past_limit = string.rep("<i>", 8200)

  for _, variant in ipairs({
    { "within the tags limit", "" },
    { "past the tags limit", past_limit },
  }) do
    local name, prefix = variant[1], variant[2]

    test("link then image of the same url stays a link, " .. name, function()
      local r = link_image_case(prefix, "real1.example.org", true)
      assert_not_nil(r, "failed to load message")
      assert_true(r.default, "link hidden from default get_urls")
      assert_true(r.images)
    end)

    test("image then link of the same url stays a link, " .. name, function()
      local r = link_image_case(prefix, "real2.example.org", false)
      assert_not_nil(r, "failed to load message")
      assert_true(r.default, "link hidden from default get_urls")
      assert_true(r.images)
    end)

    test("image only url stays excluded by default, " .. name, function()
      local r = html_case(prefix, "pic.example.org", '<img src="http://pic.example.org/i.png">')
      assert_not_nil(r, "failed to load message")
      assert_false(r.default, "image url returned by default")
      assert_true(r.images, "image url missing with images=true")
    end)
  end

  test("a message over the urls limit says so", function()
    local function limit_reached(body)
      local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
          "Content-Type: text/plain; charset=utf-8\r\n\r\n" .. body .. "\r\n"
      local res, task = rspamd_task.load_from_string(msg, rspamd_config)
      assert_true(res, "failed to load message")
      task:process_message()
      local var = task:get_mempool():get_variable("urls_limit_reached")
      task:destroy()

      return var
    end

    local junk = {}
    for i = 1, 11000 do
      junk[i] = "http://junk" .. i .. ".example.net/"
    end

    assert_equal("1", limit_reached(table.concat(junk, "\n")))
    assert_nil(limit_reached("http://one.example.org/ http://two.example.org/"))
  end)
end)
