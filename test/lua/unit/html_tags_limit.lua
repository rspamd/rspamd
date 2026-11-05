--[[
HTML past the tags limit (8192 tags per part) is still read as a browser does:
no more tags are created, but markup is not taken as text, links are found
with their displayed text (so the phishing check runs), and scripts, styles
and comments stay hidden.
]]

context("HTML past the tags limit", function()
  local rspamd_task = require "rspamd_task"

  local function scan(html)
    local msg = table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "Subject: limit",
      "MIME-Version: 1.0",
      "Content-Type: text/html",
      "",
      html,
      "",
    }, "\r\n")
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not res then
      return nil
    end
    task:process_message()

    local text = {}
    for _, tp in ipairs(task:get_text_parts() or {}) do
      text[#text + 1] = tostring(tp:get_content() or "")
    end

    local urls = {}
    for _, u in ipairs(task:get_urls({ flags = { "image" } }) or {}) do
      urls[u:get_host()] = u
    end
    for _, u in ipairs(task:get_urls(true) or {}) do
      urls[u:get_host()] = u
    end

    local phished = urls["evil.example.net"] and urls["evil.example.net"]:is_phished()
    local result = {
      text = table.concat(text, "\n"),
      phished = phished,
      image = urls["img.example.org"] ~= nil,
    }
    task:destroy()

    return result
  end

  test("content after the limit is read without its markup", function()
    -- Empty tags no browser shows use up the tags limit
    local r = scan("<html><body><p>HEADTEXT</p>" .. string.rep("<b>", 8200) ..
        " TAILTEXT <a href=\"http://evil.example.net/phish\">https://www.paypal.com/signin</a>" ..
        " <img src=\"http://img.example.org/x.png\"><!-- COMMENTTEXT -->" ..
        "<div>BLOCKTEXT</div><script>var SCRIPTTEXT = 1;</script>" ..
        "<textarea>AREATEXT</textarea></body></html>")

    assert_not_nil(r, "failed to load message")
    assert_true(r.text:find("HEADTEXT", 1, true) ~= nil, "text before the limit is missing")
    assert_true(r.text:find("TAILTEXT", 1, true) ~= nil, "text after the limit is missing")
    assert_true(r.text:find("BLOCKTEXT", 1, true) ~= nil, "text of a block is missing")
    assert_true(r.text:find("AREATEXT", 1, true) ~= nil, "text of a textarea is missing")
    assert_nil(r.text:find("<a", 1, true), "markup is taken as text")
    assert_nil(r.text:find("<b>", 1, true), "markup is taken as text")
    assert_nil(r.text:find("SCRIPTTEXT", 1, true), "a script is taken as text")
    assert_nil(r.text:find("COMMENTTEXT", 1, true), "a comment is taken as text")
    assert_true(r.phished, "the link is not checked against its displayed text")
    assert_true(r.image, "the image url is missing")
  end)

  test("an SVG link and a submit button are found after the limit", function()
    local msg = table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "Subject: limit",
      "MIME-Version: 1.0",
      "Content-Type: text/html",
      "",
      "<html><body>" .. string.rep("<b>", 8200) ..
          '<svg><a xlink:href="http://svglink.example.net/x"><text>x</text></a></svg>' ..
          '<a xlink:href="http://htmllink.example.net/x">y</a>' ..
          '<form action="http://form.example.org/f">' ..
          '<button formaction="http://button.example.net/b">Go</button>' ..
          '<button type="reset" formaction="http://reset.example.net/b">No</button></form>',
      "",
    }, "\r\n")
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls(true) or {}) do
      hosts[#hosts + 1] = u:get_host()
    end
    table.sort(hosts)
    task:destroy()

    assert_rspamd_table_eq({
      actual = hosts,
      expect = { "button.example.net", "form.example.org", "svglink.example.net" },
    })
  end)

  local function hosts_of(html)
    local msg = table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "Subject: limit",
      "MIME-Version: 1.0",
      "Content-Type: text/html",
      "",
      html,
      "",
    }, "\r\n")
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls(true) or {}) do
      hosts[#hosts + 1] = u:get_host()
    end
    table.sort(hosts)
    task:destroy()

    return hosts
  end

  test("svg and math open where the tags end go on after the limit", function()
    -- The innermost open element counts too, as the svg around a foreignObject
    -- (a style in it is raw text, as in the tree) or a self-closed <g/>
    local tail = '<style><!--</style><a href="http://link.example.net/x">x</a>-->'
    for _, html in ipairs({
      '<svg>' .. string.rep('<g>', 8200) .. '<a xlink:href="http://link.example.net/x">x</a></svg>',
      '<svg>' .. string.rep('<g/>', 8200) .. '<a xlink:href="http://link.example.net/x">x</a></svg>',
      '<svg width=99 height=99><foreignObject width=99 height=99>' .. string.rep('<wbr>', 8200) ..
          tail .. '</foreignObject></svg>',
      '<math><mi>' .. string.rep('<wbr>', 8200) .. tail .. '</mi></math>',
    }) do
      assert_rspamd_table_eq({
        actual = hosts_of("<html><body>" .. html),
        expect = { "link.example.net" },
      })
    end
  end)

  test("CDATA in HTML content of svg or math is no text after the limit", function()
    -- A div in a foreignObject (or a span in mi) is HTML: CDATA is a bogus
    -- comment there, ending at the first '>', as in the tree
    local payload = '<![CDATA[x><a href="http&#58;//cdata&#46;example&#46;net/x">click</a>]]>'
    for _, html in ipairs({
      '<svg><foreignObject><div>' .. string.rep('<wbr>', 8200) .. payload,
      '<math><mi><span>' .. string.rep('<wbr>', 8200) .. payload,
      -- HTML content or a tag that closes the svg past the limit
      '<svg><foreignObject>' .. string.rep('<wbr>', 8200) .. '<div>' .. payload,
      '<svg>' .. string.rep('<g/>', 8200) .. '<p>' .. payload,
      '<math>' .. string.rep('<mrow/>', 8200) .. '<b>' .. payload,
    }) do
      assert_rspamd_table_eq({
        actual = hosts_of("<html><body>" .. html),
        expect = { "cdata.example.net" },
      })
    end
  end)

  test("an svg open where the tags end is closed after the limit", function()
    -- An HTML link after it has no xlink:href to follow
    assert_rspamd_table_eq({
      actual = hosts_of("<html><body><svg><g>" .. string.rep("<g/>", 8200) ..
          '</g></svg><a xlink:href="https://evil.example.net/x">text</a>'),
      expect = {},
    })
  end)

  test("deeply nested svg after the limit", function()
    assert_rspamd_table_eq({
      actual = hosts_of("<html><body>" .. string.rep("<b>", 8200) .. string.rep("<svg>", 70) ..
          string.rep("</svg>", 64) .. '<a xlink:href="http://deep.example.net/x">x</a>'),
      expect = { "deep.example.net" },
    })
  end)

  test("markup browsers accept is read after the limit", function()
    local filler = string.rep("<b>", 8200)
    local cases = {
      -- An abruptly closed comment ends right away
      { "<!--> TAILTEXT <a href=\"http://evil.example.net/x\">https://www.paypal.com/</a>", true },
      { "<!-- x --!> TAILTEXT <a href=\"http://evil.example.net/x\">https://www.paypal.com/</a>", true },
      -- `/` between attributes
      { "TAILTEXT <a/href=\"http://evil.example.net/x\">https://www.paypal.com/</a>", true },
      -- A relative link against a base given after the limit
      { "<base href=\"http://evil.example.net/\"> TAILTEXT <a href=\"login.php\">https://www.paypal.com/</a>", true },
      -- Character references in a textarea
      { "<textarea>TAIL&#84;EXT</textarea>", false },
    }

    for i, c in ipairs(cases) do
      local r = scan(filler .. c[1])
      assert_not_nil(r, "failed to load message " .. i)
      assert_true(r.text:find("TAILTEXT", 1, true) ~= nil, "text is missing in case " .. i)
      if c[2] then
        assert_true(r.phished, "the link is not checked in case " .. i)
      end
    end
  end)

  test("text and links where the limit is hit are kept", function()
    -- The text before the tag that hits the limit, and a link open there
    local r = scan(string.rep("<b>", 8190) ..
        "<a href=\"http://evil.example.net/x\">GAPTEXT" .. string.rep("<i>", 10) ..
        " https://www.paypal.com/</a>")

    assert_not_nil(r, "failed to load message")
    assert_true(r.text:find("GAPTEXT", 1, true) ~= nil, "text before the limit is missing")
    assert_true(r.phished, "the link open at the limit is not checked")
  end)

  test("a quoted `>` does not end a tag after the limit", function()
    local r = scan(string.rep("<b>", 8200) ..
        "<a title=\"a > b\" href=\"http://evil.example.net/x\">https://www.paypal.com/</a>")

    assert_not_nil(r, "failed to load message")
    assert_nil(r.text:find("b\"", 1, true), "the rest of the tag is taken as text")
    assert_true(r.phished, "the link is not checked against its displayed text")
  end)
end)
