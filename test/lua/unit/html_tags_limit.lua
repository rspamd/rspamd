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

  test("a link repeated after the limit is counted and checked each time", function()
    local link = "<a href=\"http://rep.example.net/path\">text</a> "
    local msg = table.concat({
      "From: sender@example.com",
      "Subject: limit",
      "MIME-Version: 1.0",
      "Content-Type: text/html",
      "",
      "<html><body>" .. string.rep("<b>", 8200) .. string.rep(link, 3) ..
          "<a href=\"http://rep.example.net/path\">https://www.paypal.com/signin</a>" ..
          " <a href=\"http://other.example.net/\">other</a></body></html>",
      "",
    }, "\r\n")
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local urls = {}
    for _, u in ipairs(task:get_urls(true) or {}) do
      urls[u:get_host()] = u
    end

    assert_not_nil(urls["rep.example.net"], "the repeated link is missing")
    assert_not_nil(urls["other.example.net"], "the link after the repeated ones is missing")
    assert_equal(4, urls["rep.example.net"]:get_count())
    assert_true(urls["rep.example.net"]:is_phished(),
        "a repeated link is not checked against its displayed text")
    task:destroy()
  end)

  -- Reads the message and returns what the tests below look at: the visible
  -- and the hidden text, the tags of the tree by name, and the urls with flags
  local function inspect(html)
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

    local r = { text = "", invisible = "", counts = {}, urls = {} }
    local tp = (task:get_text_parts() or {})[1]
    if tp then
      r.text = tostring(tp:get_content() or "")
      local hc = tp:get_html()
      if hc then
        r.invisible = tostring(hc:get_invisible() or "")
        hc:foreach_tag("any", function(tag)
          local name = tag:get_type()
          r.counts[name] = (r.counts[name] or 0) + 1
          return false
        end)
      end
    end
    for _, u in ipairs(task:get_urls(true) or {}) do
      local flags = {}
      for k, v in pairs(u:get_flags() or {}) do
        if type(k) == "number" then
          flags[v] = true
        elseif v then
          flags[k] = true
        end
      end
      r.urls[u:get_host()] = flags
    end
    task:destroy()

    return r
  end

  local function has(text, word)
    return text:find(word, 1, true) ~= nil
  end

  local hide_tail = '<div style="display:none">HIDONE</div><p>SHOWN</p>'

  test("comments do not use up the tags limit", function()
    local r = inspect('<html><head><style>.h{display:none}</style></head><body>' ..
        string.rep("<!-- c -->", 9000) .. hide_tail .. '<div class="h">HIDTWO</div></body></html>')

    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "SHOWN"), "visible text is missing")
    assert_false(has(r.text, "HIDONE"), "text hidden by a style is visible")
    assert_false(has(r.text, "HIDTWO"), "text hidden by a rule is visible")
    assert_true(has(r.invisible, "HIDONE") and has(r.invisible, "HIDTWO"), "hidden text is missing")
    assert_equal(2, r.counts.div, "the tree is not built after the comments")
    assert_false(has(r.text, "<!--"), "a comment is taken as text")
    assert_false(has(r.text, " c "), "comment content is taken as text")
  end)

  test("comments over their budget stay out of the text", function()
    -- Text between them ends the tree: the rest is read without tags
    local r = inspect("<html><body>" .. string.rep("<!--COMMENTTEXT-->word ", 9000) ..
        '<div style="display:none">HIDONE</div>SHOWN</body></html>')

    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "word") and has(r.text, "SHOWN"), "visible text is missing")
    assert_false(has(r.text, "COMMENTTEXT"), "a comment is taken as text")
    assert_false(has(r.text, "<!--"), "a comment is taken as text")
    assert_false(has(r.text, "HIDONE"), "hidden text is visible")

    -- Whitespace between comments, comments of every kind and one that is not closed
    r = inspect("<html><body>" ..
        string.rep("<!--COMMENTTEXT--> \n<?pi COMMENTTEXT?>\n<!DOCTYPE COMMENTTEXT>\t</COMMENTTEXT>", 4000) ..
        "SHOWN<!-- COMMENTTEXT")
    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "SHOWN"), "visible text is missing")
    assert_false(has(r.text, "COMMENTTEXT"), "markup is taken as text")
    assert_false(has(r.text, "<!--"), "a comment is taken as text")
  end)

  test("a large number of comments is read", function()
    local r = inspect("<html><body>" .. string.rep("<!---->", 428571) .. "SHOWN</body></html>")

    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "SHOWN"), "visible text is missing")
    assert_false(has(r.text, "<!--"), "a comment is taken as text")
  end)

  test("runs of empty elements are stored once", function()
    local r = inspect("<html><body>" .. string.rep("<b></b>", 9000) .. hide_tail .. "</body></html>")

    assert_not_nil(r, "failed to load message")
    assert_equal(1, r.counts.b, "the run is not folded")
    assert_equal(1, r.counts.div, "the tree is not built after the run")
    assert_true(has(r.text, "SHOWN"), "visible text is missing")
    assert_false(has(r.text, "HIDONE"), "text hidden by a style is visible")
    assert_false(has(r.text, "<b>"), "markup is taken as text")

    r = inspect("<html><body>" .. string.rep("<span></span>", 300000) .. "SHOWN</body></html>")
    assert_not_nil(r, "failed to load message")
    assert_equal(1, r.counts.span)
    assert_true(has(r.text, "SHOWN"), "visible text is missing")
  end)

  test("what is not an identical empty element is not folded", function()
    local function count(html, name)
      local r = inspect("<html><body>" .. html .. "</body></html>")
      assert_not_nil(r, "failed to load message")
      return r.counts[name] or 0
    end

    assert_equal(10, count(string.rep('<b class="x"></b>', 10), "b"), "attributes")
    assert_equal(10, count(string.rep("<b></b>t", 10), "b"), "text between")
    assert_equal(10, count(string.rep("<b></b> ", 10), "b"), "whitespace between")
    assert_equal(10, count(string.rep("<b> </b>", 10), "b"), "whitespace inside")
    assert_equal(10, count(string.rep("<b></b><i></i>", 10), "b"), "other element between")
    assert_equal(10, count(string.rep("<div></div>", 10), "div"), "blocks")
    assert_equal(10, count(string.rep("<b><i></i></b>", 10), "b"), "children")
    assert_equal(10, count(string.rep("<br>", 10), "br"), "void elements")
    -- A run in a parent does not fold into one in another parent
    assert_equal(2, count("<b></b><b></b><b></b><p><b></b><b></b></p>", "b"), "parents")
  end)

  test("a sibling selector still sees an element between", function()
    local sheet = "<style>h1 + p { display: none }</style>"
    local r = inspect("<html><head>" .. sheet ..
        '</head><body><h1>t</h1><b></b><b></b><p class="x">SHOWNP</p></body></html>')
    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "SHOWNP"), "an element stands between the heading and the paragraph")

    r = inspect("<html><head>" .. sheet .. '</head><body><h1>t</h1><p class="x">HIDDENP</p></body></html>')
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDDENP"), "the rule does not apply to the control")
  end)

  test("the text of a run of empty elements is the one without it", function()
    for _, c in ipairs({
      { "a<b></b><b></b><b></b>c", "a<b></b>c" },
      { "a <b></b><b></b> c", "a <b></b> c" },
      { "<p>a</p><i></i><i></i><i></i><p>c</p>", "<p>a</p><i></i><p>c</p>" },
      { "a<span></span><span></span><br><span></span><span></span>c",
        "a<span></span><br><span></span>c" },
    }) do
      local folded = inspect("<html><body>" .. c[1] .. "</body></html>")
      local single = inspect("<html><body>" .. c[2] .. "</body></html>")
      assert_not_nil(folded, "failed to load message")
      assert_equal(single.text, folded.text, c[1])
    end
  end)

  local c_tail = '<div style="display:none">HIDONE</div><span hidden>HIDTWO</span>' ..
      '<div style="visibility:hidden">HIDTHREE<b style="visibility:visible">SHOWNTWO</b></div><p>SHOWN</p>'

  test("hidden text is not visible text after the limit", function()
    local r = inspect("<html><body>" .. string.rep("<i>", 8200) .. c_tail)

    assert_not_nil(r, "failed to load message")
    for _, w in ipairs({ "SHOWN", "SHOWNTWO" }) do
      assert_true(has(r.text, w), w .. " is missing")
    end
    for _, w in ipairs({ "HIDONE", "HIDTWO", "HIDTHREE" }) do
      assert_false(has(r.text, w), w .. " is visible")
      assert_true(has(r.invisible, w), w .. " is not in the hidden text")
    end
    assert_false(has(r.text, "<"), "markup is taken as text")
  end)

  test("an element open at the limit hides the text after it until it ends", function()
    local r = inspect('<html><body><div style="display:none">' .. string.rep("<i>", 8200) ..
        "HIDONE</div>SHOWN")
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE"), "hidden text is visible")
    assert_true(has(r.text, "SHOWN"), "text after the element is missing")

    -- By a rule of a stylesheet and by a hidden attribute, as the tree has them settled
    r = inspect('<html><head><style>.h{display:none}</style></head><body><div class="h">' ..
        string.rep("<i>", 8200) .. "HIDONE</div>SHOWN")
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE"), "text hidden by a rule is visible")
    assert_true(has(r.text, "SHOWN"), "text after the element is missing")

    r = inspect('<html><body><section hidden><p>' .. string.rep("<i>", 8200) ..
        "HIDONE</p>HIDTWO</section>SHOWN")
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE") or has(r.text, "HIDTWO"), "hidden text is visible")
    assert_true(has(r.text, "SHOWN"), "text after the element is missing")

    -- Visible elements around it do not matter
    r = inspect("<html><body><div>HEADTEXT" .. string.rep("<i>", 8200) .. "</div>SHOWN")
    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "HEADTEXT") and has(r.text, "SHOWN"), "text is missing")
  end)

  test("a stylesheet rule of one element hides text after the limit", function()
    local r = inspect('<html><head><style>.h{display:none} i.t{font-size:0} #u{display:none} ' ..
        'p span{display:none}</style></head><body>' .. string.rep("<i>", 8200) ..
        '<div class="h">HIDONE</div><b class="t">SHOWNB</b><i class="t">HIDTWO</i>' ..
        '<div id="u">HIDTHREE</div><p><span>SHOWNC</span></p>SHOWN')
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE") or has(r.text, "HIDTWO") or has(r.text, "HIDTHREE"),
        "text hidden by a rule is visible")
    -- Rules with combinators match no element past the limit
    assert_true(has(r.text, "SHOWN") and has(r.text, "SHOWNB") and has(r.text, "SHOWNC"), "text is missing")
  end)

  test("a hidden link after the limit is flagged as the tree flags it", function()
    local links = '<div style="display:none"><a href="http://hid.example.net/x">text</a></div>' ..
        '<a href="http://vis.example.net/x">text</a>'
    local tree = inspect("<html><body>" .. links)
    local past = inspect("<html><body>" .. string.rep("<i>", 8200) .. links)

    assert_not_nil(tree, "failed to load message")
    assert_not_nil(past, "failed to load message")
    assert_true(tree.urls["hid.example.net"].invisible, "the tree does not flag the link")
    assert_nil(tree.urls["vis.example.net"].invisible)
    assert_true(past.urls["hid.example.net"].invisible, "a hidden link is not flagged")
    assert_nil(past.urls["vis.example.net"].invisible, "a visible link is flagged")
  end)

  test("end tags that match nothing hide or show nothing after the limit", function()
    local filler = "<html><body>" .. string.rep("<i>", 8200)
    local r = inspect(filler .. "</div></div></div></span></p>TEXT")
    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "TEXT"), "text is hidden")

    r = inspect(filler .. '<div style="display:none">HIDONE</div></div></div>SHOWN</body></html>SHOWNTWO')
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE"), "hidden text is visible")
    assert_true(has(r.text, "SHOWN") and has(r.text, "SHOWNTWO"), "text is hidden")

    -- The extra end tags do not end the hidden element around the text
    r = inspect(filler .. '<div style="display:none"><span>HIDONE</span></p></b>HIDTWO</div>SHOWN')
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE") or has(r.text, "HIDTWO"), "hidden text is visible")
    assert_true(has(r.text, "SHOWN"), "text is hidden")

    -- An optional end tag is implied by the next paragraph
    r = inspect(filler .. '<div><p style="display:none">HIDONE<p>SHOWN</div>')
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE"), "hidden text is visible")
    assert_true(has(r.text, "SHOWN"), "text is hidden")
  end)

  test("elements nested deeper than the tracked ones show their text", function()
    local r = inspect("<html><body>" .. string.rep("<i>", 8200) .. string.rep("<span>", 5000) ..
        '<div style="display:none">HIDDEEP</div>SHOWN')
    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "HIDDEEP"), "an element past the tracked depth hides its text")
    assert_true(has(r.text, "SHOWN"), "text is hidden")

    -- Elements within the depth are tracked
    r = inspect("<html><body>" .. string.rep("<i>", 8200) .. string.rep("<span>", 1000) ..
        '<div style="display:none">HIDONE</div>SHOWN')
    assert_not_nil(r, "failed to load message")
    assert_false(has(r.text, "HIDONE"), "hidden text is visible")
  end)

  test("a large number of tags after the limit is read", function()
    local r = inspect("<html><body>" .. string.rep('<i style="display:none">h</i>', 100000) ..
        string.rep("<span>", 200000) .. string.rep("</span>", 200000) .. "SHOWN")
    assert_not_nil(r, "failed to load message")
    assert_true(has(r.text, "SHOWN"), "text is missing")
  end)

  test("an optional end tag is implied past inline elements after the limit", function()
    local filler = "<html><body>" .. string.rep("<i>x</i>", 8200)
    local cases = {
      -- A paragraph ends an open paragraph through the inline elements in it
      { '<p style="display:none"><b>HIDONE<u>HIDTWO<p>SHOWN', { "SHOWN" }, { "HIDONE", "HIDTWO" } },
      { '<p style="display:none"><b>HIDONE<div>SHOWN</div>', { "SHOWN" }, { "HIDONE" } },
      { '<ul><li style="display:none"><b>HIDONE<li>SHOWN</ul>', { "SHOWN" }, { "HIDONE" } },
      { '<table><tr><td style="display:none"><b>HIDONE<td>SHOWN</table>', { "SHOWN" }, { "HIDONE" } },
      { '<table><tr style="display:none"><td><b>HIDONE<tr><td>SHOWN</table>', { "SHOWN" }, { "HIDONE" } },
      -- A paragraph in a table cell does not end the paragraph around the table
      { '<p style="display:none">HIDONE<span><table><tr><td><p>STILLHID</table></span></p>SHOWN',
        { "SHOWN" }, { "HIDONE" } },
      -- An inline element ends nothing
      { '<p style="display:none">HIDONE<b>STILLHID</b></p>SHOWN', { "SHOWN" }, { "HIDONE", "STILLHID" } },
      { '<div style="display:none">HIDONE<p>STILLHID</p></div>SHOWN', { "SHOWN" }, { "HIDONE", "STILLHID" } },
    }

    for _, c in ipairs(cases) do
      local r = inspect(filler .. c[1])
      assert_not_nil(r, "failed to load message")
      for _, w in ipairs(c[2]) do
        assert_true(has(r.text, w), w .. " is hidden in " .. c[1])
      end
      for _, w in ipairs(c[3]) do
        assert_false(has(r.text, w), w .. " is visible in " .. c[1])
      end
    end
  end)
end)
