-- What a browser makes of an SVG image, and what limits leave of it

context("SVG as a browser reads it", function()
  local svg = require "lua_content/svg"
  local lua_content = require "lua_content"
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"

  local ns = 'xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"'

  local function doc(body)
    return '<svg ' .. ns .. '>' .. body .. '</svg>'
  end

  local function extract(body, options)
    local res, err = svg.extract(doc(body), options)
    if not res then
      error(err)
    end
    return res
  end

  -- Links

  test("href wins over xlink:href wherever it stands", function()
    local res = extract('<a xlink:href="https://benign.example/" href="https://evil.example/"><text>x</text></a>')
    assert_equal(1, #res.urls)
    assert_equal('https://evil.example/', res.urls[1])

    res = extract('<a href="https://evil.example/" xlink:href="https://benign.example/"><text>x</text></a>')
    assert_equal('https://evil.example/', res.urls[1])

    res = extract('<a xlink:href="https://only.example/"><text>x</text></a>')
    assert_equal('https://only.example/', res.urls[1])
  end)

  test("Tabs and line ends inside of an url are removed before the scheme is read", function()
    local res = extract('<a href="java&#9;scr&#10;ipt:alert(1)"><text>x</text></a>')
    assert_equal(1, res.javascript_urls)

    res = extract('<a href="ht&#10;tps://evil.example/x"><text>x</text></a>')
    assert_equal('https://evil.example/x', res.urls[1])

    local page = tostring(rspamd_util.encode_base64('<html><body>hello</body></html>'))
    res = extract('<a href="da&#13;ta:text/html;base64,' .. page .. '"><text>x</text></a>')
    assert_equal(1, res.data_uris)
    assert_equal(1, #res.payloads)
  end)

  -- Styles and scripts

  test("A style sheet is scanned past any amount of padding", function()
    local pad = string.rep('.a { fill: red; }\n', 8000)
    local res = extract('<style>' .. pad .. '@import url(https://evil.example/c.css);</style>')
    assert_equal('https://evil.example/c.css', res.urls[1])

    -- Split over pieces of text as well
    res = extract('<style>' .. pad .. '.b { fill: url(https://evil<!-- -->.example/p.png) }</style>')
    assert_equal('https://evil.example/p.png', res.urls[1])
  end)

  test("A presentation attribute with an url is a resource", function()
    local res = extract('<rect width="1" height="1" fill="url(https://evil.example/p)"/>')
    assert_equal('https://evil.example/p', res.urls[1])
    assert_equal('css', res.resources[1].kind)

    res = extract('<rect width="1" height="1" fill="url(#local)"/>')
    assert_equal(0, #res.urls)
  end)

  test("A script word split by a comment or a CDATA section is found", function()
    for _, code in ipairs({ 'var x = atob("QQ==")', 'var x = at<!-- -->ob("QQ==")',
                            'var x = at<![CDATA[ob("QQ==")]]>', '<![CDATA[var x = at]]>ob("QQ==")' }) do
      local res = extract('<script>' .. code .. '</script>')
      assert_equal(1, res.scripts)
      assert_equal('atob', res.script_indicators[1], code)
    end
  end)

  -- Limits

  test("A document over the limit of links keeps its indicators", function()
    local links = {}
    for i = 1, 600 do
      links[i] = string.format('<a href="https://h%d.example/"><text>x</text></a>', i)
    end
    local res = extract(table.concat(links) .. '<script>eval(1)</script>')
    assert_equal(512, #res.urls)
    assert_true(res.urls_truncated)
    assert_equal(1, res.scripts)
    assert_equal('eval', res.script_indicators[1])
  end)

  test("A document without limits reached has no truncation flags", function()
    local res = extract('<a href="https://a.example/"><text>hello</text></a>')
    assert_nil(res.text_truncated)
    assert_nil(res.urls_truncated)
    assert_nil(res.payloads_truncated)
  end)

  -- Whole messages

  local function message(parts)
    local out = { "From: a@example.com", "To: b@example.com", "Subject: t", "MIME-Version: 1.0",
                  'Content-Type: multipart/mixed; boundary="B"', "", "--B", "Content-Type: text/plain", "",
                  "hello" }
    for _, p in ipairs(parts) do
      out[#out + 1] = "--B"
      out[#out + 1] = "Content-Type: " .. p[1] .. '; name="' .. p[2] .. '"'
      out[#out + 1] = 'Content-Disposition: attachment; filename="' .. p[2] .. '"'
      out[#out + 1] = "Content-Transfer-Encoding: base64"
      out[#out + 1] = ""
      out[#out + 1] = tostring(rspamd_util.encode_base64(p[3], 76))
    end
    out[#out + 1] = "--B--"
    out[#out + 1] = ""
    return table.concat(out, "\r\n")
  end

  local function scan(parts)
    local ok, task = rspamd_task.load_from_string(message(parts), rspamd_config)
    if not ok then
      error('cannot load the message')
    end
    task:process_message()
    local res = {}

    for _, p in ipairs(task:get_parts()) do
      local fname = p:get_filename()
      if fname then
        res[fname] = lua_content.get_specific(p, task) or false
      end
    end

    task:destroy()
    return res
  end

  test("An image that the detection refuses is handled by its name", function()
    local with_dtd = '<?xml version="1.0"?><!DOCTYPE svg [ <!ENTITY x "y"> ]>' ..
        doc('<script>eval(1)</script>')
    local res = scan({ { "application/octet-stream", "a.svg", with_dtd } })
    assert_equal('svg', res['a.svg'].tag)
    assert_true(res['a.svg'].suspicious)
    assert_equal('dtd', res['a.svg'].reason)

    -- The name of another kind of file picks no handler
    res = scan({ { "application/octet-stream", "a.bin", with_dtd } })
    assert_false(res['a.bin'])
  end)

  test("An image after one that used the budget of links keeps its indicators", function()
    local links = {}
    for i = 1, 520 do
      -- Hosts that are urls whatever list of suffixes is loaded
      links[i] = string.format('<a href="https://h%d.example.com/"><text>x</text></a>', i)
    end
    -- The time limit is not what is tested, and a slow build would hit it
    local saved = svg.config.processing_timeout
    svg.config.processing_timeout = 60
    local res = scan({
      { "image/svg+xml", "f1.svg", doc(table.concat(links)) },
      { "image/svg+xml", "f2.svg", doc('<a href="https://late.example.com/"><text>x</text></a><script>eval(1)</script>') },
    })
    svg.config.processing_timeout = saved
    assert_nil(res['f2.svg'].suspicious)
    assert_equal(1, res['f2.svg'].scripts)
    assert_true(res['f2.svg'].urls_truncated)
  end)

  test("An image after one that used the budget of payloads tells so", function()
    local page = tostring(rspamd_util.encode_base64('<html><body>hello</body></html>'))
    local payload = '<a href="data:text/html;base64,' .. page .. '"><text>x</text></a>'
    local res = scan({
      { "image/svg+xml", "f1.svg", doc(string.rep(payload, 4)) },
      { "image/svg+xml", "f2.svg", doc(payload) },
    })
    assert_equal(4, #res['f1.svg'].payloads)
    assert_equal(0, #res['f2.svg'].payloads)
    assert_true(res['f2.svg'].payloads_truncated)
  end)

  test("Images inside of images are read a few levels deep", function()
    local function nested(inner)
      return doc('<image href="data:image/svg+xml;base64,' .. tostring(rspamd_util.encode_base64(inner)) .. '"/>')
    end
    local res = scan({ { "image/svg+xml", "f.svg", nested(nested(doc('<script>eval(1)</script>'))) } })
    assert_equal(1, res['f.svg'].scripts)
    assert_nil(res['f.svg'].nested_suspicious)

    -- A document inside that cannot be read is told about
    res = scan({ { "image/svg+xml", "g.svg", nested('<svg ' .. ns .. '><broken') } })
    assert_not_nil(res['g.svg'].nested_suspicious)
  end)
end)

context("Calendar and vcard properties", function()
  local ical = require "lua_content/ical"
  local vcard = require "lua_content/vcard"
  local mpool = require "rspamd_mempool"

  local function run(module, data)
    local pool = mpool.create()
    local urls = {}
    local task = {
      get_mempool = function()
        return pool
      end,
      inject_url = function(_, u)
        urls[#urls + 1] = tostring(u)
      end,
    }
    local res = module.process(data, nil, task)
    local keys = {}
    for i, e in ipairs(res and res.elts or {}) do
      keys[i] = e[1]
    end
    pool:destroy()
    return urls, keys, res
  end

  test("Links of attachments and of meetings are found", function()
    local urls = run(ical, "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" ..
        "ATTACH:https://attach.example.com/file\r\n" ..
        "CONFERENCE;VALUE=URI:https://meet.example.com/abc\r\n" ..
        "X-MICROSOFT-SKYPETEAMSMEETINGURL:https://teams.example.com/l/meetup\r\n" ..
        "UID:1234@uid.example.org\r\n" ..
        "END:VEVENT\r\nEND:VCALENDAR\r\n")
    table.sort(urls)
    assert_equal(3, #urls)
    assert_equal('https://attach.example.com/file', urls[1])
    assert_equal('https://meet.example.com/abc', urls[2])
    assert_equal('https://teams.example.com/l/meetup', urls[3])
  end)

  test("A line without a colon is not a part of the next property", function()
    local urls, keys = run(ical, "BEGIN:VCALENDAR\r\nthis line has no colon\r\n" ..
        "SUMMARY:see https://summary.example.com/x\r\n\r\nEND:VCALENDAR\r\n")
    assert_equal(1, #urls)
    assert_equal('https://summary.example.com/x', urls[1])
    assert_equal('begin', keys[1])
    assert_equal('summary', keys[2])
    assert_equal('end', keys[3])
  end)

  test("A folded value is one property", function()
    local urls, keys = run(ical, "BEGIN:VCALENDAR\r\nDESCRIPTION:see https://folded.exam\r\n ple.com/path\r\n" ..
        "END:VCALENDAR\r\n")
    assert_equal('https://folded.example.com/path', urls[1])
    assert_equal(3, #keys)
  end)

  test("A vcard is read the same way", function()
    local urls, keys = run(vcard, "BEGIN:VCARD\r\nno colon here\r\nURL:https://card.example.com/\r\nEND:VCARD\r\n")
    assert_equal('https://card.example.com/', urls[1])
    assert_equal(3, #keys)
  end)
end)
