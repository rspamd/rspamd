--[[
A part declared as text, whose data is not binary, is shown as text by mail
clients. A file signature that lua_magic finds in it must not make it an
image, a document or data without text, which would hide its text and URLs.
Data that is binary still goes by what lua_magic finds.
]]

context("Text parts that hold a file signature", function()
  local rspamd_task = require "rspamd_task"

  local function load(ct, body)
    local res, task = rspamd_task.load_from_string(table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      '',
      '--XX',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'first part',
      '--XX',
      'Content-Type: ' .. ct,
      '',
      body,
      '--XX--',
      '',
    }, '\n'), rspamd_config)
    assert(res, "cannot load the message")
    task:process_message()
    return task
  end

  local function text_with(task, marker)
    for _, p in ipairs(task:get_parts()) do
      if p:is_text() and tostring(p:get_text():get_content()):find(marker, 1, true) then
        return p
      end
    end
  end

  local text = 'Hello friend, see http://signature.example.com/login now\n'
  local pdf_doc = table.concat({
    '%PDF-1.4',
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj',
    '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj',
    '3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj',
    '4 0 obj << /Length 44 >> stream',
    'BT /F1 12 Tf 72 712 Td (Pay invoice now) Tj ET',
    'endstream endobj',
    'trailer << /Root 1 0 R >>',
    '%%EOF',
  }, '\n')
  local gif_bytes = 'GIF89a\1\0\1\0\128\0\0\255\255\255\0\0\0!\249\4\1\0\0\0\0,\0\0\0\0\1\0\1\0\0\2\2D\1\0;'
  local cases = {
    { 'text/plain', 'GIF89a ' .. text },
    { 'text/plain', '%PDF-1.4 ' .. text },
    { 'text/plain', 'Some words first. %PDF-1.7 ' .. text },
    { 'text/plain', '<?xml version="1.0"?>\n' .. text },
    { 'text/plain', 'BEGIN:VCALENDAR\n' .. text },
    { 'text/plain', 'BEGIN:VCARD\n' .. text },
    { 'text/html', '<html><body>%PDF-1.4 ' .. text .. '</body></html>' },
  }

  for _, c in ipairs(cases) do
    test(string.format("%s that starts with '%s' stays text", c[1],
        (c[2]:sub(1, 20):gsub('\n', ' '))), function()
      local task = load(c[1], c[2])
      assert_not_nil(text_with(task, 'signature.example.com'))
      local found = false
      for _, u in ipairs(task:get_urls(true)) do
        if u:get_host() == 'signature.example.com' then
          found = true
        end
      end
      assert_true(found)
      task:destroy()
    end)
  end

  test("what lua_magic finds in such text is kept", function()
    local task = load('text/plain', '{\\rtf1 ' .. text .. '}')
    local part = text_with(task, 'signature.example.com')
    assert_not_nil(part)
    assert_equal(part:get_detected_ext(), 'rtf')
    task:destroy()
  end)

  -- Shown inline whatever its name
  test("inline text/plain named x.gif stays text", function()
    local task = load('text/plain\nContent-Disposition: inline; filename="x.gif"',
        'GIF89a ' .. text)
    assert_not_nil(text_with(task, 'signature.example.com'))
    task:destroy()
  end)

  -- An attachment named as what lua_magic finds is a file of that type
  test("text/plain named x.pdf that holds a PDF is a PDF", function()
    local task = load('text/plain\nContent-Disposition: attachment; filename="invoice.pdf"', pdf_doc)
    assert_nil(text_with(task, '%PDF'))
    task:destroy()
  end)

  -- A name= parameter alone does not keep a client from showing text inline
  test("text/plain with only a name=x.pdf parameter stays text", function()
    local task = load('text/plain; name="x.pdf"', '%PDF-1.4 ' .. text)
    assert_not_nil(text_with(task, 'signature.example.com'))
    task:destroy()
  end)

  -- The content modules still read such text, without taking it over
  test("a PDF in a text/plain part is text and still read as a PDF", function()
    local task = load('text/plain', pdf_doc)
    local part = text_with(task, 'Pay invoice now')
    assert_not_nil(part)
    assert_not_nil(require("lua_content").get_specific(part, task))
    task:destroy()
  end)

  test("a GIF attached as x.gif is an image", function()
    local task = load('text/plain\nContent-Disposition: attachment; filename="x.gif"', gif_bytes)
    assert_nil(text_with(task, 'GIF89a'))
    local images = 0
    for _, p in ipairs(task:get_parts()) do
      if p:is_image() then
        images = images + 1
      end
    end
    assert_equal(images, 1)
    task:destroy()
  end)

  -- Attachments and resources that are binary keep what lua_magic finds

  test("a binary GIF attached under another name is an image", function()
    local task = load('text/plain\nContent-Disposition: attachment; filename="image.dat"', gif_bytes)
    local images = 0
    for _, p in ipairs(task:get_parts()) do
      if p:is_image() then
        images = images + 1
      end
    end
    assert_equal(images, 1)
    task:destroy()
  end)

  test("a binary GIF that the HTML refers to is an image", function()
    local res, task = rspamd_task.load_from_string(table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/related; boundary="RR"',
      '',
      '--RR',
      'Content-Type: text/html',
      '',
      '<html><body><img src="cid:img1"></body></html>',
      '--RR',
      'Content-Type: text/plain',
      'Content-ID: <img1>',
      '',
      gif_bytes,
      '--RR--',
      '',
    }, '\n'), rspamd_config)
    assert_true(res)
    task:process_message()
    local images = 0
    for _, p in ipairs(task:get_parts()) do
      if p:is_image() then
        images = images + 1
      end
    end
    assert_equal(images, 1)
    task:destroy()
  end)

  local function has_url(task, host)
    for _, u in ipairs(task:get_urls(true)) do
      if u:get_host() == host then
        return u
      end
    end
  end

  test("the links of binary data that clients show as text are read", function()
    -- Control bytes make it binary, so it is read as a GIF, but clients show
    -- the text and its link
    local task = load('text/plain', 'GIF89a ' .. text .. string.rep('\1', 4096))
    local u = has_url(task, 'signature.example.com')
    assert_not_nil(u)
    assert_true(u:get_flags().content)
    task:destroy()
  end)

  test("binary text/html is read as HTML for its links", function()
    -- Clients show it as HTML, which decodes entities in links and text
    local task = load('text/html', 'GIF89a ' .. string.rep('\1', 600) ..
        '<a href="https&#58;//entity.example.com/x">a</a>' ..
        '<p>https&#x3a;&#x2f;&#x2f;text.example.com/y</p>\n')
    assert_not_nil(has_url(task, 'entity.example.com'))
    assert_not_nil(has_url(task, 'text.example.com'))
    task:destroy()
  end)

  test("such data is read in the charset it declares", function()
    -- UTF-16 hides all its ASCII from a read of the bytes
    local function utf16le(s)
      return (s:gsub('.', function(c)
        return c .. '\0'
      end))
    end
    local body = 'GIF89a' .. utf16le('<a href="https&#58;//u16.example.com/x">a</a> https://u16text.example.com/y')
    local task = load('text/html; charset=utf-16le\nContent-Transfer-Encoding: base64',
        tostring(require('rspamd_util').encode_base64(body, 76)))
    assert_not_nil(has_url(task, 'u16.example.com'))
    assert_not_nil(has_url(task, 'u16text.example.com'))
    task:destroy()
  end)

  test("UTF-16 without a byte order mark is read in the order of its data", function()
    -- Browsers and Thunderbird take it as little-endian, Apple Mail as big-endian
    local function utf16le(s)
      return (s:gsub('.', function(c)
        return c .. '\0'
      end))
    end
    local function utf16be(s)
      return (s:gsub('.', function(c)
        return '\0' .. c
      end))
    end
    local b64 = require('rspamd_util').encode_base64
    local body = 'GIF89a' .. utf16le(' <a href="https://le16.example.com/x">a</a> ')
    local task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(body, 76)))
    assert_not_nil(has_url(task, 'le16.example.com'))
    task:destroy()
    task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(utf16le('<a href="https://text16.example.com/x">a</a>'), 76)))
    assert_not_nil(has_url(task, 'text16.example.com'))
    task:destroy()
    task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(utf16be('<a href="https://be16.example.com/x">a</a>'), 76)))
    assert_not_nil(has_url(task, 'be16.example.com'))
    task:destroy()
    -- WHATWG labels of each order
    task = load('text/html; charset=unicodefffe\nContent-Transfer-Encoding: base64',
        tostring(b64(utf16be('<a href="https://fffe.example.com/x">a</a>'), 76)))
    assert_not_nil(has_url(task, 'fffe.example.com'))
    task:destroy()
  end)

  test("UTF-16 without a byte order mark has its links read in both orders", function()
    -- Padding can choose the order rspamd reads, and clients read either one
    local function utf16le(s)
      return (s:gsub('.', function(c)
        return c .. '\0'
      end))
    end
    local function utf16be(s)
      return (s:gsub('.', function(c)
        return '\0' .. c
      end))
    end
    local b64 = require('rspamd_util').encode_base64
    local cases = {
      -- Big-endian padding, a little-endian link, and the other way round
      { 'text/html', string.rep('\0A', 400) .. utf16le('<a href="https://le.example.com/x">a</a>'),
        'le.example.com' },
      { 'text/html', string.rep('A\0', 400) .. utf16be('<a href="https://be.example.com/x">a</a>'),
        'be.example.com' },
      { 'text/plain', string.rep('\0A', 400) .. utf16le(' https://plain.example.com/x '),
        'plain.example.com' },
      -- Read as a file, shown as text
      { 'text/html', 'GIF89a' .. string.rep('\0A', 400) ..
          utf16le('<a href="https://gif.example.com/x">a</a>'), 'gif.example.com' },
    }
    for _, c in ipairs(cases) do
      local task = load(c[1] .. '; charset=utf-16\nContent-Transfer-Encoding: base64',
          tostring(b64(c[2], 76)))
      assert_not_nil(has_url(task, c[3]), c[3])
      task:destroy()
    end
    -- A link in both orders is counted once, as in one
    local link = '<a href="https://same.example.com/x">a</a>'
    local task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(utf16le(link) .. utf16be(link), 76)))
    local u = has_url(task, 'same.example.com')
    assert_not_nil(u)
    assert_equal(1, u:get_count())
    task:destroy()
    -- Lines are joined as in the first read: a link in brackets over two lines
    task = load('text/plain; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(string.rep('\0A', 400) ..
            utf16le('see <https://br.example.com/very/long\n/tail.php?id=1> now'), 76)))
    u = has_url(task, 'br.example.com')
    assert_not_nil(u)
    assert_equal('very/long/tail.php', u:get_path())
    task:destroy()
    -- A link that the other order shows under another name is phished, not counted again
    -- A space ends the text of the link, so it reads the same in both messages
    local shown = string.rep('A\0', 200) ..
        utf16le('<a href="https://evil.example.com/x">https://evil.example.com/x</a> ')
    task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64', tostring(b64(shown, 76)))
    local count = has_url(task, 'evil.example.com'):get_count()
    task:destroy()
    task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(shown .. utf16be('<a href="https://evil.example.com/x">https://paypal.com/signin</a>'), 76)))
    -- The link itself: its text, glued to the letters before it and with the
    -- other half read as garbage after it, is an url of its own in the text
    u = nil
    for _, cand in ipairs(task:get_urls() or {}) do
      if tostring(cand) == 'https://evil.example.com/x' then
        u = cand
      end
    end
    assert_not_nil(u)
    assert_true(u:is_phished())
    assert_equal(count, u:get_count())
    task:destroy()
    -- It pretends to be the name it is shown under, not the link it is in the query of
    task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(string.rep('A\0', 200) ..
            utf16le('<a href="https://wrap.example.com/r?u=https://evil.example.com/x">a</a>') ..
            utf16be('<a href="https://evil.example.com/x">https://paypal.com/signin</a>'), 76)))
    u = has_url(task, 'evil.example.com')
    assert_not_nil(u)
    assert_true(u:is_phished())
    assert_equal('paypal.com', u:get_phished():get_host())
    task:destroy()
    -- Nor a name that does not parse (obscured), with or without a link it is in the query of
    require('rspamd_test_helper').init_url_parser()
    for _, first in ipairs({
      '<a href="https://evil.example.com/x">http://1.2.3.4.5/</a>',
      '<a href="https://wrap.example.com/r?u=https://evil.example.com/x">a</a>' ..
          '<a href="https://evil.example.com/x">http://1.2.3.4.5/</a>',
    }) do
      task = load('text/html; charset=utf-16\nContent-Transfer-Encoding: base64',
          tostring(b64(string.rep('A\0', 200) .. utf16le(first) ..
              utf16be('<a href="https://evil.example.com/x">https://paypal.com/signin</a>'), 76)))
      u = has_url(task, 'evil.example.com')
      assert_not_nil(u)
      assert_true(u:get_flags().obscured)
      local phished = u:get_phished()
      assert_not_nil(phished)
      assert_equal('paypal.com', phished:get_host())
      task:destroy()
    end
    -- Nor the link it is in the query of, when another read shows that link as text
    local function part(body)
      return table.concat({ '--XX', 'Content-Type: text/html; charset=utf-16',
        'Content-Transfer-Encoding: base64', '', tostring(b64(body, 76)) }, '\n')
    end
    local res
    res, task = rspamd_task.load_from_string(table.concat({
      'Subject: t', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="XX"', '',
      part(string.rep('A\0', 200) .. utf16le('<p>hi</p>') ..
          utf16be('<a href="https://evil.example.com/x">https://paypal.com/signin</a>')),
      part(string.rep('A\0', 200) ..
          utf16le('<a href="https://wrap.example.com/r?u=https://evil.example.com/x">a</a>' ..
              '<a href="https://evil.example.com/x">http://1.2.3.4.5/</a>') ..
          utf16be('<a href="https://z.example.net/">https://wrap.example.com/r?u=https://evil.example.com/x</a>')),
      '--XX--', '',
    }, '\n'), rspamd_config)
    assert_true(res)
    task:process_message()
    u = has_url(task, 'evil.example.com')
    assert_not_nil(u)
    assert_not_nil(u:get_phished())
    assert_equal('paypal.com', u:get_phished():get_host())
    -- A link is still checked when another read only shows it as text
    assert_false(has_url(task, 'wrap.example.com'):is_html_displayed())
    task:destroy()
    -- The other order of text is junk, which is no bad unicode clients show
    task = load('text/plain; charset=utf-16\nContent-Transfer-Encoding: base64',
        tostring(b64(utf16le('Hello ') .. '\0\173\172\185' .. utf16le(' team, see you soon.\n'), 76)))
    assert_false(task:has_flag('bad_unicode'))
    task:destroy()
  end)

  test("binary data under a label clients do not decode is read as it is", function()
    -- Converted, ASCII under utf-32 would turn into junk
    local task = load('text/html; charset=utf-32', 'GIF89a ' .. string.rep('\1', 600) ..
        '<a href="https://u32.example.com/x">a</a>\n')
    assert_not_nil(has_url(task, 'u32.example.com'))
    task:destroy()
  end)

  test("links of binary text/html are counted as in an HTML part", function()
    local html = '<a href="https://dup.example.com/">https://dup.example.com/</a>' ..
        '<a href="https://amp.example.com/c?u=1&amp;id=2">x</a>\n'
    local function count(task)
      local n = 0
      for _, u in ipairs(task:get_urls(true)) do
        n = n + u:get_count()
      end
      return n
    end
    local plain = load('text/html', html)
    local binary = load('text/html', 'GIF89a <!--' .. string.rep('\1', 600) .. '-->' .. html)
    assert_equal(count(binary), count(plain))
    plain:destroy()
    binary:destroy()
  end)

  test("links in the query of such links are read too", function()
    local task = load('text/plain', 'GIF89a ' .. string.rep('\1', 600) ..
        'https://www.google.com/url?q=https%3A%2F%2Fquery.example.com%2Flogin&sa=D\n')
    assert_not_nil(has_url(task, 'query.example.com'))
    task:destroy()
  end)

  test("an image the HTML shows by its Content-ID is not read for links", function()
    -- Clients show it as an image, not as text
    local res, task = rspamd_task.load_from_string(table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/related; boundary="RR"',
      '',
      '--RR',
      'Content-Type: text/html',
      '',
      '<html><body><img src="cid:img3"></body></html>',
      '--RR',
      'Content-Type: text/plain',
      'Content-ID: <img3>',
      '',
      'GIF89a ' .. text .. string.rep('\1', 4096),
      '--RR--',
      '',
    }, '\n'), rspamd_config)
    assert_true(res)
    task:process_message()
    assert_nil(has_url(task, 'signature.example.com'))
    task:destroy()
  end)

  test("a Content-ID alone does not keep links from being read", function()
    local task = load('text/plain\nContent-ID: <img4>', 'GIF89a ' .. text .. string.rep('\1', 4096))
    assert_not_nil(has_url(task, 'signature.example.com'))
    task:destroy()
  end)

  test("nested links in queries are read in linear time", function()
    local link = 'https://end.example.com/x'
    for n = 1, 24 do
      link = string.format('https://h%d.example.com/r?u=%s', n, link)
    end
    local task = load('text/plain', 'GIF89a ' .. string.rep('\1', 600) .. link .. '\n')
    assert_not_nil(has_url(task, 'h24.example.com'))
    task:destroy()
  end)

  test("a child without Content-Type named as its type is a file", function()
    local res, task = rspamd_task.load_from_string(table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      '',
      '--XX',
      'Content-Disposition: inline; filename="image.gif"',
      'Content-Transfer-Encoding: 8bit',
      '',
      'GIF89a' .. string.rep('\16', 300) .. text,
      '--XX--',
      '',
    }, '\n'), rspamd_config)
    assert_true(res)
    task:process_message()
    assert_nil(has_url(task, 'signature.example.com'))
    task:destroy()
  end)

  test("the links of a binary child without Content-Type are read", function()
    local res, task = rspamd_task.load_from_string(table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      '',
      '--XX',
      'Content-Transfer-Encoding: 8bit',
      '',
      string.rep('\16', 300) .. text,
      '--XX--',
      '',
    }, '\n'), rspamd_config)
    assert_true(res)
    task:process_message()
    assert_not_nil(has_url(task, 'signature.example.com'))
    task:destroy()
  end)

  test("a calendar with control bytes in it stays text", function()
    -- Text formats have no binary form
    local task = load('text/plain', 'BEGIN:VCALENDAR\n' .. text .. string.rep('\1', 2000) ..
        '\n' .. string.rep('END:VCALENDAR\n', 8))
    assert_not_nil(text_with(task, 'signature.example.com'))
    task:destroy()
  end)

  test("a binary GIF with a Content-ID is an image", function()
    local task = load('text/plain\nContent-ID: <img2>', gif_bytes)
    local images = 0
    for _, p in ipairs(task:get_parts()) do
      if p:is_image() then
        images = images + 1
      end
    end
    assert_equal(images, 1)
    task:destroy()
  end)

end)
