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
