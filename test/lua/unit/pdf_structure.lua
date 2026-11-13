-- Forms of the pdf syntax that readers accept and that must not hide content

context("PDF structure parsing", function()
  local rspamd_text = require "rspamd_text"
  local pdf = require "lua_content/pdf"

  local js = string.rep("app.alert('hello world this is js');", 10)
  local catalog = '<< /Type /Catalog /Pages 2 0 R >>'
  local pages = '<< /Type /Pages /Kids [] /Count 0 >>'
  local js_action = '<< /Type /Action /S /JavaScript /JS (' .. js .. ') >>'
  local default_trailer = 'trailer\n<< /Size 9 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n'

  local function build(objs, objfmt, trailer)
    local out = { '%PDF-1.4\n' }

    for i, o in ipairs(objs) do
      out[#out + 1] = string.format(objfmt or '%d 0 obj\n%s\nendobj\n', i, o)
    end

    out[#out + 1] = trailer or default_trailer

    return table.concat(out)
  end

  local function process(data)
    return pdf.process(rspamd_text.fromstring(data), nil, {})
  end

  local function stream(data, dict)
    return string.format('<< %s /Length %d >>\nstream\n%s\nendstream', dict or '', #data, data)
  end

  -- Ways to lay the objects out

  local layouts = {
    { 'a line per keyword', '%d 0 obj\n%s\nendobj\n' },
    { 'objects separated by spaces', '%d 0 obj %s endobj ' },
    { 'nothing after the obj keyword', '%d 0 obj%s\nendobj\n' },
    { 'CR line ends', '%d 0 obj\r%s\rendobj\r' },
    { 'CRLF line ends', '%d 0 obj\r\n%s\r\nendobj\r\n' },
    { 'blank lines between', '\r\n   \r\n%d 0 obj\r\n%s\r\nendobj\r\n' },
    { 'a space after endobj', '%d 0 obj\n%s\nendobj \n' },
    { 'white space inside the header', '%d \n\t ' .. string.rep(' ', 60) .. '0   obj\n%s\nendobj\n' },
  }

  for _, l in ipairs(layouts) do
    test("Objects are found with " .. l[1], function()
      local res = process(build({ catalog, pages, js_action }, l[2]))
      assert_equal(3, #res.objects)
      assert_true(res.scripts)
    end)
  end

  test("The last object is found when the file ends with endobj", function()
    local data = build({ catalog, pages, js_action }, nil, '')
    data = data:sub(1, #data - 1)
    assert_equal('endobj', data:sub(-6))
    local res = process(data)
    assert_equal(3, #res.objects)
    assert_true(res.scripts)
  end)

  test("An object without endobj does not shift the objects after it", function()
    local data = '%PDF-1.4\n1 0 obj\n' .. catalog .. '\n2 0 obj\n' .. pages .. '\nendobj\n3 0 obj\n' ..
        js_action .. '\nendobj\n' .. default_trailer
    local res = process(data)
    assert_equal(3, #res.objects)
    assert_true(res.scripts)
  end)

  -- Markers inside of the data of a stream

  test("A stream with endobj in its data is not cut there", function()
    local body = js .. '\nendobj\n' .. js
    local res = process(build({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>', stream(body) }))
    assert_true(res.scripts)
    assert_equal(1, #res.fuzzy_hashes)
    assert_equal(4, #res.objects)
  end)

  test("Object headers in the data of a stream start no objects", function()
    local body = string.rep('\n1 0 obj\n', 5) .. 'padding'
    local res = process(build({ catalog, pages, stream(body), js_action }))
    assert_equal(4, #res.objects)
    assert_true(res.scripts)
  end)

  test("A declared length that is too short does not cut the stream", function()
    local short = string.format('<< /Length 10 >>\nstream\n%s\nendstream', js)
    local full = process(build({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>', stream(js) }))
    local cut = process(build({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>', short }))
    assert_true(cut.scripts)
    assert_equal(1, #cut.fuzzy_hashes)
    assert_equal(full.fuzzy_hashes[1], cut.fuzzy_hashes[1])
  end)

  test("Blanks after the stream keyword and no line end after endstream", function()
    local body = string.format('<< /Length %d >>\nstream \n%s\nendstream endobj', #js, js)
    local res = process(build({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>', body },
        '%d 0 obj\n%s\n'):gsub('endobj\n(%d) 0 obj', 'endobj\n%1 0 obj'))
    assert_true(res.scripts)
  end)

  -- Tokens of a dictionary

  local dict_forms = {
    { 'null as a value', '/Foo null' },
    { 'a hex string with white space', '/Foo <41 42\n43>' },
    { 'an octal escape over 255', '/Foo (\\777)' },
    { 'an unknown bare word', '/Foo bar /Baz 12abc' },
    { 'the empty name', '/Foo / /Bar /' },
    { 'a comment', '/Foo 1 % note >> )\n' },
    { 'padding over 32K', '/Pad (' .. string.rep('x', 40000) .. ')' },
  }

  for _, f in ipairs(dict_forms) do
    test("A dictionary is read with " .. f[1], function()
      local res = process(build({ catalog, pages,
                                  '<< /Type /Action /S /JavaScript ' .. f[2] .. ' /JS (' .. js .. ') >>' }))
      assert_true(res.scripts)
      assert_nil(res.flags.unparsed_objects)
    end)
  end

  for _, ref in ipairs({ '4 0 R', '4  0  R', '4\n0\nR', '4\t0 R' }) do
    test("A reference is read as " .. ref:gsub('%s', '_'), function()
      local res = process(build({ catalog, pages, '<< /Type /Action /S /JavaScript /JS ' .. ref .. ' >>',
                                  stream(js) }))
      assert_true(res.scripts)
    end)
  end

  for _, key in ipairs({ '/JS', '/J#53', '/#4AS', '/#4a#53' }) do
    test("A name is unescaped: " .. key, function()
      local res = process(build({ catalog, pages,
                                  '<< /Type /Action /S /JavaScript ' .. key .. ' (' .. js .. ') >>' }))
      assert_true(res.scripts)
    end)
  end

  test("Escapes of a string are decoded", function()
    local res = process(build({ catalog, pages,
                                '<< /Type /Annot /V (a\\(b\\)c\\\\d\\101\\1012\\8\\\n!\\t) >>' }))
    assert_equal('a(b)c\\dAA28!\t', res.objects[3].dict.V)
  end)

  -- Actions

  test("An action written in place in the catalog is seen", function()
    local res = process(build({ '<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (' ..
                                    js .. ') >> >>', pages }))
    assert_true(res.scripts)
    assert_true(res.openaction)
  end)

  test("An action that is an object is still an open action", function()
    local res = process(build({ '<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>', pages, js_action }))
    assert_true(res.scripts)
    assert_true(res.openaction)
  end)

  test("A destination is not an open action", function()
    local res = process(build({ '<< /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /Fit] >>', pages,
                                '<< /Type /Page /Parent 2 0 R >>' }))
    assert_nil(res.scripts)
    assert_nil(res.openaction)
  end)

  test("Additional actions written in place are seen", function()
    local res = process(build({ catalog, pages,
                                '<< /Type /Page /Parent 2 0 R /AA << /O << /S /JavaScript /JS (' ..
                                    js .. ') >> >> >>' }))
    assert_true(res.scripts)

    res = process(build({ catalog, pages,
                          '<< /Type /Annot /Subtype /Link /A << /S /JavaScript /JS (' .. js .. ') >> >>' }))
    assert_true(res.scripts)
  end)

  test("A launch action in the catalog is reported", function()
    local res = process(build({ '<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) >> >>',
                                pages }))
    assert_true(res.launch)
    assert_true(res.openaction)
  end)

  test("A page that names an action as its content does not hide it", function()
    local res = process(build({ '<< /Type /Page /Contents [4 0 R] >>', catalog, pages, js_action }))
    assert_true(res.scripts)
  end)

  -- Encryption

  local encrypted = {
    { 'a reference', 'trailer\n<< /Size 9 /Root 1 0 R /Encrypt 5 0 R >>\n%%EOF\n', true },
    { 'a dictionary at once', 'trailer\n<< /Size 9 /Root 1 0 R /Encrypt<</Filter/Standard>> >>\n%%EOF\n', true },
    { 'the value on the next line', 'trailer\n<< /Size 9 /Root 1 0 R /Encrypt\n5 0 R >>\n%%EOF\n', true },
    { 'the dictionary after the keyword', 'trailer<< /Size 9 /Root 1 0 R /Encrypt 5 0 R >>\n%%EOF\n', true },
    { 'an empty trailer added after it',
      'trailer\n<< /Size 9 /Root 1 0 R /Encrypt 5 0 R >>\n%%EOF\n\ntrailer\n<< >>\n', true },
    { 'no such key', 'trailer\n<< /Size 9 /Root 1 0 R /EncryptMetadata false >>\n%%EOF\n', nil },
  }

  for _, e in ipairs(encrypted) do
    test("Encryption in the trailer: " .. e[1], function()
      local res = process(build({ catalog, pages }, nil, e[2]))
      assert_equal(e[3], res.encrypted)
    end)
  end

  -- Filters

  test("ASCII85 data with runs of zeroes is decoded", function()
    local rspamd_util = require "rspamd_util"
    -- A `z` is four zero bytes, `!!` with the end mark is one
    local decoded = rspamd_util.decode_ascii85(string.rep('z', 100) .. '87cURDZ~>')
    assert_not_nil(decoded)
    assert_equal(string.rep('\0', 400) .. 'Hello', tostring(decoded))
    assert_nil(rspamd_util.decode_ascii85(string.rep('z', 100) .. '~>', 100))
    assert_equal(400, #rspamd_util.decode_ascii85(string.rep('z', 100) .. '~>', 400))
  end)

  test("A stream that cannot be decoded is counted", function()
    local res = process(build({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>',
                                stream('not deflate at all, not at all', '/Filter /FlateDecode') }))
    assert_equal(1, res.flags.undecoded_streams)
  end)

  test("Inflate tells what is wrong", function()
    local res, err = require("rspamd_util").inflate('not deflate at all', 1024)
    assert_nil(res)
    assert_equal('string', type(err))
  end)
end)
