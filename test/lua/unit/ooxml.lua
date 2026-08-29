context("OOXML package reader", function()
  local archive = require "archive"
  local ooxml = require "lua_content/ooxml"
  local rspamd_ooxml = require "rspamd_ooxml"

  local content_types = [[
    <ct:Types xmlns:ct="http://schemas.openxmlformats.org/package/2006/content-types">
      <ct:Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
      <ct:Default Extension="xml" ContentType="application/xml"/>
      <ct:Override PartName="/word/document.xml"
        ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
      <ct:Override PartName="/word/header1.xml"
        ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
    </ct:Types>
  ]]

  local package_relationships = [[
    <r:Relationships xmlns:r="http://schemas.openxmlformats.org/package/2006/relationships">
      <r:Relationship Id="main"
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
        Target="word/subdir/../document.xml"/>
    </r:Relationships>
  ]]

  local document_relationships = [[
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="header"
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header"
        Target="header1.xml"/>
      <Relationship Id="link"
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
        Target="https://example.test/login" TargetMode="External"/>
    </Relationships>
  ]]

  local header_relationships = [[
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="header-link"
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
        Target="https://header.example.test/" TargetMode="External"/>
    </Relationships>
  ]]

  local function make_package(extra_files)
    local files = {
      { name = "[Content_Types].xml", content = content_types },
      { name = "_rels/.rels", content = package_relationships },
      { name = "word/document.xml", content = "<document/>" },
      { name = "word/_rels/document.xml.rels", content = document_relationships },
      { name = "word/header1.xml", content = "<header/>" },
      { name = "word/_rels/header1.xml.rels", content = header_relationships },
      { name = "word/media/ignored.bin", content = string.rep("X", 256 * 1024) },
    }
    for _, file in ipairs(extra_files or {}) do
      files[#files + 1] = file
    end
    return archive.zip(files)
  end

  test("normalizes safe internal relationship targets", function()
    local name, err = ooxml.resolve_part_name("word/document.xml", "../docProps/core.xml")
    assert_equal(err, nil)
    assert_equal(name, "docProps/core.xml")

    name, err = ooxml.resolve_part_name("word/document.xml", "headers/header%201.xml#bookmark")
    assert_equal(err, nil)
    assert_equal(name, "word/headers/header%201.xml")
  end)

  test("rejects unsafe internal relationship targets", function()
    local invalid = {
      "../../outside.xml",
      "/word/document.xml",
      "https://example.test/document.xml",
      "mailto:document.xml",
      "custom+scheme:document.xml",
      "word\\document.xml",
      "word/%2e%2e/document.xml",
      "word/%2fdocument.xml",
      "word/%00document.xml",
      "word/bad%escape.xml",
      "word//document.xml",
      "word/directory/",
    }
    for _, target in ipairs(invalid) do
      local name = ooxml.resolve_part_name('', target)
      assert_equal(name, nil, target)
    end
  end)

  test("discovers the main and related Word story parts", function()
    local package, err = ooxml.open(make_package())
    assert_not_nil(package, err)
    assert_equal(package.main_part, "word/document.xml")
    assert_equal(package.main_content_type,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
    assert_not_nil(package.parts["word/document.xml"])
    assert_not_nil(package.parts["word/header1.xml"])
    assert_equal(package.parts["word/media/ignored.bin"], nil)
    assert_equal(package.story_parts[1], "word/header1.xml")
    assert_equal(package.relationships["word/document.xml"].by_id.link.external, true)
    assert_equal(package.relationships["word/document.xml"].by_id.link.target,
        "https://example.test/login")
    assert_equal(package.relationships["word/header1.xml"].by_id["header-link"].target,
        "https://header.example.test/")
  end)

  test("fails when selected XML exceeds extraction limits", function()
    local package, err = ooxml.open(make_package(), { max_file_size = 64 })
    assert_equal(package, nil)
    assert_not_nil(err:find("limit", 1, true))
  end)

  test("rejects duplicate critical package parts", function()
    local package, err = ooxml.open(make_package({
      { name = "_rels/.rels", content = package_relationships },
    }))
    assert_equal(package, nil)
    assert_not_nil(err:find("duplicate", 1, true))
  end)

  test("native metadata parsing rejects DTDs and enforces relationship limits", function()
    local parsed, err = rspamd_ooxml.parse_content_types([[
      <!DOCTYPE Types [<!ENTITY x "expanded">]>
      <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>
    ]], {})
    assert_equal(parsed, nil)
    assert_not_nil(err:find("DTD", 1, true))

    parsed, err = rspamd_ooxml.parse_relationships(document_relationships,
        "word/document.xml", { max_relationships = 1 })
    assert_equal(parsed, nil)
    assert_not_nil(err:find("relationship limit", 1, true))
  end)

  test("native metadata parsing accepts BOM marked UTF-16LE", function()
    local ascii = [[
      <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
        <Default Extension="xml" ContentType="application/xml"/>
      </Types>
    ]]
    local encoded = { "\255\254" }
    for i = 1, #ascii do
      encoded[#encoded + 1] = ascii:sub(i, i)
      encoded[#encoded + 1] = "\0"
    end

    local parsed, err = rspamd_ooxml.parse_content_types(table.concat(encoded), {})
    assert_not_nil(parsed, err)
    assert_equal(parsed.defaults.xml, "application/xml")
  end)

  test("native metadata parsing enforces structural XML limits", function()
    local parsed, err = rspamd_ooxml.parse_content_types([[
      <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
        <Default Extension="xml" ContentType="application/xml"/>
      </Types>
    ]], { xml = { max_attributes = 1 } })
    assert_equal(parsed, nil)
    assert_not_nil(err:find("attribute limit", 1, true))

    parsed, err = rspamd_ooxml.parse_content_types([[
      <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    ]], {})
    assert_equal(parsed, nil)
    assert_not_nil(err:find("unclosed", 1, true))

    parsed, err = rspamd_ooxml.parse_content_types(
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">bad\1</Types>",
        {})
    assert_equal(parsed, nil)
    assert_not_nil(err:find("control character", 1, true))
  end)

  test("native metadata parsing rejects invalid XML entities and limits", function()
    local template = [[
      <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">%s</Types>
    ]]
    for _, entity in ipairs({ "&copy;", "&#0;", "&#x110000;", "&#xZZ;" }) do
      local parsed, err = rspamd_ooxml.parse_content_types(template:format(entity), {})
      assert_equal(parsed, nil)
      assert_not_nil(err, entity)
    end

    local parsed, err = rspamd_ooxml.parse_content_types(template:format(""), {
      xml = { max_depth = "unbounded" },
    })
    assert_equal(parsed, nil)
    assert_not_nil(err:find("bad type", 1, true))
  end)
end)
