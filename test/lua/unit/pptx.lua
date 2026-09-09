context("PPTX content extraction", function()
  local archive = require "archive"
  local ooxml = require "lua_content/ooxml"
  local pptx = require "lua_content/pptx"

  local relationships_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
  local document_rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"

  local function rels(entries)
    local out = { string.format('<Relationships xmlns="%s">', relationships_ns) }
    for _, entry in ipairs(entries) do
      out[#out + 1] = string.format('<Relationship Id="%s" Type="%s" Target="%s"%s/>',
          entry[1], entry[2], entry[3], entry[4] and ' TargetMode="External"' or '')
    end
    out[#out + 1] = '</Relationships>'
    return table.concat(out)
  end

  local content_types = [[
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
      <Default Extension="xml" ContentType="application/xml"/>
      <Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>
      <Override PartName="/ppt/presentation.xml"
        ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
      <Override PartName="/ppt/slides/slide1.xml"
        ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
      <Override PartName="/ppt/notesSlides/notesSlide1.xml"
        ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>
    </Types>
  ]]

  local presentation = [[
    <p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst>
    </p:presentation>
  ]]

  local slide = [[
    <p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
      xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <p:cSld><p:spTree>
        <p:sp>
          <p:nvSpPr><p:cNvPr id="2" name="Title"><a:hlinkClick r:id="rId1"/></p:cNvPr></p:nvSpPr>
          <p:txBody>
            <a:p><a:r><a:t>Quarterly </a:t></a:r>
              <a:r><a:rPr lang="en-US"><a:hlinkClick r:id="rId2"/></a:rPr><a:t>report</a:t></a:r></a:p>
            <a:p><a:r><a:t>Second line</a:t></a:r><a:br/><a:r><a:t>after break</a:t></a:r></a:p>
            <a:p><a:fld id="{1}" type="slidenum"><a:t>1</a:t></a:fld></a:p>
          </p:txBody>
        </p:sp>
        <p:graphicFrame><a:graphic>
          <a:graphicData uri="http://schemas.openxmlformats.org/presentationml/2006/ole">
            <p:oleObj r:id="rId3" progId="Package"/>
          </a:graphicData>
        </a:graphic></p:graphicFrame>
      </p:spTree></p:cSld>
    </p:sld>
  ]]

  local notes = [[
    <p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
      xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
      <p:cSld><p:spTree><p:sp><p:txBody>
        <a:p><a:r><a:t>Speaker notes</a:t></a:r></a:p>
      </p:txBody></p:sp></p:spTree></p:cSld>
    </p:notes>
  ]]

  local function make_package()
    return archive.zip({
      { name = "[Content_Types].xml", content = content_types },
      { name = "_rels/.rels", content = rels({
        { "rId1", document_rel .. "officeDocument", "ppt/presentation.xml" },
      }) },
      { name = "ppt/presentation.xml", content = presentation },
      { name = "ppt/_rels/presentation.xml.rels", content = rels({
        { "rId1", document_rel .. "slide", "slides/slide1.xml" },
        { "rId2", document_rel .. "slideMaster", "slideMasters/slideMaster1.xml" },
      }) },
      { name = "ppt/slides/slide1.xml", content = slide },
      { name = "ppt/slides/_rels/slide1.xml.rels", content = rels({
        { "rId1", document_rel .. "hyperlink", "https://shape.example.com/", true },
        { "rId2", document_rel .. "hyperlink", "https://run.example.com/login", true },
        { "rId3", document_rel .. "oleObject", "../embeddings/oleObject1.bin" },
        { "rId4", document_rel .. "notesSlide", "../notesSlides/notesSlide1.xml" },
        { "rId5", document_rel .. "slideLayout", "../slideLayouts/slideLayout1.xml" },
      }) },
      { name = "ppt/notesSlides/notesSlide1.xml", content = notes },
      { name = "ppt/embeddings/oleObject1.bin", content = "MZ not really" },
      { name = "ppt/slideMasters/slideMaster1.xml", content = "<p:sldMaster/>" },
    })
  end

  test("discovers slides and their notes", function()
    local package, err = ooxml.open(make_package())
    assert_not_nil(package, err)
    assert_equal(package.format, 'pptx')
    assert_equal(package.main_part, "ppt/presentation.xml")
    assert_equal(package.kinds["ppt/presentation.xml"], nil)
    assert_equal(package.kinds["ppt/slides/slide1.xml"], 'slide')
    assert_equal(package.kinds["ppt/notesSlides/notesSlide1.xml"], 'slide')
    assert_equal(package.parts["ppt/slideMasters/slideMaster1.xml"], nil)
    assert_equal(package.parts["ppt/embeddings/oleObject1.bin"], nil)
    assert_equal(#package.story_parts, 2)
  end)

  test("extracts slide text and hyperlinks", function()
    local package, err = ooxml.open(make_package())
    assert_not_nil(package, err)
    local extracted
    extracted, err = pptx.extract(package)
    assert_not_nil(extracted, err)

    local text = tostring(extracted.text)
    assert_not_nil(text:find("Quarterly report\n", 1, true))
    assert_not_nil(text:find("Second line\nafter break\n", 1, true))
    assert_not_nil(text:find("Speaker notes", 1, true))

    local urls = {}
    for _, url in ipairs(extracted.urls) do urls[url] = true end
    assert_equal(urls["https://shape.example.com/"], true)
    assert_equal(urls["https://run.example.com/login"], true)
    assert_equal(#extracted.urls, 2)

    local summary = ooxml.summarize_relationships(package)
    assert_equal(#summary.macros, 0)
    assert_equal(summary.ole_objects, 1)
    assert_equal(#summary.external_targets, 0)
  end)

  test("dispatches a presentation through lua_content", function()
    local lua_content = require "lua_content"
    local rspamd_mempool = require "rspamd_mempool"
    local package_data = make_package()

    local part = {
      get_type = function() return 'application',
          'vnd.openxmlformats-officedocument.presentationml.presentation' end,
      get_detected_ext = function() return 'pptx' end,
      is_archive = function() return true end,
      is_specific = function() return false end,
      get_specific = function() return nil end,
      get_content = function() return package_data end,
      get_id = function() return 61 end,
    }
    local cache = {}
    local injected_text
    local injected_urls = {}
    local task = {
      pool = rspamd_mempool.create(),
      cache_set = function(_, key, value) cache[key] = value end,
      cache_get = function(_, key) return cache[key] end,
      get_mempool = function(self) return self.pool end,
      inject_part = function(_, kind, value, parent)
        assert_equal(kind, 'text')
        assert_equal(parent, part)
        injected_text = value
      end,
      inject_url = function(_, url, parent)
        assert_equal(parent, part)
        injected_urls[tostring(url)] = true
      end,
    }

    lua_content.maybe_process_mime_part(part, task)
    local specific = lua_content.get_specific(part, task)
    assert_not_nil(specific)
    assert_equal(specific.tag, 'pptx')
    assert_equal(specific.suspicious, nil)
    assert_equal(specific.sheets, nil)
    assert_not_nil(injected_text:find("Quarterly report", 1, true))
    assert_equal(injected_urls["https://run.example.com/login"], true)
    assert_equal(specific.relationships.ole_objects, 1)
  end)
end)
