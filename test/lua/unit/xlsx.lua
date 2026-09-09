context("XLSX content extraction", function()
  local archive = require "archive"
  local ooxml = require "lua_content/ooxml"
  local xlsx = require "lua_content/xlsx"

  local relationships_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
  local document_rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
  local microsoft_rel = "http://schemas.microsoft.com/office/2006/relationships/"

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
      <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
      <Override PartName="/xl/workbook.xml"
        ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
      <Override PartName="/xl/worksheets/sheet1.xml"
        ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
      <Override PartName="/xl/sharedStrings.xml"
        ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
    </Types>
  ]]

  local workbook = [[
    <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <sheets>
        <sheet name="Invoice" sheetId="1" r:id="rId1"/>
        <sheet name="Macro1" sheetId="2" state="veryHidden" r:id="rId2"/>
        <sheet name="Notes" sheetId="3" state="hidden" r:id="rId6"/>
      </sheets>
      <externalReferences><externalReference r:id="rId4"/></externalReferences>
      <definedNames>
        <definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName>
        <definedName name="Totals">Invoice!$B$1</definedName>
      </definedNames>
    </workbook>
  ]]

  local shared_strings = [[
    <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2" uniqueCount="2">
      <si><t>Invoice total</t></si>
      <si><r><t>Pay at </t></r><r><rPr><b/></rPr><t>https://shared.example.com/pay</t></r>
        <rPh sb="0" eb="1"><t>phonetic</t></rPh></si>
      <si><t/></si>
    </sst>
  ]]

  local sheet = [[
    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <sheetData>
        <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><v>42</v></c>
          <c r="C1" t="inlineStr"><is><t>Inline</t><t xml:space="preserve"> cell</t></is></c>
          <c r="D1" t="str"><f>A1&amp;"x"</f><v>Computed</v></c></row>
        <row r="2"><c r="A2" t="str"><f>HYPERLINK("https://formula.example.com/login","Click")</f><v>Click</v></c></row>
        <row r="3"><c r="A3"><f>_xlfn.WEBSERVICE("http://webservice.example.com/x")</f><v>0</v></c></row>
        <row r="4"><c r="A4" t="str"><f>HYPERLINK(B4,"Not a URL")</f><v>Not a URL</v></c></row>
      </sheetData>
      <hyperlinks>
        <hyperlink ref="C1" r:id="rId1"/>
        <hyperlink ref="D1" location="Sheet2!A1"/>
      </hyperlinks>
      <drawing r:id="rId2"/>
    </worksheet>
  ]]

  local drawing = [[
    <xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
      xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <xdr:twoCellAnchor><xdr:sp>
        <xdr:nvSpPr><xdr:cNvPr id="2" name="Button"><a:hlinkClick r:id="rId1"/></xdr:cNvPr></xdr:nvSpPr>
        <xdr:txBody><a:p><a:r><a:t>Open document</a:t></a:r></a:p></xdr:txBody>
      </xdr:sp></xdr:twoCellAnchor>
    </xdr:wsDr>
  ]]

  local macrosheet = [[
    <xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"
      xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
      <sheetData><row r="1"><c r="A1" t="str"><f>EXEC("calc.exe")</f><v>macro cell</v></c></row></sheetData>
    </xm:macrosheet>
  ]]

  local function make_package()
    return archive.zip({
      { name = "[Content_Types].xml", content = content_types },
      { name = "_rels/.rels", content = rels({
        { "rId1", document_rel .. "officeDocument", "xl/workbook.xml" },
      }) },
      { name = "xl/workbook.xml", content = workbook },
      { name = "xl/_rels/workbook.xml.rels", content = rels({
        { "rId1", document_rel .. "worksheet", "worksheets/sheet1.xml" },
        { "rId2", microsoft_rel .. "xlMacrosheet", "macrosheets/sheet1.xml" },
        { "rId3", document_rel .. "sharedStrings", "sharedStrings.xml" },
        { "rId4", document_rel .. "externalLink", "externalLinks/externalLink1.xml" },
        { "rId5", document_rel .. "vbaProject", "vbaProject.bin" },
        { "rId6", document_rel .. "worksheet", "worksheets/sheet2.xml" },
      }) },
      { name = "xl/sharedStrings.xml", content = shared_strings },
      { name = "xl/worksheets/sheet1.xml", content = sheet },
      { name = "xl/worksheets/_rels/sheet1.xml.rels", content = rels({
        { "rId1", document_rel .. "hyperlink", "https://sheet.example.com/", true },
        { "rId2", document_rel .. "drawing", "../drawings/drawing1.xml" },
      }) },
      { name = "xl/drawings/drawing1.xml", content = drawing },
      { name = "xl/drawings/_rels/drawing1.xml.rels", content = rels({
        { "rId1", document_rel .. "hyperlink", "https://drawing.example.com/open", true },
      }) },
      { name = "xl/macrosheets/sheet1.xml", content = macrosheet },
      { name = "xl/externalLinks/externalLink1.xml", content = "<externalLink/>" },
      { name = "xl/externalLinks/_rels/externalLink1.xml.rels", content = rels({
        { "rId1", document_rel .. "externalLinkPath", "https://external.example.com/data.xlsx", true },
      }) },
      { name = "xl/vbaProject.bin", content = "not really a VBA project" },
      { name = "xl/media/image1.png", content = string.rep("P", 64 * 1024) },
    })
  end

  local function url_set(urls)
    local result = {}
    for _, url in ipairs(urls or {}) do result[tostring(url)] = true end
    return result
  end

  test("discovers workbook stories two relationship levels deep", function()
    local package, err = ooxml.open(make_package())
    assert_not_nil(package, err)
    assert_equal(package.format, 'xlsx')
    assert_equal(package.main_part, "xl/workbook.xml")
    assert_equal(package.kinds["xl/workbook.xml"], 'workbook')
    assert_equal(package.kinds["xl/worksheets/sheet1.xml"], 'worksheet')
    assert_equal(package.kinds["xl/macrosheets/sheet1.xml"], 'worksheet')
    assert_equal(package.kinds["xl/sharedStrings.xml"], 'shared_strings')
    assert_equal(package.kinds["xl/drawings/drawing1.xml"], 'drawing')
    assert_equal(package.parts["xl/externalLinks/externalLink1.xml"], nil)
    assert_equal(package.parts["xl/vbaProject.bin"], nil)
    assert_equal(package.parts["xl/media/image1.png"], nil)
    assert_not_nil(package.relationships["xl/externalLinks/externalLink1.xml"])
    assert_equal(package.truncated, nil)

    -- the drawing follows its worksheet, not the other level one stories
    assert_equal(package.story_parts[1], "xl/worksheets/sheet1.xml")
    assert_equal(package.story_parts[2], "xl/drawings/drawing1.xml")
    assert_equal(package.story_parts[3], "xl/macrosheets/sheet1.xml")
    assert_equal(package.story_parts[4], "xl/sharedStrings.xml")
  end)

  test("extracts cell text, formulas, hyperlinks and workbook facts", function()
    local package, err = ooxml.open(make_package())
    assert_not_nil(package, err)
    local extracted
    extracted, err = xlsx.extract(package)
    assert_not_nil(extracted, err)

    local text = tostring(extracted.text)
    assert_not_nil(text:find("Invoice total\n", 1, true))
    assert_not_nil(text:find("Pay at https://shared.example.com/pay\n", 1, true))
    assert_equal(text:find("phonetic", 1, true), nil)
    assert_not_nil(text:find("Inline cell\tComputed\n", 1, true))
    assert_not_nil(text:find("Click\n", 1, true))
    assert_not_nil(text:find("Open document\n", 1, true))
    assert_not_nil(text:find("macro cell\n", 1, true))
    assert_equal(text:find("42", 1, true), nil)
    assert_equal(text:find("HYPERLINK", 1, true), nil)

    local urls = url_set(extracted.urls)
    assert_equal(urls["https://formula.example.com/login"], true)
    assert_equal(urls["http://webservice.example.com/x"], true)
    assert_equal(urls["https://sheet.example.com/"], true)
    assert_equal(urls["https://drawing.example.com/open"], true)
    assert_equal(urls["Not a URL"], nil)
    assert_equal(urls["Click"], nil)
    assert_equal(urls["x"], nil)
    assert_equal(#extracted.urls, 4)

    assert_equal(extracted.sheets, 3)
    assert_equal(extracted.hidden_sheets, 1)
    assert_equal(extracted.very_hidden_sheets, 1)
    assert_equal(#extracted.auto_exec_names, 1)
    assert_equal(extracted.auto_exec_names[1], "_xlnm.Auto_Open")
  end)

  test("summarises macros and external relationships", function()
    local package, err = ooxml.open(make_package())
    assert_not_nil(package, err)
    local summary = ooxml.summarize_relationships(package)
    local macros = {}
    for _, kind in ipairs(summary.macros) do macros[kind] = true end
    assert_equal(macros.vba, true)
    assert_equal(macros.xlm, true)
    assert_equal(#summary.macros, 2)
    assert_equal(summary.ole_objects, 0)
    assert_equal(summary.remote_template, nil)
    assert_equal(#summary.external_targets, 1)
    assert_equal(summary.external_targets[1].type, "externalLinkPath")
    assert_equal(summary.external_targets[1].target, "https://external.example.com/data.xlsx")
    assert_equal(summary.external_targets[1].part, "xl/externalLinks/externalLink1.xml")
  end)

  test("truncates story selection instead of failing on the part budget", function()
    local package, err = ooxml.open(make_package(), { max_parts = 8 })
    assert_not_nil(package, err)
    assert_equal(package.truncated, true)
    assert_not_nil(package.parts["xl/worksheets/sheet1.xml"])
    assert_equal(package.parts["xl/sharedStrings.xml"], nil)
    local extracted
    extracted, err = xlsx.extract(package)
    assert_not_nil(extracted, err)
    assert_not_nil(tostring(extracted.text):find("Inline cell", 1, true))
  end)

  test("refuses packages of another format", function()
    local docx = require "lua_content/docx"
    local package, err = ooxml.open(make_package())
    assert_not_nil(package, err)
    local extracted
    extracted, err = docx.extract(package)
    assert_equal(extracted, nil)
    assert_not_nil(err:find("not a DOCX", 1, true))
  end)

  test("rejects unsupported office document types when opening", function()
    local package, err = ooxml.open(archive.zip({
      { name = "[Content_Types].xml", content = [[
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Override PartName="/visio/document.xml"
            ContentType="application/vnd.ms-visio.drawing.main+xml"/>
        </Types>
      ]] },
      { name = "_rels/.rels", content = rels({
        { "rId1", document_rel .. "officeDocument", "visio/document.xml" },
      }) },
      { name = "visio/document.xml", content = "<VisioDocument/>" },
    }))
    assert_equal(package, nil)
    assert_not_nil(err:find("unsupported OOXML document type", 1, true))
  end)

  test("dispatches a macro enabled workbook through lua_content", function()
    local lua_content = require "lua_content"
    local rspamd_mempool = require "rspamd_mempool"
    local package_data = make_package()

    local part = {
      get_type = function() return 'application', 'vnd.ms-excel.sheet.macroenabled.12' end,
      get_detected_ext = function() return 'xlsx' end,
      is_archive = function() return true end,
      is_specific = function() return false end,
      get_specific = function() return nil end,
      get_content = function() return package_data end,
      get_id = function() return 51 end,
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
    assert_equal(specific.tag, 'xlsx')
    assert_equal(specific.suspicious, nil)
    assert_equal(specific.declared_format, nil)
    assert_not_nil(injected_text:find("Invoice total", 1, true))
    assert_equal(injected_urls["https://formula.example.com/login"], true)
    assert_equal(injected_urls["https://drawing.example.com/open"], true)
    assert_equal(specific.sheets, 3)
    assert_equal(specific.very_hidden_sheets, 1)
    assert_equal(specific.auto_exec_names[1], "_xlnm.Auto_Open")
    assert_equal(#specific.relationships.macros, 2)
    assert_equal(specific.relationships.external_targets[1].type, "externalLinkPath")
  end)

  test("processes a workbook declared as a Word document by its real format", function()
    local lua_content = require "lua_content"
    local rspamd_mempool = require "rspamd_mempool"
    local package_data = make_package()

    local part = {
      get_type = function() return 'application',
          'vnd.openxmlformats-officedocument.wordprocessingml.document' end,
      get_detected_ext = function() return 'xlsx' end,
      is_archive = function() return true end,
      is_specific = function() return false end,
      get_specific = function() return nil end,
      get_content = function() return package_data end,
      get_id = function() return 52 end,
    }
    local cache = {}
    local task = {
      pool = rspamd_mempool.create(),
      cache_set = function(_, key, value) cache[key] = value end,
      cache_get = function(_, key) return cache[key] end,
      get_mempool = function(self) return self.pool end,
      inject_part = function() end,
      inject_url = function() end,
    }

    lua_content.maybe_process_mime_part(part, task)
    local specific = lua_content.get_specific(part, task)
    assert_not_nil(specific)
    assert_equal(specific.tag, 'xlsx')
    assert_equal(specific.declared_format, 'docx')
  end)
end)
