context("DOCX content extraction", function()
  local archive = require "archive"
  local docx = require "lua_content/docx"

  local document = [[
    <x:document xmlns:x="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
      xmlns:rel="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
      xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
      <x:body>
        <x:p><x:t>Invoice </x:t><x:hyperlink rel:id="link"><x:t>sign in</x:t></x:hyperlink>
          <x:del><x:t>deleted.example.test</x:t></x:del></x:p>
        <x:p><x:fldSimple x:instr=' HYPERLINK "https://field.example.com/pay" '>
          <x:r><x:t>Pay now</x:t></x:r></x:fldSimple></x:p>
        <x:p><x:r><x:fldChar x:fldCharType="begin"/></x:r>
          <x:r><x:instrText> HYPERLINK "https://complex.example.com/" </x:instrText></x:r>
          <x:r><x:fldChar x:fldCharType="separate"/></x:r><x:r><x:t>Portal</x:t></x:r>
          <x:r><x:fldChar x:fldCharType="end"/></x:r></x:p>
        <x:p><a:t>Drawing text</a:t><x:tab/><x:t>after tab</x:t></x:p>
      </x:body>
    </x:document>
  ]]

  local header = [[
    <w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <w:p><w:t>Confidential header</w:t>
        <w:hyperlink r:id="header-link"><w:t>Header link</w:t></w:hyperlink></w:p>
    </w:hdr>
  ]]

  local function relationship(id, relation_type, target)
    return {
      id = id,
      type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/" .. relation_type,
      target = target,
      external = true,
    }
  end

  local package = {
    main_part = "word/document.xml",
    main_content_type =
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    story_parts = { "word/header1.xml" },
    parts = {
      ["word/document.xml"] = document,
      ["word/header1.xml"] = header,
    },
    relationships = {
      ["word/document.xml"] = {
        list = {
          relationship("link", "hyperlink", "https://relationship.example.com/login"),
        },
        by_id = {
          link = relationship("link", "hyperlink", "https://relationship.example.com/login"),
        },
      },
      ["word/header1.xml"] = {
        list = {
          relationship("header-link", "hyperlink", "https://header.example.com/"),
        },
        by_id = {
          ["header-link"] = relationship("header-link", "hyperlink", "https://header.example.com/"),
        },
      },
    },
  }

  test("extracts visible story text and explicit hyperlinks", function()
    local extracted, err = docx.extract(package)
    assert_not_nil(extracted, err)
    assert_equal(type(extracted.text), "userdata")
    assert_not_nil(extracted.text:find("Invoice sign in", 1, true))
    assert_not_nil(extracted.text:find("Pay now", 1, true))
    assert_not_nil(extracted.text:find("Portal", 1, true))
    assert_not_nil(extracted.text:find("Drawing text\tafter tab", 1, true))
    assert_not_nil(extracted.text:find("Confidential header", 1, true))
    assert_equal(extracted.text:find("deleted.example.test", 1, true), nil)
    assert_equal(extracted.text:find("HYPERLINK", 1, true), nil)

    local urls = {}
    for _, url in ipairs(extracted.urls) do urls[url] = true end
    assert_equal(urls["https://relationship.example.com/login"], true)
    assert_equal(urls["https://field.example.com/pay"], true)
    assert_equal(urls["https://complex.example.com/"], true)
    assert_equal(urls["https://header.example.com/"], true)
  end)

  test("decodes entities directly into the native text buffer", function()
    local entity_package = {
      main_part = "word/document.xml",
      main_content_type = package.main_content_type,
      story_parts = {},
      parts = {
        ["word/document.xml"] = [[
          <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:body><w:p><w:t>One &amp; two &#x41;</w:t></w:p></w:body>
          </w:document>
        ]],
      },
      relationships = {},
    }

    local extracted, err = docx.extract(entity_package)
    assert_not_nil(extracted, err)
    assert_not_nil(tostring(extracted.text):find("One & two A", 1, true))
  end)

  test("native story parsing preserves XML safety limits", function()
    local extracted, err = docx.extract(package, { xml = { max_depth = 2 } })
    assert_equal(extracted, nil)
    assert_not_nil(err:find("depth limit", 1, true))

    local unsafe = {
      main_part = "word/document.xml",
      main_content_type = package.main_content_type,
      story_parts = {},
      parts = {
        ["word/document.xml"] = [[
          <!DOCTYPE document [<!ENTITY x "expanded">]>
          <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:p><w:t>&x;</w:t></w:p>
          </w:document>
        ]],
      },
      relationships = {},
    }
    extracted, err = docx.extract(unsafe)
    assert_equal(extracted, nil)
    assert_not_nil(err:find("DTD", 1, true))
  end)

  test("parses hyperlink field instructions conservatively", function()
    assert_equal(docx.hyperlink_from_instruction(' HYPERLINK "https://example.test/a" '),
        "https://example.test/a")
    assert_equal(docx.hyperlink_from_instruction(' HYPERLINK https://example.test/b '),
        "https://example.test/b")
    assert_equal(docx.hyperlink_from_instruction(' HYPERLINK \\l "bookmark" '), nil)
    assert_equal(docx.hyperlink_from_instruction(' NOTAHYPERLINK "https://example.test" '), nil)
  end)

  test("enforces the cumulative visible text limit", function()
    local extracted, err = docx.extract(package, { max_text = 8 })
    assert_equal(extracted, nil)
    assert_not_nil(err:find("text limit", 1, true))
  end)

  test("shares text and XML budgets across documents", function()
    local state = {}
    local extracted, err = docx.extract(package, {}, state)
    assert_not_nil(extracted, err)

    extracted, err = docx.extract(package, { max_text = state.text }, state)
    assert_equal(extracted, nil)
    assert_not_nil(err:find("text limit", 1, true))
    assert_not_nil(state.xml_tokens)
  end)

  test("rejects non-DOCX office document content types", function()
    local other = {}
    for key, value in pairs(package) do other[key] = value end
    other.main_content_type =
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    local extracted, err = docx.extract(other)
    assert_equal(extracted, nil)
    assert_not_nil(err:find("not a DOCX", 1, true))
  end)

  test("dispatches an archive DOCX without replacing archive metadata", function()
    local lua_content = require "lua_content"
    local rspamd_mempool = require "rspamd_mempool"
    local saved_max_documents = docx.config.max_documents
    docx.config.max_documents = 1
    local package_data = archive.zip({
      {
        name = "[Content_Types].xml",
        content = [[
          <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
            <Default Extension="rels"
              ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
            <Override PartName="/word/document.xml"
              ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
          </Types>
        ]],
      },
      {
        name = "_rels/.rels",
        content = [[
          <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
            <Relationship Id="main"
              Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
              Target="word/document.xml"/>
          </Relationships>
        ]],
      },
      { name = "word/document.xml", content = document },
      {
        name = "word/_rels/document.xml.rels",
        content = [[
          <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
            <Relationship Id="link"
              Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
              Target="https://relationship.example.com/login" TargetMode="External"/>
          </Relationships>
        ]],
      },
    })

    local specific_replaced = false
    local part = {
      get_type = function() return 'application',
          'vnd.openxmlformats-officedocument.wordprocessingml.document' end,
      get_detected_ext = function() return 'docx' end,
      is_archive = function() return true end,
      is_specific = function() return false end,
      get_specific = function() return nil end,
      get_content = function() return package_data end,
      get_id = function() return 42 end,
      set_specific = function() specific_replaced = true end,
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
    assert_equal(specific_replaced, false)
    assert_not_nil(specific)
    assert_equal(specific.tag, 'docx')
    assert_not_nil(injected_text:find("Invoice sign in", 1, true))
    assert_equal(injected_urls["https://relationship.example.com/login"], true)
    assert_equal(injected_urls["https://field.example.com/pay"], true)
    assert_equal(injected_urls["https://complex.example.com/"], true)

    local second_part = {}
    for name, value in pairs(part) do second_part[name] = value end
    second_part.get_id = function() return 43 end
    lua_content.maybe_process_mime_part(second_part, task)
    local second_specific = lua_content.get_specific(second_part, task)
    assert_not_nil(second_specific)
    assert_equal(second_specific.tag, 'docx')
    assert_equal(second_specific.suspicious, true)
    assert_equal(second_specific.reason, 'document_limit')
    docx.config.max_documents = saved_max_documents
  end)

  test("marks a malformed DOCX package as suspicious", function()
    local lua_content = require "lua_content"
    local package_data = archive.zip({
      {
        name = "[Content_Types].xml",
        content = [[
          <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
            &unsupported;
          </Types>
        ]],
      },
      {
        name = "_rels/.rels",
        content = [[
          <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
        ]],
      },
    })
    local part = {
      get_type = function() return 'application',
          'vnd.openxmlformats-officedocument.wordprocessingml.document' end,
      get_detected_ext = function() return 'docx' end,
      is_archive = function() return true end,
      is_specific = function() return false end,
      get_specific = function() return nil end,
      get_content = function() return package_data end,
      get_id = function() return 44 end,
    }
    local cache = {}
    local task = {
      cache_set = function(_, key, value) cache[key] = value end,
      cache_get = function(_, key) return cache[key] end,
    }

    lua_content.maybe_process_mime_part(part, task)
    local specific = lua_content.get_specific(part, task)
    assert_not_nil(specific)
    assert_equal(specific.tag, 'docx')
    assert_equal(specific.suspicious, true)
    assert_equal(specific.reason, 'package')
  end)
end)
