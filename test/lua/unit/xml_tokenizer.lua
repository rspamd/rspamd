context("OOXML XML tokenizer", function()
  local xml = require "lua_content/xml_tokenizer"

  local function collect(input, opts)
    local events = {}
    local ok, err = xml.parse(input, {
      start_element = function(namespace, name, attrs)
        events[#events + 1] = { "start", namespace, name, attrs }
      end,
      end_element = function(namespace, name)
        events[#events + 1] = { "end", namespace, name }
      end,
      text = function(value)
        events[#events + 1] = { "text", value }
      end,
    }, opts)

    return ok, err, events
  end

  test("resolves arbitrary namespace prefixes and XML entities", function()
    local ok, err, events = collect([[
      <x:document xmlns:x="urn:word" xmlns:r="urn:rels">
        <x:p><x:t r:id="rId1" plain="yes">One &amp; two</x:t></x:p>
      </x:document>
    ]])

    assert_true(ok, err)
    assert_equal(events[1][1], "text")
    assert_equal(events[2][1], "start")
    assert_equal(events[2][2], "urn:word")
    assert_equal(events[2][3], "document")

    local text_event
    local text_start
    for _, event in ipairs(events) do
      if event[1] == "start" and event[3] == "t" then
        text_start = event
      elseif event[1] == "text" and event[2]:find("One", 1, true) then
        text_event = event
      end
    end

    assert_not_nil(text_start)
    assert_equal(text_start[4][1].namespace, "urn:rels")
    assert_equal(text_start[4][1].name, "id")
    assert_equal(text_start[4][1].value, "rId1")
    assert_equal(text_start[4][2].namespace, nil)
    assert_equal(text_start[4][2].name, "plain")
    assert_equal(text_event[2], "One & two")
  end)

  test("restores namespace bindings after nested elements", function()
    local ok, err, events = collect([[
      <a:root xmlns:a="urn:outer">
        <a:item xmlns:a="urn:inner"/>
        <a:item/>
      </a:root>
    ]])

    assert_true(ok, err)
    local namespaces = {}
    for _, event in ipairs(events) do
      if event[1] == "start" and event[3] == "item" then
        namespaces[#namespaces + 1] = event[2]
      end
    end
    assert_equal(namespaces[1], "urn:inner")
    assert_equal(namespaces[2], "urn:outer")
  end)

  test("handles CDATA and numeric entities", function()
    local ok, err, events = collect([=[<root><![CDATA[a < b]]>&#32;&#x41;</root>]=])

    assert_true(ok, err)
    local texts = {}
    for _, event in ipairs(events) do
      if event[1] == "text" then
        texts[#texts + 1] = event[2]
      end
    end
    assert_equal(table.concat(texts), "a < b A")
  end)

  test("converts BOM marked UTF-16LE", function()
    local ascii = [[<root>hello</root>]]
    local encoded = { "\255\254" }
    for i = 1, #ascii do
      encoded[#encoded + 1] = ascii:sub(i, i)
      encoded[#encoded + 1] = "\0"
    end

    local ok, err, events = collect(table.concat(encoded))
    assert_true(ok, err)
    assert_equal(events[2][1], "text")
    assert_equal(events[2][2], "hello")
  end)

  test("rejects DTD declarations", function()
    local ok, err = collect([[<!DOCTYPE root [<!ENTITY x "expanded">]><root>&x;</root>]])
    assert_equal(ok, false)
    assert_not_nil(err:find("DTD", 1, true))
  end)

  test("rejects mismatched end elements", function()
    local ok, err = collect([[<root><a></root>]])
    assert_equal(ok, false)
    assert_not_nil(err:find("mismatched", 1, true))
  end)

  test("rejects invalid literal controls and attribute markup", function()
    local ok_control = xml.parse("<root>bad\1text</root>", {})
    assert_equal(ok_control, false)

    local ok_attribute = xml.parse([[<root value="bad<value"/>]], {})
    assert_equal(ok_attribute, false)
  end)

  test("enforces depth, attribute, token, and text limits", function()
    local ok_depth = xml.parse([[<a><b><c/></b></a>]], {}, { max_depth = 2 })
    assert_equal(ok_depth, false)

    local ok_attrs = xml.parse([[<a x="1" y="2"/>]], {}, { max_attributes = 1 })
    assert_equal(ok_attrs, false)

    local ok_tokens = xml.parse([[<a><b/><c/></a>]], {}, { max_tokens = 3 })
    assert_equal(ok_tokens, false)

    local ok_text = xml.parse([[<a>12345</a>]], {}, { max_text = 4 })
    assert_equal(ok_text, false)
  end)
end)
