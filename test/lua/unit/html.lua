context("HTML processing", function()
  local rspamd_util = require("rspamd_util")
  local cases = {
    -- Entities
    { [[<html><body>.&#102;&#105;&#114;&#101;&#98;&#97;&#115;&#101;&#97;&#112;&#112;.&#99;&#111;&#109;</body></html>]],
      [[.firebaseapp.com]] },
    { [[
<?xml version="1.0" encoding="iso-8859-1"?>
 <!DOCTYPE html
   PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
   "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
 <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
   <head>
     <title>
       Wikibooks
     </title>
   </head>
   <body>
     <p>
       Hello,          world!

     </p>
   </body>
 </html>]], 'Hello, world!\n' },
    { [[
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
    <style><!--
- -a -a -a -- --- -
  --></head>
  <body>
    <!-- page content -->
    Hello, world!
  </body>
</html>
      ]], 'Hello, world!' },
    { [[
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>
    <!-- page content -->
    Hello, world!<br>test</br><br>content</hr>more content<br>
    <div>
      content inside div
    </div>
  </body>
</html>
      ]], 'Hello, world!\ntest\ncontentmore content\ncontent inside div\n' },
    { [[
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>
    <!-- tabular content -->
    <table>
      content
    </table>
    <table>
      <tr>
        <th>heada</th>
        <th>headb</th>
      </tr>
      <tr>
        <td>data1</td>
        <td>data2</td>
      </tr>
    </table>

  </body>
</html>
      ]], 'content\nheada headb\ndata1 data2\n' },
    { [[
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>
    <!-- escape content -->
    a&nbsp;b a &gt; b a &lt; b a &amp; b &apos;a &quot;a&quot;
  </body>
</html>
      ]], 'a b a > b a < b a & b \'a "a"' },
  }

  for i, c in ipairs(cases) do
    test("Extract text from HTML " .. tostring(i), function()
      local t = rspamd_util.parse_html(c[1])

      assert_not_nil(t)
      assert_equal(c[2], tostring(t), string.format("'%s' doesn't match with '%s'",
        c[2], t))
    end)
  end

  -- Test cases for new HTML tag API methods
  local function parse_html_and_extract_tags(html_content, pool)
    local rspamd_parsers = require("rspamd_parsers")

    local parsed = rspamd_parsers.parse_html_content(html_content, pool)
    local tags = {}

    if parsed then
      parsed:foreach_tag("any", function(tag, content_length, is_leaf)
        table.insert(tags, tag)
        return false
      end)
    end

    return parsed, tags
  end

  test("HTML tag get_all_attributes basic test", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[<div class="test-class" id="test-id" style="color: red;" width="100">content</div>]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)
    assert_true(#tags > 0)

    -- Find the div tag
    local div_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "div" then
        div_tag = tag
        break
      end
    end

    assert_not_nil(div_tag)

    local attrs = div_tag:get_all_attributes()
    assert_not_nil(attrs)

    -- Check that we have the expected attributes
    assert_equal("test-class", attrs["class"])
    assert_equal("test-id", attrs["id"])
    assert_equal("color: red;", attrs["style"])
    assert_equal("100", attrs["width"])

    pool:destroy()
  end)

  test("HTML tag has_attribute test", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[<img src="test.jpg" width="100" height="50" alt="Test image" hidden />]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    local img_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "img" then
        img_tag = tag
        break
      end
    end

    assert_not_nil(img_tag)

    -- Test existing attributes
    assert_true(img_tag:has_attribute("src"))
    assert_true(img_tag:has_attribute("width"))
    assert_true(img_tag:has_attribute("height"))
    assert_true(img_tag:has_attribute("alt"))
    assert_true(img_tag:has_attribute("hidden"))

    -- Test non-existing attributes
    assert_false(img_tag:has_attribute("nonexistent"))
    assert_false(img_tag:has_attribute("class"))
    assert_false(img_tag:has_attribute(""))

    pool:destroy()
  end)

  test("HTML tag get_numeric_attribute test", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[<div width="200" height="150" font-size="14" opacity="0.8" tabindex="5">content</div>]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    local div_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "div" then
        div_tag = tag
        break
      end
    end

    assert_not_nil(div_tag)

    -- Test numeric attributes
    assert_equal(200, div_tag:get_numeric_attribute("width"))
    assert_equal(150, div_tag:get_numeric_attribute("height"))
    assert_equal(14, div_tag:get_numeric_attribute("font-size"))

    -- Test opacity with floating-point tolerance
    local opacity = div_tag:get_numeric_attribute("opacity")
    assert_not_nil(opacity)
    assert_true(math.abs(opacity - 0.8) < 0.01, string.format("Expected opacity ~0.8, got %f", opacity))

    assert_equal(5, div_tag:get_numeric_attribute("tabindex"))

    -- Test non-numeric attributes
    assert_nil(div_tag:get_numeric_attribute("nonexistent"))

    pool:destroy()
  end)

  test("HTML tag get_unknown_attributes test", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[<div class="known" data-track="analytics" unknown-attr="test-value" custom-id="12345">content</div>]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    local div_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "div" then
        div_tag = tag
        break
      end
    end

    assert_not_nil(div_tag)

    local unknown_attrs = div_tag:get_unknown_attributes()
    assert_not_nil(unknown_attrs)

    -- Should include unknown attributes but not known ones like "class"
    assert_not_nil(unknown_attrs["unknown-attr"])
    assert_equal("test-value", unknown_attrs["unknown-attr"])
    assert_not_nil(unknown_attrs["custom-id"])
    assert_equal("12345", unknown_attrs["custom-id"])

    -- data-track should be recognized as a known attribute now
    -- but if not, it would appear in unknown attributes

    pool:destroy()
  end)

  test("HTML tag get_children test", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[
      <div id="parent">
        <p>First child</p>
        <span>Second child</span>
        <img src="test.jpg" />
      </div>
    ]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    local parent_div = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "div" and tag:has_attribute("id") and tag:get_attribute("id") == "parent" then
        parent_div = tag
        break
      end
    end

    assert_not_nil(parent_div)

    local children = parent_div:get_children()
    assert_not_nil(children)
    assert_equal(3, #children)

    -- Check child types
    local child_types = {}
    for _, child in ipairs(children) do
      table.insert(child_types, child:get_type())
    end

    -- Should contain p, span, and img
    local child_types_str = table.concat(child_types, ",")
    assert_true(child_types_str:find("p") ~= nil)
    assert_true(child_types_str:find("span") ~= nil)
    assert_true(child_types_str:find("img") ~= nil)

    pool:destroy()
  end)

  test("HTML tag get_attribute vs get_all_attributes consistency", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[<a href="https://example.com" class="link" target="_blank" title="Example Link">Link</a>]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    local a_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "a" then
        a_tag = tag
        break
      end
    end

    assert_not_nil(a_tag)

    local all_attrs = a_tag:get_all_attributes()

    -- Test that individual get_attribute calls match get_all_attributes
    for attr_name, attr_value in pairs(all_attrs) do
      assert_equal(attr_value, a_tag:get_attribute(attr_name),
        string.format("Attribute '%s' mismatch: get_attribute='%s', get_all_attributes='%s'",
          attr_name, a_tag:get_attribute(attr_name) or "nil", attr_value))
    end

    -- Test specific expected attributes
    assert_equal("https://example.com", a_tag:get_attribute("href"))
    assert_equal("link", a_tag:get_attribute("class"))
    assert_equal("_blank", a_tag:get_attribute("target"))
    assert_equal("Example Link", a_tag:get_attribute("title"))

    pool:destroy()
  end)



  test("HTML tag attribute edge cases", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[<div class="" hidden style=" " width="0" height="abc">content</div>]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    local div_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "div" then
        div_tag = tag
        break
      end
    end

    assert_not_nil(div_tag)

    -- Test empty attribute value
    assert_true(div_tag:has_attribute("class"))
    assert_equal("", div_tag:get_attribute("class"))

    -- Test boolean attribute (hidden)
    assert_true(div_tag:has_attribute("hidden"))

    -- Test whitespace-only attribute
    assert_true(div_tag:has_attribute("style"))
    assert_equal(" ", div_tag:get_attribute("style"))

    -- Test numeric attributes with edge cases
    assert_equal(0, div_tag:get_numeric_attribute("width"))
    assert_nil(div_tag:get_numeric_attribute("height")) -- "abc" is not numeric

    -- Test non-existent attribute
    assert_false(div_tag:has_attribute("nonexistent"))
    assert_nil(div_tag:get_attribute("nonexistent"))
    assert_nil(div_tag:get_numeric_attribute("nonexistent"))

    pool:destroy()
  end)

  test("HTML tag complex nested structure", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html = [[
      <table cellpadding="5" cellspacing="2" border="1">
        <tr>
          <td align="center" valign="top" width="100">
            <img src="image1.jpg" width="80" height="60" alt="Image 1" />
          </td>
          <td align="left" valign="middle">
            <p font-size="12">Text content</p>
          </td>
        </tr>
      </table>
    ]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    -- Find table tag
    local table_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "table" then
        table_tag = tag
        break
      end
    end

    assert_not_nil(table_tag)

    -- Test table attributes
    assert_equal(5, table_tag:get_numeric_attribute("cellpadding"))
    assert_equal(2, table_tag:get_numeric_attribute("cellspacing"))
    assert_equal("1", table_tag:get_attribute("border"))

    -- Test that table has children
    local children = table_tag:get_children()
    assert_not_nil(children)
    assert_true(#children > 0)

    -- Find img tag
    local img_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "img" then
        img_tag = tag
        break
      end
    end

    assert_not_nil(img_tag)

    -- Test img attributes
    assert_equal("image1.jpg", img_tag:get_attribute("src"))
    assert_equal(80, img_tag:get_numeric_attribute("width"))
    assert_equal(60, img_tag:get_numeric_attribute("height"))
    assert_equal("Image 1", img_tag:get_attribute("alt"))

    pool:destroy()
  end)

  test("HTML tag with mixed known and unknown attributes", function()
    local rspamd_mempool = require("rspamd_mempool")
    local pool = rspamd_mempool.create()

    local html =
    [[<div class="container" data-analytics="track" custom-attr="value" style="color: blue;" unknown123="test">content</div>]]
    local parsed, tags = parse_html_and_extract_tags(html, pool)

    assert_not_nil(parsed)

    local div_tag = nil
    for _, tag in ipairs(tags) do
      if tag:get_type() == "div" then
        div_tag = tag
        break
      end
    end

    assert_not_nil(div_tag)

    local all_attrs = div_tag:get_all_attributes()
    local unknown_attrs = div_tag:get_unknown_attributes()

    -- All attributes should include both known and unknown
    assert_not_nil(all_attrs["class"])       -- known
    assert_not_nil(all_attrs["style"])       -- known
    assert_not_nil(all_attrs["custom-attr"]) -- unknown
    assert_not_nil(all_attrs["unknown123"])  -- unknown

    -- Unknown attributes should only include unrecognized ones
    assert_nil(unknown_attrs["class"])           -- known, shouldn't be here
    assert_nil(unknown_attrs["style"])           -- known, shouldn't be here
    assert_not_nil(unknown_attrs["custom-attr"]) -- unknown, should be here
    assert_not_nil(unknown_attrs["unknown123"])  -- unknown, should be here

    assert_equal("value", unknown_attrs["custom-attr"])
    assert_equal("test", unknown_attrs["unknown123"])

    pool:destroy()
  end)
end)
