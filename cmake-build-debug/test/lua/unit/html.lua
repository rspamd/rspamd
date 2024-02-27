context("HTML processing", function()
  local rspamd_util = require("rspamd_util")
  local logger = require("rspamd_logger")
  local cases = {
      -- Entities
      {[[<html><body>.&#102;&#105;&#114;&#101;&#98;&#97;&#115;&#101;&#97;&#112;&#112;.&#99;&#111;&#109;</body></html>]],
       [[.firebaseapp.com]]},
      {[[
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
 </html>]], 'Hello, world!\n'},
       {[[
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
      ]], 'Hello, world!'},
      {[[
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
      ]], 'Hello, world!\ntest\ncontentmore content\ncontent inside div\n'},
      {[[
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
      ]], 'content\nheada headb\ndata1 data2\n'},
      {[[
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
      ]], 'a b a > b a < b a & b \'a "a"'},
  }

  for i,c in ipairs(cases) do
    test("Extract text from HTML " .. tostring(i), function()
      local t = rspamd_util.parse_html(c[1])

      assert_not_nil(t)
      assert_equal(c[2], tostring(t), string.format("'%s' doesn't match with '%s'",
          c[2], t))

    end)
  end
end)
