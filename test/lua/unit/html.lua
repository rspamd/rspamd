context("HTML processing", function()
  local rspamd_util = require("rspamd_util")
  local logger = require("rspamd_logger")
  
  test("Extract text from HTML", function()
    local cases = {
      {[[
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>
    <!-- page content -->
    Hello, world!
  </body>
</html>
      ]], 'Hello, world!'},
    }
    
    for _,c in ipairs(cases) do
      local t = rspamd_util.parse_html(c[1])
      
      assert_not_nil(t)
      assert_equal(c[2], tostring(t))
    end
  end)
end)