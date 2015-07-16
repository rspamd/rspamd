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
    Hello, world! <b>test</b>
    <p>data<>
    </P>
    <b>stuff</p>?
  </body>
</html>
      ]], 'Hello, world! test data stuff?'},
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
 </html>]], 'Hello, world!'},
    }
    
    for _,c in ipairs(cases) do
      local t = rspamd_util.parse_html(c[1])
      
      assert_not_nil(t)
      assert_equal(c[2], tostring(t))
    end
  end)
end)