context("CSS syntax", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_parsers = require "rspamd_parsers"

  -- Visible text of an HTML part with the given stylesheet and body
  local function visible(style, body)
    local html = '<html><head><style>' .. style .. '</style></head><body>' ..
        body .. '<p>vis</p></body></html>'
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: text/html; charset=utf-8\r\n\r\n" .. html .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    local text = tostring(task:get_text_parts()[1]:get_content())
    task:destroy()
    return text
  end

  -- Visible text of an element with the inline style
  local function inline(style)
    local html = '<html><body><div style="' .. style .. '">HID</div><p>vis</p></body></html>'
    return tostring(rspamd_parsers.parse_html(html))
  end

  local default_body = '<div class="h">HID</div>'

  local function hides(style, body)
    local text = visible(style, body or default_body)
    return text:find("HID", 1, true) == nil and text:find("vis", 1, true) ~= nil
  end

  local function shows(style, body)
    local text = visible(style, body or default_body)
    return text:find("HID", 1, true) ~= nil and text:find("vis", 1, true) ~= nil
  end

  local function inline_hides(style)
    local text = inline(style)
    return text:find("HID", 1, true) == nil and text:find("vis", 1, true) ~= nil
  end

  local function inline_shows(style)
    local text = inline(style)
    return text:find("HID", 1, true) ~= nil and text:find("vis", 1, true) ~= nil
  end

  local deep_open = string.rep("[", 30)
  local deep_close = string.rep("]", 30)

  test("sanity: a plain rule hides and the control text stays", function()
    assert_true(hides('.h{display:none}'))
    assert_true(shows('.h{display:block}'))
    assert_true(shows(''))
  end)

  test("comments do not nest", function()
    assert_true(hides('/* a /* b */ .h{display:none} /* c */'))
    assert_true(hides('/* a /* b /* c */ .h{display:none}'))
    assert_true(hides('.h{display:none} /* unterminated'))
    -- the opposite: the rule stays inside of the comment
    assert_true(shows('/* .h{display:none} */'))
    assert_true(shows('/* a /* b .h{display:none} */'))
    assert_true(shows('/* .h{display:none}'))
    assert_true(shows('/* a */ /* .h{display:none} */ .h{display:block}'))
  end)

  test("strings end at the unescaped quote", function()
    assert_true(hides('.x{content:"a\\"b"} .h{display:none}'))
    assert_true(hides(".x{content:'a\\'b'} .h{display:none}"))
    -- an escaped backslash does not escape the closing quote
    assert_true(hides('.x{content:"a\\\\"} .h{display:none}'))
    assert_true(hides('.x{content:"\\\\"} .h{display:none}'))
    -- the opposite: the second quote opens a string that eats the rule
    assert_true(shows('.x{content:"a\\\\"b"} .h{display:none}'))
    assert_true(shows('.x{content:"a\\"} .h{display:none}'))
    assert_true(shows('.x{content:"a;} .h{display:none}'))
    -- quotes in comments and strings do not disturb the escapes after them
    assert_true(hides("/* it's */ .\\68 {display:none}"))
    assert_true(hides('/* "a */ .\\68 {display:none}'))
    assert_true(hides('.x{content:"\\\\"} .\\68 {display:none}'))
    assert_true(hides("/* it's */ DIV{display:none} .\\7a {}", '<div>HID</div>'))
    assert_true(shows("/* it's */ DIV{display:block} .\\7a {}", '<div>HID</div>'))
  end)

  test("a raw newline ends a string and invalidates its declaration", function()
    assert_true(hides('.h{color:"red\n;display:none}'))
    assert_true(hides('.h{color:"red\r\n;display:none}'))
    assert_true(hides('.h{display:none;color:"red\n}'))
    assert_true(hides('.h{color:"red\n;display:none} .k{}'))
    -- the opposite: no newline, the string runs on and swallows the declaration
    assert_true(shows('.h{color:"red;display:none"}'))
    assert_true(shows('.h{color:"red;display:none"} .k{}'))
    -- an escaped newline continues the string
    assert_true(shows('.h{color:"red\\\n;display:none"}'))
    assert_true(hides('.h{color:"red\\\n"; display:none}'))
  end)

  test("one bad rule does not drop the rest of the sheet", function()
    assert_true(hides('a' .. deep_open .. 'x' .. deep_close .. '{} .h{display:none}'))
    assert_true(hides('.k{} a' .. deep_open .. 'x' .. deep_close .. '{} .h{display:none}'))
    assert_true(hides('a{x:' .. deep_open .. deep_close .. '} .h{display:none}'))
    assert_true(hides('a{x:' .. deep_open .. deep_close .. ';display:block} .h{display:none}'))
    -- the body of the dropped rule is not read as rules
    assert_true(shows('a' .. deep_open .. 'x' .. deep_close .. '{ .h{display:none} }'))
    assert_true(shows('a' .. deep_open .. 'x' .. deep_close .. '{ .h{display:none} } .k{}'))
    -- the dropped rule itself does not apply
    assert_true(shows('.h' .. deep_open .. 'x' .. deep_close .. '{display:none}'))
    -- an unclosed block swallows everything after it, also in a browser
    assert_true(shows('a' .. deep_open .. 'x{} .h{display:none}'))
    assert_true(hides('@media all{ a' .. deep_open .. 'x' .. deep_close .. '{} .h{display:none} }'))
    assert_true(hides('@foo a' .. deep_open .. deep_close .. '; .h{display:none}'))
  end)

  test("empty declarations are skipped", function()
    assert_true(inline_hides(';display:none'))
    assert_true(inline_hides(';;display:none'))
    assert_true(inline_hides('color:red;;display:none'))
    assert_true(inline_hides('color:red; ; ;display:none'))
    assert_true(inline_hides('display:none;;'))
    assert_true(hides('.h{;display:none}'))
    assert_true(hides('.h{color:red;;display:none}'))
    assert_true(shows('.h{;display:block}'))
    assert_true(shows('.h{color:red;;display:block}'))
    assert_true(inline_shows(';display:block'))
    assert_true(inline_shows('color:red;;display:block'))
    assert_true(inline_shows(';;'))
  end)

  test("a declaration with an unusable value is dropped alone", function()
    assert_true(inline_hides('x:[a];display:none'))
    assert_true(inline_hides('y:(b);display:none'))
    assert_true(inline_hides('z:{c};display:none'))
    assert_true(inline_hides('color:[a];display:none'))
    assert_true(inline_hides('display:none;z:{c}'))
    assert_true(hides('.h{x:[a];display:none}'))
    assert_true(hides('.h{y:(b);display:none}'))
    assert_true(hides('.h{z:{c};display:none}'))
    -- the opposite: the block holds the semicolon, so nothing follows it
    assert_true(inline_shows('x:[a;display:none]'))
    assert_true(inline_shows('z:{a;display:none}'))
    assert_true(inline_shows('y:(a;display:none)'))
    assert_true(inline_shows('color:{display:none}'))
    assert_true(inline_shows('x:[a];display:block'))
    assert_true(shows('.h{x:[a;display:none]}'))
    assert_true(shows('.h{z:{a;display:none}}'))
    -- a bad nesting inside of an inline style
    assert_true(inline_hides('x:' .. deep_open .. deep_close .. ';display:none'))
    assert_true(inline_shows('display:none ' .. deep_open .. deep_close .. ';display:block'))
  end)

  test("important wins within a block regardless of the order", function()
    assert_true(inline_hides('display:none !important; display:block'))
    assert_true(inline_hides('display:block; display:none !important'))
    assert_true(inline_hides('display:none ! important; display:block'))
    assert_true(inline_hides('display:none !IMPORTANT; display:block'))
    assert_true(inline_hides('display:none!important;display:block'))
    assert_true(hides('.h{display:none !important; display:block}'))
    assert_true(hides('.h{display:block; display:none !important}'))
    assert_true(hides('.h{display:block; display:none ! important}'))
    -- the opposite
    assert_true(inline_shows('display:none; display:block'))
    assert_true(inline_shows('display:block !important; display:none'))
    assert_true(inline_shows('display:none !important; display:block !important'))
    assert_true(inline_shows('display:none important; display:block'))
    assert_true(shows('.h{display:none; display:block}'))
    assert_true(shows('.h{display:block !important; display:none}'))
  end)

  test("shorthands and longhands apply in the source order", function()
    assert_true(inline_hides('font-size:12px; font:0 Arial'))
    assert_true(inline_hides('font:12px Arial; font-size:0'))
    assert_true(hides('.h{font-size:12px; font:0 Arial}'))
    assert_true(inline_shows('font:0 Arial; font-size:12px'))
    assert_true(inline_shows('font-size:0; font:12px Arial'))
    assert_true(shows('.h{font:0 Arial; font-size:12px}'))
    assert_true(inline_shows('font-size:12px !important; font:0 Arial'))
    -- display and visibility are separate properties, both hide
    assert_true(inline_hides('display:none; visibility:visible'))
    assert_true(inline_hides('visibility:hidden; display:block'))
    assert_true(inline_hides('display:block; visibility:hidden'))
    assert_true(inline_shows('display:none; display:block'))
    assert_true(inline_shows('visibility:hidden; visibility:visible'))
    assert_true(inline_shows('display:block; visibility:visible'))
  end)

  test("media rules apply only for queries every client matches", function()
    assert_true(hides('@media all{.h{display:none}}'))
    assert_true(hides('@media screen{.h{display:none}}'))
    assert_true(hides('@media only screen{.h{display:none}}'))
    assert_true(hides('@media  ONLY   SCREEN  {.h{display:none}}'))
    assert_true(hides('@MEDIA ALL{.h{display:none}}'))
    assert_true(hides('@media all{.k{} .h{display:none}} .m{}'))
    assert_true(hides('@media all{.h{display:none}'))
    -- nested media follows the same test
    assert_true(hides('@media all{@media screen{.h{display:none}}}'))
    assert_true(hides('@media all{@media print{.k{}} .h{display:none}}'))
    -- the position among the rules is kept
    assert_true(hides('.h{display:block} @media all{.h{display:none}}'))
    assert_true(shows('.h{display:none} @media all{.h{display:block}}'))
    assert_true(hides('@media all{.h{display:block}} .h{display:none}'))
    -- the opposite
    assert_true(shows('@media print{.h{display:none}}'))
    assert_true(shows('@media (max-width:100px){.h{display:none}}'))
    assert_true(shows('@media (min-width:1px){.h{display:none}}'))
    assert_true(shows('@media screen and (min-width:1px){.h{display:none}}'))
    assert_true(shows('@media only screen and (max-width:600px){.h{display:none}}'))
    assert_true(shows('@media screen,print{.h{display:none}}'))
    assert_true(shows('@media all,print{.h{display:none}}'))
    assert_true(shows('@media not all{.h{display:none}}'))
    assert_true(shows('@media not screen{.h{display:none}}'))
    assert_true(shows('@media{.h{display:none}}'))
    assert_true(shows('@media all{@media print{.h{display:none}}}'))
    assert_true(shows('@media all{@media (max-width:1px){.h{display:none}}}'))
    assert_true(shows('@supports (display:grid){.h{display:none}}'))
    assert_true(shows('@font-face{display:none} @page{.h{display:none}}'))
    assert_true(shows('@media print{.h{display:none}} .h{display:block}'))
    assert_true(shows('@media all{ .h } .k{}'))
  end)

  test("escapes do not create syntax", function()
    -- an escape never turns into a brace, a colon or a semicolon
    assert_true(shows('.h\\7b display\\3a none\\3b \\7d'))
    assert_true(shows('.h\\7b display\\3a none\\3b \\7d .k{}'))
    assert_true(shows('.h\\7bdisplay\\3a none\\3b \\7d'))
    assert_true(shows('.h\\{display:none;\\}'))
    assert_true(shows('.h\\{display:none\\}'))
    assert_true(shows('.h{display\\3a none}'))
    assert_true(shows('.h{color\\3a red; display\\3a none}'))
    assert_true(shows('.h{display:block;\\7d .z{display:none}'))
    -- the plain way still works
    assert_true(hides('.h{display:none}'))
    -- escaped name characters still match
    assert_true(hides('.\\68  {display:none}'))
    assert_true(hides('.\\68 {display:none}'))
    assert_true(hides('.\\68ide{display:none}', '<div class="hide">HID</div>'))
    assert_true(hides('.\\68 ide{display:none}', '<div class="hide">HID</div>'))
    assert_true(hides('.h\\69 de{display:none}', '<div class="hide">HID</div>'))
    assert_true(hides('.H\\49 DE{display:none}', '<div class="hide">HID</div>'))
    assert_true(hides('.h{display:\\6e one}'))
    assert_true(hides('.h{d\\69 splay:none}'))
    assert_true(hides('.h{display:no\\6e e}'))
    assert_true(shows('.h{display:\\62 lock}'))
    assert_true(shows('.\\68ide{display:none}'))
  end)
end)
