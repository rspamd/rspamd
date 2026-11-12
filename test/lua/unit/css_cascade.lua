context("CSS cascade", function()
  local rspamd_task = require("rspamd_task")
  local rspamd_parsers = require("rspamd_parsers")

  -- Stylesheets are applied only for a task, so go through a real message.
  -- Returns the invisible text
  local function invisible(style, body)
    local html = '<html><head><style>' .. style .. '</style></head><body>' .. body ..
        '<p>vis</p></body></html>'
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: text/html; charset=utf-8\r\n\r\n" .. html .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not res then return nil end
    task:process_message()
    local hp = task:get_text_parts()[1]:get_html()
    local inv = tostring(hp:get_invisible())
    task:destroy()
    return inv
  end

  -- Tags live as long as the pool, which is released with the process
  local pool = require("rspamd_mempool").create()

  -- First tag of the given type of a document parsed without stylesheets
  local function first_tag(html, typ)
    local hp = rspamd_parsers.parse_html_content(html, pool)
    local res
    hp:foreach_tag("any", function(tag)
      if tag:get_type() == typ then
        res = tag
        return true
      end
      return false
    end)
    return res
  end

  -- 1. A descendant cannot un-hide a hidden ancestor
  test("stylesheet display cannot reset a display:none ancestor", function()
    local css = '.h{display:none} span{display:inline}'
    assert_equal('HID', invisible(css, '<div class="h"><span>HID</span></div>'))
    assert_equal('HID', invisible('.h{display:none} .s{display:block}',
        '<div class="h"><span class="s">HID</span></div>'))
    -- deeper in the subtree too
    assert_equal('HID', invisible(css, '<div class="h"><p><span>HID</span></p></div>'))
    -- the hiding comes from opacity
    assert_equal('HID', invisible('.h{opacity:0} span{display:inline}',
        '<div class="h"><span>HID</span></div>'))
  end)

  test("stylesheet display still applies where no ancestor is hidden", function()
    assert_equal('', invisible('.h{display:none} span{display:inline}',
        '<div class="g"><span>SHOWN</span></div>'))
    assert_equal('', invisible('div{display:none} .s{display:block}',
        '<span class="s">SHOWN</span>'))
    -- a hidden sibling does not hide the next one
    assert_equal('HID', invisible('.h{display:none} span{display:inline}',
        '<div class="h"><span>HID</span></div><div><span>SHOWN</span></div>'))
  end)

  -- 2. Unknown elements get class, id and universal rules
  test("class and id rules apply to unknown elements", function()
    assert_equal('HID', invisible('.h{display:none}', '<x-foo class="h">HID</x-foo>'))
    assert_equal('HID', invisible('#i{display:none}', '<x-foo id="i">HID</x-foo>'))
    assert_equal('HID', invisible('.h{display:none}', '<o:p class="h">HID</o:p>'))
    assert_equal('HID', invisible('.h{font-size:0}', '<x-foo class="h">HID</x-foo>'))
    assert_equal('HID', invisible('.h{display:none}', '<custom class="h">HID</custom>'))
  end)

  test("rules that do not match unknown elements leave them visible", function()
    assert_equal('', invisible('.h{display:none}', '<x-foo class="k">SHOWN</x-foo>'))
    -- a type selector naming an unknown tag is dropped
    assert_equal('', invisible('x-foo{display:none}', '<x-foo>SHOWN</x-foo>'))
    assert_equal('', invisible('x-foo.h{display:none}', '<x-foo class="h">SHOWN</x-foo>'))
    assert_equal('', invisible('div.h{display:none}', '<x-foo class="h">SHOWN</x-foo>'))
  end)

  test("unknown elements take part in combinators", function()
    assert_equal('HID', invisible('.a > .h{display:none}',
        '<x-foo class="a"><span class="h">HID</span></x-foo>'))
    assert_equal('HID', invisible('.a .h{display:none}',
        '<x-foo class="a"><div><span class="h">HID</span></div></x-foo>'))
    assert_equal('HID', invisible('.a + .h{display:none}',
        '<x-foo class="a"></x-foo><x-bar class="h">HID</x-bar>'))
    assert_equal('', invisible('.a > .h{display:none}',
        '<x-foo class="b"><span class="h">SHOWN</span></x-foo>'))
    -- children of a hidden unknown element are hidden
    assert_equal('HID', invisible('.h{display:none}',
        '<x-foo class="h"><span>HID</span></x-foo>'))
  end)

  -- 3. Attribute names after '/' and after a valueless attribute
  test("a slash between attributes is skipped", function()
    local tag = first_tag('<html><body><div a /style="display:none">HID</div></body></html>', 'div')
    assert_equal('display:none', tag:get_attribute('style'))
    assert_nil(tag:get_attribute('/style'))
    assert_false(tag:get_style().visible)

    tag = first_tag('<html><body><div a/style="display:none">HID</div></body></html>', 'div')
    assert_equal('display:none', tag:get_attribute('style'))
  end)

  test("a name after a valueless attribute starts a new attribute", function()
    local tag = first_tag('<html><body><div a b style="display:none">HID</div></body></html>', 'div')
    assert_equal('display:none', tag:get_attribute('style'))
    assert_nil(tag:get_attribute('bstyle'))
    assert_false(tag:get_style().visible)

    tag = first_tag('<html><body><div a b=1 c = 2 class="k">x</div></body></html>', 'div')
    assert_equal('1', tag:get_attribute('b'))
    assert_equal('2', tag:get_attribute('c'))
    assert_equal('k', tag:get_attribute('class'))

    tag = first_tag('<html><body><div a  b   style="display:none">HID</div></body></html>', 'div')
    assert_equal('display:none', tag:get_attribute('style'))
  end)

  test("ordinary attributes and slashes keep their meaning", function()
    local tag = first_tag('<html><body><div class="k" style="color:red">x</div></body></html>', 'div')
    assert_equal('k', tag:get_attribute('class'))
    assert_equal('color:red', tag:get_attribute('style'))
    assert_true(tag:get_style().visible)

    tag = first_tag('<html><body><div a = "x" / style="display:none">x</div></body></html>', 'div')
    assert_equal('x', tag:get_attribute('a'))
    assert_equal('display:none', tag:get_attribute('style'))

    local hp = rspamd_parsers.parse_html_content('<html><body><a href=/x/>y</a><p>vis</p></body></html>', pool)
    assert_equal('', tostring(hp:get_invisible()))
  end)

  -- Whether text with the colour declaration on white is not seen
  local function on_white(color_decl)
    local tag = first_tag('<html><body><div style="' .. color_decl ..
        ';background-color:#ffffff">TXT</div></body></html>', 'div')
    return tag:get_style().transparent
  end

  -- 4. hsl()
  test("hsl greys are converted", function()
    assert_true(on_white('color:hsl(0,0%,100%)'))
    assert_true(on_white('color:hsl(200,0%,100%)'))
    assert_true(on_white('color:hsla(0,0%,100%,1)'))
    -- black and mid grey on white are readable
    assert_false(on_white('color:hsl(0,0%,0%)'))
    assert_false(on_white('color:hsl(0,0%,50%)'))
  end)

  test("hsl hue wraps around", function()
    -- hue 360 and -360 are red; a huge hue must not crash
    assert_false(on_white('color:hsl(360,100%,50%)'))
    assert_false(on_white('color:hsl(-360,100%,50%)'))
    assert_false(on_white('color:hsl(1e30,100%,50%)'))
    assert_false(on_white('color:hsl(-1e30,100%,50%)'))
    -- full lightness is white for any hue
    assert_true(on_white('color:hsl(-120,100%,100%)'))
    assert_true(on_white('color:hsl(480,100%,100%)'))
  end)

  -- 5. hex colours
  test("invalid hex colours are dropped", function()
    -- the invalid declaration is dropped, the earlier white stays
    assert_true(on_white('color:#ffffff;color:#12345g'))
    assert_true(on_white('color:#fff;color:#zzz'))
    assert_true(on_white('color:#ffffff;color:#00000g'))
    -- a valid later value wins
    assert_false(on_white('color:#ffffff;color:#123456'))
  end)

  test("four and eight digit hex colours carry alpha", function()
    -- fully transparent text is not seen
    assert_true(on_white('color:#0000'))
    assert_true(on_white('color:#00000000'))
    assert_true(on_white('color:#ffff'))
    assert_true(on_white('color:#ffffffff'))
    -- opaque dark text is seen
    assert_false(on_white('color:#000f'))
    assert_false(on_white('color:#000000ff'))
  end)

  -- 6. legacy color attributes
  local function legacy_transparent(attrs)
    local tag = first_tag('<html><body><div ' .. attrs .. '>TXT</div></body></html>', 'div')
    return tag:get_style().transparent
  end

  test("legacy color attributes are normalised", function()
    assert_true(legacy_transparent('color="white" bgcolor="white"'))
    assert_true(legacy_transparent('color="WHITE" bgcolor="White"'))
    assert_true(legacy_transparent('color=" white " bgcolor="\twhite\n"'))
    assert_true(legacy_transparent('color="FFFFFF" bgcolor="ffffff"'))
    assert_true(legacy_transparent('color="fff" bgcolor="FFF"'))
    assert_true(legacy_transparent('color="#FFFFFF" bgcolor="#FFF"'))
  end)

  test("legacy color attribute garbage is not recognised", function()
    assert_false(legacy_transparent('color="whitee" bgcolor="white"'))
    assert_false(legacy_transparent('color="ffff" bgcolor="ffffff"'))
    assert_false(legacy_transparent('color="fffffg" bgcolor="ffffff"'))
    assert_false(legacy_transparent('color="000000" bgcolor="ffffff"'))
  end)

  -- 7. specificity
  test("an id outranks any number of classes", function()
    local classes = 'a b c d e f g h1 i1 j k'
    local sel = '.a.b.c.d.e.f.g.h1.i1.j.k'
    assert_equal('HID', invisible('#i{display:none} ' .. sel .. '{display:block}',
        '<div id="i" class="' .. classes .. '">HID</div>'))
    -- source order does not matter against specificity
    assert_equal('HID', invisible(sel .. '{display:block} #i{display:none}',
        '<div id="i" class="' .. classes .. '">HID</div>'))
    -- and the reverse: the id rule shows it
    assert_equal('', invisible('#i{display:block} ' .. sel .. '{display:none}',
        '<div id="i" class="' .. classes .. '">SHOWN</div>'))
  end)

  test("a class outranks any number of types, equal specificity goes by order", function()
    assert_equal('HID', invisible('.h{display:none} body div div div{display:block}',
        '<div><div><div class="h">HID</div></div></div>'))
    assert_equal('', invisible('div.a{display:none} div.a{display:block}',
        '<div class="a">SHOWN</div>'))
    assert_equal('HID', invisible('.a{display:block} .a{display:none}',
        '<div class="a">HID</div>'))
    -- more classes win over fewer regardless of order
    assert_equal('HID', invisible('.a.b{display:none} .a{display:block}',
        '<div class="a b">HID</div>'))
    assert_equal('', invisible('.a.b{display:block} .a{display:none}',
        '<div class="a b">SHOWN</div>'))
    -- ids in ancestors count
    assert_equal('HID', invisible('#p .h{display:none} .x.y.z.w .h{display:block}',
        '<div id="p" class="x y z w"><span class="h">HID</span></div>'))
  end)
end)
