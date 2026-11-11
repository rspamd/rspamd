--[[
What is hidden and what is shown: styles over the layers of a declaration
block, formatting elements carried over an implied end tag, the tags limit.
]]

context("HTML visibility after implied end tags and important styles", function()
  local rspamd_task = require "rspamd_task"

  local function look(body, style)
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: text/html; charset=utf-8\r\n\r\n" ..
        '<html><head><style>' .. (style or '') .. '</style></head>' .. body .. "</html>\r\n"
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    local tp = task:get_text_parts()[1]
    local res = {
      visible = tostring(tp:get_content()),
      invisible = tostring(tp:get_html():get_invisible()),
    }
    task:destroy()

    return res
  end

  local function shown(res, word)
    return res.visible:find(word, 1, true) ~= nil
  end
  local function hidden(res, word)
    return res.invisible:find(word, 1, true) ~= nil and not shown(res, word)
  end

  -- Hidden by what is not `display`

  local forced = {
    { 'opacity', '<span style="opacity:0;display:block!important">HID</span>' },
    { 'a text indent', '<span style="text-indent:-9999px;display:block!important">HID</span>' },
    { 'an important offset', '<span style="position:absolute;left:-9999px !important">HID</span>' },
    { 'opacity inline and display in a class', '<span class="c" style="opacity:0">HID</span>',
      '.c{display:block !important}' },
    { 'opacity and display in a class', '<span class="c">HID</span>',
      '.c{opacity:0;display:block !important}' },
    { 'a clip in a class', '<span class="c">HID</span>',
      '.c{clip-path:inset(100%);display:block !important}' },
    { 'opacity of a parent', '<span style="opacity:0"><b style="display:block!important">HID</b></span>' },
  }

  for _, c in ipairs(forced) do
    test("An important display does not show what is hidden by " .. c[1], function()
      local res = look('<body>' .. c[2] .. '<p>shown</p></body>', c[3])
      assert_true(hidden(res, 'HID'), res.visible)
      assert_true(shown(res, 'shown'))
    end)
  end

  test("An important opacity wins over a normal one", function()
    local res = look('<body><span style="opacity:0;opacity:1 !important">SEEN</span></body>')
    assert_true(shown(res, 'SEEN'))
    res = look('<body><span style="opacity:1;display:block">SEEN</span></body>')
    assert_true(shown(res, 'SEEN'))
  end)

  -- Formatting elements are open again after an implied end tag

  test("The colour of a font goes on in the paragraphs that follow", function()
    local res = look('<body bgcolor="#000000"><p><font color="#ffffff">line one<p>line two' ..
        '<p>line three</font></body>')
    assert_true(shown(res, 'line one'))
    assert_true(shown(res, 'line two'), res.visible)
    assert_true(shown(res, 'line three'), res.visible)
  end)

  test("A hidden font hides the paragraphs that follow it", function()
    local res = look('<body><p>shown<font style="display:none">HID0<p>RECON1</p><p>RECON2</p>' ..
        '<div>RECON3</div></body>')
    assert_true(shown(res, 'shown'))
    for _, w in ipairs({ 'HID0', 'RECON1', 'RECON2', 'RECON3' }) do
      assert_true(hidden(res, w), w .. ': ' .. res.visible)
    end
  end)

  test("A hidden element hides the list items that follow it", function()
    local res = look('<body><ul><li>one<b style="display:none">HID0<li>L1<li>L2</ul></body>')
    assert_true(shown(res, 'one'))
    assert_true(hidden(res, 'L1'), res.visible)
    assert_true(hidden(res, 'L2'), res.visible)
  end)

  test("The end tag of a formatting element ends it for what follows", function()
    local res = look('<body><p><font style="display:none">HID<p>hid2</font><p>SEEN</p></body>')
    assert_true(hidden(res, 'HID'))
    assert_true(hidden(res, 'hid2'))
    assert_true(shown(res, 'SEEN'), res.visible)
  end)

  test("Formatting does not go into a table from outside", function()
    local res = look('<body><p><font style="display:none">HID<table><tr><td>CELL</td></tr></table></body>')
    assert_true(hidden(res, 'HID'))
    assert_true(shown(res, 'CELL'), res.visible)
  end)

  test("Plain formatting changes nothing of what is shown", function()
    local res = look('<body><p><b>bold<p>next</b> plain <p>third</p></body>')
    for _, w in ipairs({ 'bold', 'next', 'plain', 'third' }) do
      assert_true(shown(res, w), w)
    end
  end)

  -- Past the limit of tags

  local pad = string.rep('<p>para <b>x</b></p>', 4200)

  test("A hidden element past the limit ends with the element around it", function()
    local res = look('<body><div>' .. pad .. '<span style="display:none">HID</div>SEEN2<div>SEEN3</div></body>')
    assert_true(hidden(res, 'HID'))
    assert_true(shown(res, 'SEEN2'))
    assert_true(shown(res, 'SEEN3'))

    res = look('<body><table><tr><td>' .. pad .. '<p style="display:none">HID</td></tr></table>SEEN1</body>')
    assert_true(hidden(res, 'HID'))
    assert_true(shown(res, 'SEEN1'))
  end)

  -- Small things

  test("A numeric no-break space is the space that its name gives", function()
    local res = look('<body>a&#160;b c&nbsp;d e&#xA0;f</body>')
    assert_nil(res.visible:find('\194\160', 1, true))
    assert_not_nil(res.visible:find('a b', 1, true))
    assert_not_nil(res.visible:find('e f', 1, true))
  end)

  test("Three digits without a sharp are not a short colour", function()
    -- `fff` is #0f0f0f by the legacy rules: dark on white
    local res = look('<body><table><tr><td bgcolor="FFFFFF"><font color="fff">DARK</font> ' ..
        '<font color="ffffff">WHITE</font></td></tr></table></body>')
    assert_true(shown(res, 'DARK'), res.visible)
    assert_false(shown(res, 'WHITE'))
  end)
end)
