-- The visible text of an HTML part must be what a browser renders: the tree
-- is built as the HTML Standard says (implied end tags, text in the head and
-- after the last tag, no character references in tag names)
context("HTML tree building", function()
  local rspamd_parsers = require "rspamd_parsers"
  local rspamd_task = require "rspamd_task"
  local rspamd_config = rspamd_config

  local function visible(html)
    return tostring(rspamd_parsers.parse_html(html))
  end

  -- The cases that give another text, one per line; empty if all are right
  local function mismatches(cases)
    local bad = {}
    for _, c in ipairs(cases) do
      local got = visible(c[1])
      if got ~= c[2] then
        bad[#bad + 1] = string.format('%q: expected %q, got %q', c[1], c[2], got)
      end
    end
    return table.concat(bad, '\n')
  end

  test('text after the last tag is shown', function()
    assert_equal('', mismatches({
      { '<html><body><p>one</p></body></html>TAIL', 'one\nTAIL' },
      { '<html><body><p>one</p></body>TAIL</html>', 'one\nTAIL' },
      { '<html><body><p>one</p></body></html>\nTAIL\n', 'one\nTAIL' },
      { '<style></style><p>one</p>TAIL', 'one\nTAIL' },
      { '<meta charset="utf-8"><div>one</div>TAIL', 'one\nTAIL' },
      { '<html><meta charset="utf-8"><div>one</div>TAIL', 'one\nTAIL' },
      { '<html><head><style></style></head><body><div>one</div></body></html>TAIL', 'one\nTAIL' },
      { '<div>one</div></html>TAIL<p>two</p>', 'one\nTAIL\ntwo\n' },
    }))
  end)

  test('text after the end of the body goes into the body, as in a browser', function()
    assert_equal('', mismatches({
      { '<body style="display:none">HID</body>TAIL', '' },
      { '<body><div style="display:none">HID</body>TAIL', '' },
      { '<body style="display:none">HID</body></html>TAIL', '' },
    }))
  end)

  test('text in the head is shown', function()
    assert_equal('', mismatches({
      { '<html><head>HEADTXT</head><body>body</body></html>', 'HEADTXTbody' },
      { '<html><head>  <title>T</title> HEADTXT</head>', 'HEADTXT' },
      { '<html><head><!-- c -->HEADTXT', 'HEADTXT' },
      { '<html><head>HEADTXT', 'HEADTXT' },
    }))
  end)

  test('head elements and whitespace stay out of the text', function()
    assert_equal('', mismatches({
      { '<html><head><title>T</title></head><body>body</body></html>', 'body' },
      { '<html><head> \n <title>T</title>\n</head>\n<body>body</body></html>', 'body' },
      { '<html><head><script>SCR</script><style>STY</style></head><body>body</body></html>', 'body' },
      { 'x<title>T</title>y', 'xy' },
      { '<html><head><title>T</title><meta charset="utf-8"><base href="http://a.example/"></head>' ..
          '<body>body</body></html>', 'body' },
    }))
  end)

  test('a start tag ends the open paragraph', function()
    assert_equal('', mismatches({
      { '<p style="display:none">HID<p>SHOWN', 'SHOWN\n' },
      { '<p style="display:none">HID<div>SHOWN</div>', 'SHOWN\n' },
      { '<p style="display:none"><span>HID</span><h2>SHOWN</h2>', 'SHOWN\n' },
      { '<p style="display:none">HID<ul><li>SHOWN</ul>', 'SHOWN\n' },
      { '<p style="display:none">HID<pre>SHOWN</pre>', 'SHOWN\n' },
      { '<p style="display:none">HID<hr>SHOWN', '\nSHOWN' },
      { '<p style="display:none">HID<table><tr><td>SHOWN', 'SHOWN\n' },
      { '<p style="display:none">HID<form>SHOWN</form>', 'SHOWN\n' },
    }))
  end)

  test('implied end tags of lists, headings, options and tables', function()
    assert_equal('', mismatches({
      { '<ul><li style="display:none">HID<li>SHOWN', 'SHOWN\n' },
      { '<dl><dt style="display:none">HID<dd>SHOWN', 'SHOWN\n' },
      { '<dl><dd style="display:none">HID<dt>SHOWN', 'SHOWN\n' },
      { '<h1 style="display:none">HID<h2>SHOWN', 'SHOWN\n' },
      { '<select><option style="display:none">HID<option>SHOWN</select>', 'SHOWN' },
      { '<select><optgroup style="display:none"><option>HID<optgroup>SHOWN</select>', 'SHOWN' },
      { '<table><tr><td style="display:none">HID<td>SHOWN', 'SHOWN\n' },
      { '<table><tr><th style="display:none">HID<td>SHOWN', 'SHOWN\n' },
      { '<table><tr style="display:none"><td>HID<tr><td>SHOWN', 'SHOWN\n' },
      { '<table><tbody style="display:none"><tr><td>HID<tbody><tr><td>SHOWN', 'SHOWN\n' },
      { '<li style="display:none">HID<span>HID2<li>SHOWN', 'SHOWN' },
      { '<li style="display:none">HID<div>HID2<li>SHOWN', 'SHOWN' },
    }))
  end)

  test('nested elements keep the style of the one around them', function()
    assert_equal('', mismatches({
      { '<div style="display:none">HID<p>STILL HIDDEN</p></div>', '' },
      { '<p style="display:none"><span>HID</span><b>HID2</b></p>', '' },
      { '<p style="display:none">HID<span><a>HID2</a></span>', '' },
      { '<p style="display:none">HID<button><div>HID2</div></button>', '' },
      { '<p style="display:none">HID<marquee><p>HID2</marquee>', '' },
      { '<p style="display:none">HID<object><div>HID2</div></object>', '' },
      { '<table style="display:none"><tr><td>HID<td>HID2<tr><td>HID3</table>', '' },
      { '<table style="display:none"><tr><td><p>HID<td><p>HID2</table>', '' },
      { '<ul style="display:none"><li>HID<ul><li>HID2<li>HID3</ul><li>HID4</ul>', '' },
      { '<li style="display:none">HID<ul><li>HID2</ul>', '' },
      { '<li style="display:none">HID<section><li>HID2</section>', '' },
      { '<select style="display:none"><option>HID<option>HID2</select>', '' },
      { '<h1 style="display:none">HID<b><h2>HID2</h2></b>', '' },
      -- A cell of an inner table does not end the one of the outer table
      { '<table><tr><td style="display:none">HID<table><tr><td>HID2<td>HID3</table>HID4', '' },
    }))
  end)

  test('an end tag of an element that was ended implicitly', function()
    assert_equal('', mismatches({
      { '<p>a<p>b</p></p>c', 'a\nb\nc' },
      { '<p>a</p></p>c', 'a\nc' },
      { '<span>a<p>b<p>c</span>d', 'a\nb\nc\nd' },
      { '<ul><li>a<li>b</li></li></ul>c', 'ab\nc' },
      { '<p style="display:none">HID<p>SHOWN</p></p>after', 'SHOWN\nafter' },
    }))
  end)

  test('links are not nested', function()
    local res, task = rspamd_task.load_from_string(
        'From: test@example.com\r\nContent-Type: text/html; charset=utf-8\r\n\r\n' ..
        '<a href="https://example.com/">https://example.org/<a href="https://example.net/">x</a></a>',
        rspamd_config)
    assert_true(res)
    task:process_message()
    local seen = {}
    for _, u in ipairs(task:get_urls() or {}) do
      seen[u:get_host()] = u
    end
    -- The urls belong to the task: read them before it is destroyed
    local first, second = seen['example.com'], seen['example.net']
    local first_phished = first and first:is_phished()
    local first_visible = first and first:get_visible()
    local second_phished = second and second:is_phished()
    task:destroy()
    assert_not_nil(first)
    assert_true(first_phished)
    assert_equal('https://example.org/', first_visible)
    assert_not_nil(second)
    assert_false(second_phished)
    assert_equal(
        'onetwothree',
        visible('<a href="http://a.example/">one<a href="http://b.example/">two</a></a>three'))
  end)

  test('tag names are not decoded', function()
    assert_equal('', mismatches({
      { 'x<scr&#105;pt>INSIDE</scr&#105;pt>y', 'xINSIDEy' },
      { 'x<scr&#105;pt>INSIDE</script>y', 'xINSIDEy' },
      { 'x<sty&#108;e>INSIDE</sty&#108;e>y', 'xINSIDEy' },
      { '<div style="display:none">x<d&#105;v>HID</d&#105;v></div>y', 'y' },
      { 'x<script>INSIDE</script>y', 'xy' },
      { 'x<style>INSIDE</style>y', 'xy' },
      { 'x<SCRIPT>INSIDE</SCRIPT>y', 'xy' },
    }))
  end)
end)
