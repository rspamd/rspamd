-- What a reader shows of the text of a pdf, and in what order

context("PDF text layout", function()
  local rspamd_text = require "rspamd_text"
  local pdf = require "lua_content/pdf"

  local function build(objs, trailer)
    local out = { '%PDF-1.4\n' }

    for i, o in ipairs(objs) do
      out[#out + 1] = string.format('%d 0 obj\n%s\nendobj\n', i, o)
    end

    out[#out + 1] = trailer or 'trailer\n<< /Size 30 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n'

    return rspamd_text.fromstring(table.concat(out))
  end

  local function stream(data, dict)
    return string.format('<< %s /Length %d >>\nstream\n%s\nendstream', dict or '', #data, data)
  end

  local font = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'

  -- One page with the content given; objects after the fifth are extra ones
  local function page_pdf(content, extra, resources)
    local objs = {
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> ' .. (resources or '') ..
          ' >> /Contents 4 0 R >>',
      stream(content),
      font,
    }

    for _, o in ipairs(extra or {}) do
      objs[#objs + 1] = o
    end

    return build(objs)
  end

  local function text_of(res)
    local out = {}

    for _, t in ipairs(res.text_pages or {}) do
      out[#out + 1] = tostring(t)
    end

    return table.concat(out, '\f')
  end

  local function extract(content, extra, resources)
    return text_of(pdf.process(page_pdf(content, extra, resources), nil, {}))
  end

  -- Operators that are not about text must not stop the reading

  local unknown = {
    { 'marked content', '/Span <</MCID 0>> BDC (one) Tj EMC (two) Tj' },
    { 'a colour operator with a name', '/Cs1 cs 0.5 0.2 /P1 SCN (one) Tj 1 0 0 scn (two) Tj' },
    { 'an operand without an operator', '5 (one) Tj 7 8 9 (two) Tj' },
    { 'an operator that does not exist', '(one) Tj 1 2 foo bar* (two) Tj' },
    { 'an inline image', '(one) Tj BI /W 2 /H 2 /BPC 8 ID \1\2(\3[<\4 EI (two) Tj' },
    { 'a stray closing bracket', '(one) Tj ) ] >> (two) Tj' },
    { 'a comment with brackets', '(one) Tj % ( [ <<\n(two) Tj' },
    { 'a dictionary operand', '(one) Tj /GS1 gs << /A [1 2 (x)] /B << /C null >> >> DP (two) Tj' },
  }

  for _, c in ipairs(unknown) do
    test("Text after " .. c[1] .. " is read", function()
      assert_equal('onetwo\n', extract('BT /F1 12 Tf ' .. c[2] .. ' ET'))
    end)
  end

  test("Text after a bracket that is never closed is read", function()
    local text = extract('BT /F1 12 Tf (one) Tj [ 1 2 (two) Tj ET')
    assert_not_nil(text:find('one', 1, true))
    assert_not_nil(text:find('two', 1, true))
  end)

  test("Tokens that do not read at the start of a page do not hide its text", function()
    local cases = {
      string.rep('<x> ', 40),
      string.rep('[)] ', 40),
      string.rep('q BI /W 1 /H 1 /BPC 8 ID \255EI Q ', 40),
    }

    for _, lead in ipairs(cases) do
      local text = extract(lead .. 'BT /F1 12 Tf (after) Tj ET')
      assert_not_nil(text:find('after', 1, true), lead:sub(1, 12))
    end
  end)

  test("A hex string with zero bytes between its digits is read", function()
    assert_equal('one\n', extract('BT /F1 12 Tf <6f\0 6e\0\n65> Tj ET'))
  end)

  test("Differences of an encoding that are an object of their own are applied", function()
    local page = '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>'
    local function with_font(encoding, extra)
      local objs = {
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        page,
        stream('BT /F1 12 Tf (ABC) Tj ET'),
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding ' .. encoding .. ' >>',
      }
      objs[#objs + 1] = extra

      return text_of(pdf.process(build(objs), nil, {}))
    end

    local inline = with_font('<< /Type /Encoding /Differences [65 /x /y /z] >>')
    local indirect = with_font('<< /Type /Encoding /Differences 6 0 R >>', '[65 /x /y /z]')
    assert_equal('xyz\n', inline)
    assert_equal(inline, indirect)
  end)

  -- The forms of a text object

  local objects = {
    { 'the first bytes of the stream', 'BT /F1 12 Tf (one) Tj ET', 'one\n' },
    { 'no white space after BT', 'q BT/F1 12 Tf(one)Tj ET Q', 'one\n' },
    { 'CRLF line ends', 'q\r\nBT\r\n/F1 12 Tf\r\n(one) Tj\r\nET\r\nQ\r\n', 'one\n' },
    { 'ET inside of a string', 'BT /F1 12 Tf (x ET y) Tj (z) Tj ET', 'x ET yz\n' },
    { 'the font set before the text object', '/F1 12 Tf BT (caf\233) Tj ET', 'café\n' },
    { 'a hex string with white space', 'BT /F1 12 Tf <6f 6e\n65> Tj ET', 'one\n' },
    { 'an octal escape over 255', 'BT /F1 12 Tf (o\\556e) Tj ET', 'one\n' },
    { 'escaped brackets', 'BT /F1 12 Tf (a\\(b\\)c\\\\d) Tj ET', 'a(b)c\\d\n' },
  }

  for _, c in ipairs(objects) do
    test("A text object with " .. c[1], function()
      assert_equal(c[3], extract(c[2]))
    end)
  end

  test("A text object larger than 32K is read", function()
    local text = extract('BT /F1 12 Tf ' .. string.rep('(padding ) Tj ', 4000) .. '(the end) Tj ET')
    assert_not_nil(text:find('the end', 1, true))
  end)

  -- Where the pieces of text go

  local moves = {
    { 'a move along the line past the text is a gap', '(foo) Tj 50 0 Td (bar) Tj', 'foo bar\n' },
    { 'a move by the width of the text is not', '(foo) Tj 18 0 Td (bar) Tj', 'foobar\n' },
    { 'a move to another line', '(foo) Tj 0 -14 Td (bar) Tj', 'foo\nbar\n' },
    { 'a matrix on the same line past the text', '1 0 0 1 50 700 Tm (foo) Tj 1 0 0 1 150 700 Tm (bar) Tj', 'foo bar\n' },
    { 'a matrix right after the text', '1 0 0 1 50 700 Tm (foo) Tj 1 0 0 1 68 700 Tm (bar) Tj', 'foobar\n' },
    { 'a matrix on another line', '1 0 0 1 50 700 Tm (foo) Tj 1 0 0 1 50 680 Tm (bar) Tj', 'foo\nbar\n' },
    { 'a scaled matrix with a font of size one',
      'ET BT /F1 1 Tf 12 0 0 12 50 700 Tm (foo) Tj 12 0 0 12 150 700 Tm (bar) Tj 12 0 0 12 168 700 Tm (baz) Tj',
      '\nfoo barbaz\n' },
    { 'a large offset in an array', '[(foo) -250 (bar) -100 (baz)] TJ', 'foo barbaz\n' },
    { 'the next line operators', "(foo) Tj T* (bar) Tj (baz) '", 'foo\nbar\nbaz\n' },
  }

  for _, c in ipairs(moves) do
    test("Positioning: " .. c[1], function()
      assert_equal(c[3], extract('BT /F1 12 Tf ' .. c[2] .. ' ET'))
    end)
  end

  -- Pages

  test("Pages come in the order of the page tree", function()
    local objs = {
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [8 0 R 3 0 R] /Count 2 /Resources << /Font << /F1 5 0 R >> >> >>',
      '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>',
      stream('BT /F1 12 Tf (second page) Tj ET'),
      font,
      -- Not in the tree: no reader shows it
      '<< /Type /Page /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>',
      stream('BT /F1 12 Tf (orphan page) Tj ET'),
      '<< /Type /Page /Parent 2 0 R /Contents 9 0 R >>',
      stream('BT /F1 12 Tf (first page) Tj ET'),
    }
    local res = pdf.process(build(objs), nil, {})
    assert_equal('first page\n\fsecond page\n', text_of(res))
    assert_equal('first page\n', res.extract_text(res)[1])
  end)

  test("Pages that are not in the tree do not use up the budget", function()
    local objs = {
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
      stream('BT /F1 12 Tf (the real text of the document) Tj ET'),
      font,
      stream('BT /F1 12 Tf ' .. string.rep('(junk junk junk junk) Tj ', 2000) .. ' ET'),
    }
    local head = {}

    for i = 1, 60 do
      head[i] = '<< /Type /Page /Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>'
    end

    -- The orphans stand before the real page in the file
    local out = { '%PDF-1.4\n' }

    for i, o in ipairs(head) do
      out[#out + 1] = string.format('%d 0 obj\n%s\nendobj\n', 100 + i, o)
    end

    for i, o in ipairs(objs) do
      out[#out + 1] = string.format('%d 0 obj\n%s\nendobj\n', i, o)
    end

    out[#out + 1] = 'trailer\n<< /Size 200 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n'

    local saved = pdf.config.max_extracted_text_size
    pdf.config.max_extracted_text_size = 64 * 1024
    local res = pdf.process(rspamd_text.fromstring(table.concat(out)), nil, {})
    pdf.config.max_extracted_text_size = saved
    assert_equal('the real text of the document\n', text_of(res))
  end)

  test("A file without a page tree still gives its pages", function()
    local objs = {
      '<< /Type /Page /Resources << /Font << /F1 3 0 R >> >> /Contents 2 0 R >>',
      stream('BT /F1 12 Tf (no tree here) Tj ET'),
      font,
    }
    assert_equal('no tree here\n', text_of(pdf.process(build(objs, 'trailer\n<< /Size 4 >>\n'), nil, {})))
  end)

  test("The text of a form that a page draws is read", function()
    local form = stream('BT /F1 12 Tf (inside the form) Tj ET',
        '/Type /XObject /Subtype /Form /BBox [0 0 100 100] /Resources << /Font << /F1 5 0 R >> >>')
    local image = stream('\1\2\3\4', '/Type /XObject /Subtype /Image /Width 2 /Height 2')
    local text = extract('BT /F1 12 Tf (before) Tj ET q /Fm1 Do /Im1 Do /Nope Do Q BT (after) Tj ET',
        { form, image }, '/XObject << /Fm1 6 0 R /Im1 7 0 R >>')
    assert_equal('before\ninside the form\nafter\n', text)
  end)

  test("A form that draws itself ends", function()
    local form = stream('BT /F1 12 Tf (again) Tj ET /Fm1 Do',
        '/Type /XObject /Subtype /Form /Resources << /Font << /F1 5 0 R >> /XObject << /Fm1 6 0 R >> >>')
    local text = extract('/Fm1 Do', { form }, '/XObject << /Fm1 6 0 R >>')
    assert_not_nil(text:find('again', 1, true))
    assert_true(#text < 100)
  end)

  -- Fonts

  test("A simple font with a two byte codespace in its cmap is read by bytes", function()
    local cmap = 'begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n' ..
        '3 beginbfchar\n<41> <0062>\n<0042> <0063>\n<43> <00E9>\nendbfchar\nendcmap\n'
    local objs = {
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
      stream('BT /F1 12 Tf (ABCD\233) Tj ET'),
      '<< /Type /Font /Subtype /TrueType /BaseFont /X /Encoding /WinAnsiEncoding /ToUnicode 6 0 R >>',
      stream(cmap),
    }
    -- A and C by one byte codes, B by a two byte one, the rest by the encoding
    assert_equal('bcéDé\n', text_of(pdf.process(build(objs), nil, {})))
  end)

  -- Text that is not seen

  test("Text in the invisible mode is extracted and counted", function()
    local res = pdf.process(page_pdf('BT /F1 12 Tf (seen) Tj 3 Tr ( hidden) Tj 0 Tr ( again) Tj ET'), nil, {})
    assert_equal('seen hidden again\n', text_of(res))
    assert_equal(7, res.flags.invisible_text)

    res = pdf.process(page_pdf('BT /F1 12 Tf (seen) Tj ET'), nil, {})
    assert_nil(res.flags.invisible_text)
  end)

  -- The quality filter

  test("Garbage added to a page does not take its text away", function()
    local real = 'Buy cheap pills now at our online pharmacy store'
    -- A font that maps a letter to a zero width character, and one that
    -- maps it to a control character
    local content = 'BT /F1 12 Tf (' .. real .. ') Tj T* /F2 12 Tf (' .. string.rep('A', 400) ..
        ') Tj T* /F3 12 Tf (' .. string.rep('A', 400) .. ') Tj ET'
    local objs = {
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R /F3 7 0 R >> >> /Contents 4 0 R >>',
      stream(content),
      font,
      '<< /Type /Font /Subtype /Type1 /BaseFont /X /Encoding << /BaseEncoding /WinAnsiEncoding ' ..
          '/Differences [65 /uni200B] >> >>',
      '<< /Type /Font /Subtype /Type1 /BaseFont /Y /Encoding << /BaseEncoding /WinAnsiEncoding ' ..
          '/Differences [65 /uni0001] >> >>',
    }
    local text = text_of(pdf.process(build(objs), nil, {}))
    assert_not_nil(text:find(real, 1, true), 'the text of the page is lost')
  end)
end)
