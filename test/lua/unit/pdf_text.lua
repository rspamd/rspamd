-- Decoding of PDF simple font text (rspamd_pdf_text)

context("PDF text decoding", function()
  local pdf_text = require "rspamd_pdf_text"

  local function decode(enc, codes)
    local b = pdf_text.builder()
    b:set_encoding(enc)
    b:add_encoded(codes)
    return tostring(b:finish())
  end

  test("A code means a different character in each encoding", function()
    local std = pdf_text.encoding('StandardEncoding')
    local win = pdf_text.encoding('WinAnsiEncoding')
    local mac = pdf_text.encoding('/MacRomanEncoding')

    -- 0xe9 is Oslash, eacute and Egrave respectively
    assert_equal(decode(std, '\233'), 'Ø')
    assert_equal(decode(win, '\233'), 'é')
    assert_equal(decode(mac, '\233'), 'È')
  end)

  test("Ligature slots belong to their own encoding", function()
    local std = pdf_text.encoding('StandardEncoding')
    local win = pdf_text.encoding('WinAnsiEncoding')
    local mac = pdf_text.encoding('MacRomanEncoding')

    assert_equal(decode(std, '\174\175'), 'ﬁﬂ')
    assert_equal(decode(mac, '\222\223'), 'ﬁﬂ')
    -- the very same codes are ordinary letters in WinAnsi
    assert_equal(decode(win, '\174\223'), '®ß')
  end)

  test("Unsupported encoding names are rejected", function()
    local enc, err = pdf_text.encoding('MacExpertEncoding')
    assert_nil(enc)
    assert_equal(err, 'unknown base encoding')
  end)

  test("Literal and hex strings decode in one pass", function()
    local b = pdf_text.builder(256)
    b:set_encoding(pdf_text.encoding('WinAnsiEncoding'))

    b:add_string('caf\\351 \\(x\\)')
    b:add_char(' ')
    b:add_hexstring('636166 E9')

    assert_equal(tostring(b:finish()), 'café (x) café')
    assert_equal(b:len(), 0)
  end)

  test("Differences arrays follow the PDF convention", function()
    local enc = pdf_text.encoding('WinAnsiEncoding')

    -- a number sets the code, each name after it takes the next one
    assert_equal(enc:apply_differences({ 65, 'eacute', 'germandbls', 90, 'space' }), 3)
    assert_equal(decode(enc, 'A'), 'é')
    assert_equal(decode(enc, 'B'), 'ß')
    assert_equal(decode(enc, 'Z'), ' ')
    assert_equal(decode(enc, 'C'), 'C')
  end)

  test("Glyph slot names carry no character", function()
    local enc = pdf_text.encoding('WinAnsiEncoding')

    assert_false(enc:set_difference(68, 'g42'))
    assert_false(enc:set_difference(68, 'cid7'))
    assert_equal(decode(enc, 'D'), 'D')

    assert_true(enc:set_difference(69, 'uni20AC'))
    assert_equal(decode(enc, 'E'), '€')
  end)

  test("Ill formed utf8 never reaches the buffer", function()
    local b = pdf_text.builder()

    assert_true(b:add_utf8('héllo'))
    assert_false(b:add_utf8('\169'))
    assert_equal(tostring(b:finish()), 'héllo')
  end)

  test("A builder keeps its encoding alive", function()
    local b = pdf_text.builder()

    b:set_encoding(pdf_text.encoding('WinAnsiEncoding'))
    collectgarbage('collect')
    collectgarbage('collect')

    assert_equal(decode(pdf_text.encoding('WinAnsiEncoding'), '\233'), 'é')
    b:add_encoded('\233')
    assert_equal(tostring(b:finish()), 'é')
  end)
end)
