-- Text extraction from PDF content streams (lua_content/pdf)

context("PDF content extraction", function()
  local rspamd_text = require "rspamd_text"
  local pdf = require "lua_content/pdf"

  -- Builds a minimal one page PDF around a content stream, with a real xref so
  -- the parser sees a well formed file. Fonts is a raw dictionary body.
  local function make_pdf(stream, fonts)
    local objs = {
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      string.format('<< /Type /Page /Parent 2 0 R /Resources << /Font << %s >> >> /Contents 4 0 R >>',
        fonts),
      string.format('<< /Length %d >>\nstream\n%s\nendstream', #stream, stream),
    }

    -- Font objects start at 5
    objs[#objs + 1] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'
    objs[#objs + 1] = '<< /Type /Font /Subtype /Type1 /BaseFont /Times /Encoding /MacRomanEncoding >>'
    objs[#objs + 1] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding ' ..
        '<< /BaseEncoding /WinAnsiEncoding /Differences [65 /eacute /germandbls] >> >>'

    local out = { '%PDF-1.4\n' }
    local pos = #out[1]
    local offsets = {}

    for i, o in ipairs(objs) do
      local chunk = string.format('%d 0 obj\n%s\nendobj\n', i, o)
      offsets[i] = pos
      out[#out + 1] = chunk
      pos = pos + #chunk
    end

    local xref = pos
    out[#out + 1] = string.format('xref\n0 %d\n0000000000 65535 f \n', #objs + 1)

    for _, off in ipairs(offsets) do
      out[#out + 1] = string.format('%010d 00000 n \n', off)
    end

    out[#out + 1] = string.format('trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n',
      #objs + 1, xref)

    return rspamd_text.fromstring(table.concat(out))
  end

  local function extract(stream, fonts)
    local res = pdf.process(make_pdf(stream, fonts), nil, {})
    local texts = {}

    if type(res) == 'table' and res.objects then
      for _, obj in ipairs(res.objects) do
        if obj.text then
          texts[#texts + 1] = tostring(obj.text)
        end
      end
    end

    return table.concat(texts, '')
  end

  -- A content stream has to begin with something before BT: the parser trims the
  -- end of line that follows the stream keyword
  local prologue = 'q 1 0 0 1 0 0 cm\n'

  test("Character codes are decoded with the font that drew them", function()
    -- 0xe9 and 0xdf are eacute and germandbls in WinAnsi, 0xde is the fi
    -- ligature in MacRoman
    local text = extract(prologue ..
      'BT /F1 12 Tf (caf\233 stra\223e) Tj T* /F2 12 Tf (\222) Tj ET\nQ\n',
      '/F1 5 0 R /F2 6 0 R')

    assert_not_nil(text:find('café', 1, true), 'WinAnsi eacute, got: ' .. text)
    assert_not_nil(text:find('straße', 1, true), 'WinAnsi germandbls, got: ' .. text)
    assert_not_nil(text:find('ﬁ', 1, true), 'MacRoman fi ligature, got: ' .. text)
  end)

  test("Hex strings go through the same encoding", function()
    local text = extract(prologue .. 'BT /F1 12 Tf <41E9> Tj ET\nQ\n', '/F1 5 0 R')

    assert_not_nil(text:find('Aé', 1, true), 'hex string, got: ' .. text)
  end)

  test("A Differences array overrides the base encoding", function()
    -- 65 is remapped to eacute, so 66 takes germandbls and 67 stays a C
    local text = extract(prologue .. 'BT /F3 12 Tf (ABC) Tj ET\nQ\n', '/F3 7 0 R')

    assert_not_nil(text:find('éßC', 1, true), 'differences, got: ' .. text)
  end)

  test("Plain ascii text is unaffected", function()
    local text = extract(prologue ..
      'BT /F1 12 Tf (Hello, world) Tj ET\nQ\n', '/F1 5 0 R')

    assert_not_nil(text:find('Hello, world', 1, true), 'ascii, got: ' .. text)
  end)
end)
