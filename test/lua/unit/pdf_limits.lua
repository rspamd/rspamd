-- Resource limits and error isolation in the PDF, calendar and OOXML handlers

context("Content handlers limits", function()
  local rspamd_text = require "rspamd_text"
  local pdf = require "lua_content/pdf"

  local function build(objs)
    local out = { '%PDF-1.4\n' }
    local pos = #out[1]
    local offsets = {}

    for i, o in ipairs(objs) do
      local chunk = string.format('%d 0 obj\n%s\nendobj\n', i, o)
      offsets[i] = pos
      out[#out + 1] = chunk
      pos = pos + #chunk
    end

    out[#out + 1] = string.format('xref\n0 %d\n0000000000 65535 f \n', #objs + 1)

    for _, off in ipairs(offsets) do
      out[#out + 1] = string.format('%010d 00000 n \n', off)
    end

    out[#out + 1] = string.format('trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n',
        #objs + 1, pos)

    return rspamd_text.fromstring(table.concat(out))
  end

  local function stream(data, dict)
    return string.format('<< %s /Length %d >>\nstream\n%s\nendstream', dict or '', #data, data)
  end

  -- A zlib stream of one stored block: what a deflate filter accepts without
  -- any compressor at hand
  local function zlib_stored(data)
    assert(#data < 65536)
    local a, b = 1, 0

    for i = 1, #data do
      a = (a + data:byte(i)) % 65521
      b = (b + a) % 65521
    end

    local len = #data
    local nlen = 65535 - len

    return table.concat {
      '\120\1\1',
      string.char(len % 256, math.floor(len / 256), nlen % 256, math.floor(nlen / 256)),
      data,
      string.char(math.floor(b / 256), b % 256, math.floor(a / 256), a % 256),
    }
  end

  local function tohex(data)
    return (data:gsub('.', function(c)
      return string.format('%02x', c:byte())
    end))
  end

  local js = string.rep("app.alert('hello world this is js');", 10)
  local catalog = '<< /Type /Catalog /Pages 2 0 R >>'
  local pages = '<< /Type /Pages /Kids [] /Count 0 >>'
  local js_action = '<< /Type /Action /S /JavaScript /JS (' .. js .. ') >>'

  local function process(objs)
    return pdf.process(build(objs), nil, {})
  end

  test("A stream behind a deflate filter is decoded", function()
    local res = process({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>',
                          stream(zlib_stored(js), '/Filter /FlateDecode') })
    assert_true(res.scripts)
    assert_nil(res.flags.decode_limit)
  end)

  test("A chain of two filters is decoded", function()
    local res = process({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>',
                          stream(tohex(zlib_stored(js)) .. '>', '/Filter [/ASCIIHexDecode /FlateDecode]') })
    assert_true(res.scripts)
    assert_nil(res.flags.decode_limit)
  end)

  test("A chain of more filters than a real file uses is refused", function()
    local data = js
    local names = {}

    for i = 1, 8 do
      data = zlib_stored(data)
      names[i] = '/FlateDecode'
    end

    local res = process({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>',
                          stream(data, '/Filter [' .. table.concat(names, ' ') .. ']') })
    assert_true(res.flags.decode_limit)
  end)

  test("The output of the filters is budgeted over the file", function()
    -- A megabyte of zeroes takes about a kilobyte of deflate, as a run of
    -- stored blocks cannot show: ask for more than the budget in small pieces
    local objs = { catalog, pages }
    local piece = zlib_stored(string.rep('1 0 ', 16000))

    for _ = 1, 600 do
      objs[#objs + 1] = stream(piece, '/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode')
    end

    local saved = pdf.config.max_decoded_size
    pdf.config.max_decoded_size = 1024 * 1024
    local res = process(objs)
    pdf.config.max_decoded_size = saved
    assert_true(res.flags.decode_limit)
  end)

  test("An ASCIIHexDecode stream is decoded", function()
    local res = process({ catalog, pages, '<< /Type /Action /S /JavaScript /JS 4 0 R >>',
                          stream(tohex(js):gsub('(........)', '%1 \n') .. '>', '/Filter /ASCIIHexDecode') })
    assert_true(res.scripts)
  end)

  test("A stream that fails to decode does not hide the objects after it", function()
    local res = process({ stream('31203020zz>', '/Type /ObjStm /N 1 /First 4 /Filter /ASCIIHexDecode'),
                          catalog, pages, js_action })
    assert_true(res.scripts)
  end)

  test("An array of strings is not an indirect reference", function()
    local res = process({ '<< /Type /Page /Resources [(%REF%) (a) (b)] /Contents [(%REF%) (x) (y)] >>',
                          stream('1 0 ', '/Type /ObjStm /N [(%REF%) (a) (b)] /First [(%REF%) (a) (b)]'),
                          catalog, pages, js_action })
    assert_true(res.scripts)
    assert_nil(res.flags.object_errors)
  end)

  test("An octal escape over 255 does not lose the dictionary", function()
    local res = process({ catalog, pages,
                          '<< /Type /Action /S /JavaScript /Pad (\\777\\400) /JS (' .. js .. ') >>' })
    assert_true(res.scripts)
  end)

  test("An object stream gives its members", function()
    local members = '<< /Type /Action /S /JavaScript /JS (' .. js .. ') >>'
    local header = '10 0 '
    local res = process({ catalog, pages,
                          stream(zlib_stored(header .. members),
                              string.format('/Type /ObjStm /N 1 /First %d /Filter /FlateDecode', #header)) })
    assert_true(res.scripts)
  end)

  test("An object stream gives no more members than it declares", function()
    local header = string.rep('7 0 ', 5000)
    local res = process({ catalog, pages,
                          stream(header .. '<< /Type /Font >>',
                              string.format('/Type /ObjStm /N 2 /First %d', #header)) })
    -- Three outer objects and at most two members
    assert_true(#res.objects <= 5, string.format('%d objects', #res.objects))
  end)

  test("The text of the pages is budgeted by what is written", function()
    -- One code becomes 128 characters, and every page decodes the same stream
    local cmap = 'begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n' ..
        '1 beginbfchar <0041> <' .. string.rep('0061', 128) .. '> endbfchar\nendcmap\n'
    local body = 'q\n' .. string.rep('BT /F1 12 Tf (' .. string.rep('\0A', 7000) .. ') Tj ET\n', 2) .. 'Q\n'
    local objs = { catalog, false, stream(body),
                   '<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /ToUnicode 5 0 R >>',
                   stream(cmap) }
    local kids = {}

    for i = 1, 8 do
      objs[#objs + 1] = '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 3 0 R >>'
      kids[i] = (5 + i) .. ' 0 R'
    end

    objs[2] = '<< /Type /Pages /Kids [' .. table.concat(kids, ' ') .. '] /Count 8 >>'

    local res = process(objs)
    local total = 0

    for _, obj in ipairs(res.objects) do
      if obj.text then
        total = total + #obj.text
      end
    end

    assert_true(total > 0)
    assert_true(total <= pdf.config.max_extracted_text_size, string.format('%d bytes of text', total))
    assert_true(res.flags.text_truncated)
  end)

  test("A calendar keeps a bounded number of properties", function()
    local ical = require "lua_content/ical"
    local pool = require("rspamd_mempool").create()
    local task = {
      get_mempool = function()
        return pool
      end,
      inject_url = function()
      end,
    }
    local small = ical.process("BEGIN:VCALENDAR\r\nSUMMARY:hello\r\nEND:VCALENDAR\r\n", nil, task)
    assert_equal(3, #small.elts)
    assert_equal('summary', small.elts[2][1])
    assert_equal('hello', small.elts[2][2])
    assert_nil(small.truncated)

    local big = ical.process("BEGIN:VCALENDAR\r\n" .. string.rep("X:1\r\n", 50000), nil, task)
    assert_equal(10000, #big.elts)
    assert_true(big.truncated)
    pool:destroy()
  end)

  test("An OOXML package is not looked for inside a compressed stream", function()
    local archive = require "archive"
    local zip = archive.zip({ { name = 'a.txt', content = 'hello' } })
    local plain = archive.unpack(zip, 'zip', nil, { filters = false })
    assert_equal(1, #plain)
    assert_equal('hello', tostring(plain[1].content))

    local wrapped = require("rspamd_util").gzip_compress(zip)
    -- With the filters it is found, which is what the option turns off
    local found = archive.unpack(wrapped, 'zip')
    assert_equal(1, #found)
    assert_false(pcall(archive.unpack, wrapped, 'zip', nil, { filters = false }))
  end)
end)
