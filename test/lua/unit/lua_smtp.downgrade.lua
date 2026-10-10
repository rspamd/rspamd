-- lua_smtp.downgrade_to_7bit: RFC 6152 conversion for servers without 8BITMIME

context("lua_smtp 7bit downgrade", function()
  local lua_smtp = require "lua_smtp"
  local rspamd_util = require "rspamd_util"
  local rspamd_text = require "rspamd_text"

  -- telescope assertions only exist inside test bodies
  local function assert_7bit(str)
    assert(not string.find(str, '[\128-\255]'), str)
  end

  local function decode_qp(str)
    return rspamd_util.decode_qp(str):str()
  end

  test("7bit message is returned unchanged", function()
    local msg = 'Subject: x\r\n\r\nplain body\r\n'
    assert_equal(lua_smtp.downgrade_to_7bit(msg), msg)
  end)

  test("8bit single part is re-encoded as quoted-printable", function()
    local msg = 'Subject: x\nContent-Type: text/plain; charset=utf-8\n' ..
        'Content-Transfer-Encoding: 8bit\n\nGrüße\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    assert_not_nil(string.find(res, 'Content-Transfer-Encoding: quoted-printable', 1, true))
    assert_nil(string.find(res, '8bit', 1, true))
    local body = string.match(res, '\n\n(.*)$')
    assert_equal(decode_qp(body), 'Grüße\n')
  end)

  test("missing transfer encoding header is added", function()
    local res = lua_smtp.downgrade_to_7bit('Subject: x\r\n\r\nGrüße')
    assert_7bit(res)
    assert_not_nil(string.find(res, '^Subject: x\nContent%-Transfer%-Encoding: quoted%-printable\r\n\r\n'))
  end)

  test("rspamd_text and chunk arrays are accepted", function()
    local res = lua_smtp.downgrade_to_7bit(rspamd_text.fromstring('Subject: x\n\nGrüße'))
    assert_7bit(res)
    res = lua_smtp.downgrade_to_7bit({ 'Subject: x\n', rspamd_text.fromstring('\nGrü'), 'ße' })
    assert_7bit(res)
    assert_equal(decode_qp(string.match(res, '\n\n(.*)$')), 'Grüße')
  end)

  test("only 8bit leaves of a multipart are converted", function()
    local msg = table.concat({
      'Content-Type: multipart/mixed; boundary="b1"',
      '',
      'preamble',
      '--b1',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      'Grüße',
      '--b1',
      'Content-Type: multipart/alternative; boundary=b2',
      '',
      '--b2',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<p>Ä</p>',
      '--b2--',
      '--b1',
      'Content-Type: application/zip',
      'Content-Transfer-Encoding: base64',
      '',
      'AAEC',
      '--b1--',
      'epilogue',
    }, '\r\n')
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    -- structure and untouched parts survive byte for byte
    assert_not_nil(string.find(res, 'preamble\r\n--b1\r\n', 1, true))
    assert_not_nil(string.find(res, '\r\n--b1\r\nContent-Type: application/zip\r\n' ..
        'Content-Transfer-Encoding: base64\r\n\r\nAAEC\r\n--b1--\r\nepilogue', 1, true))
    assert_not_nil(string.find(res, 'Content-Transfer-Encoding: quoted-printable\r\n\r\nGr=C3=BC=C3=9Fe\r\n--b1', 1, true))
    assert_not_nil(string.find(res, 'text/html; charset=utf-8\nContent-Transfer-Encoding: quoted-printable' ..
        '\r\n\r\n<p>=C3=84</p>\r\n--b2--', 1, true))
  end)

  test("headerless body part gains a header block", function()
    local msg = 'Content-Type: multipart/mixed; boundary=b\n\n--b\n\nÄ\n--b--\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    assert_not_nil(string.find(res, '\n--b\nContent-Transfer-Encoding: quoted-printable\r\n\n=C3=84\n--b--', 1, true))
  end)

  test("embedded message is converted and marked 7bit", function()
    local msg = 'Content-Type: message/rfc822\nContent-Transfer-Encoding: 8bit\n\n' ..
        'Subject: inner\nContent-Transfer-Encoding: 8bit\n\nÖl\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    assert_not_nil(string.find(res, '^Content%-Type: message/rfc822\nContent%-Transfer%-Encoding: 7bit\n\n'))
  end)

  test("headerless digest entry is converted as an embedded message", function()
    local msg = 'Content-Type: multipart/digest; boundary=d\n\n--d\n\n' ..
        'Subject: inner\nContent-Type: text/plain; charset=utf-8\n' ..
        'Content-Transfer-Encoding: 8bit\n\nGrüße\n--d--\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    -- the entry stays headerless, the embedded message's own part is converted
    assert_not_nil(string.find(res, '\n--d\n\nSubject: inner\nContent-Type: text/plain; charset=utf-8\n' ..
        'Content-Transfer-Encoding: quoted-printable\n\nGr=C3=BC=C3=9Fe\n--d--', 1, true))
    assert_nil(string.find(res, '8bit', 1, true))
  end)

  test("typed digest entry keeps its own content type", function()
    local msg = 'Content-Type: multipart/digest; boundary=d\n\n--d\n' ..
        'Content-Type: text/plain; charset=utf-8\n\nÄ\n--d--\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    assert_not_nil(string.find(res, 'charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\n=C3=84\n--d--', 1, true))
  end)

  test("binary part becomes base64 and survives byte for byte", function()
    local payload = '\0\n\255\r\n\rA'
    local msg = 'Content-Type: multipart/mixed; boundary=b\n\n--b\n' ..
        'Content-Type: application/octet-stream\nContent-Transfer-Encoding: binary\n\n' ..
        payload .. '\n--b--\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    local b64 = string.match(res, 'Content%-Transfer%-Encoding: base64\n\n(.-)\n%-%-b%-%-')
    assert_not_nil(b64, res)
    assert_equal(rspamd_util.decode_base64(b64):str(), payload)
  end)

  test("boundary is taken from its own parameter only", function()
    local msg = 'Content-Type: multipart/mixed; name="; boundary=zz"; boundary="b1"\n\n' ..
        '--b1\nContent-Type: text/plain\n\nÄ\n--b1--\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    assert_not_nil(string.find(res, '=C3=84\n--b1--', 1, true))
  end)

  test("an outer delimiter ends an unterminated inner multipart", function()
    local msg = 'Content-Type: multipart/mixed; boundary=outer\n\n--outer\n' ..
        'Content-Type: multipart/alternative; boundary=inner\n\n--inner\n\nÄ\n' ..
        '--outer\nContent-Type: text/plain\n\nÖ\n--outer--\n'
    local res, err = lua_smtp.downgrade_to_7bit(msg)
    assert_not_nil(res, err)
    assert_7bit(res)
    assert_not_nil(string.find(res, '=C3=84\n--outer\nContent-Type: text/plain', 1, true))
    assert_not_nil(string.find(res, '=C3=96\n--outer--', 1, true))
  end)

  test("too deep nesting fails fast instead of recursing", function()
    local depth = 2000
    local parts = {}
    for i = 1, depth do
      parts[#parts + 1] = string.format('Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n', i, i)
    end
    parts[#parts + 1] = '\n' .. string.rep('x', 100000) .. 'Ä\n'
    for i = depth, 1, -1 do
      parts[#parts + 1] = string.format('--b%d--\n', i)
    end
    local start = os.clock()
    local res, err = lua_smtp.downgrade_to_7bit(table.concat(parts))
    assert_nil(res)
    assert_equal(err, 'MIME nesting is too deep')
    assert_true(os.clock() - start < 2.0, 'downgrade took too long')
  end)

  test("allowed nesting is converted in one pass", function()
    local depth = 60
    local parts = {}
    for i = 1, depth do
      parts[#parts + 1] = string.format('Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n', i, i)
    end
    parts[#parts + 1] = '\n' .. string.rep('x', 2000000) .. 'Ä\n'
    for i = depth, 1, -1 do
      parts[#parts + 1] = string.format('--b%d--\n', i)
    end
    local start = os.clock()
    local res, err = lua_smtp.downgrade_to_7bit(table.concat(parts))
    assert_not_nil(res, err)
    assert_7bit(res)
    assert_true(os.clock() - start < 2.0, 'downgrade took too long')
  end)

  local failures = {
    { '8-bit header', 'Subject: Grüße\n\nbody' },
    { '8-bit data in a base64 part', 'Content-Transfer-Encoding: base64\n\nÄ' },
    { 'multipart without boundary', 'Content-Type: multipart/mixed\n\n--x\n\nÄ\n--x--' },
    { '8-bit preamble', 'Content-Type: multipart/mixed; boundary=b\n\nÄ\n--b\n\nx\n--b--' },
    { '8-bit epilogue', 'Content-Type: multipart/mixed; boundary=b\n\n--b\n\nx\n--b--\nÄ' },
    { 'embedded message with 8-bit headers', 'Content-Type: message/rfc822\n\nSubject: Ä\n\nx' },
  }

  for _, c in ipairs(failures) do
    test("cannot downgrade: " .. c[1], function()
      local res, err = lua_smtp.downgrade_to_7bit(c[2])
      assert_nil(res)
      assert_equal(type(err), 'string')
    end)
  end
end)
