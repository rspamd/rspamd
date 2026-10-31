-- rspamd_util.is_valid_smtputf8_address: the binding of the
-- draft-ietf-mailmaint-smtputf8-syntax checker. The C++ unit tests cover
-- the rules themselves; these cover what Lua sees.

context("SMTPUTF8 address syntax", function()
  local rspamd_util = require "rspamd_util"

  -- Lua 5.1 has no \u{} escapes, so invisible code points are bytes
  local rlo = '\226\128\174' -- U+202E RIGHT-TO-LEFT OVERRIDE
  local nfd_cafe = 'cafe\204\129' -- e followed by U+0301

  local cases = {
    { 'gøril', 'example.com', false, true },
    { 'info', '例子.中国', false, true },
    { 'john doe', 'example.com', true, true },
    { 'xn--gr-zia', 'example.com', true, true },
    { 'xn--gr-zia', 'example.com', false, false, 'a-label' },
    { 'xn--gr-zia', 'grå.org', false, false, 'a-label' },
    { 'cel·la', 'example.com', false, true },
    { 'CEL·LA', 'example.com', false, false, 'code point' },
    { 'cel·La', 'example.com', false, false, 'code point' },
    { 'ceL·la', 'example.com', false, false, 'code point' },
    { 'ali' .. rlo .. 'moc.elpmaxe', 'kravdraa.ec', false, false, 'code point' },
    { '阿Q正传', 'dømi.fo', false, false, 'mixed scripts' },
    { nfd_cafe, 'example.com', false, false, 'not NFC' },
    { 'gr\229', 'example.com', false, false, 'invalid UTF-8' },
  }

  for _, c in ipairs(cases) do
    test(string.format('%s@%s (quoted: %s)', c[1], c[2], tostring(c[3])), function()
      local valid, reason = rspamd_util.is_valid_smtputf8_address(c[1], c[2], c[3])
      assert_equal(valid, c[4])
      assert_equal(reason, c[5])
    end)
  end

  test('the NFC and NFD forms differ in the source', function()
    assert_equal(#nfd_cafe, #'café' + 1)
  end)

  test('the quoted argument is optional', function()
    assert_equal(rspamd_util.is_valid_smtputf8_address('xn--gr-zia', 'example.com'), false)
  end)
end)
