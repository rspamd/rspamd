-- Rspamd resolver Lua tests

context("Check punycoding UTF-8 URL", function()
  local rspamd_resolver = require "rspamd_resolver"
  local rspamd_util = require "rspamd_util"

  local resolver = rspamd_resolver.init(rspamd_util.create_event_base(), rspamd_config)

  -- Helper function to detect IDNA behavior by testing a known conversion
  local function detect_idna_behavior()
    -- Use faß.de as a test case - different results in IDNA2003 vs IDNA2008
    local test_result = resolver:idna_convert_utf8('faß.de')
    if test_result == 'fass.de' then
      return 'transitional' -- IDNA2003/transitional behavior
    elseif test_result == 'xn--fa-hia.de' then
      return 'nontransitional' -- IDNA2008/nontransitional behavior
    else
      return 'unknown'
    end
  end

  local idna_behavior = detect_idna_behavior()

  -- Define test cases with both expected results
  local cases_transitional = {
    -- IDNA2003/transitional results (ICU < 76 default)
    ['faß.de'] = 'fass.de',
    ['βόλος.com'] = 'xn--nxasmq6b.com',
    ['نامه‌ای.com'] = 'xn--mgba3gch31f.com',
    ['ශ්‍රී.com'] = 'xn--10cl1a0b.com',
    ['日本語。ＪＰ'] = 'xn--wgv71a119e.jp',
    ['☕.us'] = 'xn--53h.us',
    ['example.рф'] = 'example.xn--p1ai',
  }

  local cases_nontransitional = {
    -- IDNA2008/nontransitional results (ICU >= 76 default)
    ['faß.de'] = 'xn--fa-hia.de',
    ['βόλος.com'] = 'xn--nxasmm1c.com',
    ['نامه‌ای.com'] = 'xn--mgba3gch31f060k.com',
    ['ශ්‍රී.com'] = 'xn--10cl1a0b660p.com',
    ['日本語。ＪＰ'] = 'xn--wgv71a119e.jp',
    ['☕.us'] = 'xn--53h.us',
    ['example.рф'] = 'example.xn--p1ai',
  }

  -- Choose appropriate test cases based on detected behavior
  local cases
  if idna_behavior == 'transitional' then
    cases = cases_transitional
    print("Detected IDNA transitional behavior (ICU < 76 or configured for IDNA2003)")
  elseif idna_behavior == 'nontransitional' then
    cases = cases_nontransitional
    print("Detected IDNA nontransitional behavior (ICU >= 76 default)")
  else
    error("Could not detect IDNA behavior - unexpected result for test case")
  end

  for k, v in pairs(cases) do
    test(string.format("punycode %s -> %s (%s)", k, v, idna_behavior), function()
      local res = resolver:idna_convert_utf8(k)
      assert_equal(res, v)
    end)
  end
end)
