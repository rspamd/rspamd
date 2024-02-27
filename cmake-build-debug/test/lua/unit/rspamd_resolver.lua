-- Rspamd resolver Lua tests

context("Check punycoding UTF-8 URL", function()
  local rspamd_resolver = require "rspamd_resolver"
  local rspamd_util = require "rspamd_util"

  local resolver = rspamd_resolver.init(rspamd_util.create_event_base(), rspamd_config)

  local cases = {
    -- https://unicode.org/reports/tr46/#Deviations
    ['faß.de'] = 'fass.de', -- IDNA2008 result: xn--fa-hia.de
    ['βόλος.com'] = 'xn--nxasmq6b.com', -- IDNA2008 result: xn--nxasmm1c.com
    ['نامه‌ای.com'] = 'xn--mgba3gch31f.com', -- IDNA2008 result: xn--mgba3gch31f060k.com
    ['ශ්‍රී.com'] = 'xn--10cl1a0b.com', -- IDNA2008 result: xn--10cl1a0b660p.com 

    -- https://unicode.org/reports/tr46/#Table_Example_Processing
    ['日本語。ＪＰ'] = 'xn--wgv71a119e.jp', -- Fullwidth characters are remapped, including 。
    --['u¨.com'] = 'xn--tda.com', -- Normalize changes u + umlaut to ü
    ['☕.us'] = 'xn--53h.us', -- Post-Unicode 3.2 characters are allowed

    -- Other
    ['example.рф'] = 'example.xn--p1ai',
  }

  for k, v in pairs(cases) do
    test(string.format("punycode %s -> %s", k, v), function()
      local res = resolver:idna_convert_utf8(k)
      assert_equal(res, v)
    end)
  end
end)
