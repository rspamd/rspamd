context('URL parsing for configured upstreams', function()
  local url = require 'rspamd_url'
  local helper = require 'rspamd_test_helper'
  local pool = rspamd_config:get_mempool()
  local cases = {
    {'https://llm.internal.lan/v1', 'llm.internal.lan', nil, 'https'},
    {'http://ollama:11434/api', 'ollama', 11434, 'http'},
    {'http://user:pw@llm.internal.lan:8080/x', 'llm.internal.lan', 8080, 'http', 'user'},
    {'https://user:p%40ss@127.0.0.1:8443/x', '127.0.0.1', 8443, 'https', 'user'},
    {'http://[::1]:11434/api', '::1', 11434, 'http'},
    {'https://user:pw@[::1]/api', '::1', nil, 'https', 'user'},
    {'http://[2001:db8::1]:8080/api', '2001:db8::1', 8080, 'http'},
    {'https://example.com/v1', 'example.com', nil, 'https'},
    {'http://llm.internal.lan/a(b),c?x=(v)#part)', 'llm.internal.lan', nil, 'http'},
    {'ftp://user:pw@files.internal.lan:2121/x', 'files.internal.lan', 2121, 'ftp', 'user'},
  }

  for _, loaded in ipairs({false, true}) do
    test('Parses endpoint components with TLDs loaded=' .. tostring(loaded), function()
      if loaded then
        helper.init_url_parser()
      else
        helper.ffi.C.rspamd_url_init(nil)
      end

      for _, c in ipairs(cases) do
        local parsed, err = url.parse(pool, c[1], {upstream = true})
        assert_not_nil(parsed, c[1] .. ': ' .. tostring(err))
        assert_equal(c[2], parsed:get_host())
        assert_equal(c[3], parsed:get_port())
        assert_equal(c[4], parsed:get_protocol())
        assert_equal(c[5], parsed:get_user())
        assert_equal(c[1], parsed:get_raw())
      end
      helper.init_url_parser()
    end)
  end

  test('Preserves text-extraction TLD policy', function()
    helper.init_url_parser()
    assert_nil(url.create(pool, 'https://llm.internal.lan/v1'))
    assert_nil(url.parse(pool, 'https://llm.internal.lan/v1'))
    assert_not_nil(url.parse('https://llm.internal.lan/v1', {upstream = true}))
    assert_not_nil(url.create(pool, 'text https://example.com/v1 text'))
  end)

  test('Rejects invalid or incomplete endpoints', function()
    for _, input in ipairs({
      '', 'not a url', 'http://', 'http:///path',
      'https:llm.internal.lan/x', 'https:/llm.internal.lan/x',
      'http://llm.internal.lan:65537/x', 'http://llm.internal.lan:abc/x',
      'http://[broken]/x', 'http://llm.internal.lan/x trailing text',
      'text https://example.com/x', 'http://llm.internal.lan/x\0suffix',
      'http://llm.internal.lan/' .. string.rep('x', 32768),
    }) do
      local parsed, err = url.parse(pool, input, {upstream = true})
      assert_nil(parsed)
      assert_equal('string', type(err))
    end
  end)
end)
