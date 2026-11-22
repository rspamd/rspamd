local util  = require 'lua_util'

context("Lua util - callback_from_string", function()
  local cases = {
    {'return function', 'return function(a, b) return a + b end'},
    {'function', 'function(a, b) return a + b end'},
    {'plain ops', 'local c = select(1, ...)\nreturn c + select(2, ...)'},
  }
  -- Wrapped in {label, value} pairs: a bare nil first element would end the
  -- ipairs walk immediately and silently register none of these as tests
  local fail_cases = {
    { 'nil', nil },
    { 'empty string', '' },
    { 'return function syntax error', 'return function(a, b) ( end' },
    { 'function syntax error', 'function(a, b) ( end' },
  }

  for _,c in ipairs(cases) do
    test('Success case: ' .. c[1], function()
      local ret,f = util.callback_from_string(c[2])
      assert_true(ret, f)
      assert_equal(f(2, 2), 4)
    end)
  end
  for _,c in ipairs(fail_cases) do
    test('Failure case: ' .. c[1], function()
      local ret,err = util.callback_from_string(c[2])
      assert_false(ret)
      assert_equal(type(err), 'string')
    end)
  end

  -- A bare expression is wrapped into 'return function(...) <s>; end', so it
  -- compiles even when it references undefined globals: the error surfaces on
  -- the first call, not at load time
  test('a bare expression compiles into a callback that may fail when called', function()
    local ret, f = util.callback_from_string('return a + b')
    assert_true(ret, f)
    assert_false((pcall(f)))
  end)

  test('chunkname appears in syntax error message', function()
    local ret, err = util.callback_from_string('return function(a, b) ( end', 'my_chunk')
    assert_false(ret)
    assert_not_nil(string.find(err, 'my_chunk', 1, true), err)
  end)

  test('whole chunk may set up locals before returning a callback', function()
    local ret, callback = util.callback_from_string(
      'local offset = 3\nreturn function(value) return value + offset end',
      'setup_chunk', true)
    assert_true(ret, callback)
    assert_equal(callback(2), 5)
  end)

  test('non-string input is rejected without throwing', function()
    local ok, ret, err = pcall(util.callback_from_string, {}, 'bad_chunk', true)
    assert_true(ok)
    assert_false(ret)
    assert_equal(err, 'invalid or empty string')
  end)

  -- A valid chunk that yields no callback must report a string error: callers
  -- feed the second return value straight into string.format('%s', ...), which
  -- throws on nil or on a table under LuaJIT
  for _, c in ipairs({
    { 'nothing', 'local x = 1', 'nil' },
    { 'a table', 'return { 1, 2 }', 'table' },
    { 'a string', 'return "not a function"', 'string' },
  }) do
    test('chunk returning ' .. c[1] .. ' yields a string error', function()
      local ret, err = util.callback_from_string(c[2], 'no_callback_chunk', true)
      assert_false(ret)
      assert_equal(type(err), 'string')
      assert_not_nil(string.find(err, c[3], 1, true), err)
    end)
  end

  test('runtime error inside the chunk yields a string error', function()
    local ret, err = util.callback_from_string('error("boom")', 'boom_chunk', true)
    assert_false(ret)
    assert_equal(type(err), 'string')
    assert_not_nil(string.find(err, 'boom', 1, true), err)
  end)
end)

context('Lua util - HTTP endpoint upstreams', function()
  test('Uses parsed host and port independently of TLD state', function()
    local helper = require 'rspamd_test_helper'
    local upstream_list = require 'rspamd_upstream_list'
    local original_create = upstream_list.create
    local original_lupa = package.loaded.lupa
    local calls = {}
    upstream_list.create = function(cfg, host, port)
      calls[#calls + 1] = {cfg, host, port}
      return {}
    end

    local ok, err = pcall(function()
      -- Separate module instances prevent the URL cache from hiding a
      -- dependency on parser initialization in the second pass.
      for _, loaded in ipairs({false, true}) do
        if loaded then
          helper.init_url_parser()
        else
          helper.ffi.C.rspamd_url_init(nil)
        end
        -- lua_util configures its own template engine; do not reconfigure
        -- the instance already held by other test modules.
        package.loaded.lupa = nil
        local fresh_util = dofile(rspamd_paths.LUALIBDIR .. '/lua_util.lua')
        package.loaded.lupa = original_lupa
        for _, c in ipairs({
          {'https://llm.internal.lan/v1', 'llm.internal.lan', 443},
          {'http://user:pw@llm.internal.lan:8080/x', 'llm.internal.lan', 8080},
          {'http://ollama/api', 'ollama', 80},
          {'http://127.0.0.1:11434/api', '127.0.0.1', 11434},
          {'http://[::1]:11434/api', '[::1]', 11434},
        }) do
          local result = fresh_util.http_upstreams_by_url(rspamd_config:get_mempool(), c[1], rspamd_config)
          assert_not_nil(result)
          assert_equal(rspamd_config, calls[#calls][1])
          assert_equal(c[2], calls[#calls][2])
          assert_equal(c[3], calls[#calls][3])
        end
        local n = #calls
        for _, input in ipairs({'not a url', 'http://llm.internal.lan:65537/x', 'ftp://files.internal.lan/x'}) do
          assert_nil(fresh_util.http_upstreams_by_url(rspamd_config:get_mempool(), input, rspamd_config))
        end
        assert_equal(n, #calls)
      end
    end)
    upstream_list.create = original_create
    package.loaded.lupa = original_lupa
    helper.init_url_parser()
    if not ok then
      error(err)
    end
  end)

  test('Creates numeric upstreams with the requested port', function()
    for _, c in ipairs({
      {'http://127.0.0.1:11434/api', '127.0.0.1'},
      {'http://[::1]:11434/api', '::1'},
    }) do
      local upstreams = util.http_upstreams_by_url(rspamd_config:get_mempool(), c[1], rspamd_config)
      assert_not_nil(upstreams)
      local all = upstreams:all_upstreams()
      assert_equal(1, #all)
      assert_equal(11434, all[1]:get_port())
      assert_equal(c[2], all[1]:get_addr():to_string())
    end
  end)
end)

context("Lua util - str_endswith", function()
  local ending = {
    {'a', 'a'},
    {'ab', 'b'},
    {'ab', 'ab'},
    {'abc', 'bc'},
    {'any', ''},
  }
  local not_ending = {
    {'a', 'b'},
    {'', 'a'},
    {'ab', 'a'},
    {'ab', 'ba'},
    {'ab', 'lab'},
    {'abc', 'ab'},
    {'abcd', 'bc'},
    {'a', 'A'},
    {'aB', 'b'},
  }
  for _, c in ipairs(ending) do
    test(string.format('True case: str_endswith("%s", "%s")', c[1], c[2]), function()
      assert_true(util.str_endswith(c[1], c[2]))
    end)
  end
  for _, c in ipairs(not_ending) do
    test(string.format('False case: str_endswith("%s", "%s")', c[1], c[2]), function()
      assert_false(util.str_endswith(c[1], c[2]))
    end)
  end
end)

context("Lua util - parse_time_interval", function()
  -- good: {input, expected seconds}; bad: {label, input}; wrapped in
  -- pairs because a nil input would end an ipairs walk
  local good = {
    { '42', 42 }, { '0', 0 }, { '10s', 10 }, { '10S', 10 },
    { '500ms', 0.5 }, { '500MS', 0.5 }, { '500Ms', 0.5 }, { '500mS', 0.5 },
    { '10m', 600 }, { '10M', 600 },
    { '1min', 60 }, { '1MIN', 60 }, { '2Min', 120 },
    { '1h', 3600 }, { '1H', 3600 },
    { '1d', 86400 }, { '1D', 86400 },
    { '1w', 604800 }, { '1W', 604800 },
    { '1y', 31536000 }, { '1Y', 31536000 },
    { '1.5h', 5400 }, { '.5s', 0.5 }, { '+.5s', 0.5 }, { '-.5s', -0.5 },
    { '+2d', 172800 }, { '-1s', -1 }, { '2.5', 2.5 },
    { ' 10 s ', 10 }, { '\t10m\n', 600 }, { '10 ms', 0.01 },
    { 42, 42 }, { 1.5, 1.5 }, { 0, 0 }, { -3, -3 },
    { '7days', 604800 }, { '1day', 86400 }, { '1hour', 3600 }, { '2hours', 7200 },
    { '30sec', 30 }, { '30secs', 30 }, { '1 second', 1 }, { '5 Seconds', 5 },
    { '10mins', 600 }, { '10minutes', 600 }, { '1minute', 60 },
    { '2weeks', 1209600 }, { '1week', 604800 }, { '1year', 31536000 },
    { '2Years', 63072000 },
  }
  local bad = {
    { 'empty string', '' }, { 'spaces', ' ' }, { 'unit only', 'ms' },
    { 'unknown unit', '10x' }, { 'two units', '10 m s' }, { 'compound', '1h30m' },
    { 'garbage', 'abc' }, { 'comma', '1,5s' }, { 'exponent', '1e3' },
    { 'trailing text', '10minutesx' }, { 'month', '1month' }, { 'msec', '5msec' },
    { 'huge digits', string.rep('9', 500) }, { 'huge with unit', string.rep('9', 500) .. 's' },
    { 'huge ms', string.rep('9', 500) .. 'ms' },
    { 'too large', '9007199254740993' }, { 'too large minutes', '307445734561825861m' }, { 'trailing dot text', '10s.' },
    { 'double sign', '+-1' }, { 'sign only', '-' }, { 'dot only', '.' },
    { 'nil', nil }, { 'true', true }, { 'false', false }, { 'table', {} },
  }

  for _, c in ipairs(good) do
    test(string.format('parses %s "%s"', type(c[1]), (tostring(c[1]):gsub('%c', '_'))), function()
      local res = util.parse_time_interval(c[1])
      assert_equal(type(res), 'number')
      assert_true(math.abs(res - c[2]) < 1e-9,
          string.format('%s: expected %s, got %s', tostring(c[1]), c[2], res))
    end)
  end
  for _, c in ipairs(bad) do
    test('rejects ' .. c[1], function()
      assert_equal(util.parse_time_interval(c[2]), nil)
    end)
  end
end)
