context("Lua arguments that are refused", function()
  local rspamd_ip = require "rspamd_ip"
  local rspamd_kann = require "rspamd_kann"
  local rspamd_ooxml = require "rspamd_ooxml"
  local rspamd_tensor = require "rspamd_tensor"
  local rspamd_test_helper = require "rspamd_test_helper"
  local rspamd_util = require "rspamd_util"

  -- How many times the registry holds `value`
  local function registry_refs(value)
    local n = 0

    for _, v in pairs(debug.getregistry()) do
      if rawequal(v, value) then
        n = n + 1
      end
    end

    return n
  end

  -- A config of its own, so that what a test adds does not stay in rspamd_config
  local function new_config()
    -- The assertions of the tests are not visible here
    return assert(rspamd_util.config_from_ucl(rspamd_test_helper.default_config(), 'INIT_LIBS'))
  end

  local map_url = 'http://127.0.0.1/map'

  -- A network of 2 inputs and 1 output, and the XOR function to train it on
  local function new_kann()
    local t = rspamd_kann.layer.input(2)
    t = rspamd_kann.layer.cost(rspamd_kann.layer.dense(t, 2), 1, rspamd_kann.cost.mse)

    return rspamd_kann.new.kann(t)
  end

  local xor_inputs = { { 0, 0 }, { 0, 1 }, { 1, 0 }, { 1, 1 } }
  local xor_outputs = { { 0 }, { 1 }, { 1 }, { 0 } }

  local word_story = [[
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body>
    </w:document>
  ]]

  test("a refused add_map releases its callback", function()
    local cb = function()
    end

    for _ = 1, 10 do
      -- The callback is taken before the type is found to be wrong
      local ok, err = pcall(rspamd_config.add_map, rspamd_config, {
        url = 'http://127.0.0.1/map',
        callback = cb,
        type = 1,
      })
      assert_false(ok)
      assert_not_nil(tostring(err):find('bad type for key: type', 1, true), tostring(err))
    end

    assert_equal(registry_refs(cb), 0)
  end)

  -- The argument parser takes a url that is nil as present: the call must
  -- raise an error that can be caught instead of stopping the process
  test("add_map without a url", function()
    local cb = function()
    end

    for _ = 1, 10 do
      local ok, err = pcall(rspamd_config.add_map, rspamd_config, {
        type = 'set',
        callback = cb,
      })
      assert_false(ok)
      assert_not_nil(tostring(err):find('required parameter url is missing', 1, true),
          tostring(err))
    end

    assert_equal(registry_refs(cb), 0)
  end)

  -- Only a callback map calls the function: a map of another type, added or
  -- refused, keeps no reference to it
  test("add_map of a type that takes no callback", function()
    local cfg = new_config()
    local cb = function()
    end

    for _ = 1, 3 do
      assert_not_nil(cfg:add_map({ url = map_url, type = 'set', callback = cb }))

      local ok, err = pcall(cfg.add_map, cfg, { url = map_url, type = 'bogus', callback = cb })
      assert_false(ok)
      assert_not_nil(tostring(err):find("unknown type 'bogus'", 1, true), tostring(err))
    end

    assert_equal(registry_refs(cb), 0)
  end)

  test("add_map with neither a type nor a callback", function()
    for _ = 1, 3 do
      local ok, err = pcall(rspamd_config.add_map, rspamd_config, { url = map_url })
      assert_false(ok)
      assert_not_nil(tostring(err):find('invalid map type', 1, true), tostring(err))
    end
  end)

  -- The callback is called only while the network is trained
  test("kann train1 releases its callback", function()
    local k = new_kann()
    local calls = 0
    local cb = function()
      calls = calls + 1
    end

    for _ = 1, 3 do
      local ok, err = pcall(k.train1, k, xor_inputs, xor_outputs,
          { max_epoch = 2, mini_size = 4, cb = cb })
      assert_true(ok, tostring(err))
    end

    assert_true(calls > 0)
    assert_equal(registry_refs(cb), 0)
  end)

  -- Refused after the options have been parsed, with the callback taken
  test("kann train1 refused after its options", function()
    local k = new_kann()
    local cb = function()
    end
    local refused = {
      { { { 0, 0, 0 } }, { { 0 } }, {}, 'bad input dimension 3; 2 expected' },
      { { { 0, 0 } }, { { 0, 0 } }, {}, 'bad output dimension 2; 1 expected' },
      { xor_inputs, xor_outputs, { pca = rspamd_tensor.new(1, 2) },
        'invalid pca tensor: matrix expected, got a row' },
      { xor_inputs, xor_outputs, { pca = rspamd_tensor.new(2, 3, 2) },
        'matrix must have 2 rows and it has 3 rows instead' },
    }

    for _, args in ipairs(refused) do
      local opts = args[3]
      opts.cb = cb

      for _ = 1, 3 do
        local ok, err = pcall(k.train1, k, args[1], args[2], opts)
        assert_false(ok)
        assert_not_nil(tostring(err):find(args[4], 1, true), tostring(err))
      end
    end

    assert_equal(registry_refs(cb), 0)
  end)

  test("kann train1 with options that the argument parser refuses", function()
    local k = new_kann()

    for _ = 1, 3 do
      local ok, err = pcall(k.train1, k, xor_inputs, xor_outputs, { cb = 5 })
      assert_false(ok)
      assert_not_nil(tostring(err):find('invalid params: ', 1, true), tostring(err))
    end
  end)

  -- A symbol registered twice keeps the callback of the first registration
  -- only, in every form of register_symbol
  test("register_symbol of a symbol that exists", function()
    local cfg = new_config()
    local cb = function()
    end

    cfg:register_symbol('LUA_ARGUMENT_ERRORS_DUP', 1.0, cb)
    assert_equal(registry_refs(cb), 1)

    for _ = 1, 5 do
      local ok, err = pcall(cfg.register_symbol, cfg, 'LUA_ARGUMENT_ERRORS_DUP', 1.0, cb)
      assert_false(ok)
      assert_not_nil(tostring(err):find('bad arguments', 1, true), tostring(err))

      -- A table returns -1
      ok, err = pcall(cfg.register_symbol, cfg, {
        name = 'LUA_ARGUMENT_ERRORS_DUP',
        callback = cb,
      })
      assert_true(ok, tostring(err))
      assert_equal(err, -1)

      -- An optional one returns the id of the symbol that exists
      ok, err = pcall(cfg.register_symbol, cfg, {
        name = 'LUA_ARGUMENT_ERRORS_DUP',
        callback = cb,
        optional = true,
      })
      assert_true(ok, tostring(err))
      assert_equal(type(err), 'number')
    end

    assert_equal(registry_refs(cb), 1)
  end)

  test("replace_regexp with parameters that the argument parser refuses", function()
    for _ = 1, 3 do
      local ok, err = pcall(rspamd_config.replace_regexp, rspamd_config, { pcre_only = true })
      assert_false(ok)
      assert_not_nil(tostring(err):find('cannot get parameters list: ', 1, true), tostring(err))

      ok, err = pcall(rspamd_config.replace_regexp_scoped, rspamd_config, 'scope',
          { pcre_only = true })
      assert_false(ok)
      assert_not_nil(tostring(err):find('cannot get parameters list: ', 1, true), tostring(err))
    end
  end)

  test("OOXML story content that is a userdata of another class", function()
    local ok, extracted, err, tokens = pcall(rspamd_ooxml.extract, {
      { content = word_story, relationships = {} },
      { content = rspamd_ip.from_string('127.0.0.1'), relationships = {} },
    }, {})

    assert_true(ok, tostring(extracted))
    assert_nil(extracted)
    assert_not_nil(err:find('invalid OOXML story content', 1, true), err)
    assert_true(tokens > 0)
  end)

  -- Each entry is refused by the argument parser (id is not a string). The
  -- stack of the call is checked with AddressSanitizer on PUC Lua only
  test("OOXML relationships refused by the argument parser", function()
    local list = {}

    for i = 1, 1000 do
      list[i] = { id = i, type = 'x', target = 'y', external = true }
    end

    local extracted, err = rspamd_ooxml.extract({
      { content = word_story, relationships = { list = list } },
    }, {})

    assert_nil(err)
    assert_not_nil(extracted)
    assert_not_nil(tostring(extracted.text):find('Hello', 1, true))
  end)

  -- The body of the coroutine is register_monitored itself: no Lua function
  -- calls it, so there is no caller to take the location from. Uninitialised
  -- data used there is seen with a sanitizer only
  test("register_monitored without a Lua caller", function()
    local ok, m = pcall(coroutine.wrap(rspamd_config.register_monitored), rspamd_config,
        'monitored-without-caller.example.com', 'dns')

    assert_true(ok, tostring(m))
    assert_equal(type(m), 'userdata')
  end)
end)
