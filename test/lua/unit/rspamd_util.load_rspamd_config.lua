context("rspamd_util.load_rspamd_config", function()
  local rspamd_util = require "rspamd_util"

  -- Globals that the config read sets in this Lua state. The tests use _G:
  -- a global assigned in this file lands in the environment of the file
  local globals = { 'rspamd_config', 'config', 'metrics', 'composites', 'classifiers',
                    'rspamd_classifiers', 'rspamd_maps', 'rspamd_paths', 'rspamd_env',
                    'rspamd_version' }
  local base = os.tmpname()
  local files = {}

  local function write_file(suffix, content)
    local path = base .. suffix
    local f = assert(io.open(path, 'w'))
    f:write(content)
    f:close()
    files[#files + 1] = path

    return path
  end

  -- The Lua code of the configs changes what the caller sees unless the
  -- globals are given back
  local probe_lua = [[
config['probe'] = { x = 1 }
rspamd_maps = { probe = true }
rspamd_config:register_symbol({
  name = 'LOAD_CONFIG_PROBE',
  score = 1.0,
  callback = function()
    return true
  end,
})
]]
  local good_conf = write_file('_good.conf', string.format(
      'lua = "%s";\nprobe_section { a = 1; }\n', write_file('_good.lua', probe_lua)))
  local lua_error_conf = write_file('_lua_error.conf', string.format('lua = "%s";\n',
      write_file('_lua_error.lua', probe_lua .. "error('the config fails on purpose')\n")))
  local bad_conf = write_file('_bad.conf', 'options { dns_timeout = "not a time"; }\n')
  local missing_conf = base .. '_missing.conf'

  local function save_globals()
    local saved = {}

    for _, name in ipairs(globals) do
      saved[name] = _G[name]
    end

    return saved
  end

  -- Names of the globals that are not the saved values, '' if none
  local function changed_globals(saved)
    local changed = {}

    for _, name in ipairs(globals) do
      if not rawequal(_G[name], saved[name]) then
        changed[#changed + 1] = name
      end
    end

    return table.concat(changed, ',')
  end

  -- rspamd_maps can be absent here: a table makes the check of it meaningful
  local function with_maps(f)
    local old_maps = _G.rspamd_maps
    _G.rspamd_maps = {}
    local ok, err = pcall(f)
    _G.rspamd_maps = old_maps

    if not ok then
      error(err, 0)
    end
  end

  test("a valid file gives a config, the globals stay as they are", function()
    with_maps(function()
      local saved = save_globals()
      local cfg = rspamd_util.load_rspamd_config(good_conf)

      assert_not_nil(cfg)
      assert_equal(cfg:get_all_opt('probe_section').a, 1)
      -- Registered into the new config, not into the one of the caller
      assert_not_nil(cfg:get_symbol('LOAD_CONFIG_PROBE'))
      assert_nil(_G.rspamd_config:get_symbol('LOAD_CONFIG_PROBE'))
      assert_equal(changed_globals(saved), '')
      assert_nil(_G.config.probe)
      assert_nil(_G.rspamd_maps.probe)
    end)
  end)

  test("a file that cannot be read gives nil, the globals stay as they are", function()
    with_maps(function()
      local saved = save_globals()

      for _, path in ipairs({ lua_error_conf, bad_conf, missing_conf }) do
        assert_nil(rspamd_util.load_rspamd_config(path), path)
      end

      assert_equal(changed_globals(saved), '')
      assert_nil(_G.config.probe)
      assert_nil(_G.rspamd_maps.probe)
      -- The config of the caller still works
      assert_true(_G.rspamd_config:get_symbols_count() >= 0)
      assert_nil(_G.rspamd_config:get_symbol('LOAD_CONFIG_PROBE'))
    end)
  end)

  test("remove the files", function()
    files[#files + 1] = base

    for _, path in ipairs(files) do
      assert_true(os.remove(path), path)
    end
  end)
end)
