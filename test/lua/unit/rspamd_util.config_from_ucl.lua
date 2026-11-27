context("rspamd_util.config_from_ucl", function()
  local rspamd_test_helper = require "rspamd_test_helper"
  local rspamd_util = require "rspamd_util"

  -- Without INIT_LIBS the config has no libraries
  test("a config without libraries", function()
    assert_not_nil(rspamd_util.config_from_ucl(rspamd_test_helper.default_config()))
    assert_not_nil(rspamd_util.config_from_ucl(rspamd_test_helper.default_config(), 'INIT_URL'))
  end)

  -- Such a config has no Lua thread pool, so a periodic could not run
  test("add_periodic on a config without a thread pool", function()
    local cfg = rspamd_util.config_from_ucl(rspamd_test_helper.default_config(), 'INIT_LIBS')
    assert_not_nil(cfg)

    local ok, err = pcall(cfg.add_periodic, cfg, rspamd_util.create_event_base(), 0.01,
        function()
          return false
        end)
    assert_false(ok)
    assert_not_nil(tostring(err):find('the config has no thread pool', 1, true), tostring(err))
  end)
end)
