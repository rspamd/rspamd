context("Task set_cfg", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"

  local msg = 'Subject: set_cfg\r\n\r\nbody\r\n'

  -- A task frees the config it points to: each one must hold a reference of
  -- it, also when it has been made without a config
  test("a task made without a config holds the one it is given", function()
    for _ = 1, 32 do
      local ok, task = rspamd_task.load_from_string(msg)
      assert_true(ok)
      task:set_cfg(rspamd_config)
      -- The same config again: no new reference
      task:set_cfg(rspamd_config)
      task:destroy()
    end

    assert_true(rspamd_config:get_symbols_count() >= 0)
  end)

  test("a task made with a config holds the one it is given", function()
    for _ = 1, 32 do
      local task = rspamd_task.create(rspamd_config)
      task:set_cfg(rspamd_config)
      task:destroy()
    end

    assert_true(rspamd_config:get_symbols_count() >= 0)
  end)

  test("a task switched to another config and back", function()
    local path = os.tmpname()
    local f = assert(io.open(path, 'w'))
    f:write('options { }\n')
    f:close()
    local other = rspamd_util.load_rspamd_config(path)
    os.remove(path)
    assert_not_nil(other)

    for _ = 1, 32 do
      local ok, task = rspamd_task.load_from_string(msg)
      assert_true(ok)
      task:set_cfg(rspamd_config)
      task:set_cfg(other)
      task:set_cfg(rspamd_config)
      task:set_cfg(other)
      task:destroy()
    end

    assert_true(rspamd_config:get_symbols_count() >= 0)
    assert_true(other:get_symbols_count() >= 0)
  end)
end)
