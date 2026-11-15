--[[
Lua stack discipline of task methods: arguments are addressed by absolute
index and every method returns exactly the values it documents.
]]

context("Task method stack handling", function()
  local rspamd_task = require "rspamd_task"

  local function load(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "cannot load the message")
    task:process_message()
    return task
  end

  local msg = table.concat({
    'Subject: stack',
    'From: a@example.com',
    'To: b@example.com',
    'Content-Type: text/plain',
    '',
    'original body',
    '',
  }, '\n')

  test("disable_action returns false for an unknown action", function()
    local task = load(msg)
    local n = select('#', task:disable_action('no_such_action_name'))
    assert_equal(n, 1, "disable_action must return exactly one value")
    assert_false(task:disable_action('no_such_action_name'))
  end)

  test("set_message reads its first argument, not the last one", function()
    local task = load(msg)
    local new_msg = table.concat({
      'Subject: replaced',
      'From: c@example.com',
      'To: d@example.com',
      'Content-Type: text/plain',
      '',
      'replacement body',
      '',
    }, '\n')
    local ok, len = task:set_message(new_msg, 'an extra argument')
    assert_true(ok, "set_message failed")
    assert_equal(len, #new_msg)
  end)
end)
