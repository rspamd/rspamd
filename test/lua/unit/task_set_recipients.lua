-- task:set_recipients / task:set_from: replaced addresses must be freed
-- (LSan reports them otherwise) and the original envelope sender must
-- survive repeated rewrites

context("Task address setters", function()
  local rspamd_task = require "rspamd_task"

  local msg = table.concat({
    'Return-Path: <orig@example.com>',
    'From: Sender <sender@example.com>',
    'To: First <first@example.com>, "quoted\\"user"@example.com',
    'Cc: third@example.com',
    'Subject: test',
    'Content-Type: text/plain',
    '',
    'Test.',
    '',
  }, '\r\n')

  local function load_task()
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    return task
  end

  local function mk(user)
    return { user = user, domain = 'example.com', addr = user .. '@example.com' }
  end

  local function addrs(list)
    local out = {}
    for _, a in ipairs(list or {}) do
      out[#out + 1] = a.addr
    end
    return out
  end

  test("set_recipients rewrite replaces SMTP recipients", function()
    local task = load_task()

    assert_true(task:set_recipients('smtp', { mk('a'), mk('b') }))
    assert_rspamd_table_eq({
      actual = addrs(task:get_recipients('smtp')),
      expect = { 'a@example.com', 'b@example.com' },
    })

    assert_true(task:set_recipients('smtp', { mk('c') }, 'rewrite'))
    assert_rspamd_table_eq({
      actual = addrs(task:get_recipients('smtp')),
      expect = { 'c@example.com' },
    })
    assert_rspamd_table_eq({
      actual = addrs(task:get_recipients({ 'smtp', 'orig' })),
      expect = { 'c@example.com' },
    })
    task:destroy()
  end)

  test("set_recipients rewrite replaces MIME recipients", function()
    local task = load_task()

    assert_equal(#task:get_recipients('mime'), 3)
    assert_true(task:set_recipients('mime', { mk('new') }, 'rewrite'))
    assert_rspamd_table_eq({
      actual = addrs(task:get_recipients('mime')),
      expect = { 'new@example.com' },
    })
    -- the address added by the first rewrite is dropped as well
    assert_true(task:set_recipients('mime', { mk('newer') }, 'rewrite'))
    assert_rspamd_table_eq({
      actual = addrs(task:get_recipients({ 'mime', 'orig' })),
      expect = { 'newer@example.com' },
    })
    task:destroy()
  end)

  test("set_from keeps the original envelope sender", function()
    local task = load_task()

    assert_equal(task:get_from('smtp')[1].addr, 'orig@example.com')

    for _, user in ipairs({ 'first', 'second', 'third' }) do
      assert_true(task:set_from('smtp', mk(user)))
      assert_equal(task:get_from('smtp')[1].addr, user .. '@example.com')
      assert_equal(task:get_from({ 'smtp', 'orig' })[1].addr,
          'orig@example.com')
    end
    task:destroy()
  end)

  test("address built from user and domain is not truncated", function()
    local task = load_task()

    assert_true(task:set_recipients('smtp', {
      { user = 'u', domain = 'example.com' },
      { name = 'Name', user = 'n', domain = 'example.com' },
    }, 'rewrite'))
    local rcpts = task:get_recipients('smtp')
    assert_equal(rcpts[1].addr, 'u@example.com')
    assert_equal(rcpts[1].raw, '<u@example.com>')
    assert_equal(rcpts[2].addr, 'n@example.com')
    assert_equal(rcpts[2].raw, 'Name <n@example.com>')

    assert_true(task:set_from('smtp', { user = 's', domain = 'example.com' }))
    assert_equal(task:get_from('smtp')[1].addr, 's@example.com')
    task:destroy()
  end)
end)
