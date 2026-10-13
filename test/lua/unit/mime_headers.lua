local rspamd_task = require 'rspamd_task'

context('Obsolete header field whitespace', function()
  local function parse(headers)
    local message = headers .. 'Subject: parser check\r\n\r\nBody\r\n'
    local ok, task = rspamd_task.load_from_string(message, rspamd_config)
    assert(ok, 'failed to load message')
    task:process_message()
    return task
  end

  for _, leading in ipairs({ '', 'Date: Fri, 13 May 2016 19:08:48 +0000\r\n' }) do
    for _, whitespace in ipairs({ '', ' ', '\t', ' \t  \t' }) do
      test('From before-colon whitespace: ' .. string.format('%q', whitespace) ..
          (leading == '' and ' first field' or ' after Date'), function()
        local raw = 'From' .. whitespace .. ': Sender <sender@example.org>\r\n'
        local task = parse(leading .. raw)
        local from = task:get_from({ 'mime', 'orig' }) or {}
        local headers = task:get_header_full('From') or {}
        local decoded = task:get_header('From')
        local broken = task:has_flag('broken_headers')
        task:destroy()

        assert_equal('Sender <sender@example.org>', decoded)
        assert_equal(1, #from)
        assert_equal('sender@example.org', from[1].addr)
        assert_equal(1, #headers)
        assert_equal('From', headers[1].name)
        assert_equal(raw, headers[1].raw)
        assert_equal(' ', headers[1].separator)
        assert_false(broken)
      end)
    end
  end

  test('mbox separator is still skipped', function()
    local raw = 'From: Sender <sender@example.org>\r\n'
    local task = parse('From envelope@example.net Fri May 13 19:08:48 2016\r\n' .. raw)
    local from = task:get_from('mime') or {}
    local headers = task:get_header_full('From') or {}
    task:destroy()

    assert_equal(1, #from)
    assert_equal('sender@example.org', from[1].addr)
    assert_equal(1, #headers)
    assert_equal(raw, headers[1].raw)
  end)

  test('obsolete whitespace in other fields and folded values', function()
    local raw = 'To \t: Recipient <recipient@example.net>\r\n'
    local custom = 'X-Test\t : first\r\n\tsecond\r\n'
    local task = parse(raw .. custom)
    local rcpt = task:get_recipients('mime') or {}
    local to = task:get_header_full('To') or {}
    local x = task:get_header_full('X-Test') or {}
    local decoded = task:get_header('X-Test')
    task:destroy()

    assert_equal(1, #rcpt)
    assert_equal('recipient@example.net', rcpt[1].addr)
    assert_equal(raw, to[1].raw)
    assert_equal('first second', decoded)
    assert_equal('X-Test', x[1].name)
    assert_equal(custom, x[1].raw)
  end)

  test('normal and obsolete fields share a lookup key', function()
    local task = parse('X-Test: first\r\nX-Test \t: second\r\n')
    local headers = task:get_header_full('x-test') or {}
    task:destroy()

    assert_equal(2, #headers)
    assert_equal('first', headers[1].decoded)
    assert_equal('second', headers[2].decoded)
  end)

  for _, invalid in ipairs({
    'Fr om: Sender <sender@example.org>\r\n',
    'From \tX: Sender <sender@example.org>\r\n',
    'From\v: Sender <sender@example.org>\r\n',
    'From\f: Sender <sender@example.org>\r\n',
    'From \r\n\t: Sender <sender@example.org>\r\n',
    'From \t\r\n',
  }) do
    test('reject malformed field: ' .. string.format('%q', invalid), function()
      local task = parse(invalid)
      local headers = task:get_header_full('From') or {}
      local from = task:get_from({ 'mime', 'orig' }) or {}
      local subject = task:get_header('Subject')
      task:destroy()

      assert_equal(0, #headers)
      assert_equal(0, #from)
      assert_equal('parser check', subject)
    end)
  end

  test('unterminated whitespace does not create a header', function()
    local ok, task = rspamd_task.load_from_string('From \t', rspamd_config)
    assert_true(ok)
    task:process_message()
    local headers = task:get_header_full('From') or {}
    task:destroy()
    assert_equal(0, #headers)
  end)
end)
