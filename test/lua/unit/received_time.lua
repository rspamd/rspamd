-- Received header timestamps and the nreceived_bad_time metatoken
context("Received timestamps", function()
  local rspamd_task = require "rspamd_task"
  local lua_meta = require "lua_meta"
  local cfg = rspamd_config

  local function load(received)
    local msg = table.concat(received) ..
        'From: <a@example.com>\r\nTo: <b@example.org>\r\nSubject: t\r\n\r\nbody\r\n'
    local res, task = rspamd_task.load_from_string(msg, cfg)
    -- telescope's assert_* are only visible inside test bodies
    assert(res, 'cannot load message')
    task:process_message()
    return task
  end

  local function hop(from, by, date)
    return string.format('Received: from %s (%s [192.0.2.1])\r\n\tby %s with ESMTP id x%s\r\n',
        from, from, by, date and ('; ' .. date) or '')
  end

  -- Most recent first, 10 seconds apart
  local top = hop('relay.example.org', 'mx.example.org', 'Mon, 26 Aug 2002 10:00:10 +0000')
  local bottom = hop('client.example.com', 'relay.example.org', 'Mon, 26 Aug 2002 10:00:00 +0000')
  local invalid = hop('a.example.net', 'b.example.net', '31 Apr 2002 10:00:05 +0000')
  local nodate = hop('c.example.net', 'd.example.net')

  local function timestamp_of(task, by)
    for _, rh in ipairs(task:get_received_headers()) do
      if rh.by_hostname == by then
        return rh.timestamp
      end
    end
  end

  test("valid date", function()
    local task = load({ bottom })
    assert_rspamd_eq({ expect = 1030356000, actual = timestamp_of(task, 'relay.example.org') })
    task:destroy()
  end)

  -- The parser returns -1 on errors; that must not become a 1969 timestamp
  test("invalid date is 0, like no date", function()
    local task = load({ invalid, nodate })
    assert_rspamd_eq({ expect = 0, actual = timestamp_of(task, 'b.example.net') })
    assert_rspamd_eq({ expect = 0, actual = timestamp_of(task, 'd.example.net') })
    task:destroy()
  end)

  local function bad_time(received)
    local task = load(received)
    local tok = lua_meta.rspamd_gen_metatokens(task, { 'nreceived_bad_time' })[1]
    task:destroy()
    return tok
  end

  test("nreceived_bad_time is 1 / the sum of hop delays", function()
    assert_rspamd_eq({ expect = 0.1, actual = bad_time({ top, bottom }) })
  end)

  -- A hop without a usable date used to add its distance from 1970
  test("nreceived_bad_time skips a hop without a date", function()
    assert_rspamd_eq({ expect = 0.1, actual = bad_time({ top, nodate, bottom }) })
  end)

  test("nreceived_bad_time skips a hop with an invalid date", function()
    assert_rspamd_eq({ expect = 0.1, actual = bad_time({ top, invalid, bottom }) })
  end)

  test("nreceived_bad_time is 0 without dates", function()
    assert_rspamd_eq({ expect = 0, actual = bad_time({ nodate, invalid }) })
  end)
end)
