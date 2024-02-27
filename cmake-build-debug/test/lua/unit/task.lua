context("Task processing", function()
  local fun = require("fun")
  local rspamd_task = require("rspamd_task")

  test("Process a simple task", function()
    --local cfg = rspamd_util.config_from_ucl(config)
    --assert_not_nil(cfg)

    local msg = [[
From: <>
To: <nobody@example.com>
Subject: test
Content-Type: text/plain

Test.
]]
    local res,task = rspamd_task.load_from_string(msg)
    assert_true(res, "failed to load message")
    task:process_message()
    task:destroy()
  end)

  local hdrs = [[
From: <>
To: <nobody@example.com>
Subject: test
]]
  local mpart = [[
Content-Type: multipart/mixed; boundary=XXX
]]
  local body = [[
Content-Type: text/html
Content-Transfer-Encoding: quoted-printable

<html>
<body>
=0DAttached is your new documents.
<br>
<a href=3D"http://evil.com/Information/">http:=
//example.com/privacy/XXX/YYY_April_25_2019.doc</a>
<br>
<br>
<br>
Thank you,
<br>
<b>Haloclaims.co</b>
</body></html>
]]
  test("Process mime nesting: simple", function()
    local msg = hdrs .. body
    local res,task = rspamd_task.load_from_string(msg)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({actual = fun.totable(fun.map(function(u)
      return u:get_host()
    end, task:get_urls())), expect = {
      'evil.com', 'example.com'
    }})
    task:destroy()
  end)
  test("Process mime nesting: multipart", function()
    local msg = table.concat{
      hdrs, mpart, '\n', '--XXX\n', body, '\n--XXX--\n'
    }
    local res,task = rspamd_task.load_from_string(msg)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }})
    task:destroy()
  end)
  test("Process mime nesting: multipart, broken", function()
    local msg = table.concat{
      hdrs, mpart, '\n', '--XXX\n', 'garbadge\n', '\n--XXX--\n', '--XXX\n', body
    }
    local res,task = rspamd_task.load_from_string(msg)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }})

    task:destroy()
  end)
  test("Process mime nesting: message", function()
    local msg = table.concat{
      hdrs, 'Content-Type: message/rfc822\n', '\n', hdrs, body
    }
    local res,task = rspamd_task.load_from_string(msg)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }})

    task:destroy()
  end)
  test("Process mime nesting: message in multipart", function()
    local msg = table.concat{
      hdrs, mpart, '\n',
      '--XXX\n',
      'Content-Type: message/rfc822\n', '\n', hdrs, body ,
      '\n--XXX--\n',
    }

    local res,task = rspamd_task.load_from_string(msg)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }})

    task:destroy()
  end)
  test("Process mime nesting: multipart message in multipart", function()
    local msg = table.concat{
      hdrs, mpart, '\n',
      '--XXX\n',
      'Content-Type: message/rfc822\n', '\n', hdrs,  mpart, '\n',

      '--XXX\n',
      body ,
      '\n--XXX--\n',

      '\n--XXX--\n',
    }
    local res,task = rspamd_task.load_from_string(msg)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }})

    task:destroy()
  end)
end)