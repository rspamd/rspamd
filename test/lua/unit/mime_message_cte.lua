--[[
An embedded message is read from the data of its part once that is decoded:
a part in it without Content-Transfer-Encoding must not take the encoding of
the message part, which would decode it a second time. The children of a
multipart are slices of its raw data, and they still take its encoding.
]]

context("Content-Transfer-Encoding of embedded messages", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"

  local function load(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "cannot load the message")
    task:process_message()
    return task
  end

  -- The text part that holds `marker`, and the text of all of them
  local function find_text(task, marker)
    local all, found = {}, nil
    for _, p in ipairs(task:get_parts()) do
      if p:is_text() then
        local content = tostring(p:get_text():get_content())
        all[#all + 1] = content
        if content:find(marker, 1, true) then
          found = p
        end
      end
    end
    return found, table.concat(all, " | ")
  end

  local function outer(cte, body)
    return table.concat({
      'Subject: outer',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      '',
      '--XX',
      'Content-Type: text/plain',
      '',
      'outer text',
      '--XX',
      'Content-Type: message/rfc822',
      'Content-Transfer-Encoding: ' .. cte,
      '',
      body,
      '--XX--',
      '',
    }, '\n')
  end

  local inner_text = table.concat({
    'Subject: inner',
    'From: a@example.com',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'hello world from the inner message',
    '',
  }, '\n')

  local inner_multipart = table.concat({
    'Subject: inner',
    'From: a@example.com',
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="II"',
    '',
    '--II',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'inner plain text',
    '--II--',
    '',
  }, '\n')

  test("a base64 message/rfc822 is decoded once", function()
    local task = load(outer('base64', tostring(rspamd_util.encode_base64(inner_text, 76))))
    local part, all = find_text(task, 'hello world from the inner message')
    assert_not_nil(part, all)
    assert_not_equal(part:get_cte(), 'base64')
    task:destroy()
  end)

  test("a multipart in a base64 message/rfc822 is decoded once", function()
    local task = load(outer('base64', tostring(rspamd_util.encode_base64(inner_multipart, 76))))
    local part, all = find_text(task, 'inner plain text')
    assert_not_nil(part, all)
    assert_not_equal(part:get_cte(), 'base64')
    task:destroy()
  end)

  test("a quoted-printable message/rfc822 is decoded once", function()
    -- The inner body says "a=3Db" as it is; the outer encoding adds "3D"
    local inner = inner_text:gsub('hello world', 'a=3Db hello world')
    local task = load(outer('quoted-printable', (inner:gsub('=', '=3D'))))
    local part, all = find_text(task, 'hello world from the inner message')
    assert_not_nil(part, all)
    assert_not_nil(tostring(part:get_text():get_content()):find('a=3Db', 1, true), all)
    task:destroy()
  end)

  test("an 8bit message/rfc822 passes 8bit to its parts", function()
    -- 8bit and 7bit leave the data as it is: the inner parts keep them
    local task = load(outer('8bit', (inner_text:gsub('hello world', 'caf\195\169 hello world'))))
    local part, all = find_text(task, 'hello world from the inner message')
    assert_not_nil(part, all)
    assert_equal(part:get_cte(), '8bit')
    task:destroy()
  end)

  test("an attached .eml that lua_magic promotes is decoded once", function()
    local task = load(table.concat({
      'Subject: outer',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      '',
      '--XX',
      'Content-Type: text/plain',
      '',
      'outer text',
      '--XX',
      'Content-Type: application/octet-stream; name="fwd.eml"',
      'Content-Disposition: attachment; filename="fwd.eml"',
      'Content-Transfer-Encoding: base64',
      '',
      tostring(rspamd_util.encode_base64(inner_text, 76)),
      '--XX--',
      '',
    }, '\n'))
    local part, all = find_text(task, 'hello world from the inner message')
    assert_not_nil(part, all)
    assert_not_equal(part:get_cte(), 'base64')
    task:destroy()
  end)

  -- uuencode of `s`, without the bit library
  local function uuencode(s)
    local function chr(v)
      return v == 0 and '`' or string.char(v + 32)
    end
    local lines = { 'begin 644 inner.eml' }
    for i = 1, #s, 45 do
      local chunk = s:sub(i, i + 44)
      local out = { chr(#chunk) }
      for j = 1, #chunk, 3 do
        local a, b, c = chunk:byte(j, j + 2)
        local n = a * 65536 + (b or 0) * 256 + (c or 0)
        out[#out + 1] = chr(math.floor(n / 262144) % 64) .. chr(math.floor(n / 4096) % 64) ..
            chr(math.floor(n / 64) % 64) .. chr(n % 64)
      end
      lines[#lines + 1] = table.concat(out)
    end
    lines[#lines + 1] = '`'
    lines[#lines + 1] = 'end'
    return table.concat(lines, '\n')
  end

  test("a uuencoded message/rfc822 is decoded once", function()
    local task = load(outer('x-uuencode', uuencode(inner_text)))
    local part, all = find_text(task, 'hello world from the inner message')
    assert_not_nil(part, all)
    assert_false(part:is_broken())
    task:destroy()
  end)

  test("a whole message that is a base64 message/rfc822 is decoded once", function()
    local task = load(table.concat({
      'Subject: outer',
      'MIME-Version: 1.0',
      'Content-Type: message/rfc822',
      'Content-Transfer-Encoding: base64',
      '',
      tostring(rspamd_util.encode_base64(inner_text, 76)),
      '',
    }, '\n'))
    local part, all = find_text(task, 'hello world from the inner message')
    assert_not_nil(part, all)
    assert_not_equal(part:get_cte(), 'base64')
    task:destroy()
  end)

  local function multipart_with_cte(cte, child_body)
    return table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      'Content-Transfer-Encoding: ' .. cte,
      '',
      '--XX',
      'Content-Type: text/plain; charset=utf-8',
      '',
      child_body,
      '--XX--',
      '',
    }, '\n')
  end

  -- RFC 2045 6.4 allows no such encoding on a multipart, and mail clients show
  -- its children as they are: readable text must not be decoded into garbage
  test("a base64 multipart leaves a readable child as it is", function()
    local task = load(multipart_with_cte('base64',
        'Please visit http://evil.example.com/login now'))
    local part, all = find_text(task, 'Please visit')
    assert_not_nil(part, all)
    assert_equal(#task:get_urls(true), 1)
    task:destroy()
  end)

  test("a base64 multipart still decodes a base64 child", function()
    local task = load(multipart_with_cte('base64',
        tostring(rspamd_util.encode_base64('hello world from a base64 child', 76))))
    local part, all = find_text(task, 'hello world from a base64 child')
    assert_not_nil(part, all)
    task:destroy()
  end)

  test("a uuencoded multipart leaves a readable child as it is", function()
    local task = load(multipart_with_cte('x-uuencode',
        'Please visit http://evil.example.com/login now'))
    local part, all = find_text(task, 'Please visit')
    assert_not_nil(part, all)
    assert_false(part:is_broken())
    task:destroy()
  end)

  test("a quoted-printable multipart leaves its children as they are", function()
    local task = load(table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      '--XX',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'caf=C3=A9 au lait',
      '--XX--',
      '',
    }, '\n'))
    local part, all = find_text(task, 'caf=C3=A9 au lait')
    assert_not_nil(part, all)
    assert_not_equal(part:get_cte(), 'quoted-printable')
    task:destroy()
  end)

  test("a base64 multipart leaves a child that is not all base64 as it is", function()
    local task = load(multipart_with_cte('base64',
        'A' .. string.rep('\n', 5000) .. 'Please visit http://evil.example.com/login now'))
    local part, all = find_text(task, 'Please visit')
    assert_not_nil(part, all)
    assert_equal(#task:get_urls(true), 1)
    task:destroy()
  end)
end)
