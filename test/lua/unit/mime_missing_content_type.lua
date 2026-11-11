--[[
A part without Content-Type is text/plain. Without a charset, only ASCII and
UTF-8 can be read as they are, so other 8bit data makes the content type
broken, but the part is still checked as text.
]]

context("Part without Content-Type", function()
  local rspamd_task = require "rspamd_task"

  local text = string.rep("Привет мир ", 3)
  local cases = {
    { "ascii", "hello world\n", false },
    { "valid UTF-8", text .. "\n", false },
    { "UTF-8 with a bad byte", text .. "\208 " .. text .. "\n", true },
    { "latin1", "caf\233 au lait\n", true },
  }

  for _, c in ipairs(cases) do
    test(c[1], function()
      local res, task = rspamd_task.load_from_string("Subject: t\n\n" .. c[2],
          rspamd_config)
      assert_true(res)
      task:process_message()
      local parts = task:get_parts()
      assert_equal(#parts, 1)
      assert_equal(parts[1]:is_broken(), c[3])
      assert_equal(#task:get_text_parts(), 1)
      task:destroy()
    end)
  end
end)

--[[
RFC 2046 5.1: a body part without Content-Type is text/plain too, and it is
text whatever the bytes look like; in a multipart/digest it is an embedded
message (5.1.5).
]]
context("Multipart child without Content-Type", function()
  local rspamd_task = require "rspamd_task"

  local function load(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "cannot load the message")
    task:process_message()
    return task
  end

  -- The text of every text part, and the part that holds `marker`
  local function texts(task, marker)
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
    return all, found
  end

  local function mixed(child)
    return table.concat({
      'Subject: t',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XX"',
      '',
      '--XX',
      child,
      '--XX',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'second part',
      '--XX--',
      '',
    }, '\n')
  end

  local text = string.rep("Привет мир ", 3)
  local cases = {
    -- name, child (headers, empty line, body), marker in its text, broken
    { "no headers, ascii", "\nhello world", "hello world", false },
    { "no headers, valid UTF-8", "\n" .. text .. "ok", "ok", false },
    -- lua_magic's text heuristic gives up on 1 bad byte in the last 80
    { "no headers, a bad byte", "\n" .. text .. "\208 ok", "ok", true },
    { "no headers, latin1", "\ncaf\233 au lait, cr\232me br\251l\233e\233\233",
      "au lait", true },
    { "headers without Content-Type",
      "Content-Transfer-Encoding: quoted-printable\n\ncaf=C3=A9 au lait",
      "café au lait", false },
  }

  for _, c in ipairs(cases) do
    test(c[1], function()
      local task = load(mixed(c[2]))
      local all, part = texts(task, c[3])
      assert_equal(#all, 2, "text parts: " .. table.concat(all, " | "))
      assert_not_nil(part, "no text part has: " .. c[3])
      assert_equal(part:is_broken(), c[4])
      task:destroy()
    end)
  end

  -- A format that lua_magic recognises wins over the default text/plain
  local elf = "\127ELF\2\1\1\0" .. string.rep("\0", 8) .. "\2\0\62\0\1\0\0\0" ..
      string.rep("\255\0\1\200", 40)
  local binary_cases = {
    { "ELF in base64", "Content-Transfer-Encoding: base64\n\n" ..
        tostring(require("rspamd_util").encode_base64(elf, 76)) },
    { "ELF sent raw", "Content-Transfer-Encoding: binary\n\n" .. elf },
    -- The empty line that ends no headers is not a part of the body
    { "zip sent raw without headers", "\nPK\3\4\20\0\0\0\8\0" .. string.rep("\255\0\200", 40) },
  }

  for _, c in ipairs(binary_cases) do
    test(c[1] .. " is not text nor broken", function()
      local task = load(mixed(c[2]))
      local all = texts(task, 'second part')
      assert_equal(#all, 1, "text parts: " .. table.concat(all, " | "))
      for _, p in ipairs(task:get_parts()) do
        assert_false(p:is_broken())
      end
      task:destroy()
    end)
  end

  -- Bytes that no lua_magic signature matches: whether data is binary or
  -- text comes from the data
  local function noise(n)
    local seed, out = 12345, {}
    for i = 1, n do
      seed = (seed * 1103515245 + 12345) % 2147483648
      out[i] = string.char(math.floor(seed / 65536) % 256)
    end
    return table.concat(out)
  end

  test("binary that lua_magic does not know is not text", function()
    local task = load(mixed("Content-Transfer-Encoding: base64\n\n" ..
        tostring(require("rspamd_util").encode_base64(noise(600), 76))))
    local all = texts(task, 'second part')
    assert_equal(#all, 1, "text parts: " .. table.concat(all, " | "))
    task:destroy()
  end)

  -- Some lua_magic signatures (exe "MZ", tiff "MM", uuencode "begin ") also
  -- start ordinary text: a mail client shows it, so it stays text
  for _, prefix in ipairs({ "MZ office update", "MM and friends say hi", "begin with the agenda" }) do
    local body = prefix .. ". Hello friend, see http://signature.example.com/login now\n"

    test("text that starts with '" .. prefix .. "' stays text", function()
      for _, msg in ipairs({ "Subject: t\n\n" .. body, mixed("\n" .. body) }) do
        local task = load(msg)
        local _, part = texts(task, 'signature.example.com')
        assert_not_nil(part, msg)
        local urls = task:get_urls(true)
        assert_equal(#urls, 1)
        task:destroy()
      end
    end)
  end

  -- Only the start decides: junk after the text a client shows first does not
  test("text followed by control bytes stays text", function()
    local body = string.rep("Plain words that a client shows. ", 200) ..
        "See http://after.example.com/ now\n" .. string.rep("\1", 600)
    local task = load(mixed("\n" .. body))
    local _, part = texts(task, 'after.example.com')
    assert_not_nil(part)
    task:destroy()
  end)

  -- A known format has no charset to miss
  test("an uncompressed PDF without Content-Type is not broken", function()
    local pdf = "%PDF-1.4\n%\226\227\207\211\n1 0 obj << /Type /Catalog >> endobj\n" ..
        "trailer << /Root 1 0 R >>\n%%EOF\n"
    local task = load(mixed("\n" .. pdf))
    for _, p in ipairs(task:get_parts()) do
      assert_false(p:is_broken())
    end
    task:destroy()
  end)

  -- A whole message without Content-Type is read as text whatever it starts
  -- with: bytes in front of the text must not hide it
  for _, prefix in ipairs({ string.rep("\0", 140), "MZ" .. string.rep("\0", 140) }) do
    test(string.format("a whole message starting with %d binary bytes is text", #prefix), function()
      local task = load("Subject: t\n\n" .. prefix ..
          "Hello friend, see http://nul-padded.example.com/login now\n")
      local _, part = texts(task, 'Hello friend')
      assert_not_nil(part)
      local found = false
      for _, u in ipairs(task:get_urls(true)) do
        if u:get_host() == 'nul-padded.example.com' then
          found = true
        end
      end
      assert_true(found)
      task:destroy()
    end)
  end

  test("a digest child is an embedded message", function()
    local task = load(table.concat({
      'Subject: d',
      'MIME-Version: 1.0',
      'Content-Type: multipart/digest; boundary="DD"',
      '',
      '--DD',
      '',
      'Subject: inner',
      'From: a@example.com',
      '',
      'hello from the digest',
      '--DD--',
      '',
    }, '\n'))
    local messages = 0
    for _, p in ipairs(task:get_parts()) do
      if p:is_message() then
        messages = messages + 1
      end
    end
    assert_equal(messages, 1)
    local all, part = texts(task, 'hello from the digest')
    assert_equal(#all, 1, "text parts: " .. table.concat(all, " | "))
    assert_not_nil(part)
    -- The headers of the embedded message are not its text
    assert_nil(all[1]:find('Subject: inner', 1, true))
    task:destroy()
  end)
end)
