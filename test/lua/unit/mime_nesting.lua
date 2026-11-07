--[[
MIME nesting depth must track the current depth, not the number of containers.

Each multipart, message/rfc822 or promoted .eml child used to raise the parser
nesting counter without lowering it when the child was done. After 64 sibling
containers the parser refused the next one as "too deeply nested" and dropped
the rest of the message, so content placed after enough harmless containers was
never parsed or scanned.

The depth limit itself must stay as it is: a deep chain of containers is still
cut short, but only that chain, not the parts after it.
]]

context("MIME nesting depth", function()
  local rspamd_task = require "rspamd_task"

  local function message_with_siblings(n, child)
    local buf = {
      "From: sender@example.com\r\n",
      "To: rcpt@example.com\r\n",
      "Subject: siblings\r\n",
      "MIME-Version: 1.0\r\n",
      "Content-Type: multipart/mixed; boundary=\"top\"\r\n",
      "\r\n",
    }

    for i = 1, n do
      buf[#buf + 1] = "--top\r\n" .. child(i) .. "\r\n"
    end

    buf[#buf + 1] = "--top\r\nContent-Type: text/plain\r\n\r\n" ..
        "see http://tail.example.org/ now\r\n--top--\r\n"

    return table.concat(buf)
  end

  local function chain(depth)
    local buf = {}

    for i = 1, depth do
      buf[#buf + 1] = string.format(
          "Content-Type: multipart/mixed; boundary=\"d%d\"\r\n\r\n--d%d\r\n", i, i)
    end

    buf[#buf + 1] = "Content-Type: text/plain\r\n\r\nsee http://deep.example.org/ now\r\n"

    for i = depth, 1, -1 do
      buf[#buf + 1] = string.format("--d%d--\r\n", i)
    end

    return table.concat(buf)
  end

  local function message_with_depth(depth)
    return "From: sender@example.com\r\n" ..
        "To: rcpt@example.com\r\n" ..
        "Subject: depth\r\n" ..
        "MIME-Version: 1.0\r\n" ..
        chain(depth)
  end

  local function scan(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls() or {}) do
      hosts[u:get_host()] = true
    end

    local nparts = #(task:get_parts() or {})
    task:destroy()

    return hosts, nparts
  end

  local siblings = {
    {
      name = "multipart/alternative",
      child = function(i)
        return string.format(
            "Content-Type: multipart/alternative; boundary=\"a%d\"\r\n\r\n" ..
                "--a%d\r\nContent-Type: text/plain\r\n\r\nhello %d\r\n--a%d--", i, i, i, i)
      end,
    },
    {
      name = "message/rfc822",
      child = function(i)
        return string.format(
            "Content-Type: message/rfc822\r\n\r\n" ..
                "From: inner@example.com\r\nSubject: inner %d\r\n\r\ninner body %d", i, i)
      end,
    },
    {
      name = "attached .eml",
      child = function(i)
        return string.format(
            "Content-Type: application/octet-stream; name=\"m%d.eml\"\r\n" ..
                "Content-Disposition: attachment; filename=\"m%d.eml\"\r\n\r\n" ..
                "From: inner@example.com\r\nSubject: inner %d\r\n\r\ninner body %d", i, i, i, i)
      end,
    },
  }

  for _, s in ipairs(siblings) do
    test("a part after 80 sibling " .. s.name .. " parts is parsed", function()
      local hosts, nparts = scan(message_with_siblings(80, s.child))
      assert_true(hosts["tail.example.org"], "url of the trailing part is missing")
      -- top level, each sibling and the trailing part at least
      assert_true(nparts >= 80 + 2, "parts: " .. tostring(nparts))
    end)
  end

  test("a moderately deep chain of multiparts is parsed", function()
    local hosts = scan(message_with_depth(30))
    assert_true(hosts["deep.example.org"], "url of the innermost part is missing")
  end)

  test("a very deep chain of multiparts is still cut short", function()
    local hosts = scan(message_with_depth(40))
    assert_nil(hosts["deep.example.org"], "depth limit is not enforced")
  end)

  test("a part after a too deep branch is parsed", function()
    local hosts = scan(message_with_siblings(1, function()
      return chain(40)
    end))
    assert_nil(hosts["deep.example.org"], "depth limit is not enforced")
    assert_true(hosts["tail.example.org"], "url of the part after the deep branch is missing")
  end)
end)
