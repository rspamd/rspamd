--[[
An embedded message that is not encoded is a slice of the message around it,
so its boundary lines are the ones already found there. They count once
against the limit of boundary candidates, however deep the message is embedded.
]]

context("MIME embedded message boundaries", function()
  local rspamd_task = require "rspamd_task"

  -- `depth` message/rfc822 levels around `inner`
  local function embedded(depth, inner)
    local buf = {
      "From: sender@example.com\r\n",
      "To: rcpt@example.com\r\n",
      "Subject: embedded\r\n",
      "MIME-Version: 1.0\r\n",
    }

    for i = 1, depth do
      buf[#buf + 1] = "Content-Type: message/rfc822\r\n\r\n"
      buf[#buf + 1] = string.format("From: level%d@example.com\r\nSubject: level %d\r\n", i, i)
    end

    buf[#buf + 1] = inner

    return table.concat(buf)
  end

  local function multipart(nparts)
    local buf = { "Content-Type: multipart/mixed; boundary=\"inner\"\r\n\r\n" }

    for i = 1, nparts do
      buf[#buf + 1] = string.format("--inner\r\nContent-Type: text/plain\r\n\r\npart %d\r\n", i)
    end

    buf[#buf + 1] = "--inner\r\nContent-Type: text/plain\r\n\r\n" ..
        "see http://tail.example.org/ now\r\n--inner--\r\n"

    return table.concat(buf)
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
    local broken = task:has_flag('broken_headers')
    task:destroy()

    return hosts, nparts, broken
  end

  test("a multipart in an embedded message is parsed", function()
    local hosts, nparts, broken = scan(embedded(2, multipart(3)))
    assert_true(hosts["tail.example.org"], "url of the last part is missing")
    -- a part per embedded level, the multipart and its 4 children
    assert_equal(2 + 1 + 4, nparts)
    assert_false(broken, "message is marked as broken")
  end)

  test("boundaries of a deeply embedded multipart are counted once", function()
    -- 3001 delimiter lines seen from 41 levels: 123041 candidates if each level counts them
    local depth, n = 40, 3000
    local hosts, nparts, broken = scan(embedded(depth, multipart(n)))
    assert_true(hosts["tail.example.org"], "url of the last part is missing")
    assert_equal(depth + 1 + n + 1, nparts)
    assert_false(broken, "the limit of boundary candidates is reached")
  end)
end)
