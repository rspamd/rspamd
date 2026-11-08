--[[
Best-effort recovery of broken MIME boundaries.

A multipart part whose declared boundary only appears after its own end still
looks it up there: a boundary named `b4--` reopens a `--b4--` line that would
otherwise close its parent, so the parent goes on and the parts after that line
are parsed. That search must not be dropped or limited, or such content is no
longer scanned.

Orphan boundaries (that no multipart declares) start parts of their own, also
inside embedded messages, but the content of each embedded message is parsed
only once, and nothing that a mail client shows after an empty part or a
garbage region is skipped. Delimiters may carry transport padding, while a
signature line ("-- ") in a text body stays text.
]]

context("MIME boundary recovery", function()
  local rspamd_task = require "rspamd_task"

  local reopened = {
    "Content-Type: multipart/mixed; boundary=\"b4\"",
    "",
    "--b4",
    "Content-Type: multipart/mixed; boundary=\"b4--\"",
    "",
    "preamble",
    "--b4--",
    "Content-Type: text/plain",
    "",
    "see http://recovered.example.org/ now",
    "--b4----",
    "--b4",
    "Content-Type: text/plain",
    "",
    "see http://second.example.org/ now",
    "--b4--",
  }

  -- Test assertions only exist inside test functions
  local function hosts_of(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not res then
      return {}
    end
    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls() or {}) do
      hosts[u:get_host()] = true
    end
    task:destroy()

    return hosts
  end

  test("parts after a boundary reopened by a nested part are parsed", function()
    local lines = {
      "From: sender@example.com",
      "To: rcpt@example.com",
      "Subject: broken",
      "MIME-Version: 1.0",
    }
    for _, l in ipairs(reopened) do
      lines[#lines + 1] = l
    end
    lines[#lines + 1] = ""

    local hosts = hosts_of(table.concat(lines, "\r\n"))
    assert_true(hosts["recovered.example.org"], "url after the reopened boundary is missing")
    assert_true(hosts["second.example.org"], "url of the last part is missing")
  end)

  test("parts without their boundary do not stop the recovery of later parts", function()
    -- Each of these parts looks for its boundary up to the end of the message
    local lines = {
      "From: sender@example.com",
      "To: rcpt@example.com",
      "Subject: broken",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=\"top\"",
      "",
    }
    for i = 1, 3000 do
      lines[#lines + 1] = "--top"
      lines[#lines + 1] = string.format("Content-Type: multipart/mixed; boundary=\"absent%d\"", i)
      lines[#lines + 1] = ""
      lines[#lines + 1] = "preamble"
    end
    lines[#lines + 1] = "--top"
    for _, l in ipairs(reopened) do
      lines[#lines + 1] = l
    end
    lines[#lines + 1] = "--top--"
    for i = 1, 4000 do
      lines[#lines + 1] = string.format("--garbage%d", i)
    end
    lines[#lines + 1] = ""

    local hosts = hosts_of(table.concat(lines, "\r\n"))
    assert_true(hosts["recovered.example.org"], "url after the reopened boundary is missing")
    assert_true(hosts["second.example.org"], "url of the last part is missing")
  end)

  test("an empty part does not hide the parts after it", function()
    local hosts = hosts_of(table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=\"b\"",
      "",
      "--b",
      "",
      "--b",
      "Content-Type: text/plain",
      "",
      "see http://after-empty.example.org/ now",
      "--b--",
      "",
    }, "\r\n"))
    assert_true(hosts["after-empty.example.org"], "url after the empty part is missing")
  end)

  test("an orphan boundary at the start of an embedded message is parsed", function()
    local hosts = hosts_of(table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=\"b\"",
      "",
      "--b",
      "Content-Type: message/rfc822",
      "",
      "--orphan",
      "Content-Type: text/plain",
      "",
      "see http://orphan.example.org/ now",
      "--b--",
      "",
    }, "\r\n"))
    assert_true(hosts["orphan.example.org"], "url after the orphan boundary is missing")
  end)

  test("delimiters with transport padding are recognised", function()
    -- RFC 2046 allows spaces after a delimiter; the boundary itself cannot end with one
    local hosts = hosts_of(table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=\"b\"",
      "",
      "--b ",
      "Content-Type: text/plain",
      "",
      "first http://first.example.org/",
      "--b\t",
      "Content-Type: text/html",
      "",
      "<a href=\"http://padded.example.org/\">x</a>",
      -- Without padding the close delimiter used to be the only one found
      "--b--",
      "",
    }, "\r\n"))
    assert_true(hosts["first.example.org"], "url of the first part is missing")
    assert_true(hosts["padded.example.org"], "url of the second part is missing")
  end)

  test("a signature line in a forwarded message does not start a part", function()
    local msg = table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=\"outer\"",
      "",
      "--outer",
      "Content-Type: text/plain",
      "",
      "see attached",
      "--outer",
      "Content-Type: message/rfc822",
      "",
      "From: c@example.com",
      "Subject: original",
      "Content-Type: text/plain",
      "",
      "Hello, see http://body.example.org/ please.",
      "",
      "-- ",
      "John Doe",
      "http://sig.example.org/",
      "--outer--",
      "",
    }, "\r\n")
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    local texts = 0
    for _, p in ipairs(task:get_parts() or {}) do
      if p:is_text() then
        texts = texts + 1
      end
    end
    task:destroy()

    assert_equal(2, texts, "text parts")
  end)

  test("an embedded message with a false base64 encoding is still recovered", function()
    -- message/rfc822 cannot be base64 (RFC 2046, 5.2.1), and this one is not
    local hosts = hosts_of(table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=\"top\"",
      "",
      "--top",
      "Content-Type: text/plain",
      "",
      "see attached",
      "--top",
      "Content-Type: message/rfc822",
      "Content-Transfer-Encoding: base64",
      "",
      "From: c@example.com",
      "Content-Type: multipart/mixed; boundary=\"in\"",
      "",
      "--in",
      "Content-Type: text/html",
      "",
      "<a href=\"http://false-base64.example.org/\">click</a>",
      "--in--",
      "",
    }, "\r\n"))
    assert_true(hosts["false-base64.example.org"], "url of the embedded message is missing")
  end)

  test("embedded messages are recovered when boundary candidates run out", function()
    -- Each level looks for boundaries in the leaf again, until there are too many
    local leaf = {
      "From: c@example.com",
      "Subject: leaf",
      "Content-Type: multipart/mixed; boundary=\"leaf\"",
      "",
      "--leaf",
      "Content-Type: text/plain",
      "",
      "table:",
    }
    for i = 0, 12999 do
      leaf[#leaf + 1] = string.format("--x %d", i)
    end
    for _, l in ipairs({ "--leaf", "Content-Type: text/html", "",
                         "<a href=\"http://target.example.org/\">click</a>", "--leaf--", "" }) do
      leaf[#leaf + 1] = l
    end
    local body = table.concat(leaf, "\r\n")
    for i = 0, 7 do
      body = string.format("From: w%d@example.com\r\nSubject: fwd %d\r\n" ..
          "Content-Type: message/rfc822\r\n\r\n", i, i) .. body
    end

    local hosts = hosts_of("To: rcpt@example.com\r\nMIME-Version: 1.0\r\n" .. body)
    assert_true(hosts["target.example.org"], "url of the innermost message is missing")
  end)

  -- Each level hides the next one from the outer levels with quoted-printable
  local function qp_hide(s)
    local out = {}
    s = s:gsub("=", "=3D")
    for line in (s .. "\r\n"):gmatch("(.-)\r\n") do
      if line:sub(1, 1) == "-" then
        line = "=2D" .. line:sub(2)
      end
      out[#out + 1] = line
    end
    return table.concat(out, "\r\n")
  end

  test("orphan boundaries of embedded messages are parsed once", function()
    local m = "Content-Type: text/plain\r\n\r\nsee http://leaf.example.org/ now\r\n"
    for i = 1, 14 do
      m = "Content-Type: message/rfc822\r\n\r\n" ..
          string.format("--q%d\r\n", i) ..
          "Content-Type: message/rfc822\r\n" ..
          "Content-Transfer-Encoding: quoted-printable\r\n\r\n" .. qp_hide(m)
    end
    m = "From: sender@example.com\r\nTo: rcpt@example.com\r\n" .. m

    local res, task = rspamd_task.load_from_string(m, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    local nparts = #(task:get_parts() or {})
    local found = false
    for _, u in ipairs(task:get_urls() or {}) do
      if u:get_host() == "leaf.example.org" then
        found = true
      end
    end
    task:destroy()

    assert_true(found, "url of the innermost message is missing")
    -- Two parts per level; parsing each level twice gave 2^14
    assert_true(nparts < 100, "parts: " .. tostring(nparts))
  end)
end)
