--[[
Best-effort recovery of broken MIME boundaries.

A multipart part whose declared boundary only appears after its own end still
looks it up there: a boundary named `b4--` reopens a `--b4--` line that would
otherwise close its parent, so the parent goes on and the parts after that line
are parsed. That search must not be dropped or limited, or such content is no
longer scanned.
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
end)
