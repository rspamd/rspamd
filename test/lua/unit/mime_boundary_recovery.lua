--[[
Best-effort recovery of broken MIME boundaries.

A multipart part whose declared boundary only appears after its own end still
looks it up there: a boundary named `b4--` reopens a `--b4--` line that would
otherwise close its parent, so the parent goes on and the parts after that line
are parsed. The search after the end of a part is bounded for the whole
message, but it must not be dropped, or such content is no longer scanned.
]]

context("MIME boundary recovery", function()
  local rspamd_task = require "rspamd_task"

  test("parts after a boundary reopened by a nested part are parsed", function()
    local msg = table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "Subject: broken",
      "MIME-Version: 1.0",
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
      "",
    }, "\r\n")

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls() or {}) do
      hosts[u:get_host()] = true
    end
    task:destroy()

    assert_true(hosts["recovered.example.org"], "url after the reopened boundary is missing")
    assert_true(hosts["second.example.org"], "url of the last part is missing")
  end)
end)
