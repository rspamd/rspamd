context("lua_magic text part heuristic", function()
  local rspamd_task = require("rspamd_task")
  local rspamd_util = require("rspamd_util")

  local rows = {}
  for i = 1, 20 do
    rows[#rows + 1] = string.format(
        [[{"id":%d,"location":"<a href='https:\/\/example.com\/?q=%d'>%d<\/a>"}]], i, i, i)
  end
  local payload = '{"rows":[' .. table.concat(rows, ',') .. ']}'

  local function message(ct, fname)
    return string.format([[
From: test@example.com
To: nobody@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain

report attached
--b
Content-Type: %s
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="%s"

%s
--b--
]], ct, fname, tostring(rspamd_util.encode_base64(payload, 76)))
  end

  local function attachment(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not res then
      return
    end
    task:process_message()

    for _, p in ipairs(task:get_parts()) do
      if p:is_attachment() then
        return task, p
      end
    end

    task:destroy()
  end

  local cases = {
    { 'application/json', 'report.json' },
    { 'application/vnd.api+json', 'report.json' },
  }

  for _, c in ipairs(cases) do
    test(string.format("markup inside %s is not sniffed as html", c[1]), function()
      local task, part = attachment(message(c[1], c[2]))
      assert_not_nil(part, "attachment not found")
      assert_not_equal(part:get_detected_ext(), 'html')
      assert_false(part:is_text())
      task:destroy()
    end)
  end

  test("same markup in an octet stream is still sniffed as html", function()
    local task, part = attachment(message('application/octet-stream', 'report.bin'))
    assert_not_nil(part, "attachment not found")
    assert_equal(part:get_detected_ext(), 'html')
    task:destroy()
  end)
end)
