--[[
Many url candidates in one token (`sip:sip:sip:...`) share what the lookahead
for the userinfo has learnt of the token: it is scanned once, and the urls
found are the same as when each candidate scans it.
]]

context("URL candidates in one token", function()
  local rspamd_task = require "rspamd_task"

  -- Urls of a plain text body as "url {user|host|obscured}", sorted
  local function urls_of(body)
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: text/plain; charset=utf-8\r\n\r\n" .. body .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()

    local out = {}
    for _, u in ipairs(task:get_urls(true) or {}) do
      out[#out + 1] = string.format("%s {%s|%s|%s}", tostring(u), tostring(u:get_user()),
          u:get_host(), tostring(u:get_flags().obscured ~= nil))
    end
    task:destroy()
    table.sort(out)

    return table.concat(out, " ; ")
  end

  local cases = {
    { "http://user@example.com/x",
      "http://user@example.com/x {user|example.com|false}" },
    { "http:http:http://user@example.com/x",
      "http://http:http://user@example.com/x {http|example.com|false}" },
    { "https:https:https:@a.example.com",
      "https://https:https:@a.example.com {https|a.example.com|false}" },
    -- A backslash ends the authority as a slash does: an `@` after it obscures
    { "http://a.example.com\\@b.example.com/p",
      "http://a.example.com\\@b.example.com/p {nil|a.example.com|true}" },
    -- The same token read by two candidates, the second one starts inside
    { "http:x\\y@b.example.com/p http:z\\w.example.com/q",
      "http://x\\y@b.example.com/p {nil|x|true} ; http://z\\w.example.com/q {nil|z|false}" },
    -- A quote before a candidate ends its input before the `@` of the token
    { "http:aaa\"http:bbb\"ccc@d.example.com/x", nil },
    { "sip:sip:sip:alice@example.com", "" },
  }

  test("urls are the same as when each candidate scans the token", function()
    for _, c in ipairs(cases) do
      if c[2] then
        assert_equal(c[2], urls_of(c[1]), c[1])
      else
        -- Only that it is read at all
        assert_not_nil(urls_of(c[1]))
      end
    end
  end)

  test("a long run of candidates on one line is read", function()
    -- Each candidate used to scan the rest of the line: 250000 scans of it
    assert_equal("", urls_of(string.rep("sip:", 250000)))
    assert_equal("https://https:@a.example.com {https|a.example.com|false}",
        urls_of(string.rep("https:", 2) .. "@a.example.com"))
    assert_not_nil(urls_of(string.rep("http:", 100000) .. "\\" .. string.rep("a", 500000) ..
        "@b.example.com"))
  end)
end)
