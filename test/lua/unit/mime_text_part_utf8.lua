--[[
A text part flagged as UTF-8 must hold valid UTF-8, whatever told rspamd the
bytes were UTF-8: the declared charset or the guess of the charset detector.
Broken sequences are replaced by '?', so the rest of the text is still matched
by UTF-8 regexps.
]]

context("Text part UTF-8 enforcement", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_regexp = require "rspamd_regexp"

  local text = string.rep("Привет мир ", 3)
  local re = rspamd_regexp.create('/привет\\s+мир/iu')

  local cases = {
    { "no charset", "" },
    { "charset=utf-8", "Content-Type: text/plain; charset=utf-8\n" },
    { "charset=us-ascii", "Content-Type: text/plain; charset=us-ascii\n" },
    { "unknown charset", "Content-Type: text/plain; charset=x-unknown\n" },
    { "html, no charset", "Content-Type: text/html\n" },
  }
  local bodies = {
    { "truncated sequence at the end", text .. "\208\n", "?" },
    { "truncated sequence in the middle", text .. "\208 " .. text .. "\n", "? " },
    { "stray continuation byte", text .. "\128" .. text .. "\n", "?" },
    -- Only NULs after the bad byte: the end of the part is not reached by a
    -- valid character
    { "truncated sequence before a NUL", text .. "\208\0", "?" },
  }

  for _, c in ipairs(cases) do
    for _, b in ipairs(bodies) do
      test(string.format("%s, %s", c[1], b[1]), function()
        local msg = "Subject: t\n" .. c[2] .. "\n" .. b[2]
        local res, task = rspamd_task.load_from_string(msg, rspamd_config)
        assert_true(res)
        task:process_message()
        local parts = task:get_text_parts()
        assert_equal(#parts, 1)
        local part = parts[1]
        assert_true(part:is_utf())
        local content = tostring(part:get_content())
        assert_true(rspamd_util.is_valid_utf8(content),
            "a part flagged UTF-8 holds invalid UTF-8")
        assert_not_nil(content:find(b[3], 1, true))
        assert_true(re:match(content))
        task:destroy()
      end)
    end
  end
end)
