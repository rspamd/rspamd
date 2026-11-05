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
