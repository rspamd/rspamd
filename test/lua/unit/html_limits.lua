--[[
Limits of the HTML and CSS parsers must not hide the text or the rules that
are within them.
]]

context("HTML and CSS limits", function()
  local rspamd_task = require "rspamd_task"

  -- Visible text of an HTML part
  local function visible(html)
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: text/html; charset=utf-8\r\n" ..
        "Content-Transfer-Encoding: 8bit\r\n\r\n" .. html .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    local text = tostring(task:get_text_parts()[1]:get_content())
    task:destroy()

    return text
  end

  test("text after many NUL bytes is still read", function()
    -- Each NUL becomes a three byte replacement character
    for _, n in ipairs({ 10, 1000, 100000 }) do
      local text = visible("<html><body><p>" .. string.rep("\0", n) ..
          "</p><p>TAILTEXT</p></body></html>")
      assert_not_nil(text:find("TAILTEXT", 1, true), "text is lost after " .. n .. " NUL bytes")
    end
  end)

  test("a token given back to the tokeniser is counted once", function()
    -- 100000 empty declarations are within the limit of 131072 tokens
    local text = visible("<html><head><style>.q{" .. string.rep(";", 100000) ..
        "} .h{display:none}</style></head><body><div class=\"h\">HIDDEN</div>" ..
        "<p>shown</p></body></html>")
    assert_nil(text:find("HIDDEN", 1, true), "the rule after the declarations is lost")
    assert_not_nil(text:find("shown", 1, true))
  end)

  test("a sheet over the tokens limit keeps the rules read before it", function()
    local text = visible("<html><head><style>.h{display:none} .q{" .. string.rep(";", 200000) ..
        "} .late{display:none}</style></head><body><div class=\"h\">HIDDEN</div>" ..
        "<p>shown</p></body></html>")
    assert_nil(text:find("HIDDEN", 1, true), "the rule before the limit is lost")
    assert_not_nil(text:find("shown", 1, true))
  end)
end)
