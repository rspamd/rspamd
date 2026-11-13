--[[
An !important declaration wins over normal ones whatever their origin and
specificity: a stylesheet rule over an inline style, a less specific rule over
a more specific one. Among important declarations the usual order applies.
]]

context("CSS !important across rules", function()
  local rspamd_task = require "rspamd_task"

  -- Visible text of an HTML part with the given stylesheet and body
  local function visible(style, body)
    local html = '<html><head><style>' .. style .. '</style></head><body>' ..
        body .. '<p>vis</p></body></html>'
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: text/html; charset=utf-8\r\n\r\n" .. html .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    local text = tostring(task:get_text_parts()[1]:get_content())
    task:destroy()

    return text
  end

  local cases = {
    { "an important rule hides over an inline style",
      '.h{display:none !important}', '<div class="h" style="display:block">TXT</div>', true },
    { "a normal rule does not hide over an inline style",
      '.h{display:none}', '<div class="h" style="display:block">TXT</div>', false },
    { "an important inline style shows over an important rule",
      '.h{display:none !important}', '<div class="h" style="display:block !important">TXT</div>', false },
    { "an important inline style hides over an important rule",
      '.h{display:block !important}', '<div class="h" style="display:none !important">TXT</div>', true },
    { "an important rule hides over a more specific normal one",
      '#i{display:block} .h{display:none !important}', '<div id="i" class="h">TXT</div>', true },
    { "an important rule shows over a more specific normal one",
      '#i{display:none} .h{display:block !important}', '<div id="i" class="h">TXT</div>', false },
    { "the more specific of two important rules wins",
      '#i{display:block !important} .h{display:none !important}', '<div id="i" class="h">TXT</div>', false },
    { "the later of two equal important rules wins",
      '.h{display:block !important} .h{display:none !important}', '<div class="h">TXT</div>', true },
    { "importance of a parent does not override the rule of a child",
      '.p{display:block !important} .h{display:none}', '<div class="p"><div class="h">TXT</div></div>', true },
    { "a child is still hidden in an important hidden parent",
      '.p{display:none !important} .c{display:block !important}',
      '<div class="p"><div class="c">TXT</div></div>', true },
    { "important and normal declarations of one rule",
      '.h{display:none !important; display:block}', '<div class="h">TXT</div>', true },
  }

  for _, c in ipairs(cases) do
    test(c[1], function()
      local text = visible(c[2], c[3])
      assert_not_nil(text:find("vis", 1, true), "visible text is missing")
      assert_equal(c[4], text:find("TXT", 1, true) == nil)
    end)
  end
end)
