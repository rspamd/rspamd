--[[
Presentational attributes (color, bgcolor, hidden) are hints that any author
declaration overrides, and `visibility` is an inherited property of its own that
a descendant can reset, unlike `display:none`.
]]

context("CSS presentational hints and visibility", function()
  local rspamd_task = require "rspamd_task"

  -- Text of an HTML part with the given stylesheet, body attributes and body
  local function text_of(style, body_attrs, body)
    local html = '<html><head><style>' .. style .. '</style></head><body ' ..
        body_attrs .. '>' .. body .. '<p>vis</p></body></html>'
    local msg = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n" ..
        "Content-Type: text/html; charset=utf-8\r\n\r\n" .. html .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    local text = tostring(task:get_text_parts()[1]:get_content())
    task:destroy()

    return text
  end

  -- Each case: name, stylesheet, body attributes, body, whether TXT is hidden
  local cases = {
    -- Task 1: presentational attributes are weaker than author CSS
    { "hidden attribute alone hides", '', '', '<div hidden>TXT</div>', true },
    { "hidden attribute loses to an inline display", '', '',
      '<div hidden style="display:block">TXT</div>', false },
    { "hidden attribute loses to a stylesheet display", '.s{display:block}', '',
      '<div hidden class="s">TXT</div>', false },
    { "hidden attribute loses to a stylesheet tag rule", 'div{display:block}', '',
      '<div hidden>TXT</div>', false },
    { "hidden attribute loses to an important stylesheet display", '.s{display:block !important}', '',
      '<div hidden class="s" style="display:none">TXT</div>', false },
    { "hidden attribute does not undo an inline display:none", '', '',
      '<div hidden style="display:none">TXT</div>', true },
    { "hidden ancestor hides a block child", '', '',
      '<div hidden><div style="display:block">TXT</div></div>', true },
    { "hidden ancestor hides a child by tag", '', '',
      '<div hidden><p>TXT</p></div>', true },
    { "ancestor display overrides its hidden attribute", '', '',
      '<div hidden style="display:block"><span>TXT</span></div>', false },
    { "ancestor stylesheet display overrides its hidden attribute", '.s{display:block}', '',
      '<div hidden class="s"><span>TXT</span></div>', false },
    { "display:none ancestor with hidden attribute hides a block child", '', '',
      '<div hidden style="display:none"><div style="display:block">TXT</div></div>', true },
    { "hidden attribute on a span hides it", '', '', '<span hidden>TXT</span>', true },

    { "font color attribute alone blanks text on a white body", '', 'bgcolor="#ffffff"',
      '<font color="white">TXT</font>', true },
    { "font color attribute loses to an inline color", '', 'bgcolor="#ffffff"',
      '<font color="white" style="color:#333333">TXT</font>', false },
    { "font color attribute loses to a stylesheet color", 'font{color:#333333}', 'bgcolor="#ffffff"',
      '<font color="white">TXT</font>', false },
    { "font color attribute loses to a class color", '.f{color:#333333}', 'bgcolor="#ffffff"',
      '<font color="white" class="f">TXT</font>', false },
    { "font color attribute loses to an important stylesheet color", 'font{color:#333333 !important}',
      'bgcolor="#ffffff"', '<font color="white" style="color:white">TXT</font>', false },
    { "visible font color attribute is shown", '', 'bgcolor="#ffffff"',
      '<font color="#333333">TXT</font>', false },
    { "inline color blanks text over a font color attribute", '', 'bgcolor="#ffffff"',
      '<font color="#333333" style="color:#ffffff">TXT</font>', true },
    { "bgcolor attribute alone blanks matching text", '', '',
      '<div bgcolor="#ffffff"><font color="#ffffff">TXT</font></div>', true },
    { "bgcolor attribute with a different font color is shown", '', '',
      '<div bgcolor="#ffffff"><font color="#000000">TXT</font></div>', false },
    { "bgcolor attribute loses to an inline background", '', '',
      '<div bgcolor="#ffffff" style="background-color:#000000"><font color="#000000">TXT</font></div>', true },
    { "bgcolor attribute loses to a stylesheet background", 'div{background-color:#000000}', '',
      '<div bgcolor="#ffffff"><font color="#000000">TXT</font></div>', true },
    { "a child inherits a hinted color", '', 'bgcolor="#ffffff"',
      '<font color="white"><span>TXT</span></font>', true },
    { "a child author color overrides an inherited hinted color", '', 'bgcolor="#ffffff"',
      '<font color="white"><span style="color:#333333">TXT</span></font>', false },
    { "a hinted color beats an inherited one", '', 'bgcolor="#ffffff"',
      '<div style="color:#333333"><font color="white">TXT</font></div>', true },
    { "an author color of a parent does not beat a hint of a child", '.p{color:#333333}', 'bgcolor="#ffffff"',
      '<div class="p"><font color="white">TXT</font></div>', true },

    -- Task 2: visibility is inherited and can be reset by descendants
    { "visibility:hidden hides", '', '', '<div style="visibility:hidden">TXT</div>', true },
    { "visibility:collapse hides", '', '', '<div style="visibility:collapse">TXT</div>', true },
    { "visibility:visible alone shows", '', '', '<div style="visibility:visible">TXT</div>', false },
    { "visible child of a hidden parent is shown", '', '',
      '<div style="visibility:hidden"><span style="visibility:visible">TXT</span></div>', false },
    { "visibility:inherit does not re-show a child of a hidden parent", '', '',
      '<div style="visibility:hidden"><span style="visibility:inherit">TXT</span></div>', true },
    { "child without visibility of a hidden parent is hidden", '', '',
      '<div style="visibility:hidden"><span>TXT</span></div>', true },
    { "text of the hidden parent itself stays hidden", '', '',
      '<div style="visibility:hidden">HIDE<span style="visibility:visible">TXT</span></div>', false },
    { "visible child by stylesheet in a hidden parent is shown", '.v{visibility:visible}', '',
      '<div style="visibility:hidden"><span class="v">TXT</span></div>', false },
    { "grandchild inherits the visibility of a re-shown child", '', '',
      '<div style="visibility:hidden"><div style="visibility:visible"><span>TXT</span></div></div>', false },
    { "grandchild can hide again", '', '',
      '<div style="visibility:hidden"><div style="visibility:visible"><span style="visibility:hidden">TXT</span></div></div>',
      true },
    { "important inline visibility:hidden beats a stylesheet visible", '.c{visibility:visible}', '',
      '<div class="c" style="visibility:hidden !important">TXT</div>', true },
    { "important stylesheet visibility:hidden beats an inline visible", '.c{visibility:hidden !important}', '',
      '<div class="c" style="visibility:visible">TXT</div>', true },
    { "normal stylesheet visibility:hidden loses to an inline visible", '.c{visibility:hidden}', '',
      '<div class="c" style="visibility:visible">TXT</div>', false },
    { "important visible child of a hidden parent is shown", '.c{visibility:visible !important}', '',
      '<div style="visibility:hidden"><span class="c" style="visibility:hidden">TXT</span></div>', false },
    { "display:none parent with a visible child stays hidden", '', '',
      '<div style="display:none"><span style="visibility:visible">TXT</span></div>', true },
    { "display:none with visibility:visible on one element stays hidden", '', '',
      '<div style="display:none;visibility:visible">TXT</div>', true },
    { "visibility:visible child of a hidden parent with display:block is shown", '', '',
      '<div style="visibility:hidden"><div style="display:block;visibility:visible">TXT</div></div>', false },
    { "wrapping the message in visibility:hidden and re-showing the content", '', '',
      '<div style="visibility:hidden"><div style="visibility:visible"><p>TXT</p></div></div>', false },
  }

  for _, c in ipairs(cases) do
    test(c[1], function()
      local text = text_of(c[2], c[3], c[4])
      assert_not_nil(text:find("vis", 1, true), "visible text is missing")
      assert_equal(c[5], text:find("TXT", 1, true) == nil)
      if c[4]:find("HIDE", 1, true) then
        assert_nil(text:find("HIDE", 1, true), "parent text must stay hidden")
      end
    end)
  end
end)
