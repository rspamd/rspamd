--[[
ISO-8859-16 (Romanian and other south-eastern European languages) has no
converter in ICU's default data, so rspamd converts it with an internal table.
Every alias of it must reach that table, both for text parts and for RFC 2047
encoded words.
]]

context("MIME charset ISO-8859-16", function()
  local rspamd_task = require "rspamd_task"

  -- S-comma, s-comma, T-comma, t-comma in ISO-8859-16 and in UTF-8
  local body = '\170\186\222\254'
  local body_utf8 = '\200\152\200\153\200\154\200\155'
  -- "Bună ziua Șș"
  local subject_utf8 = 'Bun\196\131 ziua \200\152\200\153'

  for _, cs in ipairs({ 'iso-8859-16', 'ISO-8859-16', 'latin10', 'iso-ir-226', 'l10' }) do
    test("text part and encoded word in " .. cs, function()
      local msg = table.concat({
        'From: a@example.com',
        'To: b@example.com',
        'Subject: =?' .. cs .. '?Q?Bun=E3_ziua_=AA=BA?=',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=' .. cs,
        'Content-Transfer-Encoding: 8bit',
        '',
        'Test ' .. body .. ' text',
        '',
      }, '\r\n')
      local res, task = rspamd_task.load_from_string(msg, rspamd_config)
      assert_true(res, "failed to load message")
      task:process_message()

      local tp = task:get_text_parts()[1]
      assert_true(tp:is_utf(), "text part is not converted to UTF-8")
      local content = tostring(tp:get_content())
      assert_not_nil(content:find('Test ' .. body_utf8 .. ' text', 1, true),
          "unexpected content")
      assert_equal(task:get_header('Subject'), subject_utf8)
      task:destroy()
    end)
  end
end)
