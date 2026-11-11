--[[
x-user-defined is a WHATWG label (bytes past ASCII as U+F780 to U+F7FF). It
names a charset in RFC 2231 parameters, as in Thunderbird, but not for the
text of a part: as there, its words would be private-use characters, which
words, Bayes and fuzzy hashes would lose, while readers that do not know the
label show the text as they guess it.
]]

context("MIME charset x-user-defined", function()
  local rspamd_task = require "rspamd_task"

  test("a text part declared x-user-defined keeps its words", function()
    -- "Привет мир" in UTF-8
    local text = '\208\159\209\128\208\184\208\178\208\181\209\130 \208\188\208\184\209\128'
    local msg = table.concat({
      'From: a@example.com',
      'To: b@example.com',
      'Subject: test',
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=x-user-defined',
      'Content-Transfer-Encoding: 8bit',
      '',
      text,
      '',
    }, '\r\n')
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    local content = tostring(task:get_text_parts()[1]:get_content())
    assert_not_nil(content:find(text, 1, true), content)
    task:destroy()
  end)

  test("an RFC 2231 name in x-user-defined keeps its extension", function()
    local msg = table.concat({
      'From: a@example.com',
      'To: b@example.com',
      'Subject: test',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary=B',
      '',
      '--B',
      'Content-Type: application/octet-stream',
      "Content-Disposition: attachment; filename*0=invoice.pdf; filename*=x-user-defined''invoice%FF.exe",
      '',
      'MZ',
      '--B--',
      '',
    }, '\r\n')
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    local names = {}
    for _, p in ipairs(task:get_parts()) do
      if p:get_filename() then
        names[#names + 1] = p:get_filename()
      end
    end
    assert_rspamd_table_eq({ actual = names, expect = { 'invoice\239\159\191.exe' } })
    task:destroy()
  end)
end)
