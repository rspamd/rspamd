--[[
A Content-Disposition filename that readers take no value from (pieces
without a first one) gives way to the name of Content-Type, as in Thunderbird;
an empty parameter does not hide the ones after it.
]]

context("MIME filename fallback", function()
  local rspamd_task = require "rspamd_task"

  local function filename_of(ct, cd)
    local msg = table.concat({
      'From: a@example.com',
      'To: b@example.com',
      'Subject: test',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary=B',
      '',
      '--B',
      'Content-Type: ' .. ct,
      'Content-Disposition: ' .. cd,
      '',
      'MZ',
      '--B--',
      '',
    }, '\r\n')
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    local name
    for _, p in ipairs(task:get_parts()) do
      if p:get_type() == 'application' then
        name = p:get_filename()
      end
    end
    task:destroy()
    return name
  end

  test("pieces without a first one give way to the name of Content-Type", function()
    assert_equal('invoice.exe', filename_of('application/octet-stream; name="invoice.exe"',
        'attachment; filename*1=x.pdf'))
    -- With no name there, what the pieces hold
    assert_equal('x.pdf', filename_of('application/octet-stream', 'attachment; filename*1=x.pdf'))
  end)

  test("an empty parameter does not hide the filename after it", function()
    assert_equal('invoice.exe', filename_of('application/octet-stream', 'attachment; foo=; filename="invoice.exe"'))
  end)
end)
