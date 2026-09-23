-- native 7z archive listing unit tests

context("7z archive listing", function()
  local rspamd_task = require "rspamd_task"

  -- A solid 7z with an uncompressed header: a directory, an empty file and
  -- two files packed in one folder, i.e. a folder with several substreams
  local archive_b64 = [[
N3q8ryccAASfon6QDAAAAAAAAACmAAAAAAAAAKbERhcBAAdoZWxsbwp4CgABBAYAAQkMAAcL
AQABISEBAAwIAAgNAgkGCgEgMDo2HwjqRgAABQQOAcAPAUARNwBkAAAAZQBtAHAAdAB5AC4A
YgBpAG4AAABhAC4AdAB4AHQAAABkAC8AaQBuAC4AdAB4AHQAAAAZBAAAAAAUIgEAAAhxVS9L
3QEACHFVL0vdAQCpGw8vS90BAAhxVS9L3QEVEgEAEIDtQSCApIEggKSBIICkgQAA
]]

  local msg = table.concat({
    'From: a@example.com',
    'To: b@example.com',
    'Subject: 7z',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="B"',
    '',
    '--B',
    'Content-Type: text/plain',
    '',
    'x',
    '--B',
    'Content-Type: application/x-7z-compressed; name="t.7z"',
    'Content-Disposition: attachment; filename="t.7z"',
    'Content-Transfer-Encoding: base64',
    '',
    archive_b64,
    '--B--',
    '',
  }, '\r\n')

  test("lists names from a folder with several substreams", function()
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local names
    for _, p in ipairs(task:get_parts()) do
      if p:is_archive() then
        local arch = p:get_archive()
        assert_equal(arch:get_type(), "7z")
        names = {}
        for _, f in ipairs(arch:get_files()) do
          names[#names + 1] = f
        end
      end
    end

    task:destroy()
    assert_rspamd_table_eq({
      actual = names,
      expect = { "d", "empty.bin", "a.txt", "d/in.txt" },
    })
  end)
end)
