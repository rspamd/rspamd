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

context("7z archive names", function()
  local rspamd_task = require "rspamd_task"

  -- 7-Zip -mhc=off -m0=Copy: 9 bytes of packed data put the names at an odd
  -- offset; the second one is U+20AC U+1F600 ".txt"
  local odd_offset_b64 = [[
N3q8ryccAAQbwT2bCQAAAAAAAABOAAAAAAAAAGac7kZoZWxsbyEKeAoBBAYAAgkHAgAHCwIA
AQEAAQEADAcCAAgKAQLh/38fCOpGAAAFAhkFAAAAAAARHQBhAC4AdAB4AHQAAACsID3YAN4u
AHQAeAB0AAAAAAA=
]]
  -- The same archive with "A" in place of the low surrogate of U+1F600
  local lone_lead_b64 = [[
N3q8ryccAARtyF1/CQAAAAAAAABOAAAAAAAAADeUXsloZWxsbyEKeAoBBAYAAgkHAgAHCwIA
AQEAAQEADAcCAAgKAQLh/38fCOpGAAAFAhkFAAAAAAARHQBhAC4AdAB4AHQAAACsID3YQQAu
AHQAeAB0AAAAAAA=
]]
  -- ... and with a low surrogate alone in place of U+1F600
  local lone_trail_b64 = [[
N3q8ryccAAT9PuquCQAAAAAAAABOAAAAAAAAAH9H9hNoZWxsbyEKeAoBBAYAAgkHAgAHCwIA
AQEAAQEADAcCAAgKAQLh/38fCOpGAAAFAhkFAAAAAAARHQBhAC4AdAB4AHQAAACsIADeQQAu
AHQAeAB0AAAAAAA=
]]

  -- The odd-offset archive with its header packed (kEncodedHeader), the way
  -- 7-Zip writes it by default: libarchive lists those
  local packed_header_b64 = [[
N3q8ryccAASx8LXHVwAAAAAAAAASAAAAAAAAAACkRhloZWxsbyEKeAoBBAYAAgkHAgAHCwIA
AQEAAQEADAcCAAgKAQLh/38fCOpGAAAFAhkFAAAAAAARHQBhAC4AdAB4AHQAAACsID3YAN4u
AHQAeAB0AAAAAAAXBgkBCU4ABwsBAAEBAAxOAAA=
]]
  -- ... with a lone high surrogate in the first name
  local packed_lone_lead_b64 = [[
N3q8ryccAASx8LXHVwAAAAAAAAASAAAAAAAAAACkRhloZWxsbyEKeAoBBAYAAgkHAgAHCwIA
AQEAAQEADAcCAAgKAQLh/38fCOpGAAAFAhkFAAAAAAARHQCsID3YQQAuAHQAeAB0AAAAYQAu
AHQAeAB0AAAAAAAXBgkBCU4ABwsBAAEBAAxOAAA=
]]

  local function message(archive_b64)
    return table.concat({
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
  end

  local function list(archive_b64)
    local res, task = rspamd_task.load_from_string(message(archive_b64), rspamd_config)
    if not res then
      return nil
    end
    task:process_message()
    local names, obfuscated
    for _, p in ipairs(task:get_parts()) do
      if p:is_archive() then
        local arch = p:get_archive()
        names = {}
        for _, f in ipairs(arch:get_files()) do
          names[#names + 1] = f
        end
        obfuscated = arch:is_obfuscated()
      end
    end
    task:destroy()

    return names, obfuscated
  end

  test("decodes UTF-16LE names that start at an odd offset", function()
    local names, obfuscated = list(odd_offset_b64)
    assert_rspamd_table_eq({
      actual = names,
      expect = { "a.txt", "\226\130\172\240\159\152\128.txt" },
    })
    assert_false(obfuscated)
  end)

  test("keeps a name with an unpaired surrogate and flags it", function()
    for _, c in ipairs({
      { lone_lead_b64, "\226\130\172\239\191\189A.txt" },
      { lone_trail_b64, "\226\130\172\239\191\189A.txt" },
    }) do
      local names, obfuscated = list(c[1])
      assert_rspamd_table_eq({
        actual = names,
        expect = { "a.txt", c[2] },
      })
      assert_true(obfuscated, "the archive is not flagged as obfuscated")
    end
  end)

  test("lists non-ASCII names from a packed header", function()
    local names, obfuscated = list(packed_header_b64)
    assert_rspamd_table_eq({
      actual = names,
      expect = { "a.txt", "\226\130\172\240\159\152\128.txt" },
    })
    assert_false(obfuscated)
  end)

  test("a bad name in a packed header does not hide the next files", function()
    local names, obfuscated = list(packed_lone_lead_b64)
    assert_rspamd_table_eq({
      actual = names,
      expect = { "\239\191\189", "a.txt" },
    })
    assert_true(obfuscated, "the archive is not flagged as obfuscated")
  end)
end)
