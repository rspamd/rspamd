--[[
Zip archives are read from the end of central directory record, which can be
followed by a comment of up to 64 KB. The record must be found anywhere in that
range, and a copy of its magic in the comment must not hide the real one.
]]

context("Zip archive listing", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"

  local function make_zip(name, comment)
    local local_header = "PK\3\4" .. string.rep("\0", 26) .. name
    local cd = "PK\1\2" .. string.rep("\0", 24) ..
        rspamd_util.pack("<I2", #name) .. string.rep("\0", 16) .. name
    local eocd = "PK\5\6" .. string.rep("\0", 8) ..
        rspamd_util.pack("<I4", #cd) ..
        rspamd_util.pack("<I4", #local_header) ..
        rspamd_util.pack("<I2", #comment) .. comment

    return local_header .. cd .. eocd
  end

  local function files_of(zip)
    local msg = table.concat({
      "From: a@example.com",
      "To: b@example.com",
      "Subject: zip",
      "MIME-Version: 1.0",
      "Content-Type: application/zip; name=\"a.zip\"",
      "Content-Disposition: attachment; filename=\"a.zip\"",
      "Content-Transfer-Encoding: base64",
      "",
      tostring(rspamd_util.encode_base64(zip, 76)),
      "",
    }, "\r\n")
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not res then
      return nil
    end
    task:process_message()

    local files = {}
    for _, a in ipairs(task:get_archives() or {}) do
      for _, f in ipairs(a:get_files() or {}) do
        files[#files + 1] = f
      end
    end
    task:destroy()

    return files
  end

  test("lists files of an archive without a comment", function()
    assert_rspamd_table_eq({
      actual = files_of(make_zip("invoice.pdf.exe", "")),
      expect = { "invoice.pdf.exe" },
    })
  end)

  test("lists files of an archive with a long comment", function()
    -- Mail clients and unzip look up to 64 KB back
    for _, len in ipairs({ 2000, 65535 }) do
      assert_rspamd_table_eq({
        actual = files_of(make_zip("invoice.pdf.exe", string.rep("c", len))),
        expect = { "invoice.pdf.exe" },
      })
    end
  end)

  test("the last usable end record is used, as zip readers do", function()
    -- An outer archive whose comment holds another one ending one byte before
    -- the end: readers take the last record, i.e. the inner one
    local outer_lh = "PK\3\4" .. string.rep("\0", 26) .. "readme.txt"
    local outer_cd = "PK\1\2" .. string.rep("\0", 24) ..
        rspamd_util.pack("<I2", #"readme.txt") .. string.rep("\0", 16) .. "readme.txt"
    local base = #outer_lh + #outer_cd + 22
    local inner_lh = "PK\3\4" .. string.rep("\0", 26) .. "invoice.exe"
    local inner_cd = "PK\1\2" .. string.rep("\0", 24) ..
        rspamd_util.pack("<I2", #"invoice.exe") .. string.rep("\0", 16) .. "invoice.exe"
    local inner = inner_lh .. inner_cd .. "PK\5\6" .. string.rep("\0", 8) ..
        rspamd_util.pack("<I4", #inner_cd) .. rspamd_util.pack("<I4", base + #inner_lh) .. "\0\0"
    local comment = inner .. "x"
    local zip = outer_lh .. outer_cd .. "PK\5\6" .. string.rep("\0", 8) ..
        rspamd_util.pack("<I4", #outer_cd) .. rspamd_util.pack("<I4", #outer_lh) ..
        rspamd_util.pack("<I2", #comment) .. comment
    assert_rspamd_table_eq({
      actual = files_of(zip),
      expect = { "invoice.exe" },
    })
  end)

  test("a zip64 end record is read through its locator", function()
    local name = "invoice.pdf.exe"
    local lh = "PK\3\4" .. string.rep("\0", 26) .. name
    local cd = "PK\1\2" .. string.rep("\0", 24) ..
        rspamd_util.pack("<I2", #name) .. string.rep("\0", 16) .. name
    local z64_offset = #lh + #cd
    local z64 = "PK\6\6" .. rspamd_util.pack("<I8", 44) .. string.rep("\0", 28) ..
        rspamd_util.pack("<I8", #cd) .. rspamd_util.pack("<I8", #lh)
    local locator = "PK\6\7" .. string.rep("\0", 4) ..
        rspamd_util.pack("<I8", z64_offset) .. rspamd_util.pack("<I4", 1)
    local eocd = "PK\5\6" .. string.rep("\0", 4) .. string.rep("\255", 4) ..
        string.rep("\255", 8) .. "\0\0"
    assert_rspamd_table_eq({
      actual = files_of(lh .. cd .. z64 .. locator .. eocd),
      expect = { name },
    })
  end)

  test("an archive appended to another one is read", function()
    -- Its offsets count from its own start, readers use its last end record
    assert_rspamd_table_eq({
      actual = files_of(make_zip("readme.txt", "") .. make_zip("invoice.pdf.exe", "")),
      expect = { "invoice.pdf.exe" },
    })
  end)

  test("an end record copied into the comment does not hide the archive", function()
    local fake = "PK\5\6" .. string.rep("\0", 8) ..
        rspamd_util.pack("<I4", 0xffff) .. rspamd_util.pack("<I4", 0xfffff) .. "\0\0"
    assert_rspamd_table_eq({
      actual = files_of(make_zip("invoice.pdf.exe",
          string.rep("c", 100) .. fake .. string.rep("d", 50))),
      expect = { "invoice.pdf.exe" },
    })
  end)
  test("two archives one after the other are both listed", function()
    -- The offset in the last end record points to the directory of the first
    -- archive: Python's zipfile and unzip read the directory right before the
    -- record, other readers the offset. Both lists are kept.
    local first = make_zip("readme.txt", "")
    local second = make_zip("runme_.exe", "")
    local files = files_of(first .. second)
    table.sort(files)
    assert_rspamd_table_eq({
      actual = files,
      expect = { "readme.txt", "runme_.exe" },
    })
  end)
  local function cd_record(name)
    return "PK\1\2" .. string.rep("\0", 24) ..
        rspamd_util.pack("<I2", #name) .. string.rep("\0", 16) .. name
  end

  local function eocd(cd_size, cd_offset)
    return "PK\5\6" .. string.rep("\0", 8) ..
        rspamd_util.pack("<I4", cd_size) .. rspamd_util.pack("<I4", cd_offset) .. "\0\0"
  end

  local function sorted(t)
    table.sort(t)
    return t
  end

  test("zip64 records between the directory and the end record", function()
    -- The 32-bit end record holds the real values; a first directory record of
    -- 76 bytes (the size of the zip64 records) must not shift the directory
    local name1 = string.rep("a", 30)
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local cd = cd_record(name1) .. cd_record("evil.exe")
    local z64 = "PK\6\6" .. rspamd_util.pack("<I8", 44) .. string.rep("\0", 4 + 8) ..
        rspamd_util.pack("<I8", 2) .. rspamd_util.pack("<I8", 2) ..
        rspamd_util.pack("<I8", #cd) .. rspamd_util.pack("<I8", #lh)
    local loc = "PK\6\7" .. string.rep("\0", 4) ..
        rspamd_util.pack("<I8", #lh + #cd) .. rspamd_util.pack("<I4", 1)
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. z64 .. loc .. eocd(#cd, #lh))),
      expect = sorted({ name1, "evil.exe" }),
    })
  end)

  test("a broken directory before the end record does not hide the declared one", function()
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local cd = cd_record("runme_.exe")
    local junk = "PK\1\2" .. string.rep("x", #cd - 4)
    assert_rspamd_table_eq({
      actual = files_of(lh .. cd .. junk .. eocd(#cd, #lh)),
      expect = { "runme_.exe" },
    })
  end)

  test("a declared directory that runs into the other one lists no file twice", function()
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local extra = cd_record("a.txt")
    local cd = cd_record("b.exe") .. cd_record("c.exe")
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. extra .. cd .. eocd(#cd, #lh))),
      expect = { "a.txt", "b.exe", "c.exe" },
    })
  end)
end)
