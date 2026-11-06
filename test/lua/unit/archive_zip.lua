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
    -- Its offsets count from its own start; readers that use the last end
    -- record list it, 7-Zip the first archive: both, the last one first
    assert_rspamd_table_eq({
      actual = files_of(make_zip("readme.txt", "") .. make_zip("invoice.pdf.exe", "")),
      expect = { "invoice.pdf.exe", "readme.txt" },
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
  test("a last record whose comment runs past the end record keeps its file", function()
    -- Python, unzip and 7-Zip list both files
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local last = "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", #"runme.exe") ..
        "\0\0" .. rspamd_util.pack("<I2", 0xffff) .. string.rep("\0", 12) .. "runme.exe"
    local cd = cd_record("readme.txt") .. last
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. eocd(#cd, #lh))),
      expect = { "readme.txt", "runme.exe" },
    })
  end)

  local function overrun_record(name)
    -- Its comment runs past the end record
    return "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", #name) ..
        "\0\0" .. rspamd_util.pack("<I2", 0xffff) .. string.rep("\0", 12) .. name
  end

  test("a directory that runs past its end record does not hide the declared one", function()
    -- Python lists the directory right before the record, 7-Zip the one
    -- at the offset
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local declared = cd_record("declared.exe")
    local adjacent = cd_record("a.txt") .. overrun_record("b.txt")
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. declared .. adjacent .. eocd(#adjacent, #lh))),
      expect = { "a.txt", "b.txt", "declared.exe" },
    })
  end)

  test("a directory that runs past its end record does not hide an earlier record", function()
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local first = cd_record("evil.exe")
    local last = overrun_record("readme.txt")
    local zip = lh .. first .. eocd(#first, #lh) ..
        last .. eocd(#last, #lh + #first + 22)
    assert_rspamd_table_eq({
      actual = sorted(files_of(zip)),
      expect = { "evil.exe", "readme.txt" },
    })
  end)

  test("a directory that runs past its end record does not cut the declared one", function()
    -- The directory before the end record is a record hidden in the extra
    -- field of the declared directory's first record: the declared one is
    -- still read to its end, as when the other one does not read at all
    local function cd_rec(name, extra, comment_len)
      return "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", #name) ..
          rspamd_util.pack("<I2", #extra) .. rspamd_util.pack("<I2", comment_len) ..
          string.rep("\0", 12) .. name .. extra
    end
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local hidden = cd_rec("p1.txt", "", 0xffff)
    local first = cd_rec("a1.txt", rspamd_util.pack("<I2", 0xcafe) ..
        rspamd_util.pack("<I2", #hidden) .. hidden, 0)
    local second = cd_rec("a2.exe", "", 0)
    local pad = string.rep("\0", 56)
    local cd_size = #lh + #first + #second + #pad - (#lh + 56)
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. first .. second .. pad .. eocd(cd_size, #lh))),
      expect = { "a1.txt", "a2.exe", "p1.txt" },
    })
  end)

  test("a directory read for two end records is listed once", function()
    -- The last record is empty and the directory runs past it: the record
    -- before it describes the same directory
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local cd = cd_record("a.txt") .. overrun_record("b.exe")
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. eocd(#cd, #lh) .. eocd(0, #lh))),
      expect = { "a.txt", "b.exe" },
    })
  end)

  test("an empty end record keeps the files that read before broken data", function()
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local bad = "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", 0xffff) ..
        string.rep("\0", 16)
    assert_rspamd_table_eq({
      actual = files_of(lh .. cd_record("runme.exe") .. bad .. eocd(0, #lh)),
      expect = { "runme.exe" },
    })
  end)

  test("zip64 and 32-bit values that point to different directories", function()
    -- Python and bsdtar take the zip64 values, 7-Zip the 32-bit ones
    local lh = "PK\3\4" .. string.rep("\0", 26)
    local cd32 = cd_record("payload.exe")
    local cd64 = cd_record("readme.txt")
    local z64 = "PK\6\6" .. rspamd_util.pack("<I8", 44) .. string.rep("\0", 28) ..
        rspamd_util.pack("<I8", #cd64) .. rspamd_util.pack("<I8", #lh + #cd32)
    local loc = "PK\6\7" .. string.rep("\0", 4) ..
        rspamd_util.pack("<I8", #lh + #cd32 + #cd64) .. rspamd_util.pack("<I4", 1)
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd32 .. cd64 .. z64 .. loc .. eocd(#cd32, #lh))),
      expect = { "payload.exe", "readme.txt" },
    })
  end)

  test("an archive followed by an empty one is listed", function()
    -- 7-Zip reads the first one
    assert_rspamd_table_eq({
      actual = files_of(make_zip("payload.exe", "") .. eocd(0, 0)),
      expect = { "payload.exe" },
    })
  end)

  test("a zip64 archive followed by another one is listed too", function()
    local name = "payload.exe"
    local lh = "PK\3\4" .. string.rep("\0", 26) .. name
    local cd = cd_record(name)
    local z64 = "PK\6\6" .. rspamd_util.pack("<I8", 44) .. string.rep("\0", 28) ..
        rspamd_util.pack("<I8", #cd) .. rspamd_util.pack("<I8", #lh)
    local loc = "PK\6\7" .. string.rep("\0", 4) ..
        rspamd_util.pack("<I8", #lh + #cd) .. rspamd_util.pack("<I4", 1)
    local first = lh .. cd .. z64 .. loc .. "PK\5\6" .. string.rep("\0", 4) ..
        string.rep("\255", 4) .. string.rep("\255", 8) .. "\0\0"
    assert_rspamd_table_eq({
      actual = sorted(files_of(first .. make_zip("readme.txt", ""))),
      expect = { "payload.exe", "readme.txt" },
    })
  end)

  local function cd_rec(name, lh_offset, comment, comment_len)
    return "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", #name) .. "\0\0" ..
        rspamd_util.pack("<I2", comment_len or #comment) .. string.rep("\0", 8) ..
        rspamd_util.pack("<I4", lh_offset) .. name .. comment
  end

  local function z64_rec(cd_size, cd_offset)
    return "PK\6\6" .. rspamd_util.pack("<I8", 44) .. string.rep("\0", 28) ..
        rspamd_util.pack("<I8", cd_size) .. rspamd_util.pack("<I8", cd_offset)
  end

  local function z64_loc(offset)
    return "PK\6\7" .. string.rep("\0", 4) .. rspamd_util.pack("<I8", offset) ..
        rspamd_util.pack("<I4", 1)
  end

  test("the first archive is found through the directory 7-Zip reads", function()
    -- The zip64 directory of the last archive runs past its end record; the
    -- 32-bit one, right before the record, shows the archive in front
    local first = make_zip("payload.exe", "")
    local lh = "PK\3\4" .. string.rep("\0", 26) .. "readme.txt" ..
        "PK\3\4" .. string.rep("\0", 26) .. "x.txt"
    local cd_x = cd_rec("x.txt", 40, "", 0xffff)
    local cd32_at = #lh + #cd_x
    local z64_at = #first + cd32_at + 46 + #"readme.txt"
    local cd32 = cd_rec("readme.txt", 0,
        z64_rec(#cd_x, #first + #lh) .. z64_loc(z64_at))
    local last = lh .. cd_x .. cd32 .. eocd(#cd32, cd32_at)
    assert_rspamd_table_eq({
      actual = sorted(files_of(first .. last)),
      expect = { "payload.exe", "readme.txt", "x.txt" },
    })
  end)

  test("the first archive is found when the last one counts from the start", function()
    -- `cat a.zip b.zip; zip -A`, or an empty record at its own offset. The
    -- entries of the last archive are found by their local headers
    local first = make_zip("payload.exe", "")
    local lh = "PK\3\4" .. string.rep("\0", 22) .. rspamd_util.pack("<I2", #"readme.txt") ..
        "\0\0" .. "readme.txt"
    local cd = cd_rec("readme.txt", #first, "")
    assert_rspamd_table_eq({
      actual = sorted(files_of(first .. lh .. cd .. eocd(#cd, #first + #lh))),
      expect = { "payload.exe", "readme.txt" },
    })
    assert_rspamd_table_eq({
      actual = files_of(first .. eocd(0, #first)),
      expect = { "payload.exe" },
    })
  end)

  test("a record in front that reads no directory does not hide the archive", function()
    local lh = "PK\3\4" .. string.rep("\0", 26) .. "payload.exe"
    -- File data that looks like a directory and its end record
    local fake = "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", 0xffff) ..
        string.rep("\0", 16)
    local data = fake .. eocd(#fake, #lh)
    local cd = cd_record("payload.exe")
    local first = lh .. data .. cd .. eocd(#cd, #lh + #data)
    assert_rspamd_table_eq({
      actual = sorted(files_of(first .. make_zip("readme.txt", ""))),
      expect = { "payload.exe", "readme.txt" },
    })
  end)

  test("an empty end record appended to an archive does not hide its files", function()
    -- The appended record says the directory is empty but points to it:
    -- unzip and 7-Zip list it
    local zip = make_zip("runme.exe", "")
    assert_rspamd_table_eq({
      actual = files_of(zip .. eocd(0, 30 + #"runme.exe")),
      expect = { "runme.exe" },
    })
  end)

  test("the first of two archives one after the other is listed too", function()
    -- `cat evil.zip benign.zip`: Python and unzip list the last archive,
    -- 7-Zip and WinRAR the first one
    local files = files_of(make_zip("invoice.exe", "") .. make_zip("readme.txt", ""))
    assert_rspamd_table_eq({
      actual = sorted(files),
      expect = { "invoice.exe", "readme.txt" },
    })
  end)

  local function stored_lh(name, data, flags, csize)
    return "PK\3\4" .. "\0\0" .. rspamd_util.pack("<I2", flags or 0) .. string.rep("\0", 10) ..
        rspamd_util.pack("<I4", csize or #data) .. rspamd_util.pack("<I4", csize or #data) ..
        rspamd_util.pack("<I2", #name) .. "\0\0" .. name
  end

  test("a directory in the data of a file does not hide the first archive", function()
    -- 7-Zip walks the entries of the first archive by their sizes, past
    -- data that looks like a directory and its end record
    local name = "payload.exe"
    local fake = cd_rec("fake.txt", 0, "")
    local data = "MZ" .. fake .. eocd(#fake, 30 + #name + 2)
    local lh = stored_lh(name, data)
    local cd = cd_rec(name, 0, "")
    local first = lh .. data .. cd .. eocd(#cd, #lh + #data)
    assert_rspamd_table_eq({
      actual = sorted(files_of(first .. make_zip("readme.txt", ""))),
      expect = { "payload.exe", "readme.txt" },
    })
    -- The size is only in the data descriptor after the data
    lh = stored_lh(name, data, 8, 0)
    local dd = "PK\7\8" .. string.rep("\0", 4) .. rspamd_util.pack("<I4", #data) ..
        rspamd_util.pack("<I4", #data)
    first = lh .. data .. dd .. cd .. eocd(#cd, #lh + #data + #dd)
    assert_rspamd_table_eq({
      actual = sorted(files_of(first .. make_zip("readme.txt", ""))),
      expect = { "payload.exe", "readme.txt" },
    })
  end)

  test("a record that runs past its end record does not hide the first archive", function()
    -- The lengths of the first record cover the end record of its archive
    local lh = stored_lh("payload.exe", "") .. stored_lh("x.txt", "")
    local cd = cd_rec("payload.exe", 0, "", 60) .. cd_rec("x.txt", 41, "")
    local first = lh .. cd .. eocd(#cd, #lh)
    local files = files_of(first .. make_zip("mid.txt", "") .. make_zip("readme.txt", ""))
    assert_true(#files > 0)
    local listed = {}
    for _, f in ipairs(files) do
      listed[f] = true
    end
    assert_true(listed["payload.exe"])
    assert_true(listed["readme.txt"])
  end)

  local function has_all(files, names)
    local listed = {}
    for _, f in ipairs(files) do
      listed[f] = true
    end
    for _, n in ipairs(names) do
      if not listed[n] then
        return false
      end
    end
    return true
  end

  test("the local headers of the first archive are listed when no directory lists them", function()
    -- 7-Zip lists the entries it walks: a directory that names a decoy, or
    -- lengths that lead to a fake directory, do not hide them
    local data = "MZ"
    local lh = stored_lh("payload.exe", data) .. data
    local cd = cd_rec("decoy.txt", 0, "")
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. eocd(#cd, #lh) .. make_zip("readme.txt", ""))),
      expect = { "decoy.txt", "payload.exe", "readme.txt" },
    })
    -- The comment length of the last record covers the end record, and a
    -- directory with its end record follows in the comment of that record
    cd = cd_rec("payload.exe", 0, "", 26)
    local fake = cd_rec("fake.txt", 0, "")
    local comment = "PPPP" .. fake .. eocd(#fake, #lh + #cd + 22 + 4)
    local real_eocd = eocd(#cd, #lh):sub(1, 20) .. rspamd_util.pack("<I2", #comment) .. comment
    assert_true(has_all(files_of(lh .. cd .. real_eocd .. make_zip("readme.txt", "")),
        { "payload.exe", "readme.txt" }))
  end)

  test("a directory in the zip64 end record of the first archive is passed", function()
    local data = "MZ"
    local lh = stored_lh("payload.exe", data) .. data
    local cd = cd_rec("payload.exe", 0, "")
    local z64_at = #lh + #cd
    local fake = cd_rec("fake.txt", 0, "")
    local ext = fake .. eocd(#fake, z64_at + 56)
    local z64 = "PK\6\6" .. rspamd_util.pack("<I8", 44 + #ext) .. string.rep("\0", 28) ..
        rspamd_util.pack("<I8", #cd) .. rspamd_util.pack("<I8", #lh) .. ext
    local first = lh .. cd .. z64 .. z64_loc(z64_at) .. "PK\5\6" .. string.rep("\0", 4) ..
        string.rep("\255", 4) .. string.rep("\255", 8) .. "\0\0"
    assert_rspamd_table_eq({
      actual = sorted(files_of(first .. make_zip("readme.txt", ""))),
      expect = { "payload.exe", "readme.txt" },
    })
  end)

  test("a maxed directory offset without zip64 records keeps the archive", function()
    -- Info-ZIP `zip -fz` to a pipe: readers take the directory right before
    -- the record
    local data = "MZ"
    local lh = stored_lh("payload.exe", data) .. data
    local cd = cd_rec("payload.exe", 0, "")
    assert_rspamd_table_eq({
      actual = files_of(lh .. cd .. eocd(#cd, 0xffffffff)),
      expect = { "payload.exe" },
    })
  end)

  local function cd_upath(name, upath, lh_offset)
    local crc = require("rspamd_util").crc32(name)
    local field = "\117\112" .. rspamd_util.pack("<I2", 5 + #upath) .. "\1" ..
        rspamd_util.pack("<I4", crc) .. upath
    return "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", #name) ..
        rspamd_util.pack("<I2", #field) .. string.rep("\0", 10) ..
        rspamd_util.pack("<I4", lh_offset) .. name .. field
  end

  local function aliases_of(zip)
    local msg = table.concat({
      "Subject: zip",
      "MIME-Version: 1.0",
      "Content-Type: application/zip; name=\"a.zip\"",
      "Content-Disposition: attachment; filename=\"a.zip\"",
      "Content-Transfer-Encoding: base64",
      "",
      tostring(rspamd_util.encode_base64(zip, 76)),
      "",
    }, "\r\n")
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    local aliases = {}
    for _, a in ipairs(task:get_archives() or {}) do
      for _, f in ipairs(a:get_files_full() or {}) do
        if f.alias then
          aliases[#aliases + 1] = f.name
        end
      end
    end
    task:destroy()
    table.sort(aliases)

    return aliases
  end

  test("local headers named otherwise than the directory are listed", function()
    -- bsdtar and macOS go by local headers, 7-Zip too when they differ
    local data = "MZ"
    local lh = stored_lh("payload.exe", data) .. data
    local cd = cd_rec("readme.txt", 0, "")
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. eocd(#cd, #lh))),
      expect = { "payload.exe", "readme.txt" },
    })
    -- Another name of the one file, which counts of files skip
    assert_rspamd_table_eq({
      actual = aliases_of(lh .. cd .. eocd(#cd, #lh)),
      expect = { "payload.exe" },
    })
  end)

  test("the size in the header of an entry with a descriptor does not lead the walk", function()
    -- 7-Zip takes the descriptor whose size is its distance from the data
    local fake = cd_rec("decoy.txt", 0, "")
    local data = string.rep("A", 40) .. fake .. eocd(#fake, 30 + 5 + 40) .. string.rep("B", 30)
    local lh = stored_lh("a.txt", data, 8, 40)
    local dd = "PK\7\8" .. string.rep("\0", 4) .. rspamd_util.pack("<I4", #data) ..
        rspamd_util.pack("<I4", #data)
    local lh2 = stored_lh("payload.exe", "MZ")
    local entries = lh .. data .. dd .. lh2 .. "MZ"
    local cd = cd_rec("a.txt", 0, "") .. cd_rec("payload.exe", #lh + #data + #dd, "")
    local first = entries .. cd .. eocd(#cd, #entries)
    assert_true(has_all(files_of(first .. make_zip("readme.txt", "")),
        { "a.txt", "payload.exe", "readme.txt" }))
  end)

  test("an archive with a fake directory appended under a maxed offset is listed", function()
    local data = "MZ"
    local lh = stored_lh("payload.exe", data) .. data
    local cd = cd_rec("payload.exe", 0, "")
    local fake = cd_rec("decoy.txt", 0, "")
    assert_true(has_all(files_of(lh .. cd .. eocd(#cd, #lh) .. fake .. eocd(#fake, 0xffffffff)),
        { "payload.exe" }))
  end)

  test("the Unicode Path of a file is listed", function()
    -- 7-Zip, bsdtar and Python show it when its CRC is the one of the name
    local data = "MZ"
    local lh = stored_lh("readme.txt", data) .. data
    local cd = cd_upath("readme.txt", "payload.exe", 0)
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. eocd(#cd, #lh))),
      expect = { "payload.exe", "readme.txt" },
    })
    assert_rspamd_table_eq({
      actual = aliases_of(lh .. cd .. eocd(#cd, #lh)),
      expect = { "payload.exe" },
    })
    -- Another version, and one Unicode Path after another (bsdtar)
    local up2 = "\117\112" .. rspamd_util.pack("<I2", 5 + #"report.txt") .. "\1" ..
        rspamd_util.pack("<I4", require("rspamd_util").crc32("payload.exe")) .. "report.txt"
    local cd2 = cd_upath("readme.txt", "payload.exe", 0):gsub("\117\112(..)\1", "\117\112%1\0")
    cd2 = cd2:sub(1, 30) .. rspamd_util.pack("<I2", #cd2 - 46 - #"readme.txt" + #up2) ..
        cd2:sub(33) .. up2
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd2 .. eocd(#cd2, #lh))),
      expect = { "payload.exe", "readme.txt", "report.txt" },
    })
    -- With a CRC of another name, it is not
    cd = cd_upath("readme.txt", "payload.exe", 0):gsub("\117\112(..)\1....", function(len)
      return "\117\112" .. len .. "\1" .. "\0\0\0\0"
    end)
    assert_rspamd_table_eq({
      actual = files_of(lh .. cd .. eocd(#cd, #lh)),
      expect = { "readme.txt" },
    })
  end)

  -- A Unicode Path field: version, CRC of the name it replaces, name
  local function upath(version, crc_of, name)
    return "\117\112" .. rspamd_util.pack("<I2", 5 + #name) .. string.char(version) ..
        rspamd_util.pack("<I4", rspamd_util.crc32(crc_of)) .. name
  end

  local function cd_extra(name, extra, lh_offset)
    return "PK\1\2" .. string.rep("\0", 24) .. rspamd_util.pack("<I2", #name) ..
        rspamd_util.pack("<I2", #extra) .. string.rep("\0", 10) ..
        rspamd_util.pack("<I4", lh_offset) .. name .. extra
  end

  local function lh_extra(name, data, extra)
    return "PK\3\4" .. string.rep("\0", 14) .. rspamd_util.pack("<I4", #data) ..
        rspamd_util.pack("<I4", #data) .. rspamd_util.pack("<I2", #name) ..
        rspamd_util.pack("<I2", #extra) .. name .. extra .. data
  end

  test("the Unicode Path each reader shows is listed", function()
    -- bsdtar takes the one with the CRC of the name it shows so far: d.exe
    local lh = lh_extra("a.txt", "MZ", upath(1, "a.txt", "b.txt") .. upath(1, "a.txt", "c.txt") ..
        upath(1, "b.txt", "d.exe"))
    local cd = cd_extra("a.txt", "", 0)
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. eocd(#cd, #lh))),
      expect = { "a.txt", "b.txt", "c.txt", "d.exe" },
    })
  end)

  test("Unicode Paths after a name bsdtar cannot convert are listed", function()
    -- bsdtar checks no CRC after a name that does not convert: evil.exe
    local extra = upath(1, "a.txt", "x\255.txt") .. upath(1, "a.txt", "evil.exe") ..
        upath(1, "a.txt", "safe.txt")
    local lh = lh_extra("a.txt", "MZ", extra)
    local cd = cd_extra("a.txt", "", 0)
    assert_true(has_all(files_of(lh .. cd .. eocd(#cd, #lh)), { "evil.exe", "safe.txt" }))
  end)

  test("bsdtar converts a Unicode Path up to its first NUL", function()
    -- a.txt converts, so the CRC of a.txt leads to evil.exe, not any field to decoy.txt
    local extra = upath(1, "n.txt", "x\255.txt") .. upath(1, "qqq", "a.txt\0\255") ..
        upath(1, "zzz", "decoy.txt") .. upath(1, "a.txt", "evil.exe")
    local lh = lh_extra("n.txt", "MZ", extra)
    local cd = cd_extra("n.txt", "", 0)
    assert_true(has_all(files_of(lh .. cd .. eocd(#cd, #lh)), { "evil.exe" }))
  end)

  test("the first Unicode Path of version 1 is listed (yauzl)", function()
    for _, first in ipairs({ upath(0, "a.txt", "a1.txt"), upath(2, "a.txt", "a1.txt"), upath(1, "a.txt", "") }) do
      local extra = first .. upath(1, "a.txt", "evil.exe") .. upath(1, "a.txt", "safe.txt")
      local lh = lh_extra("a.txt", "MZ", "")
      local cd = cd_extra("a.txt", extra, 0)
      assert_true(has_all(files_of(lh .. cd .. eocd(#cd, #lh)), { "evil.exe", "safe.txt" }))
    end
  end)

  test("an entry lists the names readers show of its Unicode Paths, not all of them", function()
    -- 7-Zip and bsdtar show the first one, unzip and Python the last one
    local fields = {}
    for i = 1, 50 do
      fields[i] = upath(1, "a.txt", string.format("n%d.txt", i))
    end
    local extra = table.concat(fields)
    local lh = lh_extra("a.txt", "MZ", extra)
    local cd = cd_extra("a.txt", extra, 0)
    assert_rspamd_table_eq({
      actual = sorted(files_of(lh .. cd .. eocd(#cd, #lh))),
      expect = { "a.txt", "n1.txt", "n50.txt" },
    })
  end)
end)
