--[[
Names of files in rar archives, as readers (unrar, 7-Zip, bsdtar) show them.
]]

context("Rar archive listing", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_text = require "rspamd_text"

  local function names_of(rar)
    local msg = table.concat({
      "Subject: rar",
      "MIME-Version: 1.0",
      "Content-Type: application/x-rar; name=\"a.rar\"",
      "Content-Disposition: attachment; filename=\"a.rar\"",
      "Content-Transfer-Encoding: base64",
      "",
      tostring(rspamd_util.encode_base64(rar, 76)),
      "",
    }, "\r\n")
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    local names = {}
    for _, a in ipairs(task:get_archives() or {}) do
      for _, f in ipairs(a:get_files_full() or {}) do
        names[f.name] = f.alias and "alias" or "file"
      end
    end
    task:destroy()

    return names
  end

  -- Rar 5: headers of a CRC (which bsdtar checks), a size, then fields as small numbers
  -- (one byte each here); the name may have a size other than its own (but less than 128)
  local function rar5_block(body)
    local sized = string.char(#body) .. body
    return rspamd_util.pack("<I4", rspamd_text.fromstring(sized):crc32()) .. sized
  end

  -- File header with data: no time, no CRC, stored, then the name
  local function rar5_file(name, data, name_size)
    return rar5_block("\2\2" .. string.char(#data) .. "\0" .. string.char(#data) .. "\32\0\0" ..
        string.char(name_size or #name) .. name) .. data
  end

  local rar5_start = "Rar!\26\7\1\0" .. rar5_block("\1\0\0")
  local rar5_end = rar5_block("\5\0\0")

  local function rar5(name, data, name_size)
    return rar5_start .. rar5_file(name, data, name_size) .. rar5_end
  end

  -- Rar 4: headers of a CRC, a type, flags and a size
  local function rar4_block(htype, flags, body)
    return "\0\0" .. string.char(htype) .. rspamd_util.pack("<I2", flags) ..
        rspamd_util.pack("<I2", 7 + #body) .. body
  end

  -- A file header of any type and flags, then its data
  local function rar4_head(htype, flags, name, data, name_size)
    local fields = rspamd_util.pack("<I4", #data) .. rspamd_util.pack("<I4", #data) ..
        string.rep("\0", 11) .. rspamd_util.pack("<I2", name_size or #name) ..
        rspamd_util.pack("<I4", 0x20)
    return rar4_block(htype, flags, fields .. name) .. data
  end

  local function rar4_file(name, data, flags, name_size)
    return rar4_head(116, 0x8000 + (flags or 0), name, data, name_size)
  end

  local rar4_start = "Rar!\26\7\0" .. "\0\0\115" .. rspamd_util.pack("<I2", 0) ..
      rspamd_util.pack("<I2", 13) .. string.rep("\0", 6)

  local rar4_end = "\0\0\123" .. rspamd_util.pack("<I2", 0x4000) .. rspamd_util.pack("<I2", 7)

  local function rar4(name, data, flags, name_size)
    return rar4_start .. rar4_file(name, data, flags, name_size)
  end

  test("a rar 5 name is listed up to its first NUL, as readers show it", function()
    local names = names_of(rar5("payload.exe\0.txt", "MZ"))
    assert_equal("alias", names["payload.exe"])
    names = names_of(rar5("payload.exe", "MZ"))
    assert_equal("file", names["payload.exe"])
  end)

  test("a rar 4 name is listed up to its first NUL, as readers show it", function()
    local names = names_of(rar4("payload.exe\0.txt", "MZ"))
    assert_equal("alias", names["payload.exe"])
    -- With nothing after the NUL of a Unicode name, the name before it is the one listed
    names = names_of(rar4("readme.txt\0\0", "MZ", 0x200))
    assert_equal("file", names["readme.txt"])
  end)

  test("a rar 4 Unicode name is listed as unrar, 7-Zip and bsdtar decode it", function()
    -- They show the name after the NUL: a byte for each character
    local names = names_of(rar4("invoice.pdf\0" .. "\0" .. "\0invo\0ice.\0exe", "MZ", 0x200))
    assert_equal("file", names["invoice.exe"])
    assert_equal("alias", names["invoice.pdf"])
    -- A run of the bytes of the name, then three bytes
    names = names_of(rar4("invoice.pdf\0" .. "\0\192\6exe", "MZ", 0x200))
    assert_equal("file", names["invoice.exe"])
    -- Two bytes cut by the end: unrar goes on with the byte left, bsdtar and 7-Zip stop
    names = names_of(rar4("doc.txt\0" .. "\0\0x.ex\128e", "MZ", 0x200))
    assert_equal("file", names["x.exe"])
    assert_equal("alias", names["x.ex"])
    -- 7-Zip shows 1023 characters of a longer name, which is listed by its start and end
    local decoded = string.rep("b", 1020) .. ".exe.txt"
    local enc = {}
    for i = 1, #decoded, 4 do
      enc[#enc + 1] = "\0" .. decoded:sub(i, i + 3)
    end
    names = names_of(rar4("long.txt\0\0" .. table.concat(enc), "MZ", 0x200))
    assert_equal("file", names[string.rep("b", 768) .. "\226\128\166" .. string.rep("b", 248) .. ".exe.txt"])
    assert_equal("alias", names[string.rep("b", 1020) .. ".ex"])
  end)

  test("a rar name is read from its header only, as unrar does", function()
    -- unrar reads zeros after the header, not the data that follows: evil.exe
    local data = "MZ\144\0\3\0"
    assert_not_nil(names_of(rar4("evil.exe", data, 0, 12))["evil.exe"])
    assert_not_nil(names_of(rar4("a\0" .. "\0" .. "\0evil\0.exe", data, 0x200, 17))["evil.exe"])
    assert_not_nil(names_of(rar5("evil.exe", data, 12))["evil.exe"])
    -- A name size past the end of the archive does not hide the files after it
    local names = names_of(rar4_start .. rar4_file("a.txt", "hello", 0, 60000) ..
        rar4_file("payload.exe", "MZ"))
    assert_equal("file", names["a.txt"])
    assert_equal("file", names["payload.exe"])
  end)

  test("a rar 4 Unicode name is listed as unrar shows bytes from 0x80 on in runs", function()
    -- A run without a correction is copied as signed char: unrar on Windows shows
    -- U+FFE9, on macOS nothing, on Linux the name up to it; 7-Zip and bsdtar U+00E9
    local names = names_of(rar4("invoice.exe\233.txt\0" .. "\0\192\14", "MZ", 0x200))
    assert_equal("file", names["invoice.exe\195\169.txt"])
    assert_equal("alias", names["invoice.exe\239\191\169.txt"])
    assert_equal("alias", names["invoice.exe.txt"])
    assert_equal("alias", names["invoice.exe"])
  end)

  test("a long rar 4 Unicode name is listed by its start and its end", function()
    -- Runs over the zeros unrar reads past the header make 12904 characters of 232 bytes
    local runs = {}
    for _ = 1, 25 do
      runs[#runs + 1] = "\255" .. string.rep("\255a", 4)
    end
    local field = "a\0" .. "\0" .. table.concat(runs) .. "\0.exe"
    local rar = rar4(field, "MZ", 0x200, 65535)
    local msg = table.concat({
      "Subject: rar", "MIME-Version: 1.0",
      "Content-Type: application/x-rar; name=\"a.rar\"",
      "Content-Disposition: attachment; filename=\"a.rar\"",
      "Content-Transfer-Encoding: base64", "",
      tostring(rspamd_util.encode_base64(rar, 76)), "",
    }, "\r\n")
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    local arch = task:get_archives()[1]
    local main = arch:get_files_full()[1]
    assert_false(main.alias)
    assert_true(#main.name <= 3 * 1025, "name of " .. #main.name)
    assert_equal("aaaa.exe", main.name:sub(-8))
    assert_true(arch:is_obfuscated())
    task:destroy()
  end)

  test("files before a broken or cut rar header are listed, as readers list them", function()
    local a4, b4 = rar4_file("invoice.exe", "MZ"), rar4_file("readme.txt", "hello")
    local a5, b5 = rar5_file("invoice.exe", "MZ"), rar5_file("readme.txt", "hello")
    for i, rar in ipairs({
      -- A byte after the files, the next header cut, a block of no size
      rar4_start .. a4 .. "\0",
      rar4_start .. a4 .. b4:sub(1, 12),
      rar4_start .. a4 .. "\0\0\116\0\0\0\0" .. b4 .. rar4_end,
      rar5_start .. a5 .. "\0",
      rar5_start .. a5 .. b5:sub(1, 9),
      rar5_start .. a5 .. "\0\0\0\0\0" .. b5 .. rar5_end,
    }) do
      assert_equal("file", names_of(rar)["invoice.exe"], "case " .. i)
    end
    -- The data of the last file cut: the file is listed
    assert_equal("file", names_of(rar4_start .. a4 .. b4:sub(1, -3))["readme.txt"])
    assert_equal("file", names_of(rar5_start .. a5 .. b5:sub(1, -3))["readme.txt"])
    -- unrar skips a file of no name and goes on
    assert_equal("file", names_of(rar4_start .. a4 .. rar4_file("", "xx") .. b4 .. rar4_end)["readme.txt"])
    assert_equal("file", names_of(rar5_start .. a5 .. rar5_file("", "xx") .. b5 .. rar5_end)["readme.txt"])
    -- Readers stop at a file of no name whose data (with HIGH_PACK_SIZE) runs past the end
    local fields = rspamd_util.pack("<I4", 2) .. rspamd_util.pack("<I4", 2) .. string.rep("\0", 11) ..
        rspamd_util.pack("<I2", 0) .. rspamd_util.pack("<I4", 0x20) ..
        rspamd_util.pack("<I4", 1) .. rspamd_util.pack("<I4", 0)
    local names = names_of(rar4_start .. a4 .. "\0\0\116" .. rspamd_util.pack("<I2", 0x8100) ..
        rspamd_util.pack("<I2", 7 + #fields) .. fields .. "xx" .. rar4_file("fake.scr", "MZ") .. rar4_end)
    assert_equal("file", names["invoice.exe"])
    assert_nil(names["fake.scr"])
  end)

  test("files after the end of a rar archive are listed as readers list them", function()
    local names = names_of(rar4_start .. rar4_file("invoice.exe", "MZ") .. rar4_end ..
        rar4_file("fake.scr", "MZ"))
    assert_equal("file", names["invoice.exe"])
    assert_nil(names["fake.scr"])
    names = names_of(rar5_start .. rar5_file("invoice.exe", "MZ") .. rar5_end ..
        "Rar!\26\7\1\0" .. rar5_file("fake.scr", "MZ") .. rar5_end)
    assert_equal("file", names["invoice.exe"])
    assert_nil(names["fake.scr"])
    -- bsdtar goes on with the next volume of a rar 5 volume, at a signature in the next
    -- 512 bytes, when that many are left
    names = names_of("Rar!\26\7\1\0" .. rar5_block("\1\0\1") .. rar5_file("invoice.txt", "MZ") ..
        rar5_end .. "junk" .. "Rar!\26\7\1\0" .. rar5_file("payload.exe", "MZ") .. rar5_end ..
        string.rep("\0", 512))
    assert_equal("file", names["invoice.txt"])
    assert_equal("file", names["payload.exe"])
  end)

  local rar4_payload = rar4_file("payload.exe", "MZ")

  test("a rar 4 file is skipped with its data whatever its flags, as readers skip it", function()
    -- Headers in the data are not files
    local names = names_of(rar4_start .. rar4_head(116, 0, "invoice.exe", rar4_file("decoy.txt", "x")) ..
        rar4_payload .. rar4_end)
    assert_equal("file", names["invoice.exe"])
    assert_equal("file", names["payload.exe"])
    assert_nil(names["decoy.txt"])
  end)

  test("a rar 4 header of type 2 is a file, as unrar reads it", function()
    local names = names_of(rar4_start .. rar4_head(2, 0, "odd.exe", "MZ") .. rar4_payload .. rar4_end)
    assert_equal("file", names["odd.exe"])
    assert_equal("file", names["payload.exe"])
  end)

  test("files after rar 4 blocks that readers skip in different ways are listed", function()
    -- Without 0x8000, unrar skips the data of these blocks, 7-Zip (and bsdtar for some)
    -- reads the header after them: seven.exe, whose data hides payload.exe from them,
    -- while unrar goes to payload.exe. The files of both are listed
    local seven_data = "xx" .. rar4_payload .. "yy"
    local seven = rar4_file("seven.exe", seven_data)
    local skip = #seven - #seven_data + 2
    for i, block in ipairs({
      rar4_block(0x77, 0, rspamd_util.pack("<I4", skip) .. "\0\0\0"),
      rar4_block(0x78, 0, rspamd_util.pack("<I4", skip) .. string.rep("\0", 9)),
      -- A service header of that size of data
      rar4_head(0x7a, 0, "CMT", string.rep("\0", skip)):sub(1, -skip - 1),
    }) do
      local names = names_of(rar4_start .. block .. seven .. rar4_end)
      assert_equal("file", names["seven.exe"], "case " .. i)
      assert_equal("file", names["payload.exe"], "case " .. i)
    end
    -- unrar reads the data size of a header too short for it as zero, 7-Zip reads it
    -- from the bytes after the header
    local names = names_of(rar4_start .. "\0\0\117" .. rspamd_util.pack("<I2", 0x8000) ..
        rspamd_util.pack("<I2", 9) .. "\0\0" .. "\1\0" .. rar4_payload:sub(3) .. rar4_end)
    assert_equal("file", names["payload.exe"])
  end)

  test("a rar 4 archive of encrypted headers is listed as encrypted", function()
    local rar = "Rar!\26\7\0" .. rar4_block(0x73, 0x80, string.rep("\0", 6)) .. string.rep("\255", 64)
    local msg = table.concat({
      "Subject: rar", "MIME-Version: 1.0",
      "Content-Type: application/x-rar; name=\"a.rar\"",
      "Content-Disposition: attachment; filename=\"a.rar\"",
      "Content-Transfer-Encoding: base64", "",
      tostring(rspamd_util.encode_base64(rar, 76)), "",
    }, "\r\n")
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    assert_true(task:get_archives()[1]:is_encrypted())
    task:destroy()
  end)

  test("files after a broken rar 4 header before the main one are listed, as unrar lists them", function()
    -- unrar goes on 7 bytes after the start of a broken header
    local names = names_of("Rar!\26\7\0" .. string.rep("\0", 7) .. rar4_payload .. rar4_end)
    assert_equal("file", names["payload.exe"])
    -- unrar looks for the main header past an end block
    names = names_of("Rar!\26\7\0" .. rar4_end .. rar4_start:sub(8) .. rar4_payload .. rar4_end)
    assert_equal("file", names["payload.exe"])
  end)

  test("files bsdtar reads past the end of a rar 4 volume are listed", function()
    -- After a file split into the next volume, bsdtar takes the next file past the end
    -- block as its rest, then lists the files after it, as in concatenated volumes
    local vol_start = "Rar!\26\7\0" .. rar4_block(0x73, 0x1, string.rep("\0", 6))
    local names = names_of(vol_start .. rar4_file("a.txt", "aa", 0x2) .. rar4_end ..
        rar4_file("a.txt", "bb") .. rar4_payload .. rar4_end)
    assert_equal("file", names["payload.exe"])
    -- A name of the rest that bsdtar cannot convert stops the skip of its data, where
    -- it reads headers
    local inner = rar4_file("evil.exe", "MZ") .. rar4_end
    names = names_of(vol_start .. rar4_file("a.txt", "aa", 0x2) .. rar4_file("b\255.txt", inner, 0x200) ..
        rar4_end)
    assert_equal("file", names["evil.exe"])
  end)

  test("a rar 4 file of a packed size over 2^63 is listed, as p7zip lists it", function()
    -- unrar skips the data of the block, p7zip reads the file after its header
    local fields = rspamd_util.pack("<I4", 2) .. rspamd_util.pack("<I4", 2) .. string.rep("\0", 11) ..
        rspamd_util.pack("<I2", #"payload.exe") .. rspamd_util.pack("<I4", 0x20) ..
        rspamd_util.pack("<I4", 0x80000000) .. rspamd_util.pack("<I4", 0)
    local file = rar4_block(116, 0x8100, fields .. "payload.exe") .. "MZ"
    local names = names_of(rar4_start .. rar4_block(0x77, 0, rspamd_util.pack("<I4", #file) .. "\0\0\0") ..
        file .. rar4_end)
    assert_equal("file", names["payload.exe"])
  end)

  local function archive_task(rar)
    local msg = table.concat({
      "Subject: rar", "MIME-Version: 1.0",
      "Content-Type: application/x-rar; name=\"a.rar\"",
      "Content-Disposition: attachment; filename=\"a.rar\"",
      "Content-Transfer-Encoding: base64", "",
      tostring(rspamd_util.encode_base64(rar, 76)), "",
    }, "\r\n")
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    return task
  end

  test("a rar 5 header is read as unrar reads it, with zeros past its end", function()
    -- unrar reads a data size past the end of a header as zero and lists the next file
    local names = names_of(rar5_start .. rar5_block("\3\2") .. "\5\0\0\0" ..
        rar5_file("payload.exe", "MZ"):sub(5) .. rar5_end)
    assert_equal("file", names["payload.exe"])
  end)

  test("files of a rar 5 archive without a main header are listed, as bsdtar lists them", function()
    local names = names_of("Rar!\26\7\1\0" .. rar5_file("payload.exe", "MZ") .. rar5_end)
    assert_equal("file", names["payload.exe"])
  end)

  test("a rar 5 file is encrypted by a record at the end of its header, as unrar reads it", function()
    -- An encryption record, and bytes between the name and the extra area
    local crypt = "\36\1\0\0\15" .. string.rep("S", 16) .. string.rep("I", 16)
    for _, pad in ipairs({ "", string.rep("\0", 8) }) do
      local rar = rar5_start .. rar5_block("\2\3" .. string.char(#crypt) .. "\2\0\2\32\0\0" ..
          string.char(#"invoice.exe") .. "invoice.exe" .. pad .. crypt) .. "MZ" .. rar5_end
      local task = archive_task(rar)
      local arch = task:get_archives()[1]
      assert_true(arch:is_encrypted(), "padding of " .. #pad)
      assert_true(arch:get_files_full()[1].encrypted, "padding of " .. #pad)
      task:destroy()
    end
  end)

  test("files after a broken rar 5 header before the main one are listed, as unrar lists them", function()
    -- unrar goes on 7 bytes after the start of a broken header
    local names = names_of("Rar!\26\7\1\0" .. "\0\0\0\0\1\0\0" .. rar5_file("payload.exe", "MZ") .. rar5_end)
    assert_equal("file", names["payload.exe"])
    -- unrar looks for the main header past an end block
    names = names_of("Rar!\26\7\1\0" .. rar5_end .. rar5_block("\1\0\0") ..
        rar5_file("payload.exe", "MZ") .. rar5_end)
    assert_equal("file", names["payload.exe"])
  end)

  test("a rar name is listed as unrar decodes its UTF-8", function()
    -- unrar decodes overlong forms (WinRAR extracts invoice.exe) and stops at a byte it
    -- cannot read, for every rar 5 name and for rar 4 names on macOS
    for i, rar in ipairs({
      rar5("invoice\192\174exe", "MZ"),
      rar5("invoice.exe\255.txt", "MZ"),
      rar4("invoice\192\174exe", "MZ"),
    }) do
      assert_equal("alias", names_of(rar)["invoice.exe"], "case " .. i)
    end
    -- A name in UTF-8 has no other name
    local n = 0
    for _ in pairs(names_of(rar5("\209\129\209\135\208\181\209\130.exe", "MZ"))) do
      n = n + 1
    end
    assert_equal(1, n)
  end)

  test("files bsdtar reads in the bytes of a rar 5 header are listed", function()
    -- libarchive reads fields from the stream and never goes to the declared end of a
    -- header: padding in it, or the body of a header of an unknown type that may be
    -- skipped, is read as headers
    local hidden = rar5_file("hidden.exe", "MZ")
    local visible = rar5_file("visible.txt", "hi") .. rar5_end
    for i, rar in ipairs({
      "Rar!\26\7\1\0" .. rar5_block("\1\0\0" .. hidden) .. visible,
      rar5_start .. rar5_block("\9\4" .. hidden) .. visible,
      rar5_start .. rar5_block("\2\2\0\0\0\32\0\0\5a.txt" .. hidden) .. visible,
    }) do
      local names = names_of(rar)
      assert_equal("file", names["hidden.exe"], "case " .. i)
      assert_equal("file", names["visible.txt"], "case " .. i)
    end
  end)

  test("files bsdtar lists in odd places of a rar 5 archive are listed", function()
    -- Archives made for libarchive 3.7, with real CRCs: a solid archive whose service
    -- header marked as a directory has data (bsdtar prints its name, then stops); a file
    -- in header padding whose owner record runs past the end (libarchive goes on with the
    -- next record); a split service whose compressed data lets a later solid file be read
    local archives = {
      -- svc_dir_solid
      "Rar!\26\7\1\0\220\222^5\3\1\0\4a7\169\134\14\2\2\2\0\2 \0\0\5a.txthi\224\255\1694\17\3\2" ..
          "\2\1\2 \0\0\8evil.exeMZ\1di\252\14\2\2\2\0\2 \0\0\5c.txthi\025\178:5\3\5\0\0",
      -- owner_eof
      "Rar!\26\7\1\0\197\02632\3\1\0\0}\29^p,\2\2\0\0\0 \0\0\5a.txt\224\15\2437\18\2\3\19\0\0\0" ..
          " \0\0\8evil.exe\3\6\1\12\2\3\0\025\178:5\3\5\0\0",
      -- split_window
      "Rar!\26\7\1\0\220\222^5\3\1\0\4\251\131\149*\13\3\10\19\0\15 \128\1\0\3CMT\199\141\16\1" ..
          "\0\0\0\0\0\0\0\0\1\182\127\255\230\128\0\5\210$\23%\2\2\0\0\0 \0\0\5a.txt\18\217\223E\18" ..
          "\2\2\0\0\0 \192\1\0\8evil.exe\1di\252\14\2\2\2\0\2 \0\0\5c.txthi\025\178:5\3\5\0\0",
    }
    for i, rar in ipairs(archives) do
      assert_equal("file", names_of(rar)["evil.exe"], "case " .. i)
    end
  end)
end)
