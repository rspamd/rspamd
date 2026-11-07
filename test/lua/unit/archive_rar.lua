--[[
Names of files in rar archives, as readers (unrar, 7-Zip, bsdtar) show them.
]]

context("Rar archive listing", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"

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

  -- Rar 5: headers of a CRC, a size, then fields as small numbers (one byte each here);
  -- the name may have a size other than its own (but less than 128)
  local function rar5(name, data, name_size)
    local function block(body)
      return "\0\0\0\0" .. string.char(#body) .. body
    end
    -- File header with data: no time, no CRC, stored, then the name
    local file = "\2\2" .. string.char(#data) .. "\0" .. string.char(#data) .. "\32\0\0" ..
        string.char(name_size or #name) .. name
    return "Rar!\26\7\1\0" .. block("\1\0\0") .. block(file) .. data .. block("\5\0\0")
  end

  -- Rar 4: headers of a CRC, a type, flags and a size
  local function rar4_file(name, data, flags, name_size)
    local fields = rspamd_util.pack("<I4", #data) .. rspamd_util.pack("<I4", #data) ..
        string.rep("\0", 11) .. rspamd_util.pack("<I2", name_size or #name) ..
        rspamd_util.pack("<I4", 0x20)
    return "\0\0\116" .. rspamd_util.pack("<I2", 0x8000 + (flags or 0)) ..
        rspamd_util.pack("<I2", 7 + #fields + #name) .. fields .. name .. data
  end

  local rar4_start = "Rar!\26\7\0" .. "\0\0\115" .. rspamd_util.pack("<I2", 0) ..
      rspamd_util.pack("<I2", 13) .. string.rep("\0", 6)

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
end)
