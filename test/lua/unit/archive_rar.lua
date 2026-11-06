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

  -- Rar 5: headers of a CRC, a size, then fields as small numbers (one byte each here)
  local function rar5(name, data)
    local function block(body)
      return "\0\0\0\0" .. string.char(#body) .. body
    end
    -- File header with data: no time, no CRC, stored, then the name
    local file = "\2\2" .. string.char(#data) .. "\0" .. string.char(#data) .. "\32\0\0" ..
        string.char(#name) .. name
    return "Rar!\26\7\1\0" .. block("\1\0\0") .. block(file) .. data .. block("\5\0\0")
  end

  -- Rar 4: headers of a CRC, a type, flags and a size
  local function rar4(name, data, flags)
    local main = "\0\0\115" .. rspamd_util.pack("<I2", 0) .. rspamd_util.pack("<I2", 13) ..
        string.rep("\0", 6)
    local fields = rspamd_util.pack("<I4", #data) .. rspamd_util.pack("<I4", #data) ..
        string.rep("\0", 11) .. rspamd_util.pack("<I2", #name) .. rspamd_util.pack("<I4", 0x20)
    local file = "\0\0\116" .. rspamd_util.pack("<I2", 0x8000 + (flags or 0)) ..
        rspamd_util.pack("<I2", 7 + #fields + #name) .. fields .. name
    return "Rar!\26\7\0" .. main .. file .. data
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
    -- With a Unicode name after the NUL, the name before it is the one listed
    names = names_of(rar4("readme.txt\0\0", "MZ", 0x200))
    assert_equal("file", names["readme.txt"])
  end)
end)
