--[[
Archives that are not at the start of a part, or that lack a part of
themselves, and what the type of such a part is.
]]

context("Archive detection", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_text = require "rspamd_text"

  local function u16(n)
    return rspamd_util.pack("<I2", n)
  end
  local function u32(n)
    return rspamd_util.pack("<I4", n)
  end

  -- A zip file of stored members; returns its pieces to take it apart
  local function zip_pieces(names)
    local locals, cd = {}, {}
    local pos = 0

    for _, name in ipairs(names) do
      local data = 'data of ' .. name
      local sizes = u32(0) .. u32(#data) .. u32(#data) .. u16(#name) .. u16(0)
      local lh = "PK\3\4" .. u16(20) .. u16(0) .. u16(0) .. u32(0) .. sizes .. name .. data
      cd[#cd + 1] = "PK\1\2" .. u16(20) .. u16(20) .. u16(0) .. u16(0) .. u32(0) .. sizes ..
          u16(0) .. u16(0) .. u16(0) .. u32(0) .. u32(pos) .. name
      locals[#locals + 1] = lh
      pos = pos + #lh
    end

    local dir = table.concat(cd)
    local eocd = "PK\5\6" .. u16(0) .. u16(0) .. u16(#names) .. u16(#names) ..
        u32(#dir) .. u32(pos) .. u16(0)

    return table.concat(locals), cd, eocd
  end

  local function zip(names)
    local locals, cd, eocd = zip_pieces(names)

    return locals .. table.concat(cd) .. eocd
  end

  local two = { 'a.txt', 'evil.exe' }

  -- Loads a message of one part; returns what the part is and holds
  local function look(blob, ct, disposition)
    local msg = table.concat({
      "Subject: archive",
      "MIME-Version: 1.0",
      "Content-Type: " .. (ct or "application/octet-stream"),
      disposition and ("Content-Disposition: " .. disposition) or "X-None: 1",
      "Content-Transfer-Encoding: base64",
      "",
      tostring(rspamd_util.encode_base64(blob, 76)),
      "",
    }, "\r\n")
    local _, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()

    local res = { names = {} }

    for _, p in ipairs(task:get_parts()) do
      res.ext = p:get_detected_ext()
      res.is_archive = p:is_archive()
      res.is_text = p:is_text()

      if res.is_archive then
        local arch = p:get_archive()
        res.unreadable = arch:is_unreadable()
        res.obfuscated = arch:is_obfuscated()
        res.encrypted = arch:is_encrypted()
        res.type = arch:get_type()
        res.names = arch:get_files()
      end
    end

    task:destroy()

    return res
  end

  -- A 7z file with a plain header: the files information only
  local function wide(str)
    return (str:gsub('.', '%0\0'))
  end
  local function sz_names(names, raw)
    local body = '\0'

    for _, n in ipairs(names) do
      body = body .. (raw and n or wide(n)) .. '\0\0'
    end

    return '\17' .. string.char(#body) .. body
  end
  local function sz(nfiles, props)
    local header = '\1\5' .. string.char(nfiles) .. props .. '\0\0'

    return '7z\188\175\39\28\0\4' .. '\0\0\0\0' .. rspamd_util.pack('<I8', 0) ..
        rspamd_util.pack('<I8', #header) .. '\0\0\0\0' .. header
  end

  local function sorted(names)
    table.sort(names)

    return table.concat(names, '|')
  end

  local koly = 'koly\0\0\0\4\0\0\2\0' .. string.rep('\0', 500)

  test("A zip file is listed as before", function()
    local res = look(zip(two))
    assert_equal('zip', res.ext)
    assert_equal('a.txt|evil.exe', sorted(res.names))
  end)

  test("Data in front of a zip file does not hide it", function()
    local res = look('some junk' .. zip(two))
    assert_true(res.is_archive)
    assert_equal('zip', res.ext)
    assert_equal('a.txt|evil.exe', sorted(res.names))
  end)

  test("A program with a zip file after it is a program with files", function()
    local res = look('MZ' .. string.rep('\0', 4000) .. zip(two))
    assert_true(res.is_archive)
    assert_equal('exe', res.ext)
    assert_equal('a.txt|evil.exe', sorted(res.names))
  end)

  test("A program that holds the magic of an archive is not one", function()
    local body = 'MZ' .. string.rep('\0', 200) .. 'PK\3\4' .. string.rep('\255', 64) ..
        'Rar!\26\7\1\0' .. string.rep('\255', 64) .. '7z\188\175\39\28' .. string.rep('\255', 64) ..
        'PK\5\6' .. string.rep('\0', 18)
    local res = look(body)
    assert_false(res.is_archive)
    assert_equal('exe', res.ext)
  end)

  test("The end of a disk image after a zip file leaves a zip file", function()
    local locals, cd, eocd = zip_pieces(two)
    -- As the comment of the archive
    local res = look(locals .. table.concat(cd) .. eocd:sub(1, -3) .. u16(#koly) .. koly)
    assert_equal('zip', res.ext)
    assert_equal('a.txt|evil.exe', sorted(res.names))
  end)

  test("A disk image is told by its end when its start tells nothing", function()
    assert_equal('dmg', look(string.rep('\1\2\3\4', 512) .. koly).ext)
    -- Images of bzip2 chunks start as a bzip2 stream
    assert_equal('dmg', look('BZh91AY&SY' .. string.rep('\1\2\3\4', 512) .. koly).ext)
  end)

  test("A zip file with no central directory is listed by its local headers", function()
    local locals = zip_pieces(two)
    local res = look(locals)
    assert_true(res.is_archive)
    assert_equal('a.txt|evil.exe', sorted(res.names))
  end)

  test("A record of the directory that does not read does not hide the files", function()
    local locals, cd, eocd = zip_pieces(two)
    local res = look(locals .. cd[1] .. 'XX' .. cd[2]:sub(3) .. eocd)
    assert_true(res.is_archive)
    assert_equal('a.txt|evil.exe', sorted(res.names))
  end)

  test("A rar file after other data is listed", function()
    local function block(body)
      local sized = string.char(#body) .. body
      return u32(rspamd_text.fromstring(sized):crc32()) .. sized
    end
    local name, data = 'evil.exe', 'MZ'
    local rar = "Rar!\26\7\1\0" .. block("\1\0\0") ..
        block("\2\2" .. string.char(#data) .. "\0" .. string.char(#data) .. "\32\0\0" ..
          string.char(#name) .. name) .. data .. block("\5\0\0")

    assert_equal('evil.exe', sorted(look(rar).names))

    local res = look('MZ' .. string.rep('\0', 3000) .. rar)
    assert_true(res.is_archive)
    assert_equal('rar', res.type)
    assert_equal('exe', res.ext)
    assert_equal('evil.exe', sorted(res.names))
  end)

  test("A 7z file after other data is listed", function()
    local sz = rspamd_util.decode_base64(table.concat {
      'N3q8ryccAASfon6QDAAAAAAAAACmAAAAAAAAAKbERhcBAAdoZWxsbwp4CgABBAYAAQkMAAcL',
      'AQABISEBAAwIAAgNAgkGCgEgMDo2HwjqRgAABQQOAcAPAUARNwBkAAAAZQBtAHAAdAB5AC4A',
      'YgBpAG4AAABhAC4AdAB4AHQAAABkAC8AaQBuAC4AdAB4AHQAAAAZBAAAAAAUIgEAAAhxVS9L',
      '3QEACHFVL0vdAQCpGw8vS90BAAhxVS9L3QEVEgEAEIDtQSCApIEggKSBIICkgQAA',
    })
    local plain = look(tostring(sz))
    assert_true(#plain.names > 0)

    local res = look('MZ' .. string.rep('\0', 3000) .. tostring(sz))
    assert_true(res.is_archive)
    assert_equal('7z', res.type)
    assert_equal(sorted(plain.names), sorted(res.names))
  end)

  test("A zip file sent as a text file to save is an archive", function()
    local text = string.rep('Just some words of plain text here. ', 8) .. '\r\n'
    local locals, cd, eocd = zip_pieces(two)
    local body = text .. locals .. table.concat(cd) .. eocd:sub(1, -3) .. u16(#text) .. text
    local res = look(body, 'text/plain', 'attachment; filename="doc.zip"')
    assert_true(res.is_archive)
    assert_equal('a.txt|evil.exe', sorted(res.names))

    -- What a client shows as text stays text
    res = look(body, 'text/plain')
    assert_false(res.is_archive)
    assert_true(res.is_text)
  end)

  test("Files in a directory of a document do not make a document", function()
    assert_equal('zip', look(zip({ 'xl/a', 'xl/b', 'evil.exe' })).ext)
    assert_equal('zip', look(zip({ 'word/a', 'word/b', 'word/c' })).ext)
    assert_equal('xlsx', look(zip({ '[Content_Types].xml', 'xl/workbook.xml' })).ext)
    assert_equal('docx', look(zip({ '[Content_Types].xml', 'word/document.xml' })).ext)
  end)

  test("An archive that starts as one and does not read is told", function()
    for _, magic in ipairs({ '7z\188\175\39\28\0\4', 'Rar!\26\7\1\0', 'Rar!\26\7\0',
                             'PK\3\4' }) do
      local res = look(magic .. string.rep('\255', 100))
      assert_true(res.is_archive, magic)
      assert_true(res.unreadable, magic)
      assert_equal(0, #res.names)
    end

    local res = look(zip(two))
    assert_false(res.unreadable)
  end)

  test("The optional parts of a gzip header are read in their order", function()
    local function gz(flags, optional)
      return '\31\139\8' .. string.char(flags) .. '\0\0\0\0\0\3' .. optional ..
          '\3\0' .. string.rep('\0', 8)
    end

    assert_equal('evil.exe', sorted(look(gz(8, 'evil.exe\0')).names))
    -- A checksum of the header stands after the name, not before it
    assert_equal('evil.exe', sorted(look(gz(8 + 2, 'evil.exe\0\1\2')).names))
    -- An extra field before the name
    assert_equal('evil.exe', sorted(look(gz(8 + 4, '\4\0abcd' .. 'evil.exe\0')).names))
    assert_equal('evil.exe', sorted(look(gz(8 + 4 + 2, '\4\0abcd' .. 'evil.exe\0\1\2')).names))

    -- An empty name is no name: the data after it is not one
    local res = look(gz(8, '\0') .. 'x.pdf.exe\0')
    assert_true(res.is_archive)
    assert_equal(0, #res.names)
    assert_false(res.obfuscated)

    -- No name at all
    res = look(gz(0, ''))
    assert_true(res.is_archive)
    assert_equal(0, #res.names)
  end)

  test("Names of a 7z file are read past what is not known", function()
    assert_equal('a.txt|evil.exe', sorted(look(sz(2, sz_names({ 'a.txt', 'evil.exe' }))).names))
    -- A property of another kind before the names, and one that is not known
    assert_equal('a.txt|evil.exe',
      sorted(look(sz(2, '\24\1\0' .. sz_names({ 'a.txt', 'evil.exe' }))).names))
    assert_equal('a.txt|evil.exe',
      sorted(look(sz(2, '\48\2\0\0' .. sz_names({ 'a.txt', 'evil.exe' }))).names))
    -- An empty name does not end the list
    local res = look(sz(2, sz_names({ '', 'evil.exe' })))
    assert_equal('evil.exe', sorted(res.names))
    assert_false(res.unreadable)
  end)

  test("Characters that hide a name are told in a 7z file as in a zip file", function()
    assert_false(look(sz(1, sz_names({ 'evil.exe' }))).obfuscated)
    -- U+202E, U+200B and a control character
    for _, hidden in ipairs({ '\46\32', '\11\32', '\1\0' }) do
      local res = look(sz(1, sz_names({ wide('doc') .. hidden .. wide('fdp.exe') }, true)))
      assert_equal(1, #res.names)
      assert_true(res.obfuscated)
    end
  end)

  test("Names that share a hash of no secret cost what other names cost", function()
    -- "Aa" and "BB" have one hash under h * 31 + c, and so has any row of them
    local function many(colliding)
      local names = {}

      for i = 0, 8191 do
        local parts = {}

        for b = 0, 12 do
          if colliding then
            parts[#parts + 1] = (math.floor(i / 2 ^ b) % 2 == 1) and 'Aa' or 'BB'
          else
            parts[#parts + 1] = (math.floor(i / 2 ^ b) % 2 == 1) and 'Ab' or 'Cd'
          end
        end

        names[#names + 1] = table.concat(parts)
      end

      return zip(names)
    end

    local function timed(blob)
      local t = os.clock()
      local res = look(blob)

      return os.clock() - t, #res.names
    end

    local plain_time, plain_n = timed(many(false))
    local coll_time, coll_n = timed(many(true))
    assert_equal(8192, plain_n)
    assert_equal(8192, coll_n)
    assert_true(coll_time < plain_time * 4 + 0.1,
      string.format('%.3f s for names that collide, %.3f s for others', coll_time, plain_time))
  end)
end)

context("File types by fixed places", function()
  local rspamd_util = require "rspamd_util"
  local rspamd_text = require "rspamd_text"
  local magic = require "lua_magic"

  local function detect(s)
    local part = {
      get_content = function()
        return rspamd_text.fromstring(s)
      end,
      get_filename = function()
        return nil
      end,
    }

    return (magic.detect(part, rspamd_config))
  end

  local pe = 'MZ' .. string.rep('\0', 58) .. rspamd_util.pack('<I4', 128) ..
      string.rep('\0', 64) .. 'PE\0\0' .. string.rep('\0', 200)

  test("A program is one whatever else it holds", function()
    assert_equal('exe', detect(pe))
    assert_equal('exe', detect(pe .. 'MSCF\0\0\0\0' .. string.rep('\0', 64)))
    assert_equal('exe', detect(pe .. '\r\n@echo off\r\n'))
    -- The same bytes before the header that the pointer leads to
    assert_equal('exe', detect('MZ' .. string.rep('\0', 58) .. rspamd_util.pack('<I4', 128) ..
      'PE\0\0' .. string.rep('\0', 60) .. 'PE\0\0' .. string.rep('\0', 200) ..
      'MSCF\0\0\0\0' .. string.rep('\0', 64)))
  end)

  test("A pointer that leads nowhere leaves the other signatures", function()
    local stub = 'MZ' .. string.rep('\0', 58) .. rspamd_util.pack('<I4', 0x7fffffff) ..
        string.rep('\0', 64)
    assert_equal('exe', detect(stub))
    assert_equal('cab', detect(stub .. 'MSCF\0\0\0\0' .. string.rep('\0', 64)))
  end)

  test("A tar file is told by its place, whatever its first name is", function()
    local function tar(name)
      return name .. string.rep('\0', 257 - #name) .. 'ustar\0' .. '00' .. string.rep('\0', 512)
    end

    assert_equal('tar', detect(tar('file.txt')))
    assert_equal('tar', detect(tar('ustar/ustar.txt')))
    -- The word is not a tar file elsewhere
    assert_not_equal('tar', detect('a word: ustar' .. string.rep('\0', 600)))
  end)

  test("A disk image is told by its descriptor, whatever stands before it", function()
    local function iso(lead)
      return lead .. string.rep('\0', 0x8000 - #lead) .. '\1CD001\1' .. string.rep('\0', 2048)
    end

    assert_equal('iso', detect(iso('')))
    assert_equal('iso', detect(iso(string.rep('\0', 64) .. '\1CD001\1')))
    assert_not_equal('iso', detect(string.rep('\0', 64) .. '\1CD001\1' .. string.rep('\0', 0x9000)))
  end)

  test("An ace and a zoo archive are told by their places", function()
    assert_equal('ace', detect(string.rep('\1', 7) .. '**ACE**' .. string.rep('\1', 64)))
    assert_equal('zoo', detect(string.rep('\1', 20) .. '\220\167\196\253' .. string.rep('\1', 64)))
  end)
end)

context("Compound file detection", function()
  local rspamd_util = require "rspamd_util"
  local rspamd_text = require "rspamd_text"
  local magic = require "lua_magic"

  local function detect(s)
    local part = {
      get_content = function()
        return rspamd_text.fromstring(s)
      end,
      get_filename = function()
        return nil
      end,
    }

    return (magic.detect(part, rspamd_config))
  end

  -- A header with the directory in the first sector, then the entries
  local function ole(entries)
    local header = '\208\207\17\224\161\177\26\225' .. string.rep('\0', 16) ..
        rspamd_util.pack('<I2', 0x3e) .. rspamd_util.pack('<I2', 3) ..
        rspamd_util.pack('<I2', 0xfffe) .. rspamd_util.pack('<I2', 9) ..
        string.rep('\0', 12) .. rspamd_util.pack('<I4', 0)

    return header .. string.rep('\0', 512 - #header) .. entries
  end

  local function entry(name, dtype, clsid)
    local wide = name:gsub('.', '%0\0')

    return wide .. string.rep('\0', 64 - #wide) .. rspamd_util.pack('<I2', #wide + 2) ..
        string.char(dtype) .. '\0' .. string.rep('\0', 12) .. (clsid or string.rep('\0', 16)) ..
        string.rep('\0', 32)
  end

  test("A document stream tells the document", function()
    assert_equal('doc', detect(ole(entry('Root Entry', 5) .. entry('WordDocument', 2))))
  end)

  test("A compound file of no known stream is one all the same", function()
    assert_equal('ole', detect(ole(entry('Root Entry', 5) .. entry('Macros', 1) .. entry('VBA', 2))))
  end)

  test("A compound file cut inside an entry has a type and no error", function()
    local whole = ole(entry('Root Entry', 5) .. entry('Macros', 1))

    assert_equal('ole', detect(whole:sub(1, 512 + 70)))
    assert_equal('ole', detect(whole:sub(1, 512 + 128 + 66)))
    assert_equal('ole', detect(whole:sub(1, 300)))
  end)
end)

context("Content handler choice", function()
  local lua_content = require "lua_content"
  local rspamd_text = require "rspamd_text"

  test("A document of another kind than declared is read as what it is", function()
    local pdf = '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n' ..
        '2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n' ..
        'trailer\n<< /Root 1 0 R >>\n%%EOF\n'
    local specific
    local part = {
      get_type = function()
        return 'application', 'vnd.openxmlformats-officedocument.wordprocessingml.document'
      end,
      get_detected_ext = function()
        return 'pdf'
      end,
      is_archive = function()
        return false
      end,
      is_text = function()
        return false
      end,
      get_filename = function()
        return 'doc.docx'
      end,
      get_content = function()
        return rspamd_text.fromstring(pdf)
      end,
      get_id = function()
        return 77
      end,
      set_specific = function(_, data)
        specific = data
      end,
    }

    lua_content.maybe_process_mime_part(part, {})
    assert_not_nil(specific)
    assert_equal('pdf', specific.tag)
  end)
end)
