-- archive module unit tests

context("Lua archive bindings", function()
  local archive = require "archive"
  local rspamd_text = require "rspamd_text"

  test("pack/unpack zip roundtrip (text payload)", function()
    local files = {
      { name = "a.txt",       content = "Hello" },
      { name = "b/readme.md", content = "# Readme" },
    }
    local blob = archive.pack("zip", files)
    assert_equal(type(blob), "userdata")
    local out = archive.unpack(blob)
    assert_equal(#out, 2)
    local names = {}
    for _, f in ipairs(out) do names[f.name] = f.content end
    assert_rspamd_eq({ actual = names["a.txt"], expect = rspamd_text.fromstring("Hello") })
    assert_equal(type(names["b/readme.md"]), "userdata")
  end)

  test("zip/unzip helpers roundtrip (binary payload)", function()
    local rnd = rspamd_text.randombytes(1024)
    local files = {
      { name = "bin.dat", content = rnd },
    }
    local blob = archive.zip(files)
    assert_equal(type(blob), "userdata")
    local out = archive.unzip(blob)
    assert_equal(#out, 1)
    assert_equal(out[1].name, "bin.dat")
    assert_rspamd_eq({ actual = out[1].content, expect = rnd })
  end)

  test("zip_encrypt without password == plain zip", function()
    local files = {
      { name = "a.txt", content = "Hello" },
    }
    local blob = archive.zip_encrypt(files) -- no password
    assert_equal(type(blob), "userdata")
    local out = archive.unzip(blob)
    assert_equal(#out, 1)
    assert_equal(out[1].name, "a.txt")
    assert_rspamd_eq({ actual = out[1].content, expect = rspamd_text.fromstring("Hello") })
  end)

  test("zip_encrypt with password (ZipCrypto) roundtrip via libarchive", function()
    local files = {
      { name = "dir/x.txt", content = "secret" },
      { name = "y.bin",     content = rspamd_text.fromstring("\001\002\003") },
    }
    local pwd = "testpass123"
    local blob = archive.zip_encrypt(files, pwd)
    assert_equal(type(blob), "userdata")
    -- libarchive can read ZipCrypto, so unpack should succeed and yield the same files
    local out = archive.unpack(blob, "zip", pwd)
    assert_equal(#out, 2)
    local names = {}
    for _, f in ipairs(out) do names[f.name] = f.content end
    assert_rspamd_eq({ actual = names["dir/x.txt"], expect = rspamd_text.fromstring("secret") })
    assert_rspamd_eq({ actual = names["y.bin"], expect = rspamd_text.fromstring("\001\002\003") })
  end)

  test("zip_encrypt with wrong password fails to unpack", function()
    local files = {
      { name = "secret.txt", content = "topsecret" },
    }
    local pwd = "goodpass"
    local blob = archive.zip_encrypt(files, pwd)
    assert_equal(type(blob), "userdata")
    local ok, err = pcall(function()
      archive.unpack(blob, "zip", "badpass")
    end)
    assert_equal(ok, false)
  end)

  test("pack zip with AES-128 via libarchive roundtrip", function()
    local files = {
      { name = "dir/x.txt", content = "secret" },
      { name = "y.bin",     content = rspamd_text.fromstring("\001\002\003") },
    }
    local opts = { password = "testpass123", format_options = { encryption = "aes128" } }
    local ok_pack, blob_or_err = pcall(function()
      return archive.pack("zip", files, opts)
    end)
    -- If libarchive lacks AES write support, skip quietly
    if not ok_pack then return end
    local blob = blob_or_err
    assert_equal(type(blob), "userdata")
    local out = archive.unpack(blob, "zip", opts.password)
    assert_equal(#out, 2)
    local names = {}
    for _, f in ipairs(out) do names[f.name] = f.content end
    assert_rspamd_eq({ actual = names["dir/x.txt"], expect = rspamd_text.fromstring("secret") })
    assert_rspamd_eq({ actual = names["y.bin"], expect = rspamd_text.fromstring("\001\002\003") })
  end)

  test("pack zip with AES-256 via libarchive wrong password fails", function()
    local files = {
      { name = "a.txt", content = "Hello" },
    }
    local opts = { password = "goodpass", zip = { encryption = "aes256" } }
    local ok_pack, blob_or_err = pcall(function()
      return archive.pack("zip", files, opts)
    end)
    if not ok_pack then return end
    local blob = blob_or_err
    assert_equal(type(blob), "userdata")
    local ok, err = pcall(function()
      archive.unpack(blob, "zip", "badpass")
    end)
    assert_equal(ok, false)
  end)

  test("tar/untar helpers roundtrip (no compression)", function()
    local files = {
      { name = "x.txt", content = "X" },
      { name = "y.txt", content = "YY" },
    }
    local blob = archive.tar(files)
    assert_equal(type(blob), "userdata")
    local out = archive.untar(blob)
    assert_equal(#out, 2)
    local names = {}
    for _, f in ipairs(out) do names[f.name] = f.content end
    assert_rspamd_eq({ actual = names["x.txt"], expect = rspamd_text.fromstring("X") })
    assert_rspamd_eq({ actual = names["y.txt"], expect = rspamd_text.fromstring("YY") })
  end)

  test("tar/untar helpers roundtrip (gzip)", function()
    local files = {
      { name = "z.txt", content = "Z" },
    }
    local blob = archive.tar(files, "gz")
    assert_equal(type(blob), "userdata")
    local out = archive.untar(blob)
    assert_equal(#out, 1)
    assert_equal(out[1].name, "z.txt")
    assert_rspamd_eq({ actual = out[1].content, expect = rspamd_text.fromstring("Z") })
  end)

  test("unpack without opts reports no truncation", function()
    local files = {
      { name = "a.txt", content = "Hello" },
      { name = "b.txt", content = "World" },
    }
    local blob = archive.pack("zip", files)
    local out, truncated = archive.unpack(blob)
    assert_equal(#out, 2)
    assert_equal(truncated, false)
  end)

  test("max_files caps the number of extracted members", function()
    local files = {
      { name = "a.txt", content = "AAA" },
      { name = "b.txt", content = "BBB" },
      { name = "c.txt", content = "CCC" },
    }
    local blob = archive.zip(files)
    local out, truncated = archive.unzip(blob, { max_files = 2 })
    assert_equal(#out, 2)
    assert_equal(truncated, true)
  end)

  test("max_file_size truncates an oversized member", function()
    local big = string.rep("A", 200 * 1024)
    local blob = archive.zip({ { name = "big.txt", content = big } })
    local cap = 50 * 1024
    local out, truncated = archive.unzip(blob, { max_file_size = cap })
    assert_equal(#out, 1)
    assert_equal(out[1].content:len(), cap)
    assert_equal(truncated, true)
  end)

  test("max_output caps total uncompressed bytes across members", function()
    local part = string.rep("X", 100 * 1024)
    local files = {
      { name = "a.txt", content = part },
      { name = "b.txt", content = part },
    }
    local blob = archive.zip(files)
    local cap = 150 * 1024
    local out, truncated = archive.unzip(blob, { max_output = cap })
    assert_equal(truncated, true)
    local total = 0
    for _, f in ipairs(out) do total = total + f.content:len() end
    assert_equal(total, cap)
  end)

  test("max_ratio drops a decompression-bomb member but keeps normal ones", function()
    -- 1 MiB of a single byte compresses to a few KiB => huge ratio
    local bomb = string.rep("A", 1024 * 1024)
    local files = {
      { name = "normal.txt", content = "just some normal text content here" },
      { name = "bomb.txt",   content = bomb },
    }
    local blob = archive.zip(files)
    local out, truncated = archive.unzip(blob, { max_ratio = 10 })
    assert_equal(truncated, true)
    -- The bomb member must not be exposed
    local names = {}
    for _, f in ipairs(out) do names[f.name] = true end
    assert_equal(names["bomb.txt"], nil)
    assert_equal(names["normal.txt"], true)
  end)

  test("limits do not truncate an archive within bounds", function()
    local files = {
      { name = "a.txt", content = "small" },
      { name = "b.txt", content = "also small" },
    }
    local blob = archive.zip(files)
    local out, truncated = archive.unzip(blob, {
      max_files = 10,
      max_file_size = 1024,
      max_output = 1024 * 1024,
      max_ratio = 1000,
    })
    assert_equal(#out, 2)
    assert_equal(truncated, false)
  end)

  test("supported_formats contains some read/write entries", function()
    local caps = archive.supported_formats()
    assert_equal(type(caps), "table")
    assert_equal(type(caps.formats), "table")
    assert_equal(type(caps.filters), "table")
    -- We don't hard-require specific formats, but lists should exist (possibly empty)
    assert_equal(type(caps.formats.read), "table")
    assert_equal(type(caps.formats.write), "table")
    assert_equal(type(caps.filters.read), "table")
    assert_equal(type(caps.filters.write), "table")
  end)
end)
