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
