context("Task processing", function()
  local fun = require("fun")
  local rspamd_task = require("rspamd_task")

  test("Process a simple task", function()
    --local cfg = rspamd_util.config_from_ucl(config)
    --assert_not_nil(cfg)

    local msg = [[
From: <>
To: <nobody@example.com>
Subject: test
Content-Type: text/plain

Test.
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    task:destroy()
  end)

  local hdrs = [[
From: <>
To: <nobody@example.com>
Subject: test
]]
  local function make_many_file_zip(nfiles)
    local rspamd_util = require("rspamd_util")
    local local_header = "PK\3\4" .. string.rep("\0", 26)
    local cd_record = "PK\1\2" .. string.rep("\0", 24) ..
        "\1\0" .. string.rep("\0", 16) .. "x"
    local cd = string.rep(cd_record, nfiles)
    local eocd = "PK\5\6" .. string.rep("\0", 8) ..
        rspamd_util.pack("<I4", #cd) ..
        rspamd_util.pack("<I4", #local_header) .. "\0\0"

    return local_header .. cd .. eocd
  end
  local mpart = [[
Content-Type: multipart/mixed; boundary=XXX
]]
  local body = [[
Content-Type: text/html
Content-Transfer-Encoding: quoted-printable

<html>
<body>
=0DAttached is your new documents.
<br>
<a href=3D"http://evil.com/Information/">http:=
//example.com/privacy/XXX/YYY_April_25_2019.doc</a>
<br>
<br>
<br>
Thank you,
<br>
<b>Haloclaims.co</b>
</body></html>
]]
  test("Process mime nesting: simple", function()
    local msg = hdrs .. body
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),
      expect = {
        'evil.com', 'example.com'
      }
    })
    task:destroy()
  end)
  test("Process mime nesting: multipart", function()
    local msg = table.concat {
      hdrs, mpart, '\n', '--XXX\n', body, '\n--XXX--\n'
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }
    })
    task:destroy()
  end)
  test("Process mime nesting: multipart, broken", function()
    local msg = table.concat {
      hdrs, mpart, '\n', '--XXX\n', 'garbadge\n', '\n--XXX--\n', '--XXX\n', body
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }
    })

    task:destroy()
  end)
  test("Process mime nesting: message", function()
    local msg = table.concat {
      hdrs, 'Content-Type: message/rfc822\n', '\n', hdrs, body
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }
    })

    task:destroy()
  end)
  test("Process mime nesting: message in multipart", function()
    local msg = table.concat {
      hdrs, mpart, '\n',
      '--XXX\n',
      'Content-Type: message/rfc822\n', '\n', hdrs, body,
      '\n--XXX--\n',
    }

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }
    })

    task:destroy()
  end)
  test("Process mime nesting: multipart message in multipart", function()
    local msg = table.concat {
      hdrs, mpart, '\n',
      '--XXX\n',
      'Content-Type: message/rfc822\n', '\n', hdrs, mpart, '\n',

      '--XXX\n',
      body,
      '\n--XXX--\n',

      '\n--XXX--\n',
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_rspamd_table_eq_sorted({
      actual = fun.totable(fun.map(function(u)
        return u:get_host()
      end, task:get_urls())),

      expect = {
        'evil.com', 'example.com'
      }
    })

    task:destroy()
  end)

  test("Process mime nesting: deep message/rfc822 chain is bounded", function()
    -- Regression for the unbounded message/rfc822 recursion DoS: a long chain
    -- of bare "Content-Type: message/rfc822" wrappers must not recurse past
    -- the parser's max_nested limit (64). Before the fix the nesting counter
    -- was copied to the new parser runtime before being incremented, so the
    -- limit never fired and the parser recursed once per level (stack
    -- exhaustion / quadratic CPU). The bound is observable as the number of
    -- parsed MIME parts: capped near max_nested rather than growing with the
    -- chain length.
    local depth = 500
    local msg = string.rep('Content-Type: message/rfc822\n\n', depth) ..
      'Subject: poc\n\nInner body http://nested.example.com/\n'
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    local parts = task:get_parts()
    assert_true(#parts <= 128,
      string.format("nesting not bounded: %d parts for a %d-level chain", #parts, depth))
    task:destroy()
  end)

  test("MIME boundary candidates are bounded", function()
    local epilogue = {}

    for i = 1, 100001 do
      epilogue[i] = '--not-the-boundary--\n'
    end

    local msg = table.concat {
      hdrs,
      'Content-Type: multipart/mixed; boundary=REAL\n',
      '\n',
      '--REAL\n',
      'Content-Type: text/plain\n',
      '\n',
      'legitimate body\n',
      '--REAL--\n',
      table.concat(epilogue),
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_true(task:has_flag('broken_headers'),
      "boundary candidate limit was not applied")
    task:destroy()
  end)

  test("MIME part count is bounded", function()
    local body_parts = {}

    for i = 1, 10100 do
      body_parts[i] = '--MANY\n\npart\n'
    end

    local msg = table.concat {
      hdrs,
      'Content-Type: multipart/mixed; boundary=MANY\n',
      '\n',
      table.concat(body_parts),
      '--MANY--\n',
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_true(task:has_flag('broken_headers'),
      "MIME part limit was not applied")
    assert_true(#task:get_parts() <= 10000,
      string.format("too many MIME parts parsed: %d", #task:get_parts()))
    task:destroy()
  end)

  test("MIME header count is bounded", function()
    local msg = string.rep('X:\n', 100001) .. '\nbody\n'
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_true(task:has_flag('broken_headers'),
      "MIME header limit was not applied")
    assert_true(task:get_header_count('X') <= 100000,
      string.format("too many MIME headers parsed: %d",
        task:get_header_count('X')))
    task:destroy()
  end)

  test("Archive file metadata count is bounded", function()
    local msg = table.concat {
      hdrs,
      "Content-Type: application/zip\n",
      "Content-Disposition: attachment; filename=many.zip\n",
      "Content-Transfer-Encoding: binary\n",
      "\n",
      make_many_file_zip(100001),
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local archives = task:get_archives()
    assert_equal(1, #archives, "archive was not detected")
    local files = archives[1]:get_files()
    assert_equal(100000, #files,
      string.format("unexpected archive file count: %d", #files))
    assert_true(archives[1]:is_truncated(),
      "archive metadata truncation was not exposed")
    task:destroy()
  end)

  test("Archive file metadata count is bounded across parts", function()
    local zip = make_many_file_zip(1000)
    local body = {}

    for i = 1, 101 do
      body[#body + 1] = table.concat {
        "--MANY-ARCHIVES\n",
        "Content-Type: application/zip\n",
        string.format(
          "Content-Disposition: attachment; filename=archive-%d.zip\n", i),
        "Content-Transfer-Encoding: binary\n",
        "\n",
        zip,
        "\n",
      }
    end
    body[#body + 1] = "--MANY-ARCHIVES--\n"

    local msg = table.concat {
      hdrs,
      "Content-Type: multipart/mixed; boundary=MANY-ARCHIVES\n",
      "\n",
      table.concat(body),
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local archives = task:get_archives()
    assert_equal(101, #archives, "archives were not detected")
    local nfiles = 0
    for _, archive in ipairs(archives) do
      nfiles = nfiles + #archive:get_files()
    end
    assert_equal(100000, nfiles,
      string.format("unexpected archive file count across parts: %d", nfiles))
    assert_false(archives[100]:is_truncated(),
      "archive within the task budget was marked truncated")
    assert_true(archives[101]:is_truncated(),
      "archive exceeding the task budget was not marked truncated")
    task:destroy()
  end)

  test("Part URLs are not deduplicated across MIME parts", function()
    local msg = table.concat {
      hdrs,
      'Content-Type: multipart/alternative; boundary=XXX\n',
      '\n',
      '--XXX\n',
      'Content-Type: text/plain\n',
      '\n',
      'Visit <http://example.com/a> and <http://example.com/b>\n',
      '\n',
      '--XXX\n',
      'Content-Type: text/html\n',
      '\n',
      '<html><body>' ..
        '<a href="http://example.com/a">A</a>' ..
        '<a href="http://example.com/b">B</a>' ..
      '</body></html>\n',
      '\n',
      '--XXX--\n',
    }
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local parts = task:get_parts()
    assert_true(#parts >= 2, "should have at least two MIME parts")

    local function uniq_urls(part)
      local seen = {}

      return fun.totable(fun.filter(function(v)
        if seen[v] then
          return false
        end

        seen[v] = true
        return true
      end, fun.map(function(u)
        return u:get_host() .. '/' .. u:get_path()
      end, part:get_urls())))
    end

    assert_rspamd_table_eq_sorted({
      actual = uniq_urls(parts[#parts - 1]),
      expect = {
        'example.com/a', 'example.com/b'
      }
    })

    assert_rspamd_table_eq_sorted({
      actual = uniq_urls(parts[#parts]),
      expect = {
        'example.com/a', 'example.com/b'
      }
    })

    task:destroy()
  end)
end)
