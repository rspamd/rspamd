context("lua_scanners common", function()
  local common = require "lua_scanners/common"
  local rspamd_task = require "rspamd_task"

  context("derive_symbols", function()
    test("derives all default symbol names from sym when opts is empty", function()
      local symbol, symbol_fail, symbol_encrypted, symbol_macro, symbol_ignore =
          common.derive_symbols('clam', {})
      assert_equal(symbol, 'CLAM')
      assert_equal(symbol_fail, 'CLAM_FAIL')
      assert_equal(symbol_encrypted, 'CLAM_ENCRYPTED')
      assert_equal(symbol_macro, 'CLAM_MACRO')
      assert_equal(symbol_ignore, 'CLAM_IGNORE')
    end)

    test("honours explicit opts overrides", function()
      local symbol, symbol_fail, symbol_encrypted, symbol_macro, symbol_ignore =
          common.derive_symbols('clam', {
            symbol = 'MY_CLAM',
            symbol_fail = 'MY_CLAM_ERROR',
          })
      assert_equal(symbol, 'MY_CLAM')
      assert_equal(symbol_fail, 'MY_CLAM_ERROR')
      -- Non-overridden symbols are still derived from the (overridden) symbol
      assert_equal(symbol_encrypted, 'MY_CLAM_ENCRYPTED')
      assert_equal(symbol_macro, 'MY_CLAM_MACRO')
      assert_equal(symbol_ignore, 'MY_CLAM_IGNORE')
    end)
  end)

  context("match_patterns", function()
    test("returns default symbol/weight when no patterns are configured", function()
      local sym, weight = common.match_patterns('DEFAULT_SYM', 'SomeVirus', nil, 0.5)
      assert_equal(sym, 'DEFAULT_SYM')
      assert_equal(weight, 0.5)
    end)

    test("returns default symbol/weight when patterns table is empty", function()
      local sym, weight = common.match_patterns('DEFAULT_SYM', 'SomeVirus', {}, 0.5)
      assert_equal(sym, 'DEFAULT_SYM')
      assert_equal(weight, 0.5)
    end)

    test("matches a plain (non-array) patterns table by regex", function()
      local rspamd_regexp = require "rspamd_regexp"
      local patterns = {
        JUST_EICAR = rspamd_regexp.create('^Eicar-Test-Signature$'),
      }
      local sym, weight = common.match_patterns('DEFAULT_SYM', 'Eicar-Test-Signature', patterns, 0.5)
      assert_equal(sym, 'JUST_EICAR')
      assert_equal(weight, '1')
    end)

    test("falls back to default symbol when no pattern matches", function()
      local rspamd_regexp = require "rspamd_regexp"
      local patterns = {
        JUST_EICAR = rspamd_regexp.create('^Eicar-Test-Signature$'),
      }
      local sym, weight = common.match_patterns('DEFAULT_SYM', 'SomeOtherVirus', patterns, 0.5)
      assert_equal(sym, 'DEFAULT_SYM')
      assert_equal(weight, 0.5)
    end)
  end)

  context("yield_result / av_result_cache", function()
    local function load_task_with_attachment()
      local msg = table.concat({
        'From: <sender@example.com>\n',
        'To: <nobody@example.com>\n',
        'Subject: test\n',
        'Content-Type: multipart/mixed; boundary=XXX\n',
        '\n',
        '--XXX\n',
        'Content-Type: text/plain\n',
        '\n',
        'Test message body.\n',
        '--XXX\n',
        'Content-Type: application/octet-stream\n',
        'Content-Disposition: attachment; filename="test.bin"\n',
        'Content-Transfer-Encoding: base64\n',
        '\n',
        'dGVzdCBjb250ZW50\n',
        '--XXX--\n',
      })
      local res, task = rspamd_task.load_from_string(msg, rspamd_config)
      if not res then
        error("failed to load message")
      end
      task:process_message()
      return task
    end

    local function find_attachment_part(task)
      for _, part in ipairs(task:get_parts()) do
        if part:get_filename() then
          return part
        end
      end
      return nil
    end

    test("records a scanner verdict in the task-wide av_result_cache", function()
      local task = load_task_with_attachment()
      local part = find_attachment_part(task)
      assert_not_nil(part, "expected multipart message to contain an attachment part")

      local rule = {
        name = 'test_scanner',
        log_prefix = 'test_scanner',
        symbol = 'TEST_VIRUS',
        detection_category = 'virus',
      }

      common.yield_result(task, rule, 'Eicar-Test-Signature', 1.0, nil, part)

      local cache = task:cache_get('av_result_cache')
      assert_not_nil(cache, "av_result_cache should be populated after yield_result")

      local digest = part:get_digest()
      local entry = cache[digest]
      assert_not_nil(entry, "cache should have an entry for the scanned part's digest")
      assert_equal(entry.filename, 'test.bin')
      assert_not_nil(entry.hash_sha256)
      assert_not_nil(entry.hash_sha1)

      local scanner_entry = entry.scanners['test_scanner']
      assert_not_nil(scanner_entry)
      assert_equal(scanner_entry.category, 'virus')
      assert_rspamd_table_eq_sorted({
        actual = scanner_entry.threats,
        expect = { 'Eicar-Test-Signature' },
      })
      assert_rspamd_table_eq_sorted({
        actual = scanner_entry.symbols,
        expect = { 'TEST_VIRUS' },
      })

      task:destroy()
    end)

    test("computes the digest hashes only once for multiple scanners on the same part", function()
      local task = load_task_with_attachment()
      local part = find_attachment_part(task)
      assert_not_nil(part)
      local raw_content_reads = 0
      local tracked_part = {
        get_content = function(_, content_type)
          if content_type == 'raw_parsed' then
            raw_content_reads = raw_content_reads + 1
          end
          return part:get_content(content_type)
        end,
        get_digest = function()
          return part:get_digest()
        end,
        get_filename = function()
          return part:get_filename()
        end,
      }

      local rule1 = {
        name = 'scanner_one',
        log_prefix = 'scanner_one',
        symbol = 'SCANNER_ONE_VIRUS',
        detection_category = 'virus',
      }
      local rule2 = {
        name = 'scanner_two',
        log_prefix = 'scanner_two',
        symbol = 'SCANNER_TWO_VIRUS',
        detection_category = 'virus',
      }

      common.yield_result(task, rule1, 'Virus.One', 1.0, nil, tracked_part)
      local digest = part:get_digest()

      common.yield_result(task, rule2, 'Virus.Two', 1.0, nil, tracked_part)
      local entry = task:cache_get('av_result_cache')[digest]

      assert_equal(raw_content_reads, 1,
        "raw MIME content should be read once for scanners sharing a part")
      assert_not_nil(entry.scanners['scanner_one'])
      assert_not_nil(entry.scanners['scanner_two'])

      task:destroy()
    end)

    test("uses the scanner detection category for normal results", function()
      local task = load_task_with_attachment()
      local part = find_attachment_part(task)
      local rule = {
        name = 'hash_scanner',
        log_prefix = 'hash_scanner',
        symbol = 'TEST_HASH',
        detection_category = 'hash',
      }

      common.yield_result(task, rule, 'spam', 1.0, nil, part)

      local entry = task:cache_get('av_result_cache')[part:get_digest()]
      assert_equal(entry.scanners['hash_scanner'].category, 'hash')
      task:destroy()
    end)

    test("records arbitrary categories using the normal result symbol", function()
      local task = load_task_with_attachment()
      local part = find_attachment_part(task)
      local rule = {
        name = 'custom_scanner',
        log_prefix = 'custom_scanner',
        symbol = 'TEST_CUSTOM',
        detection_category = 'hash',
      }

      common.yield_result(task, rule, 'listed', 1.0, 'reputation', part)

      local entry = task:cache_get('av_result_cache')[part:get_digest()]
      local scanner_entry = entry.scanners['custom_scanner']
      assert_equal(scanner_entry.category, 'reputation')
      assert_rspamd_table_eq_sorted({
        actual = scanner_entry.symbols,
        expect = { 'TEST_CUSTOM' },
      })
      task:destroy()
    end)

    test("records whitelisted results as ignored", function()
      local task = load_task_with_attachment()
      local part = find_attachment_part(task)
      local rule = {
        name = 'whitelist_scanner',
        log_prefix = 'whitelist_scanner',
        symbol = 'TEST_VIRUS',
        symbol_ignore = 'TEST_VIRUS_IGNORE',
        detection_category = 'virus',
        whitelist = {
          get_key = function(_, name)
            return name == 'Eicar-Test-Signature'
          end,
        },
      }

      common.yield_result(task, rule, 'Eicar-Test-Signature', 1.0, nil, part)

      local entry = task:cache_get('av_result_cache')[part:get_digest()]
      local scanner_entry = entry.scanners['whitelist_scanner']
      assert_true(scanner_entry.is_whitelisted)
      assert_rspamd_table_eq_sorted({
        actual = scanner_entry.symbols,
        expect = { 'TEST_VIRUS_IGNORE' },
      })
      task:destroy()
    end)

    test("does not populate av_result_cache when maybe_part is nil", function()
      local task = load_task_with_attachment()

      local rule = {
        name = 'test_scanner',
        log_prefix = 'test_scanner',
        symbol = 'TEST_VIRUS',
        symbol_fail = 'TEST_VIRUS_FAIL',
        detection_category = 'virus',
      }

      common.yield_result(task, rule, 'failed to scan', 0.0, 'fail', nil)

      assert_nil(task:cache_get('av_result_cache'),
        "av_result_cache must stay unset when no mime part is involved")

      task:destroy()
    end)

    context("scanner callbacks", function()
      test("failure stubs emit the configured fail symbol", function()
        local callback, report_callback, rule = common.configure_failed_stub('clamav', 'clam', {},
          'CLAM', 'CLAM_FAIL', 'CLAM_ENCRYPTED', 'CLAM_MACRO', 'CLAM_IGNORE')
        local result

        callback({
          insert_result = function(_, symbol, score, reason)
            result = { symbol = symbol, score = score, reason = reason }
          end,
        })

        assert_nil(report_callback)
        assert_equal(rule.symbol_fail, 'CLAM_FAIL')
        assert_equal(result.symbol, 'CLAM_FAIL')
        assert_equal(result.score, 1.0)
        assert_match('configuration failed', result.reason)
      end)

      test("report callbacks use the scanner report function", function()
        local task = load_task_with_attachment()
        local received = {}
        local rule = { scan_mime_parts = false }
        local callback = common.make_report_callback({
          report = function(...)
            received = { ... }
          end,
        }, rule)

        callback(task)

        assert_equal(received[1], task)
        assert_equal(received[4], rule)
        assert_nil(received[5])

        local part_reports = {}
        local part_rule = {
          scan_mime_parts = true,
          scan_all_mime_parts = true,
        }
        local part_callback = common.make_report_callback({
          report = function(...)
            table.insert(part_reports, { ... })
          end,
        }, part_rule)

        part_callback(task)

        assert_equal(#part_reports, 1)
        assert_equal(part_reports[1][1], task)
        assert_equal(part_reports[1][4], part_rule)
        assert_not_nil(part_reports[1][5])
        task:destroy()
      end)

      test("report symbol registration keeps its configured phase", function()
        local callback = function() end
        local registration = common.report_symbol_registration('TEST_REPORT', callback, {
          symbol_report_type = 'prefilter',
        }, 'test')

        assert_equal(registration.name, 'TEST_REPORT')
        assert_equal(registration.callback, callback)
        assert_equal(registration.type, 'prefilter')
        assert_not_nil(registration.priority)
      end)
    end)
  end)
end)
