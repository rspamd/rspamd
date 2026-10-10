context("lua_scanners common", function()
  local common = require "lua_scanners/common"
  local helper = require "lua_scanners_test_helper"
  local rspamd_regexp = require "rspamd_regexp"
  local fun = require "fun"
  local extend, with_mock, with_redis_value = helper.extend, helper.with_mock, helper.with_redis_value
  local make_rule, make_task, make_part = helper.make_rule, helper.make_task, helper.make_part
  local check_cached, load_task_with_attachment = helper.check_cached, helper.load_task_with_attachment

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
    test("returns the default symbol/weight unless a pattern matches", function()
      local patterns = { JUST_EICAR = rspamd_regexp.create('^Eicar-Test-Signature$') }

      for _, case in ipairs({
        { name = 'no patterns', found = 'SomeVirus', sym = 'DEFAULT_SYM', weight = 0.5 },
        { name = 'empty patterns', patterns = {}, found = 'SomeVirus', sym = 'DEFAULT_SYM', weight = 0.5 },
        { name = 'match', patterns = patterns, found = 'Eicar-Test-Signature', sym = 'JUST_EICAR', weight = '1' },
        { name = 'no match', patterns = patterns, found = 'SomeOtherVirus', sym = 'DEFAULT_SYM', weight = 0.5 },
      }) do
        local sym, weight = common.match_patterns('DEFAULT_SYM', case.found, case.patterns, 0.5)
        assert_equal(sym, case.sym, case.name)
        assert_equal(weight, case.weight, case.name)
      end
    end)
  end)

  context("sanitize_header_filename", function()
    test("keeps plain names and replaces quotes, backslashes and control characters", function()
      assert_equal(common.sanitize_header_filename('report.pdf'), 'report.pdf')
      assert_equal(common.sanitize_header_filename(nil), nil)
      assert_equal(common.sanitize_header_filename('foo\\"bar.pdf'), 'foo__bar.pdf')
      assert_equal(common.sanitize_header_filename('foo\r\nbar.pdf'), 'foo__bar.pdf')
    end)
  end)

  context("yield_result / av_result_cache", function()
    test("records a scanner verdict in the task-wide av_result_cache", function()
      local task, part = load_task_with_attachment()

      common.yield_result(task, make_rule(), 'Eicar-Test-Signature', 1.0, nil, part)

      local cache = task:cache_get('av_result_cache')
      assert_not_nil(cache, "av_result_cache should be populated after yield_result")

      local entry = cache[part:get_digest()]
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
      local task, part = load_task_with_attachment()
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

      common.yield_result(task, make_rule({ name = 'scanner_one', symbol = 'SCANNER_ONE_VIRUS' }),
        'Virus.One', 1.0, nil, tracked_part)
      common.yield_result(task, make_rule({ name = 'scanner_two', symbol = 'SCANNER_TWO_VIRUS' }),
        'Virus.Two', 1.0, nil, tracked_part)
      local entry = task:cache_get('av_result_cache')[part:get_digest()]

      assert_equal(raw_content_reads, 1,
        "raw MIME content should be read once for scanners sharing a part")
      assert_not_nil(entry.scanners['scanner_one'])
      assert_not_nil(entry.scanners['scanner_two'])

      task:destroy()
    end)

    test("records the category and symbols of normal, custom and whitelisted results", function()
      for _, case in ipairs({
        { rule = { name = 'hash_scanner', symbol = 'TEST_HASH', detection_category = 'hash' },
          vname = 'spam', category = 'hash', symbols = { 'TEST_HASH' } },
        -- an arbitrary category string is the result symbol itself
        { rule = { name = 'custom_scanner', symbol = 'TEST_CUSTOM', detection_category = 'hash' },
          vname = 'listed', result_category = 'PEEKABOO_IN_PROCESS',
          category = 'PEEKABOO_IN_PROCESS', symbols = { 'PEEKABOO_IN_PROCESS' } },
        { rule = { name = 'whitelist_scanner', whitelist = {
          get_key = function(_, name)
            return name == 'Eicar-Test-Signature'
          end,
        } }, vname = 'Eicar-Test-Signature', category = 'virus',
          symbols = { 'TEST_VIRUS_IGNORE' }, whitelisted = true },
      }) do
        local task, part = load_task_with_attachment()

        common.yield_result(task, make_rule(case.rule), case.vname, 1.0, case.result_category, part)

        local scanner_entry = task:cache_get('av_result_cache')[part:get_digest()].scanners[case.rule.name]
        assert_equal(scanner_entry.category, case.category, case.rule.name)
        assert_equal(scanner_entry.is_whitelisted, case.whitelisted or false, case.rule.name)
        assert_rspamd_table_eq_sorted({
          actual = scanner_entry.symbols,
          expect = case.symbols,
        })
        task:destroy()
      end
    end)

    test("does not populate av_result_cache when maybe_part is nil", function()
      local task = load_task_with_attachment()

      common.yield_result(task, make_rule(), 'failed to scan', 0.0, 'fail', nil)

      assert_nil(task:cache_get('av_result_cache'),
        "av_result_cache must stay unset when no mime part is involved")

      task:destroy()
    end)

    test("defaults a missing dynamic weight to 0.0 for failures and keeps explicit weights", function()
      for _, case in ipairs({
        { category = 'fail', symbol = 'TEST_VIRUS_FAIL', weight = 0.0 },
        { category = 'TEST_CLEAN', dyn_weight = -1.0, symbol = 'TEST_CLEAN', weight = -1.0 },
      }) do
        local task = make_task()

        common.yield_result(task, make_rule(), 'verdict', case.dyn_weight, case.category)

        assert_equal(task.results[1].symbol, case.symbol, case.category)
        assert_equal(task.results[1].weight, case.weight, case.category)
        assert_equal(task.results[1].reason, 'verdict', case.category)
      end
    end)
  end)

  context("legacy category weights", function()
    test("live ClamAV macro and encrypted results retain unit weight", function()
      local clamav = require "lua_scanners/clamav"
      local tcp = require "rspamd_tcp"
      local upstream = helper.make_upstream('127.0.0.1', nil, 3310)

      for _, verdict in ipairs({
        { signature = 'Heuristics.OLE2.ContainsMacros', symbol = 'TEST_MACRO' },
        { signature = 'Heuristics.Encrypted', symbol = 'TEST_ENCRYPTED' },
      }) do
        local task = make_task()
        local rule = make_rule({
          upstreams = { get_upstream_round_robin = function() return upstream end },
        })

        with_mock(tcp, 'request', function(options)
          options.callback(nil, 'stream: ' .. verdict.signature .. ' FOUND')
        end, function()
          clamav.check(task, 'test content', 'test-digest', rule)
        end)

        assert_equal(#task.results, 1)
        assert_equal(task.results[1].symbol, verdict.symbol)
        assert_equal(task.results[1].weight, 1.0)
      end
    end)

    test("cached macro and encrypted results retain unit weight", function()
      for _, category in ipairs({ 'MACRO', 'ENCRYPTED' }) do
        local task = make_task()

        with_redis_value(category .. '\t0', function()
          assert_true(check_cached(task, make_rule({ redis_params = {} })))
        end)

        assert_equal(#task.results, 1)
        assert_equal(task.results[1].symbol, 'TEST_' .. category)
        assert_equal(task.results[1].weight, 1.0)
      end
    end)

    test("cached category results are inserted directly by default", function()
      local task = make_task()
      task.cache_get = function()
        error('unexpected av_result_cache access')
      end
      local part = make_part('test.bin')
      local rule = make_rule({
        redis_params = {},
        symbols = {},
        show_attachments = true,
        patterns = common.create_regex_table({ RENAMED = '^hash' }),
        whitelist = { get_key = function() return true end },
      })

      with_redis_value('TEST_CLEAN\vhash:0/70\t1\ttest.bin', function()
        assert_true(check_cached(task, rule, part))
      end)

      assert_equal(#task.results, 1)
      assert_equal(task.results[1].symbol, 'TEST_CLEAN')
      assert_equal(task.results[1].weight, 1.0)
      assert_equal(task.results[1].reason, 'hash:0/70')
    end)
  end)

  context("legacy scanner actions", function()
    test("forces actions only for threats, macros and encrypted content", function()
      for _, case in ipairs({
        { category = false, action = 'reject' },
        { category = 'macro', action = 'reject' },
        { category = 'encrypted', action = 'reject' },
        { category = 'fail' },
        { category = 'PEEKABOO_GOOD' },
        { category = 'PEEKABOO_PASS' },
        { category = 'PEEKABOO_IN_PROCESS' },
        { category = false, whitelisted = true, symbol = 'TEST_VIRUS_IGNORE' },
      }) do
        local task = make_task()
        local rule = make_rule({
          action = 'reject',
          whitelist = case.whitelisted and { get_key = function() return true end } or nil,
        })

        common.yield_result(task, rule, 'test verdict', 1.0, case.category)

        local name = tostring(case.category)
        assert_not_nil(task.results[1], name)
        if case.symbol then
          assert_equal(task.results[1].symbol, case.symbol, name)
        end
        assert_equal(task.actions[1] and task.actions[1].action, case.action, name)
      end
    end)
  end)

  context("scanner callbacks", function()
    test("failure stubs emit the configured fail symbol", function()
      local callback, report_callback, rule = common.configure_failed_stub('clamav', 'clam', {},
        'CLAM', 'CLAM_FAIL', 'CLAM_ENCRYPTED', 'CLAM_MACRO', 'CLAM_IGNORE')
      local task = make_task()

      callback(task)

      assert_nil(report_callback)
      assert_equal(rule.symbol_fail, 'CLAM_FAIL')
      assert_equal(task.results[1].symbol, 'CLAM_FAIL')
      assert_equal(task.results[1].weight, 1.0)
      assert_match('configuration failed', task.results[1].reason)
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

  context("check_parts_match / mime_parts_filter exclude", function()
    -- Lightweight fake parts: check_parts_match() only calls a handful of methods
    -- on each part, so we avoid depending on real MIME parsing / lua_magic detection.
    local function fake_part(spec)
      return {
        get_type = function()
          return spec.mtype, spec.msubtype
        end,
        get_detected_ext = function()
          return spec.detected_ext
        end,
        get_filename = function()
          return spec.filename
        end,
        is_archive = function()
          return spec.is_archive or false
        end,
        is_text = function()
          return spec.is_text or false
        end,
        is_image = function()
          return spec.is_image or false
        end,
        is_attachment = function()
          return false
        end,
        get_archive = function()
          return {
            get_files_full = function()
              return spec.archive_files or {}
            end,
          }
        end,
      }
    end

    -- sorted, comma separated filenames of the parts selected for scanning
    local function matched_filenames(specs, rule)
      local parts = {}
      for _, spec in ipairs(specs) do
        table.insert(parts, fake_part(spec))
      end
      local names = {}
      fun.each(function(p)
        table.insert(names, p:get_filename())
      end, common.check_parts_match({ get_parts = function() return parts end }, rule))
      table.sort(names)
      return table.concat(names, ',')
    end

    local function make_filter_rule(overrides)
      return make_rule(extend({
        scan_all_mime_parts = false,
        mime_parts_filter_ext = {},
        mime_parts_filter_regex = {},
        mime_parts_filter_ext_exclude = {},
        mime_parts_filter_regex_exclude = {},
      }, overrides))
    end

    local doc = { filename = 'invoice.doc', mtype = 'application', msubtype = 'msword' }
    local exe = { filename = 'malware.exe', mtype = 'application', msubtype = 'octet-stream' }
    local jpg = { filename = 'photo.jpg', mtype = 'image', msubtype = 'jpeg' }

    local function zip(...)
      local files = {}
      for _, name in ipairs({ ... }) do
        table.insert(files, { name = name })
      end
      return {
        filename = 'archive.zip',
        mtype = 'application',
        msubtype = 'zip',
        is_archive = true,
        archive_files = files,
      }
    end

    test("applies include and exclude filters to parts and archives", function()
      for _, case in ipairs({
        { name = 'include-only extension restricts scanning',
          parts = { doc, exe, jpg }, filters = { mime_parts_filter_ext = { doc = 'doc' } },
          expect = 'invoice.doc' },
        { name = 'exclude suppresses a part that also matches the include filter',
          parts = { doc, exe, jpg },
          filters = { mime_parts_filter_ext = { doc = 'doc' }, mime_parts_filter_ext_exclude = { doc = 'doc' } },
          expect = '' },
        { name = 'exclude-only extension means match all except excluded',
          parts = { doc, exe, jpg }, filters = { mime_parts_filter_ext_exclude = { exe = 'exe' } },
          expect = 'invoice.doc,photo.jpg' },
        { name = 'exclude-only content-type regex means match all except excluded',
          parts = { doc, exe, jpg },
          filters = { mime_parts_filter_regex_exclude = common.create_regex_table({ IMG = '^image/' }) },
          expect = 'invoice.doc,malware.exe' },
        { name = 'archive matches on the files inside it',
          parts = { zip('secret.exe') }, filters = { mime_parts_filter_ext = { exe = 'exe' } },
          expect = 'archive.zip' },
        { name = 'mime_parts_match_archive = false skips filename matching inside archives',
          parts = { zip('secret.exe') },
          filters = { mime_parts_filter_ext = { exe = 'exe' }, mime_parts_match_archive = false },
          expect = '' },
        -- the archive itself is excluded, even though a file inside matches the include filter
        { name = 'excluding the archive extension suppresses the whole archive',
          parts = { zip('secret.exe') },
          filters = { mime_parts_filter_ext = { exe = 'exe' }, mime_parts_filter_ext_exclude = { zip = 'zip' } },
          expect = '' },
        -- secret.exe is not excluded, so the archive as a whole is still scanned
        { name = 'archive with a mix of excluded and non-excluded files is still scanned',
          parts = { zip('readme.txt', 'secret.exe') },
          filters = { mime_parts_filter_ext = { exe = 'exe' }, mime_parts_filter_ext_exclude = { txt = 'txt' } },
          expect = 'archive.zip' },
        -- blacklist mode: every file inside the archive is excluded
        { name = 'archive where every contained file is excluded suppresses the whole archive',
          parts = { zip('readme.txt', 'notes.txt') },
          filters = { mime_parts_filter_ext_exclude = { txt = 'txt' } },
          expect = '' },
      }) do
        assert_equal(matched_filenames(case.parts, make_filter_rule(case.filters)), case.expect, case.name)
      end
    end)

    test("explicit exclusions override text and image scanning", function()
      local exclusions = {
        extension = { rule = { mime_parts_filter_ext_exclude = { txt = 'txt', jpg = 'jpg' } } },
        filename = { rule = {
          mime_parts_filter_regex_exclude = common.create_regex_table({ EXCLUDE = '^excluded\\.' }) } },
        content_type = { rule = {
          mime_parts_filter_regex_exclude = common.create_regex_table({ EXCLUDE = '^(text|image)/' }) } },
        detected = { rule = { mime_parts_filter_ext_exclude = { pdf = 'pdf' } },
          part = { detected_ext = 'pdf' } },
      }

      for _, media in ipairs({
        { filename = 'excluded.txt', mtype = 'text', msubtype = 'plain', is_text = true },
        { filename = 'excluded.jpg', mtype = 'image', msubtype = 'jpeg', is_image = true },
      }) do
        for _, include in ipairs({ false, true }) do
          for name, exclusion in pairs(exclusions) do
            local label = string.format('%s, include=%s, %s', media.filename, tostring(include), name)
            local parts = { extend(extend({}, media), exclusion.part) }
            local base = {
              scan_text_mime = true,
              scan_image_mime = true,
              mime_parts_filter_ext = include and { txt = 'txt', jpg = 'jpg' } or {},
            }

            assert_equal(matched_filenames(parts, make_filter_rule(extend(extend({}, base), exclusion.rule))),
              '', label)
            assert_equal(matched_filenames(parts, make_filter_rule(base)), media.filename, label)
          end
        end
      end
    end)
  end)
end)
