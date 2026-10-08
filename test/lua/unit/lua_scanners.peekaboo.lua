context("lua_scanners peekaboo", function()
  local peekaboo = require "lua_scanners/peekaboo"
  local helper = require "lua_scanners_test_helper"
  local rspamd_http = require "rspamd_http"
  local with_mock, with_redis_cache = helper.with_mock, helper.with_redis_cache
  local with_responses = helper.with_http_responses
  local make_upstream, make_upstreams, make_part = helper.make_upstream, helper.make_upstreams, helper.make_part
  local make_task, check_cached = helper.make_task, helper.check_cached

  local function make_rule(upstreams, retransmits)
    return helper.make_rule({
      name = 'peekaboo_test',
      symbol = 'PEEKABOO',
      symbol_fail = 'PEEKABOO_FAIL',
      detection_category = 'sandbox threat',
      upstreams = upstreams,
      default_score = 1.0,
      retransmits = retransmits or 0,
      url_check = '/v1/scan',
      url_report = '/v1/report',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
      defer_message = 'Awaiting attachment analysis',
      symbols = {
        peekaboo_good = { symbol = 'PEEKABOO_GOOD', score = -1.0 },
        peekaboo_pass = { symbol = 'PEEKABOO_PASS', score = 0.0 },
        peekaboo_in_process = { symbol = 'PEEKABOO_IN_PROCESS', score = 0 },
      },
    })
  end

  local function make_report_task()
    return make_task({ peekaboo_jobs = { ['test-digest'] = 'test-job' } })
  end

  local function make_metric_rule(name, options)
    options.type = 'peekaboo'
    options.servers = '127.0.0.1:8100'
    options.symbol = name
    local rule = peekaboo.configure(options)
    assert(rule)
    rule.upstreams = make_upstreams(make_upstream('127.0.0.1'))
    return helper.register_metric_rule(rule, name)
  end

  local function make_metric_task(rule, jobs)
    return helper.load_task({ [rule.peekaboo_cache_name] = jobs or { ['test-digest'] = 'test-job' } })
  end

  test("preserves the scanner-level action option and defaults deferral to disabled", function()
    local options = { type = 'peekaboo', servers = '127.0.0.1:8100', action = 'reject' }
    local rule = peekaboo.configure(options)

    assert_not_nil(rule)
    assert_equal(rule.action, 'reject')
    assert_equal(rule.score, 1.0)
    assert_equal(rule.default_score, 1.0)
    assert_false(rule.defer_if_no_result)
    assert_not_nil(rule.defer_message)
    assert_equal(options.action, 'reject')
  end)

  test("submits to the hash selected upstream and caches the job id", function()
    local task = make_task()
    local upstreams = make_upstreams(make_upstream('127.0.0.1'))
    local urls = with_responses({ { 200, '{"job_id":"job-42"}' } }, function()
      peekaboo.check(task, 'test content', 'test-digest', make_rule(upstreams), make_part())
    end)

    assert_equal(upstreams.selected[1], 'test-digest')
    assert_equal(urls[1], 'http://127.0.0.1:8100/v1/scan')
    assert_equal(task.cache.peekaboo_jobs['test-digest'], 'job-42')
  end)

  test("fails invalid submit responses without caching a job id", function()
    for _, case in ipairs({
      { 400, '{}', 'no job_id in submit response' },
      -- the job id becomes part of the report url path
      { 200, '{"job_id":"job/../../admin"}', 'invalid job_id in submit response' },
    }) do
      local task = make_task()
      with_responses({ case }, function()
        peekaboo.check(task, 'test content', 'test-digest',
          make_rule(make_upstreams(make_upstream('127.0.0.1'))), make_part())
      end)

      assert_equal(task.results[1].symbol, 'PEEKABOO_FAIL')
      assert_equal(task.results[1].weight, 0.0)
      assert_equal(task.results[1].reason, case[3])
      assert_nil(task.cache.peekaboo_jobs)
    end
  end)

  test("skips the scan when the content has no digest", function()
    local task = make_task()
    local upstreams = make_upstreams(make_upstream('127.0.0.1'))
    local urls = with_responses({ { 200, '{"job_id":"job-42"}' } }, function()
      peekaboo.check(task, 'test content', nil, make_rule(upstreams), make_part())
    end)

    assert_equal(#upstreams.selected, 0)
    assert_equal(#urls, 0)
    assert_equal(task.results[1].symbol, 'PEEKABOO_FAIL')
    assert_equal(task.results[1].weight, 0.0)
    assert_equal(task.results[1].reason, 'no digest for content')
  end)

  test("retries the submit with the upstream returned by the selector", function()
    local events = {}
    local task = make_task()
    local upstreams = make_upstreams(make_upstream('127.0.0.1', events), make_upstream('127.0.0.2', events))
    local urls = with_responses({ { 500 }, { 200, '{"job_id":"job-42"}' } }, function()
      peekaboo.check(task, 'test content', 'test-digest', make_rule(upstreams, 1), make_part())
    end)

    assert_equal(urls[1], 'http://127.0.0.1:8100/v1/scan')
    assert_equal(urls[2], 'http://127.0.0.2:8100/v1/scan')
    assert_equal(events[1], 'fail:127.0.0.1')
    assert_equal(events[2], 'ok:127.0.0.2')
    assert_equal(task.cache.peekaboo_jobs['test-digest'], 'job-42')
  end)

  test("uses the digest to select the report upstream", function()
    local upstreams = make_upstreams(make_upstream('127.0.0.1'))
    local urls = with_responses({ { 200, '{"result":"ignored","reason":"test"}' } }, function()
      peekaboo.report(make_report_task(), nil, 'test-digest', make_rule(upstreams), nil)
    end)

    assert_equal(upstreams.selected[1], 'test-digest')
    assert_equal(urls[1], 'http://127.0.0.1:8100/v1/report/test-job')
  end)

  test("does not select a report upstream when no job id is cached", function()
    local upstreams = make_upstreams(make_upstream('127.0.0.1'))
    local urls = with_responses({ { 200 } }, function()
      peekaboo.report(make_task({ peekaboo_jobs = {} }), nil, 'test-digest', make_rule(upstreams), nil)
    end)

    assert_equal(#upstreams.selected, 0)
    assert_equal(#urls, 0)
  end)

  -- the selector gets no 'except' argument, so a single node cluster legitimately
  -- hands back the node that just failed
  test("retries the report with the upstream returned by the selector", function()
    for _, retry_ip in ipairs({ '127.0.0.2', '127.0.0.1' }) do
      local events = {}
      local first = make_upstream('127.0.0.1', events)
      local retry = retry_ip == '127.0.0.1' and first or make_upstream(retry_ip, events)
      local urls = with_responses({ { 500 }, { 200, '{"result":"ignored","reason":"test"}' } }, function()
        peekaboo.report(make_report_task(), nil, 'test-digest', make_rule(make_upstreams(first, retry), 1), nil)
      end)

      assert_equal(#urls, 2)
      assert_equal(urls[1], 'http://127.0.0.1:8100/v1/report/test-job')
      assert_equal(urls[2], 'http://' .. retry_ip .. ':8100/v1/report/test-job')
      assert_equal(events[1], 'fail:127.0.0.1')
      assert_equal(events[2], 'ok:' .. retry_ip)
    end
  end)

  test("fails when no upstream is available for the report or its retry", function()
    for _, case in ipairs({
      { first = false, requests = 0, reason = 'no upstream available' },
      { first = true, requests = 1, reason = 'no upstream available for retry' },
    }) do
      local events = {}
      local task = make_report_task()
      local first = case.first and make_upstream('127.0.0.1', events) or nil
      local urls = with_responses({ { 500 } }, function()
        peekaboo.report(task, nil, 'test-digest', make_rule(make_upstreams(first), 1), nil)
      end)

      assert_equal(#urls, case.requests)
      assert_equal(events[1], case.first and 'fail:127.0.0.1' or nil)
      assert_equal(task.results[1].symbol, 'PEEKABOO_FAIL')
      assert_equal(task.results[1].reason, case.reason)
    end
  end)

  test("maps report responses to symbols and actions", function()
    for _, case in ipairs({
      { 200, '{"result":"bad","reason":"malware found"}', 'PEEKABOO', 1.0,
        'job-id test-job: malware found', 'reject' },
      { 200, '{"result":"good","reason":"clean"}', 'PEEKABOO_GOOD', 1.0, 'job-id test-job: clean' },
      { 200, '{"result":"failed","reason":"analysis error"}', 'PEEKABOO_FAIL', 0.0,
        'job-id test-job: analysis error' },
      { 500, '', 'PEEKABOO_FAIL', 0.0, 'failed to scan, maximum retransmits exceed - err: 500 - server error' },
      { 404, '', 'PEEKABOO_IN_PROCESS', 0.0, 'job_id: test-job', nil, false },
    }) do
      local task = make_report_task()
      local rule = make_rule(make_upstreams(make_upstream('127.0.0.1')))
      rule.action = 'reject'
      rule.defer_if_no_result = case[7] ~= false
      with_responses({ case }, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

      assert_equal(task.results[1].symbol, case[3])
      assert_equal(task.results[1].weight, case[4])
      assert_equal(task.results[1].reason, case[5])
      assert_equal(#task.actions, case[6] and 1 or 0)
      if case[6] then
        assert_equal(task.actions[1].action, case[6])
      end
    end
  end)

  test("optionally defers pending reports without downgrading reject", function()
    for _, metric_action in ipairs({ 'no action', 'reject' }) do
      local task = make_report_task()
      task.metric_action = metric_action
      local rule = make_rule(make_upstreams(make_upstream('127.0.0.1')))
      rule.action = 'reject'
      rule.defer_if_no_result = true
      with_responses({ { 404 } }, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

      assert_equal(task.results[1].symbol, 'PEEKABOO_IN_PROCESS')
      if metric_action == 'reject' then
        assert_equal(#task.actions, 0)
      else
        assert_equal(#task.actions, 1)
        assert_equal(task.actions[1].action, 'soft reject')
        assert_equal(task.actions[1].message, rule.defer_message)
        assert_equal(task.actions[1].module, rule.name)
        assert_equal(task.actions[1].flags, 'least')
      end
    end
  end)

  test("a bad part rejects regardless of pending part order", function()
    local rule = make_metric_rule('TEST_PEEKABOO_DEFER_ORDER', { action = 'reject', defer_if_no_result = true })
    for _, order in ipairs({ { 'pending', 'bad' }, { 'bad', 'pending' } }) do
      local task = make_metric_task(rule, { pending = 'job-pending', bad = 'job-bad' })
      with_mock(rspamd_http, 'request', function(options)
        if options.url:find('job%-pending$') then
          options.callback(nil, 404, '', {})
        else
          options.callback(nil, 200, '{"result":"bad","reason":"malware"}', {})
        end
      end, function()
        for _, digest in ipairs(order) do
          peekaboo.report(task, nil, digest, rule, nil)
        end
      end)
      assert_equal(task:get_metric_action(), 'reject')
      task:destroy()
    end
  end)

  test("replaces cache delimiters in verdict reasons", function()
    local task = make_report_task()
    local rule = make_rule(make_upstreams(make_upstream('127.0.0.1')))
    rule.redis_params = {}
    with_redis_cache(function(cached)
      with_responses({ { 200, '{"result":"bad","reason":"a\\tb\\u000bc"}' } }, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

      assert_equal(task.results[1].reason, 'job-id test-job: a b c')
      assert_not_nil(cached.value:match('^job%-id test%-job: a b c\t[^\t]+$'))
    end)
  end)

  test("applies registered metric scores to default and custom verdict weights", function()
    for _, scenario in ipairs({
      { name = 'TEST_PEEKABOO_DEFAULT_SCORE', options = {} },
      { name = 'TEST_PEEKABOO_CUSTOM_SCORE', options = { score = 2.0, default_score = 3.0 },
        good = -2.0, pass = 0.5 },
    }) do
      local rule = make_metric_rule(scenario.name, scenario.options)
      for category, score in pairs({ peekaboo_good = scenario.good, peekaboo_pass = scenario.pass }) do
        rule.symbols[category].score = score
        rspamd_config:set_metric_symbol({ name = rule.symbols[category].symbol, score = score })
      end
      rule.set_clean_symbol = true
      for _, verdict in ipairs({
        { result = 'bad', symbol = rule.symbol, score = rule.score * rule.default_score },
        { result = 'good', symbol = rule.symbols.peekaboo_good.symbol, score = rule.symbols.peekaboo_good.score },
        { result = 'unknown', symbol = rule.symbols.peekaboo_pass.symbol, score = rule.symbols.peekaboo_pass.score },
      }) do
        local task = make_metric_task(rule)
        with_responses({ { 200, string.format('{"result":"%s","reason":"test"}', verdict.result) } }, function()
          peekaboo.report(task, nil, 'test-digest', rule, nil)
        end)
        local result = task:get_symbol(verdict.symbol)
        assert_not_nil(result)
        assert_equal(result[1].score, verdict.score)
        assert_equal(task:get_metric_score()[1], verdict.score)
        task:destroy()
      end
    end
  end)

  test("cached bad verdicts preserve the configured dynamic weight and metric score", function()
    local rule = make_metric_rule('TEST_PEEKABOO_CACHED_SCORE', { score = 2.0, default_score = 2.5 })
    rule.redis_params = {}
    with_redis_cache(function(cached)
      local task = make_metric_task(rule)
      with_responses({ { 200, '{"result":"bad","reason":"malware found"}' } }, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)
      assert_equal(cached.value, 'job-id test-job: malware found\t2.5')
      assert_equal(task:get_symbol(rule.symbol)[1].score, 5.0)
      task:destroy()

      local cached_task = make_metric_task(rule)
      assert_true(check_cached(cached_task, rule))
      assert_equal(cached_task:get_symbol(rule.symbol)[1].score, 5.0)
      assert_equal(cached_task:get_metric_score()[1], 5.0)
      cached_task:destroy()
    end)
  end)

  test("cached good verdicts preserve scores, reasons and attachment metadata", function()
    for _, metric_score in ipairs({ -1.0, -2.0 }) do
      local rule = make_metric_rule('TEST_PEEKABOO_CACHED_GOOD_' .. tostring(-metric_score),
        { show_attachments = true, action = 'reject' })
      local symbol = rule.symbols.peekaboo_good.symbol
      rspamd_config:set_metric_symbol({ name = symbol, score = metric_score })
      rule.redis_params = {}
      local part = make_part('trusted.pdf')
      local details = 'job-id test-job: whitelist match'
      with_redis_cache(function(cached)
        local task = make_metric_task(rule)
        with_responses({ { 200, '{"result":"good","reason":"whitelist match"}' } }, function()
          peekaboo.report(task, nil, 'test-digest', rule, part)
        end)
        assert_equal(cached.value, symbol .. '\v' .. details .. '\t1\ttrusted.pdf')
        assert_equal(task:get_symbol(symbol)[1].score, metric_score)
        assert_false(task:has_pre_result())
        local fresh_entry = task:cache_get('av_result_cache')['test-digest']
        task:destroy()

        local cached_task = make_metric_task(rule)
        assert_true(check_cached(cached_task, rule, part))
        local result = cached_task:get_symbol(symbol)[1]
        assert_equal(result.score, metric_score)
        assert_equal(result.options[1], details .. '|trusted.pdf')
        assert_equal(cached_task:get_metric_score()[1], metric_score)
        assert_false(cached_task:has_pre_result())
        local cached_entry = cached_task:cache_get('av_result_cache')['test-digest']
        assert_equal(cached_entry.filename, fresh_entry.filename)
        assert_equal(cached_entry.hash_sha256, fresh_entry.hash_sha256)
        assert_equal(cached_entry.hash_sha1, fresh_entry.hash_sha1)
        local scanner = cached_entry.scanners[rule.log_prefix]
        assert_equal(scanner.category, symbol)
        assert_equal(scanner.threats[1], details)
        assert_equal(scanner.symbols[1], symbol)
        assert_false(scanner.is_whitelisted)
        cached_task:destroy()
      end)
    end
  end)
end)
