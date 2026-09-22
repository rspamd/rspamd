context("lua_scanners peekaboo", function()
  local peekaboo = require "lua_scanners/peekaboo"
  local rspamd_http = require "rspamd_http"

  local function with_http_request(mock, fn)
    local original_request = rspamd_http.request
    rspamd_http.request = mock
    local ok, err = xpcall(fn, debug.traceback)
    rspamd_http.request = original_request
    if not ok then
      error(err)
    end
  end

  test("returns a fail result for a submit response without job_id", function()
    local inserted_result
    local selected_digest
    local cache = {}
    local upstream = {
      get_addr = function()
        return {
          get_port = function()
            return 8100
          end,
        }
      end,
      fail = function() end,
      ok = function() end,
    }
    local task = {
      cache_get = function(_, key)
        return cache[key]
      end,
      cache_set = function(_, key, value)
        cache[key] = value
      end,
      insert_result = function(_, symbol, score, reason)
        inserted_result = { symbol = symbol, score = score, reason = reason }
      end,
    }
    local rule = {
      name = 'peekaboo_test',
      log_prefix = 'peekaboo_test',
      symbol = 'PEEKABOO',
      symbol_fail = 'PEEKABOO_FAIL',
      detection_category = 'sandbox threat',
      upstreams = {
        get_upstream_by_hash = function(_, digest)
          selected_digest = digest
          return upstream
        end,
      },
      retransmits = 0,
      url_check = '/v1/scan',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }
    local part = {
      get_header = function()
        return nil
      end,
      get_type_full = function()
        return 'application', 'octet-stream', {}
      end,
      get_detected_ext = function()
        return nil
      end,
      get_digest = function()
        return 'test-digest'
      end,
      get_content = function(_, content_type)
        if content_type == 'raw_parsed' then
          return 'test content'
        end
      end,
      get_filename = function()
        return nil
      end,
    }
    with_http_request(function(options)
        options.callback(nil, 400, '{}', {})
      end, function()
        peekaboo.check(task, 'test content', 'test-digest', rule, part)
      end)

    assert_equal(inserted_result.symbol, 'PEEKABOO_FAIL')
    assert_equal(inserted_result.score, 0.0)
    assert_equal(inserted_result.reason, 'no job_id in submit response')
    assert_nil(cache.peekaboo_jobs)
    assert_equal(selected_digest, 'test-digest')
  end)

  test("uses the digest to select the report upstream", function()
    local selected_digest
    local requested_url
    local upstream = {
      get_addr = function()
        return setmetatable({
          get_port = function()
            return 8100
          end,
        }, {
          __tostring = function()
            return '127.0.0.1'
          end,
        })
      end,
      fail = function() end,
      ok = function() end,
    }
    local task = {
      cache_get = function(_, key)
        if key == 'peekaboo_jobs' then
          return { ['test-digest'] = 'test-job' }
        end
      end,
    }
    local rule = {
      log_prefix = 'peekaboo_test',
      upstreams = {
        get_upstream_by_hash = function(_, digest)
          selected_digest = digest
          return upstream
        end,
      },
      retransmits = 0,
      url_report = '/v1/report',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }
    with_http_request(function(options)
        requested_url = options.url
        options.callback(nil, 200, '{"result":"ignored","reason":"test"}', {})
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(selected_digest, 'test-digest')
    assert_equal(requested_url, 'http://127.0.0.1:8100/v1/report/test-job')
  end)

  local function make_upstream(ip, events)
    return {
      get_addr = function()
        return setmetatable({
          get_port = function()
            return 8100
          end,
        }, {
          __tostring = function()
            return ip
          end,
        })
      end,
      fail = function()
        if events then
          table.insert(events, 'fail:' .. ip)
        end
      end,
      ok = function()
        if events then
          table.insert(events, 'ok:' .. ip)
        end
      end,
    }
  end

  local function make_part()
    return {
      get_header = function()
        return nil
      end,
      get_type_full = function()
        return 'application', 'octet-stream', {}
      end,
      get_detected_ext = function()
        return nil
      end,
      get_digest = function()
        return 'test-digest'
      end,
      get_content = function(_, content_type)
        if content_type == 'raw_parsed' then
          return 'test content'
        end
      end,
      get_filename = function()
        return nil
      end,
    }
  end

  local function make_report_rule(upstreams, retransmits)
    return {
      name = 'peekaboo_test',
      log_prefix = 'peekaboo_test',
      symbol = 'PEEKABOO',
      symbol_fail = 'PEEKABOO_FAIL',
      detection_category = 'sandbox threat',
      upstreams = upstreams,
      retransmits = retransmits or 0,
      url_report = '/v1/report',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
      symbols = {
        peekaboo_good = { symbol = 'PEEKABOO_GOOD', score = -1.0 },
        peekaboo_pass = { symbol = 'PEEKABOO_PASS', score = 0.0 },
        peekaboo_in_process = { symbol = 'PEEKABOO_IN_PROCESS', score = 0 },
      },
    }
  end

  local function make_report_task(results)
    return {
      cache_get = function(_, key)
        if key == 'peekaboo_jobs' then
          return { ['test-digest'] = 'test-job' }
        end
      end,
      cache_set = function() end,
      insert_result = function(_, symbol, score, reason)
        table.insert(results, { symbol = symbol, score = score, reason = reason })
      end,
    }
  end

  test("submits to the hash selected upstream and caches the job id", function()
    local cache = {}
    local requested_url
    local upstream = make_upstream('127.0.0.1')
    local task = {
      cache_get = function(_, key)
        return cache[key]
      end,
      cache_set = function(_, key, value)
        cache[key] = value
      end,
      insert_result = function() end,
    }
    local rule = {
      name = 'peekaboo_test',
      log_prefix = 'peekaboo_test',
      symbol = 'PEEKABOO',
      symbol_fail = 'PEEKABOO_FAIL',
      detection_category = 'sandbox threat',
      upstreams = {
        get_upstream_by_hash = function()
          return upstream
        end,
      },
      retransmits = 0,
      url_check = '/v1/scan',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }
    with_http_request(function(options)
        requested_url = options.url
        options.callback(nil, 200, '{"job_id":"job-42"}', {})
      end, function()
        peekaboo.check(task, 'test content', 'test-digest', rule, make_part())
      end)

    assert_equal(requested_url, 'http://127.0.0.1:8100/v1/scan')
    assert_equal(cache.peekaboo_jobs['test-digest'], 'job-42')
  end)

  test("skips the scan when the content has no digest", function()
    local selected = false
    local requested = false
    local inserted_result
    local rule = {
      name = 'peekaboo_test',
      log_prefix = 'peekaboo_test',
      symbol = 'PEEKABOO',
      symbol_fail = 'PEEKABOO_FAIL',
      detection_category = 'sandbox threat',
      upstreams = {
        get_upstream_by_hash = function()
          selected = true
          return make_upstream('127.0.0.1')
        end,
      },
      retransmits = 0,
      url_check = '/v1/scan',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }
    local task = {
      cache_get = function() end,
      cache_set = function() end,
      insert_result = function(_, symbol, score, reason)
        inserted_result = { symbol = symbol, score = score, reason = reason }
      end,
    }
    with_http_request(function()
        requested = true
      end, function()
        peekaboo.check(task, 'test content', nil, rule, make_part())
      end)

    assert_false(selected)
    assert_false(requested)
    assert_equal(inserted_result.symbol, 'PEEKABOO_FAIL')
    assert_equal(inserted_result.score, 0.0)
    assert_equal(inserted_result.reason, 'no digest for content')
  end)

  test("does not select a report upstream when no job id is cached", function()
    local selected = false
    local requested = false
    local task = {
      cache_get = function(_, key)
        if key == 'peekaboo_jobs' then
          return {}
        end
      end,
    }
    local rule = {
      log_prefix = 'peekaboo_test',
      upstreams = {
        get_upstream_by_hash = function()
          selected = true
          return make_upstream('127.0.0.1')
        end,
      },
      retransmits = 0,
      url_report = '/v1/report',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }
    with_http_request(function()
        requested = true
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_false(selected)
    assert_false(requested)
  end)

  test("retries the report with the upstream returned by the selector", function()
    local events = {}
    local urls = {}
    local first = make_upstream('127.0.0.1', events)
    local second = make_upstream('127.0.0.2', events)
    local task = {
      cache_get = function(_, key)
        if key == 'peekaboo_jobs' then
          return { ['test-digest'] = 'test-job' }
        end
      end,
    }
    local rule = {
      log_prefix = 'peekaboo_test',
      upstreams = {
        get_upstream_by_hash = function()
          return first
        end,
        get_upstream_round_robin = function()
          return second
        end,
      },
      retransmits = 1,
      url_report = '/v1/report',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }
    local call = 0

    with_http_request(function(options)
        call = call + 1
        table.insert(urls, options.url)
        if call == 1 then
          options.callback(nil, 500, '', {})
        else
          options.callback(nil, 200, '{"result":"ignored","reason":"test"}', {})
        end
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(urls[1], 'http://127.0.0.1:8100/v1/report/test-job')
    assert_equal(urls[2], 'http://127.0.0.2:8100/v1/report/test-job')
    assert_equal(events[1], 'fail:127.0.0.1')
    assert_equal(events[2], 'ok:127.0.0.2')
  end)

  test("retries the submit with the upstream returned by the selector", function()
    local events = {}
    local urls = {}
    local cache = {}
    local first = make_upstream('127.0.0.1', events)
    local second = make_upstream('127.0.0.2', events)
    local task = {
      cache_get = function(_, key)
        return cache[key]
      end,
      cache_set = function(_, key, value)
        cache[key] = value
      end,
      insert_result = function() end,
    }
    local rule = {
      name = 'peekaboo_test',
      log_prefix = 'peekaboo_test',
      symbol = 'PEEKABOO',
      symbol_fail = 'PEEKABOO_FAIL',
      detection_category = 'sandbox threat',
      upstreams = {
        get_upstream_by_hash = function()
          return first
        end,
        get_upstream_round_robin = function()
          return second
        end,
      },
      retransmits = 1,
      url_check = '/v1/scan',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }
    local call = 0

    with_http_request(function(options)
        call = call + 1
        table.insert(urls, options.url)
        if call == 1 then
          options.callback(nil, 500, '', {})
        else
          options.callback(nil, 200, '{"job_id":"job-42"}', {})
        end
      end, function()
        peekaboo.check(task, 'test content', 'test-digest', rule, make_part())
      end)

    assert_equal(urls[1], 'http://127.0.0.1:8100/v1/scan')
    assert_equal(urls[2], 'http://127.0.0.2:8100/v1/scan')
    assert_equal(events[1], 'fail:127.0.0.1')
    assert_equal(events[2], 'ok:127.0.0.2')
    assert_equal(cache.peekaboo_jobs['test-digest'], 'job-42')
  end)

  -- the selector gets no 'except' argument, so a single node cluster legitimately
  -- hands back the node that just failed
  test("retries the report when the selector returns the same upstream", function()
    local events = {}
    local urls = {}
    local only = make_upstream('127.0.0.1', events)
    local results = {}
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return only
      end,
      get_upstream_round_robin = function()
        return only
      end,
    }, 1)
    local call = 0

    with_http_request(function(options)
        call = call + 1
        table.insert(urls, options.url)
        if call == 1 then
          options.callback(nil, 500, '', {})
        else
          options.callback(nil, 200, '{"result":"ignored","reason":"test"}', {})
        end
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(#urls, 2)
    assert_equal(urls[2], 'http://127.0.0.1:8100/v1/report/test-job')
    assert_equal(events[1], 'fail:127.0.0.1')
    assert_equal(events[2], 'ok:127.0.0.1')
  end)

  test("fails cleanly when no upstream is available for the report", function()
    local results = {}
    local requested = false
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return nil
      end,
    })

    with_http_request(function()
        requested = true
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_false(requested)
    assert_equal(results[1].symbol, 'PEEKABOO_FAIL')
    assert_equal(results[1].reason, 'no upstream available')
  end)

  test("fails when no upstream is available for the report retry", function()
    local events = {}
    local results = {}
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return make_upstream('127.0.0.1', events)
      end,
      get_upstream_round_robin = function()
        return nil
      end,
    }, 1)
    local calls = 0

    with_http_request(function(options)
        calls = calls + 1
        options.callback(nil, 500, '', {})
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(calls, 1)
    assert_equal(events[1], 'fail:127.0.0.1')
    assert_equal(results[1].symbol, 'PEEKABOO_FAIL')
    assert_equal(results[1].reason, 'no upstream available for retry')
  end)

  test("fails after the report retransmits are exhausted", function()
    local results = {}
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return make_upstream('127.0.0.1')
      end,
    })

    with_http_request(function(options)
        options.callback(nil, 500, '', {})
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(results[1].symbol, 'PEEKABOO_FAIL')
    assert_equal(results[1].reason,
      'failed to scan, maximum retransmits exceed - err: 500 - server error')
  end)

  test("maps a 404 report response to the in process symbol", function()
    local results = {}
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return make_upstream('127.0.0.1')
      end,
    })

    with_http_request(function(options)
        options.callback(nil, 404, '', {})
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(results[1].symbol, 'PEEKABOO_IN_PROCESS')
    assert_equal(results[1].score, 0.0)
    assert_equal(results[1].reason, 'job_id: test-job')
  end)

  test("reports a bad verdict with the scanner symbol", function()
    local results = {}
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return make_upstream('127.0.0.1')
      end,
    })

    with_http_request(function(options)
        options.callback(nil, 200, '{"result":"bad","reason":"malware found"}', {})
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(results[1].symbol, 'PEEKABOO')
    assert_equal(results[1].score, 1.0)
    assert_equal(results[1].reason, 'job-id test-job: malware found')
  end)

  test("reports a good verdict with the whitelist symbol", function()
    local results = {}
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return make_upstream('127.0.0.1')
      end,
    })

    with_http_request(function(options)
        options.callback(nil, 200, '{"result":"good","reason":"clean"}', {})
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(results[1].symbol, 'PEEKABOO_GOOD')
    assert_equal(results[1].score, -1.0)
  end)

  test("reports a failed verdict as a scanner failure", function()
    local results = {}
    local task = make_report_task(results)
    local rule = make_report_rule({
      get_upstream_by_hash = function()
        return make_upstream('127.0.0.1')
      end,
    })

    with_http_request(function(options)
        options.callback(nil, 200, '{"result":"failed","reason":"analysis error"}', {})
      end, function()
        peekaboo.report(task, nil, 'test-digest', rule, nil)
      end)

    assert_equal(results[1].symbol, 'PEEKABOO_FAIL')
    assert_equal(results[1].score, 0.0)
    assert_equal(results[1].reason, 'job-id test-job: analysis error')
  end)

  test("rejects a job id that could alter the report url", function()
    local cache = {}
    local inserted_result
    local task = {
      cache_get = function(_, key)
        return cache[key]
      end,
      cache_set = function(_, key, value)
        cache[key] = value
      end,
      insert_result = function(_, symbol, score, reason)
        inserted_result = { symbol = symbol, score = score, reason = reason }
      end,
    }
    local rule = {
      name = 'peekaboo_test',
      log_prefix = 'peekaboo_test',
      symbol = 'PEEKABOO',
      symbol_fail = 'PEEKABOO_FAIL',
      detection_category = 'sandbox threat',
      upstreams = {
        get_upstream_by_hash = function()
          return make_upstream('127.0.0.1')
        end,
      },
      retransmits = 0,
      url_check = '/v1/scan',
      default_port = 8100,
      peekaboo_cache_name = 'peekaboo_jobs',
    }

    with_http_request(function(options)
        options.callback(nil, 200, '{"job_id":"job/../../admin"}', {})
      end, function()
        peekaboo.check(task, 'test content', 'test-digest', rule, make_part())
      end)

    assert_equal(inserted_result.symbol, 'PEEKABOO_FAIL')
    assert_equal(inserted_result.reason, 'invalid job_id in submit response')
    assert_nil(cache.peekaboo_jobs)
  end)
end)