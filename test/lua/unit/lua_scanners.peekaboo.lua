context("lua_scanners peekaboo", function()
  local peekaboo = require "lua_scanners/peekaboo"
  local rspamd_http = require "rspamd_http"

  test("returns a fail result for a submit response without job_id", function()
    local inserted_result
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
        get_upstream_round_robin = function()
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
    local original_request = rspamd_http.request

    rspamd_http.request = function(options)
      options.callback(nil, 400, '{}', {})
    end
    peekaboo.check(task, 'test content', 'test-digest', rule, part)
    rspamd_http.request = original_request

    assert_equal(inserted_result.symbol, 'PEEKABOO_FAIL')
    assert_equal(inserted_result.score, 0.0)
    assert_equal(inserted_result.reason, 'no job_id in submit response')
    assert_nil(cache.peekaboo_jobs)
  end)
end)