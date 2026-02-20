--[[
Test HTTP client behavior when server sends early responses.

This tests edge cases where a server responds before the client has finished
sending the request body (which is allowed by HTTP/1.1 spec).

The test server (dummy_http_early_response.py) runs on port 18083.
]]

local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"

-- Register all possible result symbols upfront
-- These are the symbols that will be inserted based on HTTP response codes
local result_symbols = {
  -- Test 1: Early reply
  'HTTP_EARLY_REPLY_ERROR',
  'HTTP_EARLY_REPLY_200',
  'HTTP_EARLY_REPLY_413',
  'HTTP_EARLY_REPLY_500',
  -- Test 2: Early 413
  'HTTP_EARLY_413_ERROR',
  'HTTP_EARLY_413_413',
  'HTTP_EARLY_413_200',
  -- Test 3: Keepalive early
  'HTTP_KEEPALIVE_EARLY_ERROR',
  'HTTP_KEEPALIVE_EARLY_200',
  -- Test 4: Coroutine early
  'HTTP_EARLY_CORO_ERROR',
  'HTTP_EARLY_CORO_200',
  -- Test 5: Normal
  'HTTP_NORMAL_ERROR',
  'HTTP_NORMAL_200',
  -- Test 6: Keepalive sequential
  'HTTP_KEEPALIVE_SEQ_ERRORS',
  'HTTP_KEEPALIVE_SEQ_SUCCESS',
  -- Test 7: Keepalive stress
  'HTTP_EARLY_KEEPALIVE_STRESS',
  -- Test 8: Immediate close
  'HTTP_IMMEDIATE_CLOSE_ERROR',
  'HTTP_IMMEDIATE_CLOSE_413',
  'HTTP_IMMEDIATE_CLOSE_200',
  -- Test 9: Slow response
  'HTTP_SLOW_RESPONSE_ERROR',
  'HTTP_SLOW_RESPONSE_200',
  -- Test 10: Rapid close
  'HTTP_RAPID_CLOSE_RESULTS',
  -- Test 11: Block and reply
  'HTTP_BLOCK_REPLY_ERROR',
  'HTTP_BLOCK_REPLY_413',
  'HTTP_BLOCK_REPLY_200',
  -- Test 12: Block and reply coro
  'HTTP_BLOCK_REPLY_CORO_ERROR',
  'HTTP_BLOCK_REPLY_CORO_413',
  'HTTP_BLOCK_REPLY_CORO_200',
  -- Test 13: Block slow
  'HTTP_BLOCK_SLOW_ERROR',
  'HTTP_BLOCK_SLOW_503',
  'HTTP_BLOCK_SLOW_200',
  -- Test 14: Instant reply (before headers even read)
  'HTTP_INSTANT_REPLY_ERROR',
  'HTTP_INSTANT_REPLY_413',
}

-- Register all result symbols as virtual symbols
for _, sym_name in ipairs(result_symbols) do
  rspamd_config:register_symbol({
    name = sym_name,
    score = 0.0,
    type = 'virtual',
    parent = -1,  -- Will be set properly by parent registration
  })
end

-- Test 1: Early reply - server responds before reading body
local function test_early_reply(task)
  rspamd_logger.errx(task, 'test_early_reply: starting')

  -- Create a large body to increase chance of race condition
  local body_parts = {}
  for i = 1, 1000 do
    body_parts[i] = string.format("line %d: some test data that we are sending\n", i)
  end
  local large_body = table.concat(body_parts)

  local function callback(err, code, body)
    if err then
      rspamd_logger.errx(task, 'test_early_reply callback error: %s', err)
      task:insert_result('HTTP_EARLY_REPLY_ERROR', 1.0, err)
    else
      rspamd_logger.errx(task, 'test_early_reply callback success: code=%s body=%s', code, body)
      task:insert_result('HTTP_EARLY_REPLY_' .. tostring(code), 1.0, body)
    end
  end

  rspamd_http.request({
    url = 'http://127.0.0.1:18083/early-reply',
    task = task,
    method = 'post',
    body = large_body,
    callback = callback,
    timeout = 5,
  })
end

-- Test 2: Early 413 error - server sends error before reading body
local function test_early_error_413(task)
  rspamd_logger.errx(task, 'test_early_error_413: starting')

  -- Create a large body
  local body_parts = {}
  for i = 1, 1000 do
    body_parts[i] = string.format("line %d: large body data\n", i)
  end
  local large_body = table.concat(body_parts)

  local function callback(err, code, body)
    if err then
      rspamd_logger.errx(task, 'test_early_error_413 callback error: %s', err)
      task:insert_result('HTTP_EARLY_413_ERROR', 1.0, err)
    else
      rspamd_logger.errx(task, 'test_early_error_413 callback success: code=%s body=%s', code, body)
      task:insert_result('HTTP_EARLY_413_' .. tostring(code), 1.0, body)
    end
  end

  rspamd_http.request({
    url = 'http://127.0.0.1:18083/early-error-413',
    task = task,
    method = 'post',
    body = large_body,
    callback = callback,
    timeout = 5,
  })
end

-- Test 3: Keep-alive with early response
local function test_keepalive_early(task)
  rspamd_logger.errx(task, 'test_keepalive_early: starting')

  local body = "test body for keepalive"

  local function callback(err, code, body_response)
    if err then
      rspamd_logger.errx(task, 'test_keepalive_early callback error: %s', err)
      task:insert_result('HTTP_KEEPALIVE_EARLY_ERROR', 1.0, err)
    else
      rspamd_logger.errx(task, 'test_keepalive_early callback success: code=%s', code)
      task:insert_result('HTTP_KEEPALIVE_EARLY_' .. tostring(code), 1.0, body_response)
    end
  end

  rspamd_http.request({
    url = 'http://127.0.0.1:18083/keepalive-early',
    task = task,
    method = 'post',
    body = body,
    callback = callback,
    timeout = 5,
    keepalive = true,
  })
end

-- Test 4: Coroutine-based early reply test
local function test_early_reply_coro(task)
  rspamd_logger.errx(task, 'test_early_reply_coro: starting')

  local body_parts = {}
  for i = 1, 500 do
    body_parts[i] = string.format("coro line %d: test data\n", i)
  end
  local body = table.concat(body_parts)

  local err, response = rspamd_http.request({
    url = 'http://127.0.0.1:18083/early-reply',
    task = task,
    method = 'post',
    body = body,
    timeout = 5,
  })

  if err then
    rspamd_logger.errx(task, 'test_early_reply_coro error: %s', err)
    task:insert_result('HTTP_EARLY_CORO_ERROR', 1.0, err)
  else
    rspamd_logger.errx(task, 'test_early_reply_coro success: code=%s', response.code)
    task:insert_result('HTTP_EARLY_CORO_' .. tostring(response.code), 1.0, response.content)
  end
end

-- Test 5: Multiple requests to normal endpoint (baseline)
local function test_normal_request(task)
  rspamd_logger.errx(task, 'test_normal_request: starting')

  local function callback(err, code, body)
    if err then
      rspamd_logger.errx(task, 'test_normal_request callback error: %s', err)
      task:insert_result('HTTP_NORMAL_ERROR', 1.0, err)
    else
      rspamd_logger.errx(task, 'test_normal_request callback success: code=%s', code)
      task:insert_result('HTTP_NORMAL_' .. tostring(code), 1.0, body)
    end
  end

  rspamd_http.request({
    url = 'http://127.0.0.1:18083/request',
    task = task,
    method = 'post',
    body = 'normal test body',
    callback = callback,
    timeout = 5,
  })
end

-- Main test symbol that runs all tests
local function http_early_response_tests(task)
  local test_type = tostring(task:get_request_header('test-type') or 'all')

  rspamd_logger.errx(task, 'http_early_response_tests: test_type=%s', test_type)

  if test_type == 'early-reply' or test_type == 'all' then
    test_early_reply(task)
  end

  if test_type == 'early-413' or test_type == 'all' then
    test_early_error_413(task)
  end

  if test_type == 'keepalive-early' or test_type == 'all' then
    test_keepalive_early(task)
  end

  if test_type == 'early-coro' or test_type == 'all' then
    test_early_reply_coro(task)
  end

  if test_type == 'normal' or test_type == 'all' then
    test_normal_request(task)
  end
end

rspamd_config:register_symbol({
  name = 'HTTP_EARLY_RESPONSE_TEST',
  score = 1.0,
  callback = http_early_response_tests,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 6: Sequential keepalive requests (stress test for keepalive pool)
local function test_keepalive_sequential(task)
  rspamd_logger.errx(task, 'test_keepalive_sequential: starting')

  local success_count = 0
  local error_count = 0
  local errors = {}

  -- Make 3 sequential requests using keepalive
  for i = 1, 3 do
    local err, response = rspamd_http.request({
      url = 'http://127.0.0.1:18083/keepalive-normal',
      task = task,
      method = 'post',
      body = string.format('request %d body', i),
      timeout = 5,
      keepalive = true,
    })

    if err then
      error_count = error_count + 1
      errors[#errors + 1] = string.format('req%d: %s', i, err)
      rspamd_logger.errx(task, 'keepalive request %d error: %s', i, err)
    else
      success_count = success_count + 1
      rspamd_logger.errx(task, 'keepalive request %d success: code=%s', i, response.code)
    end
  end

  if error_count > 0 then
    task:insert_result('HTTP_KEEPALIVE_SEQ_ERRORS', 1.0, table.concat(errors, '; '))
  end
  task:insert_result('HTTP_KEEPALIVE_SEQ_SUCCESS', 1.0, tostring(success_count))
end

rspamd_config:register_symbol({
  name = 'HTTP_KEEPALIVE_SEQUENTIAL_TEST',
  score = 1.0,
  callback = test_keepalive_sequential,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 7: Stress test with early responses + keepalive
local function test_early_keepalive_stress(task)
  rspamd_logger.errx(task, 'test_early_keepalive_stress: starting')

  local results = {}

  -- Mix of normal and early-response requests
  local endpoints = {
    '/request',
    '/early-reply',
    '/request',
    '/keepalive-early',
    '/request',
  }

  for i, endpoint in ipairs(endpoints) do
    local body_parts = {}
    for j = 1, 100 do
      body_parts[j] = string.format("stress test line %d-%d\n", i, j)
    end

    local err, response = rspamd_http.request({
      url = 'http://127.0.0.1:18083' .. endpoint,
      task = task,
      method = 'post',
      body = table.concat(body_parts),
      timeout = 5,
      keepalive = true,
    })

    if err then
      results[#results + 1] = string.format('%s:err:%s', endpoint, err)
    else
      results[#results + 1] = string.format('%s:ok:%d', endpoint, response.code)
    end
  end

  task:insert_result('HTTP_EARLY_KEEPALIVE_STRESS', 1.0, table.concat(results, '|'))
end

rspamd_config:register_symbol({
  name = 'HTTP_EARLY_KEEPALIVE_STRESS_TEST',
  score = 1.0,
  callback = test_early_keepalive_stress,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 8: Aggressive immediate close with large body
-- This should trigger actual failures - server closes socket while client writes
local function test_immediate_close_large(task)
  rspamd_logger.errx(task, 'test_immediate_close_large: starting')

  -- Create a VERY large body that won't fit in socket buffer
  -- This forces the client to block on write, at which point server closes
  local body_parts = {}
  for i = 1, 10000 do  -- ~500KB body
    body_parts[i] = string.format("line %05d: this is padding data to make the body very large and exceed socket buffers\n", i)
  end
  local large_body = table.concat(body_parts)
  rspamd_logger.errx(task, 'test_immediate_close_large: body size = %d bytes', #large_body)

  local function callback(err, code, body)
    if err then
      rspamd_logger.errx(task, 'test_immediate_close_large callback error: %s', err)
      -- Error is EXPECTED here - we want to see how client handles it
      task:insert_result('HTTP_IMMEDIATE_CLOSE_ERROR', 1.0, err)
    else
      rspamd_logger.errx(task, 'test_immediate_close_large callback success: code=%s', code)
      -- Success means client received the 413 response despite server closing
      task:insert_result('HTTP_IMMEDIATE_CLOSE_' .. tostring(code), 1.0, body)
    end
  end

  rspamd_http.request({
    url = 'http://127.0.0.1:18083/immediate-close-413',
    task = task,
    method = 'post',
    body = large_body,
    callback = callback,
    timeout = 10,
  })
end

rspamd_config:register_symbol({
  name = 'HTTP_IMMEDIATE_CLOSE_TEST',
  score = 1.0,
  callback = test_immediate_close_large,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 9: Slow response with large body - tests race condition
local function test_slow_response_large(task)
  rspamd_logger.errx(task, 'test_slow_response_large: starting')

  local body_parts = {}
  for i = 1, 5000 do  -- ~250KB body
    body_parts[i] = string.format("slow test line %05d: padding data for the test\n", i)
  end
  local body = table.concat(body_parts)

  local err, response = rspamd_http.request({
    url = 'http://127.0.0.1:18083/slow-response-no-drain',
    task = task,
    method = 'post',
    body = body,
    timeout = 10,
  })

  if err then
    rspamd_logger.errx(task, 'test_slow_response_large error: %s', err)
    task:insert_result('HTTP_SLOW_RESPONSE_ERROR', 1.0, err)
  else
    rspamd_logger.errx(task, 'test_slow_response_large success: code=%s', response.code)
    task:insert_result('HTTP_SLOW_RESPONSE_' .. tostring(response.code), 1.0, response.content)
  end
end

rspamd_config:register_symbol({
  name = 'HTTP_SLOW_RESPONSE_TEST',
  score = 1.0,
  callback = test_slow_response_large,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 10: Multiple rapid requests to immediate-close endpoint
-- This stresses the connection handling and cleanup
local function test_rapid_close_requests(task)
  rspamd_logger.errx(task, 'test_rapid_close_requests: starting')

  local results = {}
  local body = string.rep("x", 10000)  -- 10KB body

  for i = 1, 5 do
    local err, response = rspamd_http.request({
      url = 'http://127.0.0.1:18083/immediate-close-413',
      task = task,
      method = 'post',
      body = body,
      timeout = 5,
    })

    if err then
      results[#results + 1] = string.format('req%d:err:%s', i, err)
    else
      results[#results + 1] = string.format('req%d:ok:%d', i, response.code)
    end
  end

  task:insert_result('HTTP_RAPID_CLOSE_RESULTS', 1.0, table.concat(results, '|'))
end

rspamd_config:register_symbol({
  name = 'HTTP_RAPID_CLOSE_TEST',
  score = 1.0,
  callback = test_rapid_close_requests,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 11: TRUE early response test with buffer-exceeding body
-- This test sends a body larger than socket buffers (~256KB+) to ensure
-- the client actually blocks on write while server sends response
local function test_block_and_reply(task)
  rspamd_logger.errx(task, 'test_block_and_reply: starting')

  -- Create body larger than socket buffers (256KB+ for localhost)
  -- macOS has 128KB send + 128KB receive buffers
  local body_size = 512 * 1024  -- 512KB should definitely exceed buffers
  local chunk = string.rep("X", 1024)  -- 1KB chunk
  local body_parts = {}
  for i = 1, body_size / 1024 do
    body_parts[i] = chunk
  end
  local huge_body = table.concat(body_parts)
  rspamd_logger.errx(task, 'test_block_and_reply: body size = %d bytes', #huge_body)

  local function callback(err, code, body)
    if err then
      rspamd_logger.errx(task, 'test_block_and_reply error: %s', err)
      task:insert_result('HTTP_BLOCK_REPLY_ERROR', 1.0, err)
    else
      rspamd_logger.errx(task, 'test_block_and_reply success: code=%s body=%s', code, body)
      -- This is the IDEAL outcome - we got the early 413 response!
      task:insert_result('HTTP_BLOCK_REPLY_' .. tostring(code), 1.0, body)
    end
  end

  rspamd_http.request({
    url = 'http://127.0.0.1:18083/block-and-reply',
    task = task,
    method = 'post',
    body = huge_body,
    callback = callback,
    timeout = 10,
  })
end

rspamd_config:register_symbol({
  name = 'HTTP_BLOCK_REPLY_TEST',
  score = 1.0,
  callback = test_block_and_reply,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 12: Coroutine version of block-and-reply
local function test_block_and_reply_coro(task)
  rspamd_logger.errx(task, 'test_block_and_reply_coro: starting')

  -- 512KB body
  local huge_body = string.rep("Y", 512 * 1024)

  local err, response = rspamd_http.request({
    url = 'http://127.0.0.1:18083/block-and-reply',
    task = task,
    method = 'post',
    body = huge_body,
    timeout = 10,
  })

  if err then
    rspamd_logger.errx(task, 'test_block_and_reply_coro error: %s', err)
    task:insert_result('HTTP_BLOCK_REPLY_CORO_ERROR', 1.0, err)
  else
    rspamd_logger.errx(task, 'test_block_and_reply_coro success: code=%s', response.code)
    task:insert_result('HTTP_BLOCK_REPLY_CORO_' .. tostring(response.code), 1.0, response.content)
  end
end

rspamd_config:register_symbol({
  name = 'HTTP_BLOCK_REPLY_CORO_TEST',
  score = 1.0,
  callback = test_block_and_reply_coro,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 13: Slow block test - server waits even longer
local function test_block_slow(task)
  rspamd_logger.errx(task, 'test_block_slow: starting')

  -- 1MB body to really fill things up
  local huge_body = string.rep("Z", 1024 * 1024)

  local err, response = rspamd_http.request({
    url = 'http://127.0.0.1:18083/block-and-reply-slow',
    task = task,
    method = 'post',
    body = huge_body,
    timeout = 15,  -- Longer timeout since server waits 1 second
  })

  if err then
    rspamd_logger.errx(task, 'test_block_slow error: %s', err)
    task:insert_result('HTTP_BLOCK_SLOW_ERROR', 1.0, err)
  else
    rspamd_logger.errx(task, 'test_block_slow success: code=%s', response.code)
    task:insert_result('HTTP_BLOCK_SLOW_' .. tostring(response.code), 1.0, response.content)
  end
end

rspamd_config:register_symbol({
  name = 'HTTP_BLOCK_SLOW_TEST',
  score = 1.0,
  callback = test_block_slow,
  no_squeeze = true,
  flags = 'coro'
})

-- Test 14: Instant reply - server responds BEFORE reading headers
-- This is the most aggressive early response test
local function test_instant_reply(task)
  rspamd_logger.errx(task, 'test_instant_reply: starting')

  -- 512KB body - server will respond before even reading our headers
  local huge_body = string.rep("Z", 512 * 1024)

  local err, response = rspamd_http.request({
    url = 'http://127.0.0.1:18083/instant-reply',
    task = task,
    method = 'post',
    body = huge_body,
    timeout = 10,
  })

  if err then
    rspamd_logger.errx(task, 'test_instant_reply error: %s', err)
    task:insert_result('HTTP_INSTANT_REPLY_ERROR', 1.0, err)
  else
    rspamd_logger.errx(task, 'test_instant_reply success: code=%s', response.code)
    task:insert_result('HTTP_INSTANT_REPLY_' .. tostring(response.code), 1.0, response.content)
  end
end

rspamd_config:register_symbol({
  name = 'HTTP_INSTANT_REPLY_TEST',
  score = 1.0,
  callback = test_instant_reply,
  no_squeeze = true,
  flags = 'coro'
})
