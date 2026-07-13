--[[[
-- Just a test for TCP API
--]]

local rspamd_tcp = require "rspamd_tcp"
local logger = require "rspamd_logger"
local tcp_sync = require "lua_tcp_sync"

-- dummy_http / dummy_https ports come from the test harness; rspamd_env
-- strips the RSPAMD_ prefix so PORT_DUMMY_HTTP/HTTPS carry the per-pabot
-- worker slot value. Default to the historical literals for ad-hoc runs.
local http_port = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTP) or 18080
local https_port = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTPS) or 18081

-- [[ old fashioned callback api ]]
local function http_simple_tcp_async_symbol(task)
  logger.errx(task, 'http_tcp_symbol: begin')
  local function http_get_cb(err, data, conn)
    logger.errx(task, 'http_get_cb: got reply: %s, error: %s, conn: %s', data, err, conn)
    task:insert_result('HTTP_ASYNC_RESPONSE_2', 1.0, data)
  end
  local function http_read_post_cb(err, conn)
    logger.errx(task, 'http_read_post_cb: write done: error: %s, conn: %s', err, conn)
    conn:add_read(http_get_cb)
  end
  local function http_read_cb(err, data, conn)
    logger.errx(task, 'http_read_cb: got reply: %s, error: %s, conn: %s', data, err, conn)
    conn:add_write(http_read_post_cb, string.format("POST /request2 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", http_port))
    task:insert_result('HTTP_ASYNC_RESPONSE', 1.0, data or err)
  end
  rspamd_tcp:request({
    task = task,
    callback = http_read_cb,
    host = '127.0.0.1',
    data = {string.format('GET /request HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: keep-alive\r\n\r\n', http_port)},
    read = true,
    port = http_port,
  })
end

local function http_simple_tcp_ssl_symbol(task)
  logger.errx(task, 'ssl_tcp_symbol: begin')
  local function ssl_get_cb(err, data, conn)
    logger.errx(task, 'ssl_get_cb: got reply: %s, error: %s, conn: %s', data, err, conn)
    task:insert_result('TCP_SSL_RESPONSE_2', 1.0, tostring(data):gsub('%s', ''))
  end
  local function ssl_read_post_cb(err, conn)
    logger.errx(task, 'ssl_read_post_cb: write done: error: %s, conn: %s', err, conn)
    conn:add_read(ssl_get_cb)
  end
  local function ssl_read_cb(err, data, conn)
    logger.errx(task, 'ssl_read_cb: got reply: %s, error: %s, conn: %s', data, err, conn)
    conn:add_write(ssl_read_post_cb, "test2\n")
    task:insert_result('TCP_SSL_RESPONSE', 1.0, tostring(data):gsub('%s', ''))
  end
  rspamd_tcp:request({
    task = task,
    callback = ssl_read_cb,
    host = '127.0.0.1',
    data = {'test\n'},
    read = true,
    ssl = true,
    ssl_noverify = true,
    port = https_port,
  })
end

local function http_large_tcp_ssl_symbol(task)
  local data = {}

  local function ssl_get_cb(err, rep, conn)
    logger.errx(task, 'ssl_get_cb: got reply: %s, error: %s, conn: %s', rep, err, conn)
    task:insert_result('TCP_SSL_LARGE_2', 1.0)
  end
  local function ssl_read_post_cb(err, conn)
    logger.errx(task, 'ssl_large_read_post_cb: write done: error: %s, conn: %s', err, conn)
    conn:add_read(ssl_get_cb)
  end
  local function ssl_read_cb(err, rep, conn)
    logger.errx(task, 'ssl_large_read_cb: got reply: %s, error: %s, conn: %s', rep, err, conn)
    conn:add_write(ssl_read_post_cb, 'foo\n')
    task:insert_result('TCP_SSL_LARGE', 1.0)
  end

  if task:get_queue_id() == 'SSL Large TCP request' then
    logger.errx(task, 'ssl_large_tcp_symbol: begin')
    for i = 1,2 do
      local st = {}
      for j=1,300000 do
        st[j] = 't'
      end
      data[i] = table.concat(st)
    end
    data[#data + 1] = '\n'

    rspamd_tcp:request({
      task = task,
      callback = ssl_read_cb,
      host = '127.0.0.1',
      data = data,
      read = true,
      ssl = true,
      stop_pattern = '\n',
      ssl_noverify = true,
      port = https_port,
      timeout = 20,
    })
  else
    logger.errx(task, 'ssl_large_tcp_symbol: skip')
  end
end

local function http_simple_tcp_symbol(task)
  logger.errx(task, 'connect_sync, before')

  local err
  local is_ok, connection = tcp_sync.connect {
    task = task,
    host = '127.0.0.1',
    timeout = 20,
    port = http_port,
  }

  if not is_ok then
    task:insert_result('HTTP_SYNC_WRITE_ERROR', 1.0, connection)
    logger.errx(task, 'write error: %1', connection)
  end

  logger.errx(task, 'connect_sync %1, %2', is_ok, tostring(connection))

  is_ok, err = connection:write(string.format('GET /request HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: keep-alive\r\n\r\n', http_port))

  logger.errx(task, 'write %1, %2', is_ok, err)
  if not is_ok then
    task:insert_result('HTTP_SYNC_WRITE_ERROR', 1.0, err)
    logger.errx(task, 'write error: %1', err)
  end

  local data
  local got_content = ''
  repeat
    is_ok, data = connection:read_once();
    logger.errx(task, 'read_once: is_ok: %1, data: %2', is_ok, data)
    if not is_ok then
      task:insert_result('HTTP_SYNC_ERROR', 1.0, data)
      return
    else
      got_content = got_content .. data
    end
    if got_content:find('hello') then
      -- dummy_http.py responds with either hello world or hello post
      break
    end
  until false

  task:insert_result('HTTP_SYNC_RESPONSE', 1.0, got_content)

  is_ok, err = connection:write(string.format("POST /request HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", http_port))
  logger.errx(task, 'write[2] %1, %2', is_ok, err)

  got_content = ''
  repeat
    is_ok, data = connection:read_once();
    logger.errx(task, 'read_once[2]: is_ok %1, data: %2', is_ok, data)
    if not is_ok then
      task:insert_result('HTTP_SYNC_ERROR_2', 1.0, data)
      return
    else
      got_content = got_content .. data
    end
    if got_content:find('hello') then
      break
    end
  until false

  task:insert_result('HTTP_SYNC_RESPONSE_2', 1.0, data)

  connection:close()
end

local function http_tcp_symbol(task)
  local url = tostring(task:get_request_header('url'))
  local method = tostring(task:get_request_header('method'))

  if url == 'nil' then
    return
  end

  local err
  local is_ok, connection = tcp_sync.connect {
    task = task,
    host = '127.0.0.1',
    timeout = 20,
    port = http_port,
  }

  logger.errx(task, 'connect_sync %1, %2', is_ok, tostring(connection))
  if not is_ok then
    logger.errx(task, 'connect error: %1', connection)
    return
  end

  is_ok, err = connection:write(string.format('%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n', method:upper(), url, http_port))

  logger.errx(task, 'write %1, %2', is_ok, err)
  if not is_ok then
    logger.errx(task, 'write error: %1', err)
    return
  end

  local content_length, content

  while true do
    local header_line
    is_ok, header_line = connection:read_until("\r\n")
    if not is_ok then
      logger.errx(task, 'failed to get header: %1', header_line)
      return
    end

    if header_line == "" then
      logger.errx(task, 'headers done')
      break
    end

    local value
    local header = header_line:gsub("([%w-]+): (.*)",
        function (h, v) value = v; return h:lower() end)

    logger.errx(task, 'parsed header: %1 -> "%2"', header, value)

    if header == "content-length" then
      content_length = tonumber(value)
    end

  end

  if content_length then
    is_ok, content = connection:read_bytes(content_length)
    if is_ok then
      task:insert_result('HTTP_SYNC_CONTENT_' .. method, 1.0, content)
    end
  else
    is_ok, content = connection:read_until_eof()
    if is_ok then
      task:insert_result('HTTP_SYNC_EOF_' .. method, 1.0, content)
    end
  end
  logger.errx(task, '(is_ok: %1) content [%2 bytes] %3', is_ok, content_length, content)
end

rspamd_config:register_symbol({
  name = 'SIMPLE_TCP_ASYNC_TEST',
  score = 1.0,
  callback = http_simple_tcp_async_symbol,
  no_squeeze = true
})
rspamd_config:register_symbol({
  name = 'SIMPLE_TCP_ASYNC_SSL_TEST',
  score = 1.0,
  callback = http_simple_tcp_ssl_symbol,
  no_squeeze = true
})
rspamd_config:register_symbol({
  name = 'LARGE_TCP_ASYNC_SSL_TEST',
  score = 1.0,
  callback = http_large_tcp_ssl_symbol,
  no_squeeze = true
})
rspamd_config:register_symbol({
  name = 'SIMPLE_TCP_TEST',
  score = 1.0,
  callback = http_simple_tcp_symbol,
  no_squeeze = true,
  flags = 'coro',
})

rspamd_config:register_symbol({
  name = 'HTTP_TCP_TEST',
  score = 1.0,
  callback = http_tcp_symbol,
  no_squeeze = true,
  flags = 'coro',
})

-- [[ Phased timeouts: connect_timeout / read_timeout / write_timeout opt the
--    request into per-phase budgets. Verify a normal request completes when
--    these are set instead of `timeout`. ]]
local function phased_timeout_symbol(task)
  local function read_cb(err, data, _)
    if err then
      task:insert_result('PHASED_TCP_ERROR', 1.0, tostring(err))
    else
      task:insert_result('PHASED_TCP_OK', 1.0, tostring(data))
    end
  end
  rspamd_tcp:request({
    task = task,
    callback = read_cb,
    host = '127.0.0.1',
    data = {string.format('GET /request HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n', http_port)},
    read = true,
    port = http_port,
    connect_timeout = 2.0,
    read_timeout = 2.0,
    write_timeout = 2.0,
  })
end

-- [[ on_error: connect to a closed port. The on_error callback must fire and
--    the regular `callback` must NOT receive the error (proving the queue-walk
--    fanout is suppressed in connect-phase). ]]
local function on_error_refused_symbol(task)
  local function regular_cb(err, _, _)
    -- This MUST NOT fire when on_error is registered and connect fails.
    task:insert_result('ON_ERROR_REGULAR_CB_FIRED', 1.0, tostring(err))
  end
  local function err_cb(err, _)
    task:insert_result('ON_ERROR_FIRED', 1.0, tostring(err))
  end
  rspamd_tcp:request({
    task = task,
    callback = regular_cb,
    on_error = err_cb,
    host = '127.0.0.1',
    port = 1,            -- closed port: connection refused
    read = false,
    connect_timeout = 1.0,
  })
end

-- [[ on_error post-CONNECTED: connect succeeds (real HTTP server), then the
--    read times out. on_error must NOT fire; the read callback receives the
--    error as before. ]]
local function on_error_post_connect_symbol(task)
  local function read_cb(err, _, _)
    if err then
      task:insert_result('POST_CONNECT_READ_TIMEOUT', 1.0, tostring(err))
    else
      task:insert_result('POST_CONNECT_READ_OK', 1.0)
    end
  end
  local function err_cb(err, _)
    -- This MUST NOT fire because the error happens after CONNECTED is set.
    task:insert_result('POST_CONNECT_ON_ERROR_FIRED', 1.0, tostring(err))
  end
  rspamd_tcp:request({
    task = task,
    callback = read_cb,
    on_error = err_cb,
    host = '127.0.0.1',
    port = http_port,
    -- /timeout sleeps 4s before responding. read_timeout=0.5 forces the read
    -- side to time out after the connect succeeds.
    data = {string.format('GET /timeout HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n', http_port)},
    read = true,
    stop_pattern = '\r\n\r\n',
    connect_timeout = 2.0,
    read_timeout = 0.5,
    write_timeout = 2.0,
  })
end

rspamd_config:register_symbol({
  name = 'PHASED_TIMEOUT_TEST',
  score = 1.0,
  callback = phased_timeout_symbol,
  no_squeeze = true,
})
rspamd_config:register_symbol({
  name = 'ON_ERROR_REFUSED_TEST',
  score = 1.0,
  callback = on_error_refused_symbol,
  no_squeeze = true,
})
rspamd_config:register_symbol({
  name = 'ON_ERROR_POST_CONNECT_TEST',
  score = 1.0,
  callback = on_error_post_connect_symbol,
  no_squeeze = true,
})
-- ]]
