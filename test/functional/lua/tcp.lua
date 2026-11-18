--[[[
-- Just a test for TCP API
--]]

local rspamd_tcp = require "rspamd_tcp"
local logger = require "rspamd_logger"
local tcp_sync = require "lua_tcp_sync"
local rspamd_util = require "rspamd_util"

-- dummy_http / dummy_https ports come from the test harness; rspamd_env
-- strips the RSPAMD_ prefix so PORT_DUMMY_HTTP/HTTPS carry the per-pabot
-- worker slot value. Default to the historical literals for ad-hoc runs.
local http_port = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTP) or 18080
local https_port = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTPS) or 18081
-- dummy_ssl.py: TLS and STARTTLS server (the one on https_port is dummy_tcp_reset.py)
local ssl_port = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_SSL) or 14433
local unpack_fn = table.unpack or unpack

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
    task:insert_result('TCP_SSL_RESPONSE_2', 1.0, (tostring(data):gsub('%s', '')))
  end
  local function ssl_read_post_cb(err, conn)
    logger.errx(task, 'ssl_read_post_cb: write done: error: %s, conn: %s', err, conn)
    conn:add_read(ssl_get_cb)
  end
  local function ssl_read_cb(err, data, conn)
    logger.errx(task, 'ssl_read_cb: got reply: %s, error: %s, conn: %s', data, err, conn)
    conn:add_write(ssl_read_post_cb, "test2\n")
    task:insert_result('TCP_SSL_RESPONSE', 1.0, (tostring(data):gsub('%s', '')))
  end
  rspamd_tcp:request({
    task = task,
    callback = ssl_read_cb,
    host = '127.0.0.1',
    data = {'test\n'},
    read = true,
    ssl = true,
    ssl_noverify = true,
    port = ssl_port,
  })
end

local function http_large_tcp_ssl_symbol(task)
  local data = {}

  -- a 600 KB TLS upload: only the test that needs it runs it
  if task:get_queue_id() ~= 'SSL Large TCP request' then
    return
  end

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
    port = ssl_port,
    timeout = 20,
  })
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


local function get_request(close)
  return string.format('GET /request HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s\r\n',
      http_port, close and 'Connection: close\r\n' or '')
end

-- [[ Empty write handlers (string, {''} and {}) complete like any finished write,
--    and data of a wrong type is rejected instead of being queued. ]]
local function empty_write_symbol(task)
  local done = 0

  local function read_cb(_, data, _)
    task:insert_result('TCP_EMPTY_WRITE', 1.0, string.format('writes=%d', done), tostring(data))
  end
  local function w3(_, conn)
    done = done + 1
    conn:add_read(read_cb, '\r\n')
  end
  local function w2(_, conn)
    done = done + 1
    conn:add_write(w3, {})
  end
  local function w1(_, conn)
    done = done + 1
    conn:add_write(w2, { '' })
  end
  local function w0(_, conn)
    done = done + 1
    local rejected = {}
    rejected[1] = tostring(conn:add_write(nil, nil))
    rejected[2] = tostring(conn:add_write(function() end, 42))
    rejected[3] = tostring(conn:add_write(function() end, true))
    rejected[4] = tostring(conn:add_write(function() end))
    task:insert_result('TCP_WRITE_INVALID', 1.0, table.concat(rejected, ','))
    conn:add_write(w1, '')
  end

  rspamd_tcp.request({
    task = task,
    callback = w0,
    host = '127.0.0.1',
    port = http_port,
    data = get_request(true),
    read = false,
    timeout = 5,
  })
end

-- [[ Fatal error: a callback that always queues one more handler must not keep
--    the fan-out going, and the handler it adds must not be called. ]]
local function fatal_readd_symbol(task)
  local calls = 0
  local function cb(_, _, conn)
    calls = calls + 1
    task:insert_result('TCP_FATAL_READD', 1.0, 'call' .. calls)
    if calls < 5 and conn then
      conn:add_read(cb)
    end
  end
  rspamd_tcp.request({
    task = task,
    callback = cb,
    host = '127.0.0.1',
    port = 1, -- closed port
    data = 'x',
    read = true,
    timeout = 3,
  })
end

-- [[ shift_callback() inside a callback must not drop the handler that follows ]]
local function shift_callback_symbol(task)
  local got = {}

  local function r3(_, data, _)
    got[3] = tostring(data)
    task:insert_result('TCP_SHIFT_CB', 1.0, 'r1=' .. tostring(got[1]),
        'ran=' .. #got, 'distinct=' .. tostring(got[1] ~= got[2] and got[2] ~= got[3]))
  end
  local function r2(_, data, _)
    got[2] = tostring(data)
  end
  local function r1(_, data, conn)
    got[1] = tostring(data)
    conn:add_read(r2, '\r\n')
    conn:add_read(r3, '\r\n')
    conn:shift_callback()
  end

  rspamd_tcp.request({
    task = task,
    callback = r1,
    host = '127.0.0.1',
    port = http_port,
    data = get_request(true),
    read = true,
    stop_pattern = '\r\n',
    timeout = 5,
  })
end

-- [[ conn:close() in a callback: queued handlers are never called afterwards ]]
local function close_in_callback_symbol(task)
  local function r1(_, _, conn)
    task:insert_result('TCP_CLOSE_IN_CB', 1.0, 'r1')
    conn:add_read(function()
      task:insert_result('TCP_CLOSE_EXTRA', 1.0, 'read')
    end, '\r\n')
    conn:add_write(function()
      task:insert_result('TCP_CLOSE_EXTRA', 1.0, 'write')
    end, 'x')
    conn:close()
  end

  rspamd_tcp.request({
    task = task,
    callback = r1,
    host = '127.0.0.1',
    port = http_port,
    data = get_request(true),
    read = true,
    stop_pattern = '\r\n',
    timeout = 5,
  })
end

-- [[ Sync API: invalid and empty writes, read_until followed by two read_once, closed handle ]]
local function sync_misc_symbol(task)
  local is_ok, conn = tcp_sync.connect {
    task = task,
    host = '127.0.0.1',
    port = http_port,
    timeout = 5,
  }

  if not is_ok then
    task:insert_result('TCP_SYNC_MISC_CONNECT_ERROR', 1.0, tostring(conn))
    return
  end

  local rejected = 0
  if not pcall(conn.write, conn, nil) then rejected = rejected + 1 end
  if not pcall(conn.write, conn, 42) then rejected = rejected + 1 end
  if not pcall(conn.write, conn, true) then rejected = rejected + 1 end
  if not pcall(conn.write, conn) then rejected = rejected + 1 end

  local e1 = conn:write('')
  local e2 = conn:write({})
  local e3 = conn:write({ '' })

  local wok = conn:write(get_request(true))
  local line_ok, line = conn:read_until('\r\n')
  -- the rest of the first chunk is buffered by lua_tcp_sync
  local left_ok, left = conn:read_once()
  -- must not fail on the buffer that has just been consumed
  conn:read_once()

  conn:close()
  local cw_ok, cw_err = conn:write('x')
  local cr_ok, cr_err = conn:read_once()

  task:insert_result('TCP_SYNC_MISC', 1.0,
      'rejected=' .. rejected,
      string.format('empty=%s,%s,%s', tostring(e1), tostring(e2), tostring(e3)),
      'write=' .. tostring(wok),
      'line=' .. tostring(line_ok) .. ':' .. tostring(line),
      'leftover=' .. tostring(left_ok) .. ':' .. tostring(#tostring(left) > 0),
      'closed_write=' .. tostring(cw_ok) .. ':' .. tostring(cw_err),
      'closed_read=' .. tostring(cr_ok) .. ':' .. tostring(cr_err))
end

-- [[ Sync API: the connection is created by one coroutine and used by another ]]
local xthread_conn
local function sync_xthread_a_symbol(task)
  local is_ok, conn = tcp_sync.connect {
    task = task,
    host = '127.0.0.1',
    port = http_port,
    timeout = 5,
  }
  if is_ok then
    xthread_conn = conn
  else
    xthread_conn = nil
    task:insert_result('TCP_SYNC_XTHREAD_ERROR', 1.0, tostring(conn))
  end
end
local function sync_xthread_b_symbol(task)
  local conn = xthread_conn
  if not conn then
    return
  end
  local w_ok = conn:write(get_request(true))
  local r_ok, line = conn:read_until('\r\n')
  task:insert_result('TCP_SYNC_XTHREAD', 1.0, tostring(w_ok) .. ':' .. tostring(r_ok), tostring(line))
  conn:close()
  xthread_conn = nil
end

-- [[ Sync API: connect to a closed port fails cleanly (and leaks nothing) ]]
local function sync_refused_symbol(task)
  local res = {}
  for i = 1, 3 do
    local is_ok, err = tcp_sync.connect {
      task = task,
      host = '127.0.0.1',
      port = 1,
      timeout = 3,
    }
    res[i] = i .. ':' .. tostring(is_ok) .. ':' .. tostring(err)
  end
  task:insert_result('TCP_SYNC_REFUSED', 1.0, unpack_fn(res))
end

-- [[ Sync API: a reset connection is an error, not a clean end of data ]]
local function sync_reset_symbol(task)
  local is_ok, conn = tcp_sync.connect {
    task = task,
    host = '127.0.0.1',
    port = https_port, -- dummy_tcp_reset.py
    timeout = 5,
  }
  if not is_ok then
    task:insert_result('TCP_SYNC_RESET_ERROR', 1.0, tostring(conn))
    return
  end
  conn:write('x\n')
  local r_ok, data = conn:read_until_eof()
  task:insert_result('TCP_SYNC_RESET', 1.0, 'ok=' .. tostring(r_ok),
      'eof=' .. tostring(conn:eof()), tostring(r_ok and 'data' or data))
  conn:close()
end

-- [[ TLS: a response of 16300 bytes arrives in ONE TLS record, 8192 of them are read at
--    once, the rest stays decrypted inside OpenSSL while the server keeps the connection
--    open and silent. The reader must drain it (a second, bigger response goes in several records). ]]
local function tls_big_symbol(task)
  local got = {}

  local function r2(err, data, conn)
    got[2] = err and ('err:' .. tostring(err)) or tostring(#data)
    task:insert_result('TCP_TLS_BIG', 1.0, 'r1=' .. tostring(got[1]), 'r2=' .. tostring(got[2]))
    conn:close()
  end
  local function w2(_, conn)
    conn:add_read(r2, '\n')
  end
  local function r1(err, data, conn)
    got[1] = err and ('err:' .. tostring(err)) or tostring(#data)
    if err then
      task:insert_result('TCP_TLS_BIG', 1.0, 'r1=' .. got[1])
      conn:close()
      return
    end
    conn:add_write(w2, 'BIG 100000\n')
  end

  rspamd_tcp.request({
    task = task,
    callback = r1,
    host = '127.0.0.1',
    port = ssl_port,
    data = 'BIG 16300\n',
    read = true,
    ssl = true,
    ssl_noverify = true,
    stop_pattern = '\n',
    timeout = 4,
  })
end

-- [[ TLS: the peer accepts and never answers; the error callback closes the connection ]]
local function tls_silent_symbol(task)
  local function cb(err, _, conn)
    task:insert_result('TCP_TLS_SILENT', 1.0, tostring(err))
    conn:close()
  end

  rspamd_tcp.request({
    task = task,
    callback = cb,
    host = '127.0.0.1',
    port = ssl_port,
    data = 'SILENT\n',
    read = true,
    ssl = true,
    ssl_noverify = true,
    timeout = 1,
  })
end

-- [[ TLS to a plaintext port: the handshake fails, on_error closes the connection ]]
local function tls_handshake_fail_symbol(task)
  rspamd_tcp.request({
    task = task,
    callback = function()
      task:insert_result('TCP_TLS_HS_REGULAR_CB', 1.0)
    end,
    on_error = function(err, conn)
      task:insert_result('TCP_TLS_HS_ERROR', 1.0, tostring(err):match('^ssl error') or tostring(err))
      conn:close()
    end,
    host = '127.0.0.1',
    port = http_port,
    data = 'x',
    read = true,
    ssl = true,
    ssl_noverify = true,
    timeout = 3,
  })
end

-- [[ TLS: a request with nothing queued, with on_connect only, and with no handler at all ]]
local function tls_empty_symbol(task)
  -- nothing is queued: the connection finishes by itself after the handshake
  rspamd_tcp.request({
    task = task,
    callback = function() end,
    host = '127.0.0.1',
    port = ssl_port,
    read = false,
    ssl = true,
    ssl_noverify = true,
    timeout = 3,
  })
  -- on_connect is called over TLS as well, and may queue handlers
  rspamd_tcp.request({
    task = task,
    callback = function() end,
    on_connect = function(conn)
      task:insert_result('TCP_TLS_CONNECTED', 1.0)
      conn:add_write(function(_, c)
        c:add_read(function(err, data)
          task:insert_result('TCP_TLS_EMPTY', 1.0, tostring(err), (tostring(data):gsub('%s', '')))
        end)
      end, 'test\n')
    end,
    host = '127.0.0.1',
    port = ssl_port,
    read = false,
    ssl = true,
    ssl_noverify = true,
    timeout = 3,
  })
end

-- [[ STARTTLS ]]
local function starttls_request(task, command, ready_cb)
  rspamd_tcp.request({
    task = task,
    callback = ready_cb,
    host = '127.0.0.1',
    port = ssl_port,
    data = command,
    read = true,
    stop_pattern = '\r\n',
    timeout = 4,
  })
end

-- refused when plaintext is buffered: the peer has sent more than the ready line
local function starttls_inject_symbol(task)
  starttls_request(task, 'STARTTLS-INJECT\r\n', function(err, data, conn)
    if err then
      task:insert_result('TCP_STARTTLS_INJECT', 1.0, 'err:' .. tostring(err))
      return
    end
    local ready = tostring(data)
    local ok, msg = pcall(conn.starttls, conn, true)
    -- no TLS was started and the plaintext is still delivered, as plaintext
    conn:add_read(function(err2, data2, conn2)
      task:insert_result('TCP_STARTTLS_INJECT', 1.0, 'ready=' .. ready,
          'refused=' .. tostring(not ok), (tostring(msg):match('^starttls refused') or tostring(msg)),
          'plain=' .. tostring(err2 or data2))
      conn2:close()
    end, '\r\n')
  end)
end

-- starttls followed by add_read and by a write+read; the peer sends a greeting after the handshake
local function starttls_ok_symbol(task)
  starttls_request(task, 'STARTTLS-GREET\r\n', function(err, data, conn)
    if err then
      task:insert_result('TCP_STARTTLS', 1.0, 'err:' .. tostring(err))
      return
    end
    local res = { 'ready=' .. tostring(data) }
    conn:starttls(true)
    conn:add_read(function(err2, data2, conn2)
      res[#res + 1] = 'greeting=' .. tostring(err2 or (tostring(data2)))
      conn2:add_write(function(_, conn3)
        conn3:add_read(function(err4, data4, conn4)
          res[#res + 1] = 'reply=' .. tostring(err4 or tostring(data4))
          task:insert_result('TCP_STARTTLS', 1.0, unpack_fn(res))
          conn4:close()
        end, '\n')
      end, 'test\n')
    end, '\n')
  end)
end

-- starttls() verifies the peer by default: a self signed certificate is an error
local function starttls_verify_symbol(task)
  starttls_request(task, 'STARTTLS\r\n', function(err, _, conn)
    if err then
      task:insert_result('TCP_STARTTLS_VERIFY', 1.0, 'err:' .. tostring(err))
      return
    end
    -- Whether the verification fails while the handshake is being started or
    -- later on, the error comes to the next handler
    conn:starttls()
    conn:add_read(function(err2, _, conn2)
      task:insert_result('TCP_STARTTLS_VERIFY', 1.0, (tostring(err2):match('^ssl error') or tostring(err2)))
      conn2:close()
    end, '\n')
  end)
end

-- [[ The handshake fails inside of starttls() itself: the peer's (bad) reply is
--    already there when the handshake is started. The result tells it and the
--    handler added afterwards gets the same error, as if it had failed later ]]
local starttls_sync_fail_id = 'starttls reports a failure found at once to the next handler'

local function starttls_sync_fail_symbol(task)
  if task:get_queue_id() ~= starttls_sync_fail_id then
    return
  end
  starttls_request(task, 'STARTTLS-GARBAGE\r\n', function(err, _, conn)
    if err then
      task:insert_result('TCP_STARTTLS_SYNC_FAIL', 1.0, 'err:' .. tostring(err))
      return
    end
    -- Let the garbage arrive (the peer sends it 0.1s after the ready line)
    local deadline = rspamd_util.get_time() + 0.4
    while rspamd_util.get_time() < deadline do
      -- busy wait: the event loop must not run here
    end
    local started, start_err = conn:starttls(true)
    conn:add_read(function(err2, _, _)
      task:insert_result('TCP_STARTTLS_SYNC_FAIL', 1.0,
          'started=' .. tostring(started),
          'result=' .. (tostring(start_err):match('^ssl error') or tostring(start_err)),
          'handler=' .. (tostring(err2):match('^ssl error') or tostring(err2)))
    end, '\n')
  end)
end

-- [[ A handle kept by Lua code outlives its connection: methods fail cleanly ]]
local function dead_handle_symbol(task)
  local kept

  rspamd_tcp.request({
    task = task,
    callback = function(_, _, conn)
      kept = conn
      -- when the callback has returned the connection is finished and destroyed
      task:add_timer(0.3, function()
        local res = {}
        res[1] = 'close=' .. tostring(pcall(kept.close, kept))
        local ok, err = kept:add_read(function() end)
        res[2] = 'add_read=' .. tostring(ok) .. ':' .. tostring(err)
        ok, err = kept:add_write(function() end, 'x')
        res[3] = 'add_write=' .. tostring(ok) .. ':' .. tostring(err)
        ok, err = pcall(kept.shift_callback, kept)
        res[4] = 'shift=' .. tostring(ok) .. ':' .. tostring(err)
        ok, err = pcall(kept.starttls, kept)
        res[5] = 'starttls=' .. tostring(ok) .. ':' .. tostring(err)
        task:insert_result('TCP_DEAD_HANDLE', 1.0, unpack_fn(res))
      end)
    end,
    host = '127.0.0.1',
    port = http_port,
    data = get_request(true),
    read = true,
    stop_pattern = '\r\n',
    timeout = 5,
  })
end

-- [[ After conn:close() in a callback the connection is finished: new handlers are refused ]]
local function close_then_add_symbol(task)
  rspamd_tcp.request({
    task = task,
    callback = function(_, _, conn)
      conn:close()
      local ok1, err1 = conn:add_read(function()
        task:insert_result('TCP_CLOSE_THEN_ADD_LATE', 1.0)
      end)
      local ok2, err2 = conn:add_write(function()
        task:insert_result('TCP_CLOSE_THEN_ADD_LATE', 1.0)
      end, 'x')
      task:insert_result('TCP_CLOSE_THEN_ADD', 1.0, 'add_read=' .. tostring(ok1) .. ':' .. tostring(err1),
          'add_write=' .. tostring(ok2) .. ':' .. tostring(err2))
    end,
    host = '127.0.0.1',
    port = http_port,
    data = get_request(true),
    read = true,
    stop_pattern = '\r\n',
    timeout = 5,
  })
end

-- [[ conn:close() from outside the callbacks of the connection (a timer) finishes it at once ]]
local function close_outside_symbol(task)
  rspamd_tcp.request({
    task = task,
    callback = function()
      -- must never be called: the connection is closed while waiting for the reply
      task:insert_result('TCP_CLOSE_OUTSIDE_LATE', 1.0)
    end,
    on_connect = function(conn)
      task:add_timer(0.3, function()
        conn:close()
        -- the connection is gone right now, not when the task ends: the handle is dead
        local ok, err = pcall(conn.shift_callback, conn)
        local ok2, err2 = conn:add_read(function() end)
        task:insert_result('TCP_CLOSE_OUTSIDE', 1.0, 'shift=' .. tostring(ok) .. ':' .. tostring(err),
            'add_read=' .. tostring(ok2) .. ':' .. tostring(err2))
      end)
    end,
    host = '127.0.0.1',
    port = http_port,
    -- /timeout answers after 4 seconds
    data = string.format('GET /timeout HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n', http_port),
    read = true,
    stop_pattern = '\r\n',
    timeout = 20,
  })
end

-- [[ connect_sync does not implement TLS: asking for it is an error, not plaintext ]]
local function sync_ssl_symbol(task)
  local ok, err = pcall(rspamd_tcp.connect_sync, {
    task = task,
    host = '127.0.0.1',
    port = http_port,
    ssl = true,
  })
  task:insert_result('TCP_SYNC_SSL', 1.0, 'ok=' .. tostring(ok),
      'tls_error=' .. tostring(tostring(err):find('does not support TLS', 1, true) ~= nil))
end

-- [[ Sync API: the task is destroyed (task_timeout) while read_once() is pending: the
--    suspended coroutine is terminated, nothing is resumed and nothing is left behind.
--    The peer (dummy_ssl.py, plaintext) never answers. ]]
local sync_pending_queue_id = 'Sync API operation pending when the task is destroyed'
local function sync_pending_symbol(task)
  -- this one holds the task until task_timeout: only the test that needs it runs it
  if task:get_queue_id() ~= sync_pending_queue_id then
    return
  end
  local is_ok, conn = rspamd_tcp.connect_sync {
    task = task,
    host = '127.0.0.1',
    port = ssl_port,
    timeout = 60,
  }
  if not is_ok then
    task:insert_result('TCP_SYNC_PENDING_ERROR', 1.0, tostring(conn))
    return
  end
  local r_ok, data = conn:read_once()
  -- never reached: the task is gone
  task:insert_result('TCP_SYNC_PENDING_RESUMED', 1.0, tostring(r_ok), tostring(data))
end

local function sync_pending_alive_symbol(task)
  if task:get_queue_id() ~= sync_pending_queue_id then
    return
  end
  task:insert_result('TCP_SYNC_PENDING_ALIVE', 1.0)
end

-- [[ Sync API: the handle is dropped and collected while the operation that
--    resumes the coroutine is still running (it holds the connection): the
--    connection must be destroyed by the last reference, not by the collector ]]
local function sync_gc_symbol(task)
  -- every symbol of this file runs in every scan: only the test that needs it runs it
  if task:get_queue_id() ~= 'Sync API handle dropped and collected while its operation resumes the coroutine' then
    return
  end
  local ok, conn = rspamd_tcp.connect_sync {
    task = task,
    host = '127.0.0.1',
    port = ssl_port,
    timeout = 5,
  }
  if not ok then
    task:insert_result('TCP_SYNC_GC_ERROR', 1.0, tostring(conn))
    return
  end
  conn = nil
  collectgarbage()
  collectgarbage()

  local ok2, conn2 = rspamd_tcp.connect_sync {
    task = task,
    host = '127.0.0.1',
    port = http_port,
    timeout = 5,
  }
  if not ok2 then
    task:insert_result('TCP_SYNC_GC_ERROR', 1.0, tostring(conn2))
    return
  end
  local w_ok = conn2:write(get_request(true))
  local r_ok, data = conn2:read_once()
  conn2 = nil
  collectgarbage()
  collectgarbage()
  task:insert_result('TCP_SYNC_GC', 1.0, 'write=' .. tostring(w_ok),
      'read=' .. tostring(r_ok) .. ':' .. tostring(#tostring(data) > 0))
end

-- [[ A text that is sent is not taken over from Lua: it stays usable after a
--    request rejected for bad data, and cannot be freed under a pending write ]]
local rspamd_text = require "rspamd_text"

local function text_baddata_symbol(task)
  if task:get_queue_id() ~= 'A text with bad data stays valid and a sent text outlives its Lua variable' then
    return
  end
  local t = rspamd_text.fromstring('owned text')
  local ret = rspamd_tcp.request({
    task = task,
    callback = function() end,
    host = '127.0.0.1',
    port = http_port,
    data = { t, 42 },
  })
  collectgarbage()
  -- a userdata that is not a text is a bad argument, not a Lua error
  local pok, ret2 = pcall(rspamd_tcp.request, {
    task = task,
    callback = function() end,
    host = '127.0.0.1',
    port = http_port,
    data = { 'abc', task },
  })
  local t2 = rspamd_text.fromstring('second')
  local pok3, ret3 = pcall(rspamd_tcp.request, {
    task = task,
    callback = function() end,
    host = '127.0.0.1',
    port = http_port,
    data = t2,
    read = false,
  })
  collectgarbage()
  task:insert_result('TCP_TEXT_BADDATA', 1.0, 'ret=' .. tostring(ret),
      'text=' .. t:str(), 'foreign=' .. tostring(pok) .. ':' .. tostring(ret2),
      'single=' .. tostring(pok3) .. ':' .. tostring(ret3) .. ':' .. t2:str())
end

local function text_dropped_symbol(task)
  if task:get_queue_id() ~= 'TCP write of a text whose Lua variable is dropped and collected' then
    return
  end
  local function cb(err, data, _)
    task:insert_result('TCP_TEXT_DROPPED', 1.0, 'err=' .. tostring(err),
        'status=' .. tostring(tostring(data):match('^HTTP/1%.1 (%d+)')))
  end
  local t = rspamd_text.fromstring(get_request(true))
  rspamd_tcp.request({
    task = task,
    callback = cb,
    host = '127.0.0.1',
    port = http_port,
    data = { t },
  })
  -- the write has not happened yet: the owner is gone and the collector runs
  t = nil
  collectgarbage()
  collectgarbage()
end

-- [[ Requests with bad parameters fail cleanly (checked when the worker loads).
--    Leaks of such requests are visible to LeakSanitizer in the worker. ]]
local onload_res = {}
rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if not worker:is_scanner() then
    return
  end

  local function noop() end
  local function try(name, args)
    local pok, res = pcall(rspamd_tcp.request, args)
    if pok then
      onload_res[#onload_res + 1] = name .. '=returned:' .. tostring(res)
    else
      onload_res[#onload_res + 1] = name .. '=error:' .. tostring(res)
    end
  end

  -- neither task nor config
  try('noconfig', { ev_base = ev_base, host = '127.0.0.1', port = http_port,
                    callback = noop, stop_pattern = 'x', data = 'abc', on_error = noop })
  try('badport', { ev_base = ev_base, config = cfg, host = '127.0.0.1', port = 70000,
                   callback = noop, stop_pattern = 'x', data = 'abc', on_error = noop })
  try('negport', { ev_base = ev_base, config = cfg, host = '127.0.0.1', port = -1,
                   callback = noop })
  -- a data element of a wrong type
  try('baddata', { ev_base = ev_base, config = cfg, host = '127.0.0.1', port = http_port,
                   callback = noop, stop_pattern = 'x', data = { 'abc', 42 },
                   on_connect = noop, on_error = noop })
  -- nothing is read: the callback and the pattern are never used, empty data
  try('noread', { ev_base = ev_base, config = cfg, host = '127.0.0.1', port = 1,
                  callback = noop, stop_pattern = 'x', data = '', read = false,
                  on_error = noop })
  try('emptytable', { ev_base = ev_base, config = cfg, host = '127.0.0.1', port = 1,
                      callback = noop, data = {}, read = false, on_error = noop })
end)

local function onload_symbol(task)
  task:insert_result('TCP_ONLOAD', 1.0, unpack_fn(onload_res))
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

local function reg(name, cb, coro)
  rspamd_config:register_symbol({
    name = name,
    score = 1.0,
    callback = cb,
    no_squeeze = true,
    flags = coro and 'coro' or nil,
  })
end

reg('TCP_EMPTY_WRITE_TEST', empty_write_symbol)
reg('TCP_FATAL_READD_TEST', fatal_readd_symbol)
reg('TCP_SHIFT_CB_TEST', shift_callback_symbol)
reg('TCP_CLOSE_IN_CB_TEST', close_in_callback_symbol)
reg('TCP_SYNC_MISC_TEST', sync_misc_symbol, true)
reg('TCP_SYNC_XTHREAD_A_TEST', sync_xthread_a_symbol, true)
reg('TCP_SYNC_XTHREAD_B_TEST', sync_xthread_b_symbol, true)
rspamd_config:register_dependency('TCP_SYNC_XTHREAD_B_TEST', 'TCP_SYNC_XTHREAD_A_TEST')
reg('TCP_SYNC_REFUSED_TEST', sync_refused_symbol, true)
reg('TCP_SYNC_RESET_TEST', sync_reset_symbol, true)
reg('TCP_ONLOAD_TEST', onload_symbol)
reg('TCP_TLS_BIG_TEST', tls_big_symbol)
reg('TCP_TLS_SILENT_TEST', tls_silent_symbol)
reg('TCP_TLS_HS_FAIL_TEST', tls_handshake_fail_symbol)
reg('TCP_TLS_EMPTY_TEST', tls_empty_symbol)
reg('TCP_STARTTLS_INJECT_TEST', starttls_inject_symbol)
reg('TCP_STARTTLS_TEST', starttls_ok_symbol)
reg('TCP_STARTTLS_VERIFY_TEST', starttls_verify_symbol)
reg('TCP_STARTTLS_SYNC_FAIL_TEST', starttls_sync_fail_symbol)
reg('TCP_DEAD_HANDLE_TEST', dead_handle_symbol)
reg('TCP_CLOSE_OUTSIDE_TEST', close_outside_symbol)
reg('TCP_CLOSE_THEN_ADD_TEST', close_then_add_symbol)
reg('TCP_SYNC_SSL_TEST', sync_ssl_symbol, true)
reg('TCP_SYNC_PENDING_TEST', sync_pending_symbol, true)
reg('TCP_SYNC_PENDING_ALIVE_TEST', sync_pending_alive_symbol)
reg('TCP_SYNC_GC_TEST', sync_gc_symbol, true)
reg('TCP_TEXT_BADDATA_TEST', text_baddata_symbol)
reg('TCP_TEXT_DROPPED_TEST', text_dropped_symbol)

-- [[ Sync API: the handle is dropped without close() and the operation releases the
--    connection while a postfilter (or a dependent symbol) collects garbage: the
--    collector must not free the connection that the releasing code still uses ]]
local sync_unclosed_post_id = 'Sync API unclosed handle collected by a postfilter'
local sync_unclosed_dep_id = 'Sync API unclosed handle collected by a dependent symbol'

local function sync_unclosed_symbol(name, host, queue_id)
  return function(task)
    if task:get_queue_id() ~= queue_id then
      return
    end
    local ok, conn = rspamd_tcp.connect_sync {
      task = task,
      host = host,
      port = http_port,
      timeout = 5,
    }
    if not ok then
      task:insert_result(name .. '_ERROR', 1.0, tostring(conn))
      return
    end
    conn:write(get_request(true))
    local r_ok = conn:read_once()
    task:insert_result(name .. '_DONE', 1.0, tostring(r_ok))
  end
end

local function gc_symbol(name, queue_id)
  return function(task)
    if task:get_queue_id() ~= queue_id then
      return
    end
    collectgarbage()
    collectgarbage()
    task:insert_result(name, 1.0)
  end
end

rspamd_config:register_symbol({
  name = 'TCP_SYNC_UNCLOSED_POST_TEST',
  score = 1.0,
  callback = sync_unclosed_symbol('TCP_SYNC_UNCLOSED_POST', '127.0.0.1', sync_unclosed_post_id),
  no_squeeze = true,
  flags = 'coro',
})
rspamd_config:register_symbol({
  name = 'TCP_SYNC_UNCLOSED_POST_GC_TEST',
  type = 'postfilter',
  score = 0,
  callback = gc_symbol('TCP_SYNC_UNCLOSED_POST_GC', sync_unclosed_post_id),
})
rspamd_config:register_symbol({
  name = 'TCP_SYNC_UNCLOSED_DEP_TEST',
  score = 1.0,
  callback = sync_unclosed_symbol('TCP_SYNC_UNCLOSED_DEP', 'site.resolveme', sync_unclosed_dep_id),
  no_squeeze = true,
  flags = 'coro',
})
rspamd_config:register_symbol({
  name = 'TCP_SYNC_UNCLOSED_DEP_GC_TEST',
  score = 0,
  callback = gc_symbol('TCP_SYNC_UNCLOSED_DEP_GC', sync_unclosed_dep_id),
})
rspamd_config:register_dependency('TCP_SYNC_UNCLOSED_DEP_GC_TEST', 'TCP_SYNC_UNCLOSED_DEP_TEST')

-- [[ Sync API: every operation gets its own timeout ]]
local sync_timeout_id = 'Sync API operations have their own timeout'
local function sync_timeout_symbol(task)
  if task:get_queue_id() ~= sync_timeout_id then
    return
  end
  local ok, conn = rspamd_tcp.connect_sync {
    task = task,
    host = '127.0.0.1',
    port = ssl_port,
    timeout = 1,
  }
  if not ok then
    task:insert_result('TCP_SYNC_TIMEOUT_ERROR', 1.0, tostring(conn))
    return
  end
  local t0 = rspamd_util.get_time()
  local r1_ok, r1_err = conn:read_once()
  local t1 = rspamd_util.get_time()
  -- the second operation of the same connection gets a full timeout again
  local r2_ok, r2_err = conn:read_once()
  local t2 = rspamd_util.get_time()
  task:insert_result('TCP_SYNC_TIMEOUT', 1.0,
      string.format('first=%s:%s', tostring(r1_ok), tostring(r1_err)),
      string.format('second=%s:%s', tostring(r2_ok), tostring(r2_err)),
      'fast=' .. tostring(t1 - t0 < 3 and t2 - t1 < 3 and t1 - t0 >= 0.5 and t2 - t1 >= 0.5))
end
reg('TCP_SYNC_TIMEOUT_TEST', sync_timeout_symbol, true)
-- ]]
