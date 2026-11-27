--[[[
-- Coroutine safety of the APIs that suspend their caller (sync DNS, HTTP,
-- TCP, redis and ev_base:sleep() without a callback).
--
-- The suite config loads no settings plugin, so every scan runs every symbol
-- of this file: a symbol does its work only in a scan whose Coro-Test request
-- header names it (or names the test the symbol belongs to, see `test` in
-- register_test_symbol). Coroutine symbols report through their return values
-- (options of the symbol itself); the others insert result symbols that are
-- not registered (they get unknown_weight). Code that runs when the task is
-- gone reports through log lines.
--
-- A call that must be refused is reported as 'name=error:coroutine' when the
-- API raised an error that mentions coroutines, as 'name=error:<message>' when
-- it failed in another way (including a failed yield) and as 'name=no error'
-- when it was not refused at all.
--]]

local rspamd_dns = require "rspamd_dns"
local rspamd_expression = require "rspamd_expression"
local rspamd_http = require "rspamd_http"
local rspamd_ip = require "rspamd_ip"
local rspamd_redis = require "rspamd_redis"
local rspamd_spf = require "rspamd_spf"
local rspamd_tcp = require "rspamd_tcp"
local rspamd_text = require "rspamd_text"
local rspamd_udp = require "rspamd_udp"
local rspamd_upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"

local unpack_fn = table.unpack or unpack

-- Ports of the harness (RSPAMD_ prefix stripped by rspamd_env)
local env = rspamd_env or {}
-- dummy_http.py
local http_port = tonumber(env.PORT_DUMMY_HTTP) or 18080
local http_url = string.format('http://127.0.0.1:%d/request', http_port)
-- dummy_http.py answers it 4 seconds after the request
local http_slow_url = string.format('http://127.0.0.1:%d/timeout', http_port)
-- redis-server of the suite
local redis_host = string.format('%s:%s', env.REDIS_ADDR or '127.0.0.1',
    env.REDIS_PORT or '6379')
-- Nothing listens on it (310_udp.robot uses it the same way)
local udp_closed_port = (tonumber(env.PORT_DUMMY_UDP) or 5005) + 1
-- Answered by a fake record of configs/coroutines.conf
local dns_name = 'coro.resolveme'

local function sync_call_outcome(name, ok, err)
  if ok then
    return name .. '=no error'
  end
  local msg = tostring(err)
  -- Raised by the VM (e.g. 'attempt to yield from outside a coroutine') or
  -- by the thread pool: the API has not refused the call before yielding
  if msg:find('attempt to yield', 1, true) then
    return name .. '=error:' .. msg
  end
  if msg:find('coroutine', 1, true) then
    return name .. '=error:coroutine'
  end
  return name .. '=error:' .. msg
end

-- 'name=error:<label>' for an error that contains `pattern`, the same as
-- sync_call_outcome() otherwise
local function error_outcome(name, ok, err, pattern, label)
  if not ok and tostring(err):find(pattern, 1, true) then
    return name .. '=error:' .. label
  end
  return sync_call_outcome(name, ok, err)
end

-- Every value a call has returned, joined with ':'; 'none' if there is none
local function results_outcome(...)
  local n = select('#', ...)
  if n == 0 then
    return 'none'
  end
  local parts = {}
  for i = 1, n do
    parts[i] = tostring((select(i, ...)))
  end
  return table.concat(parts, ':')
end

local function dns_outcome(name, is_ok, results)
  if is_ok and type(results) == 'table' and results[1] then
    return name .. '=' .. tostring(results[1])
  end
  return name .. '=error:' .. tostring(results)
end

local function header_value(task, name, default)
  local hdr = task:get_request_header(name)
  if hdr then
    return tostring(hdr)
  end
  return default
end

local function sync_dns(task)
  return rspamd_dns.request({
    task = task,
    type = 'a',
    name = dns_name,
  })
end

-- def.test is the Coro-Test value that runs the symbol (its name by default):
-- a test that needs two symbols in one task names the first one
local function register_test_symbol(def)
  local test, cb = def.test or def.name, def.callback
  def.test = nil
  def.callback = function(task)
    if header_value(task, 'Coro-Test', '') ~= test then
      return
    end
    -- A tail call: in a coroutine symbol cb runs in the same coroutine
    return cb(task)
  end
  rspamd_config:register_symbol(def)
end

local function connect_redis(task, timeout)
  return rspamd_redis.connect_sync({
    task = task,
    host = redis_host,
    timeout = timeout,
  })
end

--[[ Health check used after every test: a coroutine symbol is still
--   suspended and resumed (by one sync DNS request, the most basic case), and
--   the pid shows whether the worker has been restarted ]]
register_test_symbol({
  name = 'CORO_ALIVE_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    task:insert_result('CORO_WORKER_PID', 1.0, tostring(rspamd_util.get_pid()))
    return true, 1.0, dns_outcome('dns', sync_dns(task))
  end,
})

--[[ Two tasks inside one coroutine symbol at once. Each run waits (every
--   sleep suspends it) until another run has entered the symbol, then is
--   suspended once more while the other one still is, so the two runs are
--   resumed in turns. Each must get its own result from its own return values
--   (the tag comes from a request header of its own scan). ]]
local concurrent_runs = {}

register_test_symbol({
  name = 'CORO_CONCURRENT_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local tag = header_value(task, 'Coro-Tag', 'none')
    local run = { overlapped = false }

    for other in pairs(concurrent_runs) do
      other.overlapped = true
      run.overlapped = true
    end
    concurrent_runs[run] = true

    -- Bounded: about 3s, well below the task timeout of the suite
    local steps = 0
    repeat
      task:get_ev_base():sleep(0.1)
      steps = steps + 1
    until run.overlapped or steps >= 30

    task:get_ev_base():sleep(0.2)
    -- Accounted to the item of this task, not to the one that entered last
    local dns_opt = dns_outcome('dns', sync_dns(task))
    concurrent_runs[run] = nil

    rspamd_logger.infox(task, 'concurrent coro run %s: overlapped=%s, steps=%s',
        tag, run.overlapped, steps)

    return true, 1.0, 'tag=' .. tag, 'overlapped=' .. tostring(run.overlapped), dns_opt
  end,
})

--[[ Sync APIs called from a symbol that is not a coroutine at all ]]
register_test_symbol({
  name = 'CORO_PLAIN_SYNC_TEST',
  score = 1.0,
  callback = function(task)
    local ok_dns, err_dns = pcall(sync_dns, task)
    local ok_sleep, err_sleep = pcall(function()
      return task:get_ev_base():sleep(0.01)
    end)
    local ok_http, err_http = pcall(rspamd_http.request, {
      task = task,
      url = http_url,
      timeout = 1,
    })
    local ok_tcp, err_tcp = pcall(rspamd_tcp.connect_sync, {
      task = task,
      host = '127.0.0.1',
      port = http_port,
      timeout = 1,
    })

    task:insert_result('CORO_PLAIN_SYNC', 1.0,
        sync_call_outcome('dns', ok_dns, err_dns),
        sync_call_outcome('sleep', ok_sleep, err_sleep),
        sync_call_outcome('http', ok_http, err_http),
        sync_call_outcome('tcp', ok_tcp, err_tcp))
  end,
})

--[[ Sync APIs called from async callbacks: a task timer, a DNS resolver
--   callback and an HTTP callback. They run on a callback thread, which can
--   not be suspended. `done` counts the callbacks that have run. ]]
local function start_async_callbacks(task, done)
  task:add_timer(0.05, function()
    local ok, err = pcall(function()
      return task:get_ev_base():sleep(0.01)
    end)
    task:insert_result('CORO_TIMER_CB', 1.0, sync_call_outcome('sleep', ok, err))
    done.count = done.count + 1
  end)

  task:get_resolver():resolve_a({
    task = task,
    name = dns_name,
    callback = function(_, _, results, dns_err)
      local ok, err = pcall(sync_dns, task)
      task:insert_result('CORO_DNS_CB', 1.0,
          'async=' .. (dns_err and ('error:' .. tostring(dns_err)) or tostring(results and results[1])),
          sync_call_outcome('dns', ok, err))
      done.count = done.count + 1
    end,
  })

  rspamd_http.request({
    task = task,
    url = http_url,
    timeout = 5,
    callback = function(http_err, code)
      local ok_http, err_http = pcall(rspamd_http.request, {
        task = task,
        url = http_url,
        timeout = 1,
      })
      local ok_tcp, err_tcp = pcall(rspamd_tcp.connect_sync, {
        task = task,
        host = '127.0.0.1',
        port = http_port,
        timeout = 1,
      })
      task:insert_result('CORO_HTTP_CB', 1.0,
          'async=' .. (http_err and ('error:' .. tostring(http_err)) or tostring(code)),
          sync_call_outcome('http', ok_http, err_http),
          sync_call_outcome('tcp', ok_tcp, err_tcp))
      done.count = done.count + 1
    end,
  })
end

-- The callbacks run after the symbol has returned
register_test_symbol({
  name = 'CORO_ASYNC_CB_PLAIN_TEST',
  score = 1.0,
  callback = function(task)
    start_async_callbacks(task, { count = 0 })
  end,
})

-- The callbacks run while the coroutine that has started them is suspended
register_test_symbol({
  name = 'CORO_ASYNC_CB_CORO_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local done = { count = 0 }
    start_async_callbacks(task, done)

    local steps = 0
    repeat
      task:get_ev_base():sleep(0.05)
      steps = steps + 1
    until done.count >= 3 or steps >= 60

    return true, 1.0, 'callbacks=' .. tostring(done.count)
  end,
})

--[[ Sync APIs called from a coroutine created by the Lua code, inside of a
--   coroutine symbol: that coroutine is not the pooled one, so the call must
--   fail instead of suspending the pooled coroutine. The symbol itself can
--   still be suspended afterwards. ]]
register_test_symbol({
  name = 'CORO_USER_COROUTINE_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    -- coroutine.wrap() raises the error of the coroutine in the caller
    local gen = coroutine.wrap(function()
      return sync_dns(task)
    end)
    local ok_wrap, err_wrap = pcall(gen)

    -- coroutine.resume() returns it
    local co_sleep = coroutine.create(function()
      return task:get_ev_base():sleep(0.01)
    end)
    local ok_sleep, err_sleep = coroutine.resume(co_sleep)

    local co_http = coroutine.create(function()
      return rspamd_http.request({
        task = task,
        url = http_url,
        timeout = 1,
      })
    end)
    local ok_http, err_http = coroutine.resume(co_http)

    task:get_ev_base():sleep(0.01)

    return true, 1.0,
        sync_call_outcome('wrap_dns', ok_wrap, err_wrap),
        sync_call_outcome('create_sleep', ok_sleep, err_sleep),
        sync_call_outcome('create_http', ok_http, err_http),
        dns_outcome('own_dns', sync_dns(task))
  end,
})

--[[ Sync APIs called by a Lua function that a C function calls (table.sort
--   comparator, string.gsub replacement): the pooled coroutine is the caller
--   but cannot yield through that C function ]]
register_test_symbol({
  name = 'CORO_NOT_YIELDABLE_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok_sort, err_sort = pcall(table.sort, { 3, 1, 2 }, function(a, b)
      sync_dns(task)
      return a < b
    end)
    local ok_gsub, err_gsub = pcall(string.gsub, 'abc', '%w', function(c)
      task:get_ev_base():sleep(0.01)
      return c
    end)

    return true, 1.0,
        sync_call_outcome('sort_dns', ok_sort, err_sort),
        sync_call_outcome('gsub_sleep', ok_gsub, err_gsub),
        dns_outcome('own_dns', sync_dns(task))
  end,
})

--[[ A sync sleep that is longer than the task can live: Coro-Sleep seconds.
--   The task times out or the client goes away while the coroutine sleeps;
--   the timer must not resume the coroutine of a freed task later. The
--   session cleanup ends the sleep early with (false, 'task is finishing'),
--   and the task takes nothing new after that: task:add_timer() refuses (its
--   callback must never run) and one more sleep raises an error. The results
--   are options of the symbol and a log line, as a task destroyed for a client
--   that has gone sends no reply. ]]
register_test_symbol({
  name = 'CORO_LONG_SLEEP_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local duration = tonumber(header_value(task, 'Coro-Sleep', '10')) or 10
    local ev_base = task:get_ev_base()
    local started = rspamd_util.get_time()
    local opts = { 'sleep=' .. results_outcome(ev_base:sleep(duration)) }

    if opts[1] ~= 'sleep=none' then
      opts[#opts + 1] = 'add_timer=' .. results_outcome(task:add_timer(0.5, function()
        rspamd_logger.infox(rspamd_config, 'long coro sleep: a timer of a finishing task has fired')
      end))
      local ok, err = pcall(ev_base.sleep, ev_base, 0.01)
      opts[#opts + 1] = error_outcome('sleep_again', ok, err,
          'the task session is terminating', 'terminating')
    end

    rspamd_logger.infox(task, 'long coro sleep: woke up after %s of %s seconds: %s',
        rspamd_util.get_time() - started, duration, table.concat(opts, ', '))

    return true, 1.0, unpack_fn(opts)
  end,
})

--[[ The same calls in a task that is not finishing: task:add_timer() and a
--   sync sleep return nothing (a value returned by add_timer() would become
--   the result of a symbol that ends with `return task:add_timer(...)`), and
--   the timer fires ]]
register_test_symbol({
  name = 'CORO_NORMAL_RETURNS_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local fired = false
    local timer_res = results_outcome(task:add_timer(0.05, function()
      fired = true
    end))
    local sleep_res = results_outcome(ev_base:sleep(0.01))

    local steps = 0
    while not fired and steps < 60 do
      ev_base:sleep(0.05)
      steps = steps + 1
    end

    return true, 1.0, 'add_timer=' .. timer_res, 'sleep=' .. sleep_res,
        'timer=' .. (fired and 'fired' or 'not fired')
  end,
})

--[[ A coroutine that outlives its task: it waits for an HTTP request made
--   with the config and the event loop of the task, but not with the task,
--   so the task session does not know the request. The task does not wait
--   for it: the task is finished and destroyed while the coroutine is
--   suspended, and the late reply must not resume it (the code after the
--   request would run for a freed task). ]]
register_test_symbol({
  name = 'CORO_ORPHAN_HTTP_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    rspamd_logger.infox(task, 'orphan coro: waiting for a request that is not bound to the task')
    local err = rspamd_http.request({
      url = http_slow_url,
      config = rspamd_config,
      ev_base = task:get_ev_base(),
      timeout = 10,
    })
    -- The task must not be used here: it is gone if this runs at all
    rspamd_logger.infox(rspamd_config, 'orphan coro: resumed after the request: %s', err)
    return true
  end,
})

--[[ Sync APIs called from a callback of an async sleep (ev_base:sleep(t, cb))
--   while the coroutine that has started it waits for the result: the
--   callback runs on a callback thread that cannot be suspended ]]
register_test_symbol({
  name = 'CORO_ASYNC_SLEEP_SYNC_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local res

    ev_base:sleep(0.05, function()
      local ok_dns, err_dns = pcall(sync_dns, task)
      local ok_sleep, err_sleep = pcall(ev_base.sleep, ev_base, 0.01)
      local ok_http, err_http = pcall(rspamd_http.request, {
        task = task,
        url = http_url,
        timeout = 1,
      })
      local ok_tcp, err_tcp = pcall(rspamd_tcp.connect_sync, {
        task = task,
        host = '127.0.0.1',
        port = http_port,
        timeout = 1,
      })
      res = {
        sync_call_outcome('dns', ok_dns, err_dns),
        sync_call_outcome('sleep', ok_sleep, err_sleep),
        sync_call_outcome('http', ok_http, err_http),
        sync_call_outcome('tcp', ok_tcp, err_tcp),
      }
    end)

    -- An async sleep does not hold the task: the coroutine does
    local steps = 0
    repeat
      ev_base:sleep(0.05)
      steps = steps + 1
    until res or steps >= 60

    if not res then
      return true, 1.0, 'callback=not called'
    end

    return true, 1.0, unpack_fn(res)
  end,
})

--[[ The callback of an async sleep fails while the coroutine that has
--   started it is suspended on a sync sleep: the coroutine is resumed later
--   as usual. The callback must not run on the lua_State of that coroutine. ]]
register_test_symbol({
  name = 'CORO_ASYNC_SLEEP_CB_ERROR_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local fired = false

    ev_base:sleep(0.1, function()
      fired = true
      error('async sleep callback fails on purpose')
    end)
    -- Suspended here when the callback fires
    ev_base:sleep(0.3)

    return true, 1.0, 'cb_fired=' .. tostring(fired), dns_outcome('dns', sync_dns(task))
  end,
})

--[[ A coroutine that starts async sleeps and then fails: its thread is
--   terminated, the task finishes. The callbacks run later on threads of
--   their own: the first one collects the garbage (the terminated thread
--   among it), the second one checks that it runs on a callback thread. The
--   task is gone by then, so they report through log lines. ]]
register_test_symbol({
  name = 'CORO_ASYNC_SLEEP_FAILED_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()

    ev_base:sleep(0.5, function()
      collectgarbage('collect')
      rspamd_logger.infox(rspamd_config, 'async sleep of a failed coroutine: garbage collected')
    end)
    ev_base:sleep(1.0, function()
      local ok, err = pcall(ev_base.sleep, ev_base, 0.01)
      rspamd_logger.infox(rspamd_config, 'async sleep of a failed coroutine: callback has run, %s',
          sync_call_outcome('sleep', ok, err))
    end)

    error('the coroutine fails on purpose')
  end,
})

--[[ A command on a sync redis connection from a symbol that is not a
--   coroutine: add_cmd() must raise before the command is sent, otherwise
--   its session event holds the task until the task timeout ]]
register_test_symbol({
  name = 'CORO_REDIS_PLAIN_TEST',
  score = 1.0,
  callback = function(task)
    local ok, conn = connect_redis(task, 1.0)
    local opts = { 'connect=' .. tostring(ok) }

    if ok then
      local ok_cmd, err_cmd = pcall(conn.add_cmd, conn, 'PING')
      opts[#opts + 1] = sync_call_outcome('add_cmd', ok_cmd, err_cmd)
    end

    task:insert_result('CORO_REDIS_PLAIN', 1.0, unpack_fn(opts))
  end,
})

--[[ Two coroutines of one task wait on one sync redis connection: the first
--   one waits in exec() for a blocking command (BLPOP for 1s), the second
--   one calls exec() meanwhile. The second one must be refused at once, it
--   must not take the place of the first one, which gets its reply. ]]
local redis_conn_key = 'coro_redis_conn'

register_test_symbol({
  name = 'CORO_REDIS_TWO_WAITERS_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 3.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    local sent, err = conn:add_cmd('BLPOP', { 'coro_redis_nokey', '1' })

    if not sent then
      return true, 1.0, 'add_cmd=' .. tostring(err)
    end

    -- Nothing runs before the yield in exec() below
    task:cache_set(redis_conn_key, conn)
    local exec_ok = conn:exec()

    return true, 1.0, 'exec=' .. tostring(exec_ok)
  end,
})

register_test_symbol({
  name = 'CORO_REDIS_SECOND_WAITER',
  test = 'CORO_REDIS_TWO_WAITERS_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local conn
    local steps = 0

    repeat
      conn = task:cache_get(redis_conn_key)
      if not conn then
        ev_base:sleep(0.05)
        steps = steps + 1
      end
    until conn or steps >= 20

    if not conn then
      return true, 1.0, 'exec=no connection'
    end

    -- Returns at once: the first coroutine still waits for BLPOP
    return true, 1.0, 'exec=' .. results_outcome(conn:exec())
  end,
})

--[[ A sync TCP connection to an IP literal (no DNS involved), a refused one
--   and a sync sleep, each followed by a sync DNS request in the same
--   coroutine symbol: the resumed coroutine must still have its symbol as the
--   current item ]]
register_test_symbol({
  name = 'CORO_TCP_DNS_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local opts = {}
    local ok, conn = rspamd_tcp.connect_sync({
      task = task,
      host = '127.0.0.1',
      port = http_port,
      timeout = 5,
    })

    if ok then
      local w_ok = conn:write(string.format(
          'GET /request HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n',
          http_port))
      local r_ok, data = conn:read_once()
      conn:close()
      opts[#opts + 1] = 'tcp=' .. tostring(w_ok and r_ok and
          tostring(data):find('HTTP/1.1 200', 1, true) ~= nil)
    else
      opts[#opts + 1] = 'tcp=error:' .. tostring(conn)
    end
    opts[#opts + 1] = dns_outcome('dns_after_tcp', sync_dns(task))

    -- Port 1 is closed: the error path resumes the coroutine
    local refused_ok = rspamd_tcp.connect_sync({
      task = task,
      host = '127.0.0.1',
      port = 1,
      timeout = 5,
    })
    opts[#opts + 1] = 'refused=' .. tostring(refused_ok)
    opts[#opts + 1] = dns_outcome('dns_after_refused', sync_dns(task))

    -- The same after a sync sleep
    task:get_ev_base():sleep(0.01)
    opts[#opts + 1] = dns_outcome('dns_after_sleep', sync_dns(task))

    return true, 1.0, unpack_fn(opts)
  end,
})

-- Suspends the coroutine by sync sleeps of `step` seconds until done()
-- returns true, at most `max_steps` times; returns what done() returns
local function sleep_until(task, done, step, max_steps)
  local ev_base = task:get_ev_base()
  local steps = 0

  while not done() and steps < max_steps do
    ev_base:sleep(step)
    steps = steps + 1
  end

  return done()
end

-- 'true' for a call that has succeeded, 'false:<error>' otherwise
local function ok_outcome(ok, err)
  if ok then
    return 'true'
  end
  return 'false:' .. tostring(err)
end

local function http_get_request(path, keep_alive)
  return string.format('GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: %s\r\n\r\n',
      path, http_port, keep_alive and 'keep-alive' or 'close')
end

--[[ A reply that comes while nobody waits for it: the coroutine sends a
--   command on one connection and is suspended elsewhere while the reply
--   arrives (Coro-Wait: a BLPOP of 0.3s on a second connection, or a sync
--   sleep of 0.3s), then calls exec(). exec() returns the stored reply at
--   once, and the command must not hold the task: the scan ends well before
--   the task timeout. ]]
register_test_symbol({
  name = 'CORO_REDIS_EARLY_REPLY_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 3.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    local sent, err = conn:add_cmd('PING', {})

    if not sent then
      return true, 1.0, 'add_cmd=' .. tostring(err)
    end

    local wait_opt

    if header_value(task, 'Coro-Wait', 'blpop') == 'sleep' then
      wait_opt = 'sleep=' .. results_outcome(task:get_ev_base():sleep(0.3))
    else
      local other_ok, other = connect_redis(task, 3.0)

      if other_ok then
        other:add_cmd('BLPOP', { 'coro_redis_nokey_early', '0.3' })
        wait_opt = 'blpop=' .. tostring((other:exec()))
      else
        wait_opt = 'blpop=connect:' .. tostring(other)
      end
    end

    return true, 1.0, wait_opt, 'exec=' .. results_outcome(conn:exec())
  end,
})

--[[ add_cmd()/exec() pairs one after another on one sync connection; the
--   reply of the second pair comes before its exec(), the last exec() returns
--   the replies of two commands ]]
register_test_symbol({
  name = 'CORO_REDIS_REPEAT_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 3.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    local key = 'coro_redis_repeat'
    local opts = {}

    conn:add_cmd('DEL', { key })
    opts[#opts + 1] = 'del=' .. tostring((conn:exec()))

    local incrs = {}

    for i = 1, 3 do
      conn:add_cmd('INCR', { key })

      if i == 2 then
        -- The reply arrives here
        task:get_ev_base():sleep(0.1)
      end

      incrs[i] = results_outcome(conn:exec())
    end

    opts[#opts + 1] = 'incr=' .. table.concat(incrs, '/')

    conn:add_cmd('INCR', { key })
    conn:add_cmd('GET', { key })
    opts[#opts + 1] = 'pipeline=' .. results_outcome(conn:exec())

    return true, 1.0, unpack_fn(opts)
  end,
})

--[[ A command whose reply is never asked for by exec(): the reply releases
--   the task, which does not wait for the task timeout ]]
register_test_symbol({
  name = 'CORO_REDIS_NO_EXEC_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 3.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    return true, 1.0, 'add_cmd=' .. tostring((conn:add_cmd('PING', {})))
  end,
})

--[[ A coroutine symbol sends a command and returns; a symbol that depends on
--   it takes the reply with exec(). The dependent symbol is started by the
--   reply itself (it lets the first symbol finish), so its exec() runs while
--   the reply gives back what its command holds. ]]
local redis_handover_key = 'coro_redis_handover_conn'

register_test_symbol({
  name = 'CORO_REDIS_HANDOVER_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 3.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    local sent, err = conn:add_cmd('PING', {})

    if not sent then
      return true, 1.0, 'add_cmd=' .. tostring(err)
    end

    task:cache_set(redis_handover_key, conn)

    return true, 1.0, 'add_cmd=true'
  end,
})

register_test_symbol({
  name = 'CORO_REDIS_HANDOVER_COLLECT',
  test = 'CORO_REDIS_HANDOVER_TEST',
  score = 1.0,
  callback = function(task)
    local conn = task:cache_get(redis_handover_key)

    if not conn then
      return true, 1.0, 'exec=no connection'
    end

    -- Not a coroutine: the reply is stored, so exec() does not have to wait
    return true, 1.0, 'exec=' .. results_outcome(conn:exec())
  end,
})

rspamd_config:register_dependency('CORO_REDIS_HANDOVER_COLLECT', 'CORO_REDIS_HANDOVER_TEST')

--[[ A command that is answered more than once (one confirmation per
--   channel): the first reply is the reply of the command, the others are
--   ignored and do not make a later exec() wait for ever ]]
register_test_symbol({
  name = 'CORO_REDIS_SUBSCRIBE_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 3.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    conn:add_cmd('SUBSCRIBE', { 'coro_redis_chan_a', 'coro_redis_chan_b' })
    -- Both confirmations arrive here
    task:get_ev_base():sleep(0.3)

    return true, 1.0, 'exec=' .. tostring((conn:exec()))
  end,
})

--[[ More replies for one exec() than a Lua stack can take on LuaJIT (8000
--   slots, 2 per reply): exec() returns an error instead of the replies,
--   which are delivered from the event loop. Other Lua VMs return them. ]]
local big_pipeline_size = 4100

register_test_symbol({
  name = 'CORO_REDIS_BIG_PIPELINE_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 3.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    for _ = 1, big_pipeline_size do
      conn:add_cmd('PING', {})
    end

    local res = { conn:exec() }

    return true, 1.0, 'vm=' .. (type(jit) == 'table' and 'luajit' or 'lua'),
        'values=' .. tostring(#res), 'exec=' .. tostring(res[1]) .. ':' .. tostring(res[2])
  end,
})

--[[ The task times out (6s) while the coroutine waits in exec() for a BLPOP
--   of 30s: the session cleanup closes the connection, so the BLPOP ends at
--   the timeout, and the coroutine is terminated (no line after exec() is
--   logged, the symbol keeps the result inserted before the wait). A
--   postfilter uses the connection afterwards (task cache) ]]
local redis_cancel_key = 'coro_redis_cancel_conn'

register_test_symbol({
  name = 'CORO_REDIS_CANCEL_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 60.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    conn:add_cmd('BLPOP', { 'coro_redis_nokey_cancel', '30' })
    task:cache_set(redis_cancel_key, conn)
    task:insert_result('CORO_REDIS_CANCEL_TEST', 1.0, 'waiting')
    rspamd_logger.infox(task, 'coro redis cancel: waiting in exec()')
    local exec_res = results_outcome(conn:exec())
    rspamd_logger.infox(rspamd_config, 'coro redis cancel: resumed after exec(): %s', exec_res)

    return true, 1.0, 'exec=' .. exec_res
  end,
})

--[[ One sync TCP connection, several operations, idle time (a sync sleep)
--   before each one: the task waits for every operation. Two requests on one
--   keep-alive connection to dummy_http.py. ]]
register_test_symbol({
  name = 'CORO_TCP_IDLE_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local ok, conn = rspamd_tcp.connect_sync({
      task = task,
      host = '127.0.0.1',
      port = http_port,
      timeout = 5,
    })

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    local opts = {}

    for i, keep_alive in ipairs({ true, false }) do
      -- Idle: no operation of the connection is pending
      ev_base:sleep(0.1)
      local w_ok, w_err = conn:write(http_get_request('/request', keep_alive))
      opts[#opts + 1] = string.format('write%d=%s', i, ok_outcome(w_ok, w_err))

      ev_base:sleep(0.1)
      local r_ok, data = conn:read_once()

      if r_ok then
        opts[#opts + 1] = string.format('read%d=%s', i,
            tostring(tostring(data):find('HTTP/1.1 200', 1, true) ~= nil))
      else
        opts[#opts + 1] = string.format('read%d=error:%s', i, tostring(data))
      end
    end

    conn:close()

    return true, 1.0, unpack_fn(opts)
  end,
})

--[[ One coroutine waits in read_once() (dummy_http.py answers /timeout after
--   4s), another coroutine of the same task closes the connection: the read
--   ends at once with an error ]]
local tcp_conn_key = 'coro_tcp_conn'

register_test_symbol({
  name = 'CORO_TCP_CLOSE_PENDING_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = rspamd_tcp.connect_sync({
      task = task,
      host = '127.0.0.1',
      port = http_port,
      timeout = 10,
    })

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    local w_ok, w_err = conn:write(http_get_request('/timeout', false))
    local started = rspamd_util.get_time()
    -- Nothing runs before the yield in read_once() below
    task:cache_set(tcp_conn_key, conn)
    local r_ok, r_err = conn:read_once()

    return true, 1.0, 'write=' .. ok_outcome(w_ok, w_err),
        'read=' .. ok_outcome(r_ok, r_err),
        'fast=' .. tostring(rspamd_util.get_time() - started < 2)
  end,
})

register_test_symbol({
  name = 'CORO_TCP_CLOSER',
  test = 'CORO_TCP_CLOSE_PENDING_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local conn

    sleep_until(task, function()
      conn = task:cache_get(tcp_conn_key)
      return conn ~= nil
    end, 0.05, 20)

    if not conn then
      return true, 1.0, 'close=no connection'
    end

    -- The other coroutine is in read_once() now
    task:get_ev_base():sleep(0.2)
    conn:close()

    return true, 1.0, 'close=done'
  end,
})

--[[ The task times out (6s) while a sync HTTP request is in flight: the
--   first request (4s) is answered, the second one is in flight from 4s to
--   8s. The session cleanup resumes the coroutine with an error, and the task
--   takes no new request then. ]]
register_test_symbol({
  name = 'CORO_HTTP_CANCELLED_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local err1, resp1 = rspamd_http.request({
      task = task,
      url = http_slow_url,
      timeout = 10,
    })
    local first = err1 and ('error:' .. tostring(err1)) or tostring(resp1 and resp1.code)
    local err2, resp2 = rspamd_http.request({
      task = task,
      url = http_slow_url,
      timeout = 10,
    })
    rspamd_logger.infox(rspamd_config, 'cancelled coro http: resumed: %s', err2)
    local err3, resp3 = rspamd_http.request({
      task = task,
      url = http_url,
      timeout = 1,
    })

    return true, 1.0, 'first=' .. first,
        'second=' .. results_outcome(err2, resp2),
        'third=' .. results_outcome(err3, resp3)
  end,
})

--[[ The body of a sync request with opaque_body is an rspamd{text}: it must
--   stay valid after the request is gone (another request and a sleep later,
--   and a garbage collection) ]]
register_test_symbol({
  name = 'CORO_HTTP_OPAQUE_BODY_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local err1, resp1 = rspamd_http.request({
      task = task,
      url = http_url,
      opaque_body = true,
      timeout = 1,
    })

    if err1 or not resp1 then
      return true, 1.0, 'first=error:' .. tostring(err1)
    end

    local body = resp1.content
    local err2, resp2 = rspamd_http.request({
      task = task,
      url = http_url,
      timeout = 1,
    })
    task:get_ev_base():sleep(0.01)
    collectgarbage('collect')

    return true, 1.0, 'type=' .. type(body), 'body=' .. tostring(body),
        'second=' .. (err2 and ('error:' .. tostring(err2)) or tostring(resp2 and resp2.content))
  end,
})

--[[ Callback requests to a closed port over TLS, to an IP literal and to a
--   name (connected from the DNS callback). The connection fails at once
--   (Linux: the TLS handshake gets ECONNREFUSED inside the call, the case
--   under test) or later. request() returns true if the callback is going to
--   be called, and then it is called once; 'once' tells that, 'not called'
--   tells that request() has returned false and no callback has come. ]]
local function http_callback_outcome(ret, ncalls)
  if ret == true and ncalls == 1 then
    return 'once'
  end
  if ret == false and ncalls == 0 then
    return 'not called'
  end
  return string.format('returned %s, called %s times', tostring(ret), tostring(ncalls))
end

register_test_symbol({
  name = 'CORO_HTTP_FAILED_CONNECT_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local calls = { ip = 0, name = 0 }
    local function counter(kind)
      return function()
        calls[kind] = calls[kind] + 1
      end
    end

    local ret_ip = rspamd_http.request({
      task = task,
      url = 'https://127.0.0.1:1/request',
      timeout = 1,
      callback = counter('ip'),
    })
    local ret_name = rspamd_http.request({
      task = task,
      url = string.format('https://%s:1/request', dns_name),
      timeout = 1,
      callback = counter('name'),
    })

    sleep_until(task, function()
      return (calls.ip > 0 or ret_ip == false) and (calls.name > 0 or ret_name == false)
    end, 0.05, 40)
    -- A second call would come right after the first one
    task:get_ev_base():sleep(0.2)

    return true, 1.0, 'ip=' .. http_callback_outcome(ret_ip, calls.ip),
        'name=' .. http_callback_outcome(ret_name, calls.name)
  end,
})

--[[ Symbol results with options that are not strings or texts (an
--   rspamd{ip}, at the top level and inside a table): they are skipped, the
--   other options are kept, in a coroutine symbol and in a plain one ]]
local function bad_option_results()
  return true, 1.0, 'good', rspamd_text.fromstring('text_opt'),
      rspamd_ip.from_string('192.0.2.1'),
      { 'in_table', rspamd_ip.from_string('192.0.2.2'), rspamd_text.fromstring('text_in_table') }
end

register_test_symbol({
  name = 'CORO_BAD_OPTION_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    task:get_ev_base():sleep(0.01)
    return bad_option_results()
  end,
})

register_test_symbol({
  name = 'CORO_BAD_OPTION_PLAIN',
  test = 'CORO_BAD_OPTION_TEST',
  score = 1.0,
  callback = function()
    return bad_option_results()
  end,
})

--[[ A function as the result of a symbol: no symbol is inserted, in a
--   coroutine symbol and in a plain one ]]
register_test_symbol({
  name = 'CORO_RETURN_FUNCTION_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    task:get_ev_base():sleep(0.01)
    return tostring
  end,
})

register_test_symbol({
  name = 'CORO_RETURN_FUNCTION_PLAIN',
  test = 'CORO_RETURN_FUNCTION_TEST',
  score = 1.0,
  callback = function()
    return tostring
  end,
})

--[[ The callback of rspamd_udp.sendto (no reply: a read timeout of 0.2s)
--   runs while the coroutine that has sent the request is suspended. It runs
--   on a thread of its own, calls a sync API (refused) and fails; the
--   coroutine is resumed as usual. ]]
register_test_symbol({
  name = 'CORO_UDP_CB_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local me = coroutine.running()
    local res
    local sent = rspamd_udp.sendto({
      task = task,
      host = '127.0.0.1',
      port = udp_closed_port,
      data = 'coro',
      timeout = 0.2,
      callback = function(ok, data)
        local ok_sleep, err_sleep = pcall(ev_base.sleep, ev_base, 0.01)
        res = {
          'udp=' .. ok_outcome(ok, data),
          'udp_own_thread=' .. tostring(coroutine.running() ~= me),
          sync_call_outcome('udp_sleep', ok_sleep, err_sleep),
        }
        error('udp callback fails on purpose')
      end,
    })

    sleep_until(task, function()
      return res ~= nil
    end, 0.05, 40)

    if not res then
      return true, 1.0, 'sent=' .. tostring(sent), 'callback=not called'
    end

    res[#res + 1] = dns_outcome('dns', sync_dns(task))

    return true, 1.0, unpack_fn(res)
  end,
})

--[[ A plain symbol whose rspamd_udp.sendto request (with the task) is
--   answered by a read timeout of 0.2s: the symbol is pending until its
--   callback has run, so a symbol that depends on it sees the result ]]
register_test_symbol({
  name = 'CORO_UDP_DEP_TEST',
  score = 1.0,
  callback = function(task)
    rspamd_udp.sendto({
      task = task,
      host = '127.0.0.1',
      port = udp_closed_port,
      data = 'dep',
      timeout = 0.2,
      callback = function(ok, data)
        task:insert_result('CORO_UDP_DEP_TEST', 1.0, 'udp=' .. ok_outcome(ok, data))
      end,
    })
  end,
})

register_test_symbol({
  name = 'CORO_UDP_DEPENDENT',
  test = 'CORO_UDP_DEP_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_UDP_DEPENDENT', 1.0,
        'dependency_done=' .. tostring(task:has_symbol('CORO_UDP_DEP_TEST')))
  end,
})

rspamd_config:register_dependency('CORO_UDP_DEPENDENT', 'CORO_UDP_DEP_TEST')

--[[ The callbacks of rspamd_spf.resolve (a record from configs/coroutines.conf,
--   from the cache on a later scan, so maybe called at once) and of a DKIM
--   verification (its key gets NXDOMAIN, always after a DNS request): each
--   runs on a thread of its own, not on the coroutine that has started it,
--   calls a sync API (refused) and fails. The coroutine is suspended while
--   they run and is resumed as usual. ]]
local dkim_zero_b64 = string.rep('A', 43) .. '='
local dkim_signature = string.format('v=1; a=rsa-sha256; c=relaxed/relaxed; d=coro-dkim.test; '
    .. 's=sel; t=1; h=from; bh=%s; b=%s', dkim_zero_b64, dkim_zero_b64)

register_test_symbol({
  name = 'CORO_SPF_DKIM_CB_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local me = coroutine.running()
    local spf_res, dkim_res

    rspamd_spf.resolve(task, function(record, _, err)
      local ok_sleep, err_sleep = pcall(ev_base.sleep, ev_base, 0.01)
      spf_res = {
        'spf=' .. (record and 'record' or ('error:' .. tostring(err))),
        'spf_own_thread=' .. tostring(coroutine.running() ~= me),
        sync_call_outcome('spf_sleep', ok_sleep, err_sleep),
      }
      error('spf callback fails on purpose')
    end)

    local dkim_api = rspamd_plugins and rspamd_plugins.dkim

    if not dkim_api then
      dkim_res = { 'dkim=no dkim plugin' }
    else
      local verify_ok, verify_err = dkim_api.verify(task, dkim_signature, function(_, ok)
        local ok_sleep, err_sleep = pcall(ev_base.sleep, ev_base, 0.01)
        dkim_res = {
          'dkim=' .. tostring(ok),
          'dkim_own_thread=' .. tostring(coroutine.running() ~= me),
          sync_call_outcome('dkim_sleep', ok_sleep, err_sleep),
        }
        error('dkim callback fails on purpose')
      end)

      if not verify_ok then
        dkim_res = { 'dkim=verify:' .. tostring(verify_err) }
      end
    end

    sleep_until(task, function()
      return spf_res ~= nil and dkim_res ~= nil
    end, 0.05, 40)

    local opts = {}

    for _, res in ipairs({ spf_res or { 'spf=not called' }, dkim_res or { 'dkim=not called' } }) do
      for _, opt in ipairs(res) do
        opts[#opts + 1] = opt
      end
    end

    return true, 1.0, unpack_fn(opts)
  end,
})

--[[ A destructor of the task pool and an expression on that pool, made by a
--   coroutine created by the Lua code, which is collected long before the
--   pool is destroyed (after the reply). The destructor runs on a thread of
--   its own, calls a sync API (refused) and fails; the release of the
--   expression does not use the collected coroutine either. ]]
local function in_collected_coroutine(f)
  return coroutine.resume(coroutine.create(f))
end

register_test_symbol({
  name = 'CORO_MEMPOOL_DTOR_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ev_base = task:get_ev_base()
    local pool = task:get_mempool()
    local ok, expr_ok, expr_err = in_collected_coroutine(function()
      pool:add_destructor(function()
        local ok_sleep, err_sleep = pcall(ev_base.sleep, ev_base, 0.01)
        rspamd_logger.infox(rspamd_config, 'coro mempool destructor: has run, %s',
            sync_call_outcome('sleep', ok_sleep, err_sleep))
        error('mempool destructor fails on purpose')
      end)

      local expr, err = rspamd_expression.create('A & B', {
        function(atom)
          return atom
        end,
        function()
          return 1
        end,
      }, pool)

      return expr ~= nil, err
    end)

    collectgarbage('collect')
    collectgarbage('collect')
    ev_base:sleep(0.01)

    return true, 1.0, 'coroutine=' .. tostring(ok),
        'expression=' .. tostring(expr_ok) .. (expr_err and (':' .. tostring(expr_err)) or '')
  end,
})

--[[ Map callbacks registered at config load by a coroutine created by the
--   Lua code, which is collected right after (below), before the maps are
--   read at start: the callback of a callback map and the on_load handler of
--   a set map. They run on a thread of their own and fail. ]]
local coro_map_file = (env.TESTDIR or '.') .. '/configs/maps/coroutines.list'
local coro_set_map

coroutine.wrap(function()
  rspamd_config:add_map({
    type = 'callback',
    url = coro_map_file,
    description = 'coroutines test: callback map',
    callback = function(data)
      rspamd_logger.infox(rspamd_config, 'coro map: callback has run, %s bytes', #tostring(data))
      error('coro map callback fails on purpose')
    end,
  })

  coro_set_map = rspamd_config:add_map({
    type = 'set',
    url = coro_map_file,
    description = 'coroutines test: set map',
  })

  if coro_set_map then
    coro_set_map:on_load(function()
      rspamd_logger.infox(rspamd_config, 'coro map: on_load has run, key=%s',
          coro_set_map:get_key('coro.example.com'))
      error('coro map on_load fails on purpose')
    end)
  end
end)()

collectgarbage('collect')
collectgarbage('collect')

--[[ A periodic whose run is suspended (a sync sleep of 0.5s) for longer than
--   its interval (0.1s): a run starts only when the previous one is over. The
--   first scan of the test starts it, it stops by itself after 4 runs, and
--   the scans report its counters. ]]
local periodic_stats = { started = 0, finished = 0, active = 0, max_active = 0 }
local periodic_added = false

register_test_symbol({
  name = 'CORO_PERIODIC_TEST',
  score = 1.0,
  callback = function(task)
    local st = periodic_stats

    if not periodic_added then
      periodic_added = true
      rspamd_config:add_periodic(task:get_ev_base(), 0.1, function(_, ev_base)
        st.started = st.started + 1
        st.active = st.active + 1

        if st.active > st.max_active then
          st.max_active = st.active
        end

        ev_base:sleep(0.5)
        st.active = st.active - 1
        st.finished = st.finished + 1

        return st.finished < 4
      end)
    end

    local done = st.finished >= 4 and st.active == 0

    task:insert_result('CORO_PERIODIC', 1.0, 'state=' .. (done and 'done' or 'running'),
        'started=' .. tostring(st.started), 'finished=' .. tostring(st.finished),
        'max_active=' .. tostring(st.max_active))
  end,
})

--[[ DNS replies that come when their request is the only event of the task.
--   The callback gets the reply while the request still holds the session, so
--   what the callback (or the coroutine it resumes) does to other events does
--   not finish the task under it. Here that is an HTTP request over TLS to a
--   closed port, which fails inside the call on Linux: its event is added and
--   removed again right away. ]]
register_test_symbol({
  name = 'CORO_DNS_LAST_EVENT_TEST',
  score = 1.0,
  callback = function(task)
    local calls = 0

    -- The name is resolved first: the connection is made by the DNS callback
    rspamd_http.request({
      task = task,
      url = string.format('https://%s:1/request', dns_name),
      timeout = 1,
      callback = function(err)
        calls = calls + 1
        task:insert_result('CORO_DNS_LAST_EVENT', 1.0, 'calls=' .. tostring(calls),
            'error=' .. tostring(err ~= nil))
      end,
    })
  end,
})

register_test_symbol({
  name = 'CORO_DNS_LAST_EVENT_CORO_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local dns_opt = dns_outcome('dns', sync_dns(task))
    -- Resumed by the DNS reply
    local calls = 0
    local ret = rspamd_http.request({
      task = task,
      url = 'https://127.0.0.1:1/request',
      timeout = 1,
      callback = function()
        calls = calls + 1
      end,
    })
    -- Whether the request has failed inside request()
    local inline = calls > 0

    -- Elsewhere the connection fails later
    sleep_until(task, function()
      return calls > 0 or ret == false
    end, 0.05, 40)

    return true, 1.0, dns_opt, 'http=' .. http_callback_outcome(ret, calls),
        'inline=' .. tostring(inline)
  end,
})

--[[ Sync DNS requests one after another in one coroutine: bound to the
--   task, to the session of the task only (the request data is not taken from
--   the config pool then), PTR requests of both kinds (answered by a fake
--   record), arguments refused before a request is made ]]
local dns_ptr_name = '127.0.0.2'

register_test_symbol({
  name = 'CORO_DNS_SEQUENCE_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local opts = {}

    for i = 1, 3 do
      opts[#opts + 1] = dns_outcome('task' .. tostring(i), sync_dns(task))
    end

    local function session_request(rtype, name)
      return rspamd_dns.request({
        config = rspamd_config,
        session = task:get_session(),
        type = rtype,
        name = name,
      })
    end

    opts[#opts + 1] = dns_outcome('session', session_request('a', dns_name))
    opts[#opts + 1] = dns_outcome('ptr', rspamd_dns.request({
      task = task,
      type = 'ptr',
      name = dns_ptr_name,
    }))
    opts[#opts + 1] = dns_outcome('session_ptr', session_request('ptr', dns_ptr_name))

    local ok, err = pcall(rspamd_dns.request, { task = task, name = dns_name, type = {} })
    opts[#opts + 1] = error_outcome('bad_type', ok, err, 'bad type for key: type', 'bad type')

    -- The callback is taken before the option is found to be wrong
    local resolver = task:get_resolver()
    ok, err = pcall(resolver.resolve_a, resolver, {
      task = task,
      name = dns_name,
      callback = function()
      end,
      option = {},
    })
    opts[#opts + 1] = error_outcome('bad_option', ok, err, 'bad type for key: option', 'bad type')

    opts[#opts + 1] = dns_outcome('task_last', sync_dns(task))

    return true, 1.0, unpack_fn(opts)
  end,
})

--[[ The callback of an async DNS request starts another request: the symbol
--   is pending until the callback of that one has inserted the result ]]
local function resolver_outcome(results, err)
  if err then
    return 'error:' .. tostring(err)
  end

  return tostring(results and results[1])
end

register_test_symbol({
  name = 'CORO_DNS_NESTED_CB_TEST',
  score = 1.0,
  callback = function(task)
    local resolver = task:get_resolver()

    resolver:resolve_a({
      task = task,
      name = dns_name,
      callback = function(_, _, results, err)
        local first = resolver_outcome(results, err)

        resolver:resolve_a({
          task = task,
          name = dns_name,
          callback = function(_, _, nested_results, nested_err)
            task:insert_result('CORO_DNS_NESTED_CB_TEST', 1.0, 'first=' .. first,
                'nested=' .. resolver_outcome(nested_results, nested_err))
          end,
        })
      end,
    })
  end,
})

register_test_symbol({
  name = 'CORO_DNS_NESTED_DEPENDENT',
  test = 'CORO_DNS_NESTED_CB_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_DNS_NESTED_DEPENDENT', 1.0,
        'dependency_done=' .. tostring(task:has_symbol('CORO_DNS_NESTED_CB_TEST')))
  end,
})

rspamd_config:register_dependency('CORO_DNS_NESTED_DEPENDENT', 'CORO_DNS_NESTED_CB_TEST')

--[[ A number as the first value returned by a symbol is its weight when it
--   is finite and not zero (a number after it is the weight then); zero, NaN,
--   infinity and other types insert nothing. A plain symbol and a coroutine
--   symbol (resumed once before it returns) agree. ]]
local weight_returns = {
  { 'HALF', function()
    return 0.5, 'half'
  end },
  { 'FRACTION', function()
    return 2.7
  end },
  { 'OVERRIDE', function()
    return 0.5, 3, 'override'
  end },
  { 'ZERO', function()
    return 0
  end },
  { 'NAN', function()
    return 0 / 0
  end },
  { 'INF', function()
    return math.huge
  end },
  { 'STRING', function()
    return '1'
  end },
}

for _, def in ipairs(weight_returns) do
  local name, results = def[1], def[2]

  register_test_symbol({
    name = 'CORO_WEIGHT_' .. name,
    test = 'CORO_WEIGHT_TEST',
    score = 1.0,
    callback = function()
      return results()
    end,
  })

  register_test_symbol({
    name = 'CORO_WEIGHT_' .. name .. '_CORO',
    test = 'CORO_WEIGHT_TEST',
    score = 1.0,
    flags = 'coro',
    callback = function(task)
      task:get_ev_base():sleep(0.01)
      return results()
    end,
  })
end

--[[ Periodics whose runs fail: a failed run is planned again with the last
--   interval of the periodic (the registered one or the number returned
--   last); one that has no interval (registered with 0, no number returned
--   yet) stops. Returning false stops a periodic. The first scan of the test
--   starts them, the scans report their counters. ]]
local periodic_errors = { runs = 0, zero = 0, num = 0 }
local periodic_errors_added = false

register_test_symbol({
  name = 'CORO_PERIODIC_ERROR_TEST',
  score = 1.0,
  callback = function(task)
    local pe = periodic_errors

    if not periodic_errors_added then
      local ev_base = task:get_ev_base()
      periodic_errors_added = true

      -- Fails on its first two runs, stops after the fourth one
      rspamd_config:add_periodic(ev_base, 0.1, function()
        pe.runs = pe.runs + 1

        if pe.runs <= 2 then
          error('periodic fails on purpose, run ' .. tostring(pe.runs))
        end

        return pe.runs < 4
      end)

      -- Registered by a coroutine whose body is add_periodic() itself: no Lua
      -- function calls it, so its position is unknown
      coroutine.wrap(rspamd_config.add_periodic)(rspamd_config, ev_base, 0, function()
        pe.zero = pe.zero + 1
        error('periodic without an interval fails on purpose')
      end)

      -- The first run gives it an interval, the second one fails
      rspamd_config:add_periodic(ev_base, 0, function()
        pe.num = pe.num + 1

        if pe.num == 1 then
          return 0.1
        elseif pe.num == 2 then
          error('periodic with a returned interval fails on purpose')
        end

        return false
      end)
    end

    local done = pe.runs >= 4 and pe.zero >= 1 and pe.num >= 3

    task:insert_result('CORO_PERIODIC_ERRORS', 1.0, 'state=' .. (done and 'done' or 'running'),
        'runs=' .. tostring(pe.runs), 'zero=' .. tostring(pe.zero), 'num=' .. tostring(pe.num))
  end,
})

--[[ A Lua handler of a control command (`rspamadm control reresolve`) in the
--   scanner worker. A scan sets what the next calls do (Coro-Mode header) and
--   numbers them from 1: 'fail' makes the next call fail; 'http' makes every
--   call start a request (4s) bound to the session of the command, which is
--   answered when the request is over. ]]
local control_state = { mode = 'none', calls = 0 }

rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if worker:get_type() ~= 'normal' then
    return
  end

  worker:add_control_handler(cfg, ev_base, 'reresolve', function(session, cmd)
    control_state.calls = control_state.calls + 1
    local call = control_state.calls

    rspamd_logger.infox(cfg, 'coro control: call %s of %s, mode %s', call, cmd,
        control_state.mode)

    if control_state.mode == 'fail' then
      control_state.mode = 'none'
      error('control handler fails on purpose')
    elseif control_state.mode == 'http' then
      rspamd_http.request({
        url = http_slow_url,
        config = cfg,
        ev_base = ev_base,
        session = session,
        timeout = 10,
        callback = function(err, code)
          rspamd_logger.infox(cfg, 'coro control: call %s: request done: %s', call,
              err or code)
        end,
      })
    end
  end)
end)

register_test_symbol({
  name = 'CORO_CONTROL_MODE_TEST',
  score = 1.0,
  callback = function(task)
    control_state.mode = header_value(task, 'Coro-Mode', 'none')
    control_state.calls = 0
    task:insert_result('CORO_CONTROL_MODE', 1.0, 'mode=' .. control_state.mode)
  end,
})

--[[ The task given to the callback of a DKIM verification is a task object:
--   its methods work ]]
register_test_symbol({
  name = 'CORO_DKIM_VERIFY_TASK_TEST',
  score = 1.0,
  callback = function(task)
    local dkim_api = rspamd_plugins and rspamd_plugins.dkim

    if not dkim_api then
      task:insert_result('CORO_DKIM_VERIFY_TASK', 1.0, 'dkim=no dkim plugin')
      return
    end

    local verify_ok, verify_err = dkim_api.verify(task, dkim_signature,
        function(cb_task, ok, _, domain)
          cb_task:insert_result('CORO_DKIM_VERIFY_TASK', 1.0, 'verified=' .. tostring(ok),
              'domain=' .. tostring(domain),
              'same_task=' .. tostring(cb_task:get_queue_id() == task:get_queue_id()))
        end)

    if not verify_ok then
      task:insert_result('CORO_DKIM_VERIFY_TASK', 1.0, 'verify=' .. tostring(verify_err))
    end
  end,
})

--[[ map:set_callback() and map:on_load() called twice at config load: the
--   maps are read with the second callbacks, and the replaced callbacks are
--   released (the weak table below loses them once they are collected) ]]
local replaced_map_callbacks = setmetatable({}, { __mode = 'k' })

do
  local cb_map = rspamd_config:add_map({
    type = 'callback',
    url = coro_map_file,
    description = 'coroutines test: callback map, callback set twice',
    callback = function()
      rspamd_logger.infox(rspamd_config, 'coro replaced map: a replaced callback has run')
    end,
  })

  if cb_map then
    local replaced = function()
      rspamd_logger.infox(rspamd_config, 'coro replaced map: a replaced callback has run')
    end
    replaced_map_callbacks[replaced] = 'set_callback'
    cb_map:set_callback(replaced)
    cb_map:set_callback(function(data)
      rspamd_logger.infox(rspamd_config, 'coro replaced map: the second callback has run, %s bytes',
          #tostring(data))
    end)
  end

  local set_map = rspamd_config:add_map({
    type = 'set',
    url = coro_map_file,
    description = 'coroutines test: set map, on_load set twice',
  })

  if set_map then
    local replaced = function()
      rspamd_logger.infox(rspamd_config, 'coro replaced map: a replaced on_load has run')
    end
    replaced_map_callbacks[replaced] = 'on_load'
    set_map:on_load(replaced)
    set_map:on_load(function()
      rspamd_logger.infox(rspamd_config, 'coro replaced map: the second on_load has run, key=%s',
          set_map:get_key('coro.example.com'))
    end)
  end
end

register_test_symbol({
  name = 'CORO_MAP_REPLACED_TEST',
  score = 1.0,
  callback = function(task)
    collectgarbage('collect')
    collectgarbage('collect')

    local kept = {}

    for _, kind in pairs(replaced_map_callbacks) do
      kept[kind] = true
    end

    task:insert_result('CORO_MAP_REPLACED', 1.0,
        'set_callback=' .. (kept.set_callback and 'kept' or 'released'),
        'on_load=' .. (kept.on_load and 'kept' or 'released'))
  end,
})

--[[ rspamd_http.request() takes one table: other arguments are refused ]]
register_test_symbol({
  name = 'CORO_HTTP_ARGS_TEST',
  score = 1.0,
  callback = function(task)
    local ok_pos, err_pos = pcall(rspamd_http.request, http_url, function()
    end)
    local ok_str, err_str = pcall(rspamd_http.request, http_url)

    task:insert_result('CORO_HTTP_ARGS', 1.0,
        error_outcome('positional', ok_pos, err_pos, 'requires a table argument', 'table expected'),
        error_outcome('string', ok_str, err_str, 'requires a table argument', 'table expected'))
  end,
})

--[[ A sync request whose connection fails while request() starts it (TLS to
--   a closed port on Linux): request() returns the error of the connection.
--   The option is the part of the error before the first colon (the rest has
--   the details of the TLS library). ]]
register_test_symbol({
  name = 'CORO_HTTP_START_ERROR_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local err, resp = rspamd_http.request({
      task = task,
      url = 'https://127.0.0.1:1/request',
      timeout = 1,
    })

    return true, 1.0, 'err=' .. (tostring(err):match('^[^:]*')), 'resp=' .. tostring(resp)
  end,
})

--[[ The same request to an upstream: the failed connection counts as one
--   failure of the upstream ]]
register_test_symbol({
  name = 'CORO_HTTP_UPSTREAM_FAIL_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ups = rspamd_upstream_list.create(rspamd_config, '127.0.0.1:1', 1)
    local failures = 0

    ups:add_watcher('failure', function()
      failures = failures + 1
    end)

    local err = rspamd_http.request({
      task = task,
      url = 'https://127.0.0.1:1/request',
      upstream = ups:get_upstream_round_robin(),
      timeout = 1,
    })
    -- A failure reported later would come right after
    task:get_ev_base():sleep(0.1)

    return true, 1.0, 'err=' .. (tostring(err):match('^[^:]*')),
        'failures=' .. tostring(failures)
  end,
})

--[[ The same as CORO_HTTP_CANCELLED_TEST with callbacks in a plain symbol:
--   the callback of the first request (4s) starts a second one, which is in
--   flight at the task timeout (6s) ]]
register_test_symbol({
  name = 'CORO_HTTP_CANCELLED_PLAIN_TEST',
  score = 1.0,
  callback = function(task)
    rspamd_http.request({
      task = task,
      url = http_slow_url,
      timeout = 10,
      callback = function(err, code)
        task:insert_result('CORO_HTTP_CANCELLED_PLAIN_TEST', 1.0,
            'first=' .. (err and ('error:' .. tostring(err)) or tostring(code)))
        rspamd_http.request({
          task = task,
          url = http_slow_url,
          timeout = 10,
          callback = function(second_err)
            rspamd_logger.infox(rspamd_config, 'cancelled plain http: second callback: %s',
                second_err)
          end,
        })
      end,
    })
  end,
})

-- A postfilter that depends on a symbol whose request is cancelled by the
-- task timeout: the session cleanup finishes that symbol, so this one runs
local function register_dependent_postfilter(name, test)
  register_test_symbol({
    name = name,
    test = test,
    type = 'postfilter',
    score = 1.0,
    callback = function(task)
      task:insert_result(name, 1.0, 'dependency_done=' .. tostring(task:has_symbol(test)))
    end,
  })

  rspamd_config:register_dependency(name, test)
end

-- A postfilter that depends on a symbol whose operation is cancelled by the
-- task timeout, and uses the connection that the symbol has stored in the
-- task cache under `key` after the cleanup: no call of it may start anything.
-- use(conn) returns the options of the postfilter
local function register_closed_conn_postfilter(name, test, key, use)
  register_test_symbol({
    name = name,
    test = test,
    type = 'postfilter',
    score = 1.0,
    callback = function(task)
      local conn = task:cache_get(key)

      if not conn then
        task:insert_result(name, 1.0, 'no connection')
        return
      end

      task:insert_result(name, 1.0, unpack_fn(use(conn)))
    end,
  })

  rspamd_config:register_dependency(name, test)
end

register_dependent_postfilter('CORO_HTTP_CANCELLED_DEPENDENT', 'CORO_HTTP_CANCELLED_TEST')
register_dependent_postfilter('CORO_HTTP_CANCELLED_PLAIN_DEPENDENT', 'CORO_HTTP_CANCELLED_PLAIN_TEST')

--[[ Requests of plain symbols in flight at the task timeout (6s): a request
--   timeout of 30s, so only the session cleanup finishes the symbol, and the
--   postfilter that depends on it runs ]]

-- An async TCP request: a BLPOP of 30s, sent to redis as an inline command
register_test_symbol({
  name = 'CORO_TCP_CANCELLED_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_TCP_CANCELLED_TEST', 1.0, 'sent')
    rspamd_tcp.request({
      task = task,
      host = env.REDIS_ADDR or '127.0.0.1',
      port = tonumber(env.REDIS_PORT) or 6379,
      data = 'BLPOP coro_tcp_nokey_cancel 30\r\n',
      read = true,
      timeout = 30,
      callback = function(err)
        rspamd_logger.infox(rspamd_config, 'cancelled tcp: callback: %s', err)
      end,
    })
  end,
})

-- An async redis request: a BLPOP of 8s, whose reply comes after the cleanup
register_test_symbol({
  name = 'CORO_REDIS_ASYNC_CANCELLED_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_REDIS_ASYNC_CANCELLED_TEST', 1.0, 'sent')
    rspamd_redis.make_request({
      task = task,
      host = redis_host,
      timeout = 30,
      cmd = 'BLPOP',
      args = { 'coro_redis_async_cancel', '8' },
      callback = function(err)
        rspamd_logger.infox(rspamd_config, 'cancelled async redis: callback: %s', err)
      end,
    })
  end,
})

-- A command of a sync connection that is never executed: the coroutine
-- returns, the command alone holds the symbol
register_test_symbol({
  name = 'CORO_REDIS_NOEXEC_CANCELLED_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_redis(task, 60.0)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    conn:add_cmd('BLPOP', { 'coro_redis_noexec_cancel', '30' })

    return true, 1.0, 'sent'
  end,
})

-- A UDP request to a port nobody listens on: the read waits
register_test_symbol({
  name = 'CORO_UDP_CANCELLED_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_UDP_CANCELLED_TEST', 1.0, 'sent')
    rspamd_udp.sendto({
      task = task,
      host = '127.0.0.1',
      port = udp_closed_port,
      data = 'cancelled',
      timeout = 30,
      callback = function(ok, data)
        rspamd_logger.infox(rspamd_config, 'cancelled udp: callback: %s %s', ok, data)
      end,
    })
  end,
})

register_dependent_postfilter('CORO_TCP_CANCELLED_DEPENDENT', 'CORO_TCP_CANCELLED_TEST')
register_dependent_postfilter('CORO_REDIS_ASYNC_CANCELLED_DEPENDENT', 'CORO_REDIS_ASYNC_CANCELLED_TEST')
register_dependent_postfilter('CORO_REDIS_NOEXEC_CANCELLED_DEPENDENT',
    'CORO_REDIS_NOEXEC_CANCELLED_TEST')
register_dependent_postfilter('CORO_UDP_CANCELLED_DEPENDENT', 'CORO_UDP_CANCELLED_TEST')

-- An async redis SUBSCRIBE: the subscription holds the symbol after its
-- confirmation, until the session cleanup
register_test_symbol({
  name = 'CORO_REDIS_SUBSCRIBE_CANCELLED_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_REDIS_SUBSCRIBE_CANCELLED_TEST', 1.0, 'sent')
    rspamd_redis.make_request({
      task = task,
      host = redis_host,
      timeout = 30,
      cmd = 'SUBSCRIBE',
      args = { 'coro_redis_subscribe_cancel' },
      callback = function(err, data)
        rspamd_logger.infox(rspamd_config, 'cancelled redis subscription: callback: %s %s',
            err, type(data))
      end,
    })
  end,
})

register_dependent_postfilter('CORO_REDIS_SUBSCRIBE_CANCELLED_DEPENDENT',
    'CORO_REDIS_SUBSCRIBE_CANCELLED_TEST')

--[[ The connection of an async redis request, kept by the Lua code (in the
--   task cache, and after the task, so that the late reply is read): a BLPOP
--   of 8s, cancelled by the session cleanup at the task timeout (6s). A
--   postfilter adds a command to it then: the symbol of the connection is
--   finished, so the connection takes no more commands, and the reply of the
--   BLPOP that comes later is dropped ]]
local redis_reused_key = 'coro_redis_async_reused_conn'
local kept_redis_conns = {}

register_test_symbol({
  name = 'CORO_REDIS_ASYNC_REUSED_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_REDIS_ASYNC_REUSED_TEST', 1.0, 'sent')
    local _, conn = rspamd_redis.make_request({
      task = task,
      host = redis_host,
      timeout = 30,
      cmd = 'BLPOP',
      args = { 'coro_redis_async_reused', '8' },
      callback = function(err)
        rspamd_logger.infox(rspamd_config, 'reused async redis: BLPOP callback: %s', err)
      end,
    })

    task:cache_set(redis_reused_key, conn)
    kept_redis_conns[#kept_redis_conns + 1] = conn
    -- The log tag of the task is the one of the connection
    rspamd_logger.infox(task, 'reused async redis: BLPOP sent')
  end,
})

register_dependent_postfilter('CORO_REDIS_ASYNC_REUSED_DEPENDENT', 'CORO_REDIS_ASYNC_REUSED_TEST')
register_closed_conn_postfilter('CORO_REDIS_ASYNC_REUSED_ADD_CMD', 'CORO_REDIS_ASYNC_REUSED_TEST',
    redis_reused_key, function(conn)
      return { 'add_cmd=' .. results_outcome(conn:add_cmd(function(err, data)
        rspamd_logger.infox(rspamd_config, 'reused async redis: PING callback: %s %s', err, data)
      end, 'PING', {})) }
    end)

--[[ An async redis subscription of a task, kept by the Lua code: the session
--   cleanup at the task timeout (6s) finishes it, and the connection stays
--   subscribed. The task is gone when a message comes: the message is read
--   and dropped, the callback is not called for it ]]
local kept_subscriptions = {}

register_test_symbol({
  name = 'CORO_REDIS_SUBSCRIBE_KEPT_TEST',
  score = 1.0,
  callback = function(task)
    task:insert_result('CORO_REDIS_SUBSCRIBE_KEPT_TEST', 1.0, 'sent')
    local _, conn = rspamd_redis.make_request({
      task = task,
      host = redis_host,
      timeout = 30,
      cmd = 'SUBSCRIBE',
      args = { 'coro_redis_subscribe_kept' },
      callback = function(err, data)
        rspamd_logger.infox(rspamd_config, 'kept redis subscription: %s %s', err,
            type(data) == 'table' and tostring(data[1]) or tostring(data))
      end,
    })

    kept_subscriptions[#kept_subscriptions + 1] = conn
    -- The log tag of the task is the one of the connection
    rspamd_logger.infox(task, 'kept redis subscription: subscribing')
  end,
})

register_dependent_postfilter('CORO_REDIS_SUBSCRIBE_KEPT_DEPENDENT', 'CORO_REDIS_SUBSCRIBE_KEPT_TEST')

--[[ An async redis subscription made by the scanner worker at start, with
--   no task: nothing finishes it, it gets every message of its channel ]]
local taskless_subscriptions = {}

rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if worker:get_type() ~= 'normal' then
    return
  end

  local ok, conn = rspamd_redis.make_request({
    config = cfg,
    ev_base = ev_base,
    host = redis_host,
    timeout = 30,
    cmd = 'SUBSCRIBE',
    args = { 'coro_redis_taskless' },
    callback = function(err, data)
      if type(data) == 'table' then
        rspamd_logger.infox(cfg, 'taskless redis subscription: %s %s %s', err,
            tostring(data[1]), tostring(data[3]))
      else
        rspamd_logger.infox(cfg, 'taskless redis subscription: %s %s', err, data)
      end
    end,
  })

  rspamd_logger.infox(cfg, 'taskless redis subscription: request=%s', ok)
  taskless_subscriptions[#taskless_subscriptions + 1] = conn
end)

--[[ A coroutine that waits in a sync TCP read_once() (a BLPOP of 30s sent to
--   redis) at the task timeout (6s). The session cleanup closes the
--   connection and terminates the coroutine, which is not resumed: the symbol
--   keeps the result inserted before the wait. A postfilter uses the
--   connection afterwards (task cache). ]]
local tcp_read_cancel_key = 'coro_tcp_read_cancel_conn'

register_test_symbol({
  name = 'CORO_TCP_SYNC_CANCELLED_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = rspamd_tcp.connect_sync({
      task = task,
      host = env.REDIS_ADDR or '127.0.0.1',
      port = tonumber(env.REDIS_PORT) or 6379,
      timeout = 30,
    })

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    task:cache_set(tcp_read_cancel_key, conn)
    task:insert_result('CORO_TCP_SYNC_CANCELLED_TEST', 1.0, 'waiting')
    local w_ok, w_err = conn:write('BLPOP coro_tcp_sync_cancel 30\r\n')
    rspamd_logger.infox(task, 'coro tcp cancel: waiting in read_once(), write=%s',
        ok_outcome(w_ok, w_err))
    local r_ok, r_data = conn:read_once()
    rspamd_logger.infox(rspamd_config, 'coro tcp cancel: resumed after read_once(): %s',
        ok_outcome(r_ok, r_data))

    return true, 1.0, 'read=' .. ok_outcome(r_ok, r_data)
  end,
})

--[[ Sync TCP operations pending at the task timeout (6s), on a socket of
--   the test (Coro-Port) that never accepts: a write of 16 MB that nobody
--   reads, and a connection to a socket whose accept queue is full. The
--   session cleanup closes the connection and terminates the coroutine,
--   which is not resumed: the symbol keeps the result inserted before the
--   wait. ]]
local tcp_write_cancel_key = 'coro_tcp_write_cancel_conn'

local function connect_test_port(task)
  return rspamd_tcp.connect_sync({
    task = task,
    host = '127.0.0.1',
    port = tonumber(header_value(task, 'Coro-Port', '0')),
    timeout = 30,
  })
end

register_test_symbol({
  name = 'CORO_TCP_SYNC_WRITE_CANCELLED_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local ok, conn = connect_test_port(task)

    if not ok then
      return true, 1.0, 'connect=' .. tostring(conn)
    end

    task:cache_set(tcp_write_cancel_key, conn)
    task:insert_result('CORO_TCP_SYNC_WRITE_CANCELLED_TEST', 1.0, 'waiting')
    rspamd_logger.infox(task, 'coro tcp write cancel: waiting in write()')
    -- Far more than the socket buffers of both ends take
    local w_ok, w_err = conn:write(string.rep('x', 16 * 1024 * 1024))
    rspamd_logger.infox(rspamd_config, 'coro tcp write cancel: resumed after write(): %s',
        ok_outcome(w_ok, w_err))

    return true, 1.0, 'write=' .. ok_outcome(w_ok, w_err)
  end,
})

register_test_symbol({
  name = 'CORO_TCP_SYNC_CONNECT_CANCELLED_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    task:insert_result('CORO_TCP_SYNC_CONNECT_CANCELLED_TEST', 1.0, 'waiting')
    rspamd_logger.infox(task, 'coro tcp connect cancel: waiting in connect_sync()')
    local ok, conn = connect_test_port(task)
    rspamd_logger.infox(rspamd_config, 'coro tcp connect cancel: resumed after connect_sync(): %s',
        ok_outcome(ok, conn))

    return true, 1.0, 'connect=' .. ok_outcome(ok, conn)
  end,
})

--[[ A periodic waits on a sync connection of a task (Coro-Conn: redis or
--   tcp): the coroutine symbol connects, sends a BLPOP of 30s and starts the
--   periodic, which waits for the reply (exec() or read_once()). The task
--   timeout (6s) cancels the operation: the symbol is finished, the run of
--   the periodic is terminated and planned again (0.1s). The next run does
--   not use the connection and stops. ]]

-- Sends the BLPOP; returns the function that waits for its reply, or nil
-- and an error
local periodic_conn_kinds = {
  redis = function(task)
    local ok, conn = connect_redis(task, 60.0)

    if not ok then
      return nil, conn
    end

    conn:add_cmd('BLPOP', { 'coro_periodic_task_conn', '30' })

    return function()
      return results_outcome(conn:exec())
    end
  end,
  tcp = function(task)
    local ok, conn = rspamd_tcp.connect_sync({
      task = task,
      host = env.REDIS_ADDR or '127.0.0.1',
      port = tonumber(env.REDIS_PORT) or 6379,
      timeout = 30,
    })

    if not ok then
      return nil, conn
    end

    local w_ok, w_err = conn:write('BLPOP coro_periodic_task_conn 30\r\n')

    if not w_ok then
      return nil, w_err
    end

    return function()
      return results_outcome(conn:read_once())
    end
  end,
}

register_test_symbol({
  name = 'CORO_PERIODIC_TASK_CONN_TEST',
  score = 1.0,
  flags = 'coro',
  callback = function(task)
    local kind = header_value(task, 'Coro-Conn', 'redis')
    local st = { runs = 0, waiting = false }
    local wait, err = periodic_conn_kinds[kind](task)

    if not wait then
      return true, 1.0, 'connect=' .. tostring(err)
    end

    -- The periodic holds the connection, not the task
    rspamd_config:add_periodic(task:get_ev_base(), 0.1, function(cfg)
      st.runs = st.runs + 1

      if st.runs > 1 then
        rspamd_logger.infox(cfg, 'periodic of a task %s connection: run %s', kind, st.runs)

        return false
      end

      st.waiting = true
      rspamd_logger.infox(cfg, 'periodic of a task %s connection: waiting', kind)
      local res = wait()
      rspamd_logger.infox(cfg, 'periodic of a task %s connection: resumed: %s', kind, res)

      return false
    end)

    local waiting = sleep_until(task, function()
      return st.waiting
    end, 0.05, 40)

    return true, 1.0, 'periodic_waiting=' .. tostring(waiting)
  end,
})

-- The coroutines of these symbols are terminated by the session cleanup,
-- which finishes the symbols
register_dependent_postfilter('CORO_REDIS_CANCEL_DEPENDENT', 'CORO_REDIS_CANCEL_TEST')
register_dependent_postfilter('CORO_TCP_SYNC_CANCELLED_DEPENDENT', 'CORO_TCP_SYNC_CANCELLED_TEST')
register_dependent_postfilter('CORO_TCP_SYNC_WRITE_CANCELLED_DEPENDENT',
    'CORO_TCP_SYNC_WRITE_CANCELLED_TEST')
register_dependent_postfilter('CORO_TCP_SYNC_CONNECT_CANCELLED_DEPENDENT',
    'CORO_TCP_SYNC_CONNECT_CANCELLED_TEST')
register_dependent_postfilter('CORO_PERIODIC_TASK_CONN_DEPENDENT', 'CORO_PERIODIC_TASK_CONN_TEST')

-- The connections that the cleanup has closed, used afterwards
register_closed_conn_postfilter('CORO_REDIS_CANCEL_REUSE', 'CORO_REDIS_CANCEL_TEST',
    redis_cancel_key, function(conn)
      return { 'add_cmd=' .. results_outcome(conn:add_cmd('PING', {})),
               'exec=' .. results_outcome(conn:exec()) }
    end)

local function tcp_closed_outcome(conn)
  return { 'read=' .. results_outcome(conn:read_once()),
           'write=' .. results_outcome(conn:write('PING\r\n')),
           'close=' .. results_outcome(conn:close()) }
end

register_closed_conn_postfilter('CORO_TCP_SYNC_CANCELLED_REUSE', 'CORO_TCP_SYNC_CANCELLED_TEST',
    tcp_read_cancel_key, tcp_closed_outcome)
register_closed_conn_postfilter('CORO_TCP_SYNC_WRITE_CANCELLED_REUSE',
    'CORO_TCP_SYNC_WRITE_CANCELLED_TEST', tcp_write_cancel_key, tcp_closed_outcome)

--[[ Plain symbols registered by coroutines: by a coroutine created by the Lua
--   code at config load and collected right after, and by two on_load
--   coroutines of the scanner worker, one that stays suspended (a sync sleep)
--   while the worker lives and one that fails, whose thread is terminated and
--   collected. Each symbol runs on a thread of its own, never on the coroutine
--   that has registered it. The weak table keeps the registering coroutines
--   while something else holds them: an option tells what has become of the
--   coroutine (collected, or its status). ]]
local late_registrars = setmetatable({}, { __mode = 'v' })

local function register_late_symbol(name)
  late_registrars[name] = coroutine.running()

  register_test_symbol({
    name = name,
    test = 'CORO_LATE_TEST',
    score = 1.0,
    callback = function()
      local registrar = late_registrars[name]
      local on_registrar = registrar ~= nil and coroutine.running() == registrar

      return true, 1.0, 'thread=' .. (on_registrar and 'registrar' or 'own'),
          'registrar=' .. (registrar and coroutine.status(registrar) or 'collected')
    end,
  })
end

-- With the Coro-GC header, a full garbage collection before the symbols run
register_test_symbol({
  name = 'CORO_LATE_GC',
  test = 'CORO_LATE_TEST',
  type = 'prefilter',
  score = 1.0,
  callback = function(task)
    if header_value(task, 'Coro-GC', 'no') == 'full' then
      collectgarbage('collect')
      collectgarbage('collect')
      task:insert_result('CORO_LATE_GC', 1.0, 'collected')
    end
  end,
})

coroutine.wrap(function()
  register_late_symbol('CORO_LATE_WRAPPED')
end)()

collectgarbage('collect')
collectgarbage('collect')

rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if worker:get_type() ~= 'normal' then
    return
  end

  register_late_symbol('CORO_LATE_SUSPENDED')
  cfg:promote_symbols_cache_resort()
  rspamd_logger.infox(cfg, 'coro late symbol: registered by a coroutine that sleeps')
  -- Longer than the suite
  ev_base:sleep(86400)
end)

rspamd_config:add_on_load(function(cfg, _, worker)
  if worker:get_type() ~= 'normal' then
    return
  end

  register_late_symbol('CORO_LATE_FAILED')
  cfg:promote_symbols_cache_resort()
  error('coro late symbol: the registering coroutine fails on purpose')
end)

--[[ worker:add_control_handler() called twice for one command (`rspamadm
--   control reload`): the second handler serves the commands, the first one is
--   released. The second handler replaces itself by a third one and fails;
--   the third one serves the next command. ]]
rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if worker:get_type() ~= 'normal' then
    return
  end

  worker:add_control_handler(cfg, ev_base, 'reload', function()
    rspamd_logger.infox(cfg, 'coro control: the first reload handler has run')
  end)
  worker:add_control_handler(cfg, ev_base, 'reload', function()
    rspamd_logger.infox(cfg, 'coro control: the second reload handler has run')
    worker:add_control_handler(cfg, ev_base, 'reload', function()
      rspamd_logger.infox(cfg, 'coro control: the third reload handler has run')
    end)
    error('the second reload handler replaces itself and fails')
  end)
end)

--[[ A UDP request with a negative retransmit count: it is not retransmitted,
--   the callback gets the read timeout (0.2s) ]]
register_test_symbol({
  name = 'CORO_UDP_RETRANSMITS_TEST',
  score = 1.0,
  callback = function(task)
    local started = rspamd_util.get_time()

    rspamd_udp.sendto({
      task = task,
      host = '127.0.0.1',
      port = udp_closed_port,
      data = 'retransmits',
      timeout = 0.2,
      retransmits = -1,
      callback = function(ok, data)
        task:insert_result('CORO_UDP_RETRANSMITS_TEST', 1.0, 'udp=' .. ok_outcome(ok, data),
            'fast=' .. tostring(rspamd_util.get_time() - started < 2))
      end,
    })
  end,
})

--[[ A coroutine that waits in a sync redis exec() (a BLPOP of 30s) while the
--   scanner worker terminates: the worker frees its Lua state and its redis
--   pool with the command in flight. A periodic started by a scan, so that no
--   task holds it. ]]
register_test_symbol({
  name = 'CORO_SHUTDOWN_PARK_TEST',
  score = 1.0,
  callback = function(task)
    rspamd_config:add_periodic(task:get_ev_base(), 0, function(cfg, ev_base)
      local ok, conn = rspamd_redis.connect_sync({
        config = cfg,
        ev_base = ev_base,
        host = redis_host,
        timeout = 60,
      })

      if not ok then
        rspamd_logger.infox(cfg, 'coro shutdown: cannot connect: %s', conn)
        return false
      end

      conn:add_cmd('BLPOP', { 'coro_redis_nokey_shutdown', '30' })
      rspamd_logger.infox(cfg, 'coro shutdown: waiting in exec()')
      local res = results_outcome(conn:exec())
      rspamd_logger.infox(cfg, 'coro shutdown: resumed after exec(): %s', res)

      return false
    end)

    task:insert_result('CORO_SHUTDOWN_PARK', 1.0, 'periodic=added')
  end,
})

--[[ The finish script, run by the scanner worker on a task of its own when it
--   terminates, waits for a sync DNS request, the only event of that task.
--   Resumed by the reply, it makes a request that fails inside request() (on
--   Linux): that request removes its event while the coroutine runs, which
--   must not finish and free the task under it. The task is gone afterwards,
--   so the result is a log line. ]]
rspamd_config:register_finish_script(function(task)
  local opts = { dns_outcome('dns', sync_dns(task)) }
  local calls = 0
  local ret = rspamd_http.request({
    task = task,
    url = 'https://127.0.0.1:1/request',
    timeout = 1,
    callback = function()
      calls = calls + 1
    end,
  })

  opts[#opts + 1] = 'http=' .. http_callback_outcome(ret, calls)
  opts[#opts + 1] = dns_outcome('dns_again', sync_dns(task))
  rspamd_logger.infox(rspamd_config, 'coro finish script: %s', table.concat(opts, ', '))
end)
