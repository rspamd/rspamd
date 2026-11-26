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
local rspamd_http = require "rspamd_http"
local rspamd_redis = require "rspamd_redis"
local rspamd_tcp = require "rspamd_tcp"
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
