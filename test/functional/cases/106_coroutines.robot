*** Settings ***
Documentation   APIs that suspend their caller (sync DNS, HTTP, TCP, redis,
...             ev_base:sleep): concurrent tasks in one coroutine symbol, calls
...             from places that cannot be suspended, coroutines that outlive
...             their task, tasks that are finishing, async sleep callbacks,
...             replies that come while nobody waits for them, callbacks
...             registered by a coroutine that is suspended or gone, symbol
...             results, periodics, DNS replies that come as the last event of
...             their task, Lua control handlers, finish scripts, requests
...             cancelled by the task timeout and their connections used
...             afterwards, redis subscriptions, symbols registered by
...             coroutines. The last test stops rspamd.
...             A scan runs the symbol of lua/coroutines.lua named by its
...             Coro-Test header. Every test checks that the only scanner worker
...             is still the same process (a crashed worker is restarted by the
...             main process).
Suite Setup     Coroutines Setup
Suite Teardown  Coroutines Teardown
Test Setup      Coroutines Test Setup
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/coroutines.conf
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
# Fake DNS record of configs/coroutines.conf
${DNS_ANSWER}           127.0.0.2
# Pid of the scanner worker, taken before the first test
${WORKER_PID}           ${NONE}
# The status of a failed control command: EINVAL, as the C handlers report errors
${CONTROL_FAILED}       22

*** Test Cases ***
Two tasks in one coroutine symbol at once
  [Documentation]  Both scans wait inside the symbol until the other one has
  ...              entered it (overlapped=true proves they did), and each gets
  ...              its own result well before the task timeout (6s)
  ${first} =  Start Process  ${RSPAMC}  -j  -t  30  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}
  ...  --header  Coro-Test\=CORO_CONCURRENT_TEST  --header  Coro-Tag\=first  ${MESSAGE}
  ...  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  Scan File  ${MESSAGE}  Coro-Test=CORO_CONCURRENT_TEST  Coro-Tag=second
  Expect Symbol With Exact Options  CORO_CONCURRENT_TEST  tag=second  overlapped=true
  ...  dns=${DNS_ANSWER}
  Should Be True  ${SCAN_RESULT}[time_real] < 5
  ${result} =  Wait For Process  ${first}  timeout=30s  on_timeout=kill
  Log  ${result.stdout}
  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  ${first_result} =  Evaluate  json.loads($result.stdout)  modules=json
  Set Test Variable  ${SCAN_RESULT}  ${first_result}
  Expect Symbol With Exact Options  CORO_CONCURRENT_TEST  tag=first  overlapped=true
  ...  dns=${DNS_ANSWER}
  Should Be True  ${SCAN_RESULT}[time_real] < 5
  Coroutines Still Work

Sync API from a symbol that is not a coroutine
  Scan File  ${MESSAGE}  Coro-Test=CORO_PLAIN_SYNC_TEST
  Expect Symbol With Exact Options  CORO_PLAIN_SYNC  dns=error:coroutine
  ...  sleep=error:coroutine  http=error:coroutine  tcp=error:coroutine
  Coroutines Still Work

Sync API from async callbacks of a plain symbol
  [Documentation]  A task timer, a DNS resolver callback and an HTTP callback
  ...              call sync APIs after the symbol has returned
  Scan File  ${MESSAGE}  Coro-Test=CORO_ASYNC_CB_PLAIN_TEST
  Expect Async Callback Results
  Coroutines Still Work

Sync API from async callbacks while their coroutine is suspended
  [Documentation]  The same callbacks, started by a coroutine symbol that sleeps
  ...              until all of them have run
  Scan File  ${MESSAGE}  Coro-Test=CORO_ASYNC_CB_CORO_TEST
  Expect Async Callback Results
  Expect Symbol With Exact Options  CORO_ASYNC_CB_CORO_TEST  callbacks=3
  Coroutines Still Work

Sync API from a coroutine created by Lua code
  [Documentation]  coroutine.wrap and coroutine.create inside a coroutine symbol;
  ...              the symbol itself can still be suspended afterwards
  Scan File  ${MESSAGE}  Coro-Test=CORO_USER_COROUTINE_TEST
  Expect Symbol With Exact Options  CORO_USER_COROUTINE_TEST  wrap_dns=error:coroutine
  ...  create_sleep=error:coroutine  create_http=error:coroutine  own_dns=${DNS_ANSWER}
  Coroutines Still Work

Sync API from a Lua function called by a C function
  [Documentation]  table.sort comparator and string.gsub replacement function
  ...              inside a coroutine symbol: no yield through those C functions
  Scan File  ${MESSAGE}  Coro-Test=CORO_NOT_YIELDABLE_TEST
  Expect Symbol With Exact Options  CORO_NOT_YIELDABLE_TEST  sort_dns=error:coroutine
  ...  gsub_sleep=error:coroutine  own_dns=${DNS_ANSWER}
  Coroutines Still Work

Sync TCP and sleep, then sync DNS in the same coroutine
  [Documentation]  The coroutine resumed by a TCP connect (to an IP literal, then
  ...              to a closed port) or by a sleep still accounts its DNS request
  ...              to its own symbol
  Scan File  ${MESSAGE}  Coro-Test=CORO_TCP_DNS_TEST
  Expect Symbol With Exact Options  CORO_TCP_DNS_TEST  tcp=true  dns_after_tcp=${DNS_ANSWER}
  ...  refused=false  dns_after_refused=${DNS_ANSWER}  dns_after_sleep=${DNS_ANSWER}
  Coroutines Still Work

Sync sleep longer than the task timeout
  [Documentation]  The symbol sleeps 10s, the task times out after 6s; the sleep
  ...              must not wake up a coroutine of a freed task at 10s. The
  ...              timeout ends the sleep early with false, "task is finishing";
  ...              then task:add_timer() refuses and one more sleep fails
  Scan File  ${MESSAGE}  Coro-Test=CORO_LONG_SLEEP_TEST  Coro-Sleep=10
  # The sleeping symbol holds the task until task_timeout, not to the end of the sleep
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  Expect Symbol With Exact Options  CORO_LONG_SLEEP_TEST  sleep=false:task is finishing
  ...  add_timer=false:task is finishing  sleep_again=error:terminating
  # Past the moment the sleep would have ended and the refused timer would have fired
  Sleep  5s
  Log Since Test Start Should Not Contain  a timer of a finishing task has fired
  Coroutines Still Work

Client gives up while a coroutine symbol sleeps
  [Documentation]  rspamc gives up after 1s, the worker destroys the task while
  ...              the symbol sleeps (4s): the same early end of the sleep as on
  ...              a timeout, reported by the log as there is no reply
  ${client} =  Start Process  ${RSPAMC}  -t  1  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}
  ...  --header  Coro-Test\=CORO_LONG_SLEEP_TEST  --header  Coro-Sleep\=4  ${MESSAGE}
  ...  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  ${result} =  Wait For Process  ${client}  timeout=30s  on_timeout=kill
  Log  ${result.stdout}
  Log  ${result.stderr}
  Should Not Be Equal As Integers  ${result.rc}  0  msg=rspamc did not time out
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Log Since Test Start Should Contain  the peer has closed connection unexpectedly
  ${outcome} =  Catenate  sleep=false:task is finishing,  add_timer=false:task is finishing,
  ...  sleep_again=error:terminating
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Log Since Test Start Should Contain  ${outcome}
  # Past the moment the sleep would have ended
  Sleep  4s
  Log Since Test Start Should Not Contain  a timer of a finishing task has fired
  Coroutines Still Work

Sync sleep and task timer of a task that is not finishing
  [Documentation]  Both return nothing, and the timer fires
  Scan File  ${MESSAGE}  Coro-Test=CORO_NORMAL_RETURNS_TEST
  Expect Symbol With Exact Options  CORO_NORMAL_RETURNS_TEST  add_timer=none  sleep=none
  ...  timer=fired
  Coroutines Still Work

Coroutine outlives its task on a request not bound to the task
  [Documentation]  The symbol waits for an HTTP request made without the task
  ...              (dummy_http.py answers it after 4s). The task does not wait
  ...              for it and is destroyed after the reply while the coroutine
  ...              is suspended; the late reply must not resume it
  Scan File  ${MESSAGE}  Coro-Test=CORO_ORPHAN_HTTP_TEST
  Do Not Expect Symbol  CORO_ORPHAN_HTTP_TEST
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Log Since Test Start Should Contain  terminate a suspended thread: its task is destroyed
  # The reply comes 4s after the request
  Wait Until Keyword Succeeds  60x  0.2s
  ...  Log Since Test Start Should Contain  do not resume a terminated coroutine
  # The request was in flight when the task was destroyed
  Log Since Test Start Should Contain In Order
  ...  orphan coro: waiting for a request that is not bound to the task
  ...  terminate a suspended thread: its task is destroyed
  ...  do not resume a terminated coroutine
  Log Since Test Start Should Not Contain  orphan coro: resumed after the request
  Coroutines Still Work

Sync API from an async sleep callback
  [Documentation]  The callback of ev_base:sleep(t, cb) runs while its
  ...              coroutine is suspended, on a thread that cannot be suspended
  Scan File  ${MESSAGE}  Coro-Test=CORO_ASYNC_SLEEP_SYNC_TEST
  Expect Symbol With Exact Options  CORO_ASYNC_SLEEP_SYNC_TEST  dns=error:coroutine
  ...  sleep=error:coroutine  http=error:coroutine  tcp=error:coroutine
  Coroutines Still Work

Async sleep callback fails while its coroutine is suspended
  [Documentation]  The callback raises an error while the coroutine that has
  ...              started it sleeps; the coroutine is resumed as usual
  Scan File  ${MESSAGE}  Coro-Test=CORO_ASYNC_SLEEP_CB_ERROR_TEST
  Expect Symbol With Exact Options  CORO_ASYNC_SLEEP_CB_ERROR_TEST  cb_fired=true
  ...  dns=${DNS_ANSWER}
  Log Since Test Start Should Contain In Order  call to sleep callback failed
  ...  async sleep callback fails on purpose
  Coroutines Still Work

Async sleep callbacks of a coroutine that has failed
  [Documentation]  The coroutine starts two async sleeps and fails; its thread
  ...              is terminated and collected (0.5s) before the last callback
  ...              runs (1s) on a thread of its own
  Scan File  ${MESSAGE}  Coro-Test=CORO_ASYNC_SLEEP_FAILED_TEST
  Do Not Expect Symbol  CORO_ASYNC_SLEEP_FAILED_TEST
  Log Since Test Start Should Contain In Order  call to coroutine (CORO_ASYNC_SLEEP_FAILED_TEST) failed
  ...  the coroutine fails on purpose
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Log Since Test Start Should Contain  async sleep of a failed coroutine: callback has run
  Log Since Test Start Should Contain In Order
  ...  async sleep of a failed coroutine: garbage collected
  ...  async sleep of a failed coroutine: callback has run, sleep=error:coroutine
  Coroutines Still Work

Sync redis from a symbol that is not a coroutine
  [Documentation]  add_cmd() is refused before the command is sent, so nothing
  ...              holds the task until the task timeout (6s)
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_PLAIN_TEST
  Expect Symbol With Exact Options  CORO_REDIS_PLAIN  connect=true  add_cmd=error:coroutine
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Coroutines Still Work

Two coroutines wait on one sync redis connection
  [Documentation]  The second exec() on a connection, made while the first one
  ...              waits for BLPOP (1s), is refused and does not take the
  ...              place of the first one
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_TWO_WAITERS_TEST
  Expect Symbol With Exact Options  CORO_REDIS_TWO_WAITERS_TEST  exec=true
  Expect Symbol With Exact Options  CORO_REDIS_SECOND_WAITER
  ...  exec=false:another exec() is in progress on this connection
  Should Be True  ${SCAN_RESULT}[time_real] < 4
  Coroutines Still Work

Sync redis exec() after the reply has come during a BLPOP
  [Documentation]  The coroutine waits for a BLPOP (0.3s) on a second connection
  ...              while the reply of the first one comes; exec() returns it,
  ...              and the command does not hold the task until the task
  ...              timeout (6s)
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_EARLY_REPLY_TEST  Coro-Wait=blpop
  Expect Symbol With Exact Options  CORO_REDIS_EARLY_REPLY_TEST  blpop=true  exec=true:PONG
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Log Since Test Start Should Not Contain  processing of task time out
  Coroutines Still Work

Sync redis exec() after the reply has come during a sleep
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_EARLY_REPLY_TEST  Coro-Wait=sleep
  Expect Symbol With Exact Options  CORO_REDIS_EARLY_REPLY_TEST  sleep=none  exec=true:PONG
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Log Since Test Start Should Not Contain  processing of task time out
  Coroutines Still Work

Sync redis add_cmd and exec repeated on one connection
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_REPEAT_TEST
  Expect Symbol With Exact Options  CORO_REDIS_REPEAT_TEST  del=true
  ...  incr=true:1/true:2/true:3  pipeline=true:4:true:4
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Coroutines Still Work

Sync redis command that exec() never asks for
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_NO_EXEC_TEST
  Expect Symbol With Exact Options  CORO_REDIS_NO_EXEC_TEST  add_cmd=true
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Log Since Test Start Should Not Contain  processing of task time out
  Coroutines Still Work

Sync redis reply taken by a dependent symbol
  [Documentation]  A coroutine symbol sends a command and returns, the symbol
  ...              that depends on it calls exec(). The reply starts the
  ...              dependent symbol, so that exec() runs while the command of
  ...              the reply is being released
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_HANDOVER_TEST
  Expect Symbol With Exact Options  CORO_REDIS_HANDOVER_TEST  add_cmd=true
  Expect Symbol With Exact Options  CORO_REDIS_HANDOVER_COLLECT  exec=true:PONG
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Log Since Test Start Should Not Contain  processing of task time out
  Coroutines Still Work

Sync redis command with more than one reply
  [Documentation]  SUBSCRIBE to two channels is confirmed twice: exec() returns
  ...              the first confirmation and the second one is ignored
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_SUBSCRIBE_TEST
  Expect Symbol With Exact Options  CORO_REDIS_SUBSCRIBE_TEST  exec=true
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Log Since Test Start Should Not Contain  processing of task time out
  Coroutines Still Work

Sync redis exec() with more replies than the Lua stack can take
  [Documentation]  4100 replies, 2 stack slots each: more than LuaJIT allows
  Scan File  ${MESSAGE}  Coro-Test=CORO_REDIS_BIG_PIPELINE_TEST
  Expect Symbol  CORO_REDIS_BIG_PIPELINE_TEST
  ${options} =  Set Variable  ${SCAN_RESULT}[symbols][CORO_REDIS_BIG_PIPELINE_TEST][options]
  IF  'vm=luajit' in $options
    Expect Symbol With Exact Options  CORO_REDIS_BIG_PIPELINE_TEST  vm=luajit  values=2
    ...  exec=false:cannot resize stack to fit 4100 replies
  ELSE
    Expect Symbol With Exact Options  CORO_REDIS_BIG_PIPELINE_TEST  vm=lua  values=8200
    ...  exec=true:PONG
  END
  Should Be True  ${SCAN_RESULT}[time_real] < 5
  Coroutines Still Work

Sync redis exec() cancelled by the task timeout
  [Documentation]  The coroutine waits for a BLPOP of 30s; the task timeout
  ...              (6s) closes the connection, which ends the BLPOP on the
  ...              server, and terminates the coroutine, which finishes the
  ...              symbol: the postfilters that depend on it run, and the
  ...              connection refuses what one of them asks of it
  Redis Blocked Clients Should Be  0
  ${client} =  Start Process  ${RSPAMC}  -j  -t  30  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}
  ...  --header  Coro-Test\=CORO_REDIS_CANCEL_TEST  ${MESSAGE}
  ...  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  1
  ${result} =  Wait For Process  ${client}  timeout=30s  on_timeout=kill
  Log  ${result.stdout}
  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  ${scan} =  Evaluate  json.loads($result.stdout)  modules=json
  Set Test Variable  ${SCAN_RESULT}  ${scan}
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  # Only the result inserted before exec(): the coroutine never returns
  Expect Symbol With Exact Options  CORO_REDIS_CANCEL_TEST  waiting
  Expect Symbol With Exact Options  CORO_REDIS_CANCEL_DEPENDENT  dependency_done=true
  Expect Symbol With Exact Options  CORO_REDIS_CANCEL_REUSE
  ...  add_cmd=false:Connection is terminated  exec=false:Connection is terminated
  # Long before the BLPOP would have ended (30s)
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  Log Since Test Start Should Contain  coro redis cancel: waiting in exec()
  Log Since Test Start Should Not Contain  coro redis cancel: resumed after exec()
  Log Since Test Start Should Contain  coroutine of symbol CORO_REDIS_CANCEL_TEST is terminated
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Coroutines Still Work

Sync TCP connection used after idle time
  [Documentation]  A sleep before each write and read: the task waits for
  ...              each operation of the connection, also for the ones started
  ...              when it has been idle
  Scan File  ${MESSAGE}  Coro-Test=CORO_TCP_IDLE_TEST
  Expect Symbol With Exact Options  CORO_TCP_IDLE_TEST  write1=true  read1=true
  ...  write2=true  read2=true
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Log Since Test Start Should Not Contain  symbols are pending without any async events
  Coroutines Still Work

Sync TCP connection closed while another coroutine reads from it
  [Documentation]  The read (of a reply that comes after 4s) ends with an
  ...              error as soon as the other coroutine of the task closes the
  ...              connection
  Scan File  ${MESSAGE}  Coro-Test=CORO_TCP_CLOSE_PENDING_TEST
  Expect Symbol With Exact Options  CORO_TCP_CLOSE_PENDING_TEST  write=true
  ...  read=false:connection is closed  fast=true
  Expect Symbol With Exact Options  CORO_TCP_CLOSER  close=done
  Should Be True  ${SCAN_RESULT}[time_real] < 3
  Coroutines Still Work

Sync HTTP request cancelled by the task timeout
  [Documentation]  The second request is in flight from 4s to 8s, the task
  ...              timeout (6s) resumes the coroutine with an error; the next
  ...              request fails at once
  Scan File  ${MESSAGE}  Coro-Test=CORO_HTTP_CANCELLED_TEST
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  Expect Symbol With Exact Options  CORO_HTTP_CANCELLED_TEST  first=200
  ...  second=session is terminating:nil  third=session is terminating:nil
  # The postfilter that depends on the symbol runs: the cleanup has finished it
  Expect Symbol With Exact Options  CORO_HTTP_CANCELLED_DEPENDENT  dependency_done=true
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Log Since Test Start Should Contain  cancelled coro http: resumed: session is terminating
  # Past the moment the second reply comes (8s)
  Sleep  3s
  Log Since Test Start Should Not Contain  lost HTTP
  Coroutines Still Work

Sync HTTP opaque body outlives its request
  Scan File  ${MESSAGE}  Coro-Test=CORO_HTTP_OPAQUE_BODY_TEST
  Expect Symbol With Exact Options  CORO_HTTP_OPAQUE_BODY_TEST  type=userdata
  ...  body=hello world  second=hello world
  Coroutines Still Work

HTTP callback of a failed connection is called once
  [Documentation]  TLS to a closed port, to an IP literal and to a name. On
  ...              Linux the handshake fails inside request(); elsewhere the
  ...              connection to the IP literal can fail before the request
  ...              is made, and request() returns false then
  Scan File  ${MESSAGE}  Coro-Test=CORO_HTTP_FAILED_CONNECT_TEST
  ${linux} =  Evaluate  sys.platform.startswith('linux')  modules=sys
  IF  ${linux}
    Expect Symbol With Exact Options  CORO_HTTP_FAILED_CONNECT_TEST  ip=once  name=once
  ELSE
    Expect Symbol With Option  CORO_HTTP_FAILED_CONNECT_TEST  name=once
    ${options} =  Convert To List  ${SCAN_RESULT}[symbols][CORO_HTTP_FAILED_CONNECT_TEST][options]
    Should Contain Any  ${options}  ip=once  ip=not called
  END
  Coroutines Still Work

Symbol options that are neither strings nor texts
  Scan File  ${MESSAGE}  Coro-Test=CORO_BAD_OPTION_TEST
  Expect Symbol With Exact Options  CORO_BAD_OPTION_TEST  good  text_opt  in_table
  ...  text_in_table
  Expect Symbol With Exact Options  CORO_BAD_OPTION_PLAIN  good  text_opt  in_table
  ...  text_in_table
  Log Since Test Start Should Contain
  ...  invalid option for CORO_BAD_OPTION_TEST: userdata that is not a text, ignored
  Log Since Test Start Should Contain
  ...  invalid option for CORO_BAD_OPTION_PLAIN: userdata that is not a text, ignored
  Coroutines Still Work

Symbol that returns a function
  Scan File  ${MESSAGE}  Coro-Test=CORO_RETURN_FUNCTION_TEST
  Do Not Expect Symbol  CORO_RETURN_FUNCTION_TEST
  Do Not Expect Symbol  CORO_RETURN_FUNCTION_PLAIN
  Log Since Test Start Should Contain  invalid return value for CORO_RETURN_FUNCTION_TEST: function
  Log Since Test Start Should Contain  invalid return value for CORO_RETURN_FUNCTION_PLAIN: function
  Coroutines Still Work

UDP callback while its coroutine is suspended
  [Documentation]  The callback (read timeout) runs on a thread of its own,
  ...              cannot sleep and fails; the coroutine goes on
  Scan File  ${MESSAGE}  Coro-Test=CORO_UDP_CB_TEST
  Expect Symbol With Exact Options  CORO_UDP_CB_TEST  udp=false:read timeout
  ...  udp_own_thread=true  udp_sleep=error:coroutine  dns=${DNS_ANSWER}
  Log Since Test Start Should Contain  udp callback fails on purpose
  Coroutines Still Work

UDP request holds its symbol until the callback
  [Documentation]  The dependent symbol runs after the callback has inserted
  ...              the result (a read timeout after 0.2s)
  Scan File  ${MESSAGE}  Coro-Test=CORO_UDP_DEP_TEST
  Expect Symbol With Exact Options  CORO_UDP_DEP_TEST  udp=false:read timeout
  Expect Symbol With Exact Options  CORO_UDP_DEPENDENT  dependency_done=true
  Coroutines Still Work

SPF and DKIM callbacks while their coroutine is suspended
  [Documentation]  Twice: the second SPF lookup can come from the cache and
  ...              call back at once
  FOR  ${i}  IN RANGE  2
    Scan File  ${MESSAGE}  Coro-Test=CORO_SPF_DKIM_CB_TEST  From=user@coro-spf.test
    Expect Symbol With Exact Options  CORO_SPF_DKIM_CB_TEST  spf=record
    ...  spf_own_thread=true  spf_sleep=error:coroutine
    ...  dkim=false  dkim_own_thread=true  dkim_sleep=error:coroutine
  END
  Log Since Test Start Should Contain  spf callback fails on purpose
  Log Since Test Start Should Contain  dkim callback fails on purpose
  Coroutines Still Work

Task pool destructor added by a collected coroutine
  [Documentation]  The destructor runs when the task is freed, after the
  ...              reply, on a thread of its own. A use of the collected
  ...              coroutine there is reliably seen with AddressSanitizer only
  Scan File  ${MESSAGE}  Coro-Test=CORO_MEMPOOL_DTOR_TEST
  Expect Symbol With Exact Options  CORO_MEMPOOL_DTOR_TEST  coroutine=true  expression=true
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Log Since Test Start Should Contain  coro mempool destructor: has run, sleep=error:coroutine
  Log Since Test Start Should Contain In Order  call to destructor failed
  ...  mempool destructor fails on purpose
  Coroutines Still Work

Map callbacks registered by a collected coroutine
  [Documentation]  Registered at config load, run when the maps are read at
  ...              start (a crash there stops rspamd before any test)
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Rspamd Log Should Contain  coro map: on_load has run, key=true
  Rspamd Log Should Contain  coro map: callback has run
  Rspamd Log Should Contain  coro map callback fails on purpose
  Rspamd Log Should Contain  coro map on_load fails on purpose
  Coroutines Still Work

Plain symbols registered by coroutines
  [Documentation]  By a coroutine created by the Lua code at config load and
  ...              collected, by an on_load coroutine that sleeps while the
  ...              worker lives and by one that has failed: each symbol runs on
  ...              a thread of its own, also after a full garbage collection
  Rspamd Log Should Contain  coro late symbol: registered by a coroutine that sleeps
  Rspamd Log Should Contain  the registering coroutine fails on purpose
  Scan File  ${MESSAGE}  Coro-Test=CORO_LATE_TEST
  Expect Symbol With Exact Options  CORO_LATE_WRAPPED  thread=own  registrar=collected
  Expect Symbol With Exact Options  CORO_LATE_SUSPENDED  thread=own  registrar=suspended
  # The failed coroutine can be collected already
  Expect Symbol With Option  CORO_LATE_FAILED  thread=own
  Scan File  ${MESSAGE}  Coro-Test=CORO_LATE_TEST  Coro-GC=full
  Expect Symbol With Exact Options  CORO_LATE_GC  collected
  Expect Symbol With Exact Options  CORO_LATE_WRAPPED  thread=own  registrar=collected
  Expect Symbol With Exact Options  CORO_LATE_SUSPENDED  thread=own  registrar=suspended
  Expect Symbol With Exact Options  CORO_LATE_FAILED  thread=own  registrar=collected
  Coroutines Still Work

Periodic suspended for longer than its interval
  [Documentation]  Each run sleeps 0.5s, the interval is 0.1s: no run starts
  ...              while another one is suspended
  Wait Until Keyword Succeeds  30x  0.5s  Periodic Runs Are Over
  Expect Symbol With Exact Options  CORO_PERIODIC  state=done  started=4  finished=4
  ...  max_active=1
  Coroutines Still Work

DNS reply as the last event, a request fails in its callback
  [Documentation]  A plain symbol makes an HTTP request over TLS to a closed
  ...              port of a name: the DNS callback, run for the only event of
  ...              the task, connects, and the connection fails there. The task
  ...              is finished once, after the callback
  Scan File  ${MESSAGE}  Coro-Test=CORO_DNS_LAST_EVENT_TEST
  Expect Symbol With Exact Options  CORO_DNS_LAST_EVENT  calls=1  error=true
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Coroutines Still Work

Coroutine resumed by the DNS reply of the last event
  [Documentation]  The coroutine waits for a sync DNS request, the only event
  ...              of the task. Resumed by the reply, it makes a request that
  ...              fails inside request() on Linux, which adds an event and
  ...              removes it: the task is not finished under the coroutine,
  ...              whose result is in the reply
  Scan File  ${MESSAGE}  Coro-Test=CORO_DNS_LAST_EVENT_CORO_TEST
  ${linux} =  Evaluate  sys.platform.startswith('linux')  modules=sys
  IF  ${linux}
    Expect Symbol With Exact Options  CORO_DNS_LAST_EVENT_CORO_TEST  dns=${DNS_ANSWER}
    ...  http=once  inline=true
  ELSE
    Expect Symbol With Option  CORO_DNS_LAST_EVENT_CORO_TEST  dns=${DNS_ANSWER}
  END
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Coroutines Still Work

Sync DNS requests in a row
  [Documentation]  Bound to the task and to the session of the task only, A
  ...              and PTR, and arguments that are refused
  Scan File  ${MESSAGE}  Coro-Test=CORO_DNS_SEQUENCE_TEST
  Expect Symbol With Exact Options  CORO_DNS_SEQUENCE_TEST  task1=${DNS_ANSWER}
  ...  task2=${DNS_ANSWER}  task3=${DNS_ANSWER}  session=${DNS_ANSWER}  ptr=coro.resolveme
  ...  session_ptr=coro.resolveme  bad_type=error:bad type  bad_option=error:bad type
  ...  task_last=${DNS_ANSWER}
  Coroutines Still Work

DNS callback that starts another request
  Scan File  ${MESSAGE}  Coro-Test=CORO_DNS_NESTED_CB_TEST
  Expect Symbol With Exact Options  CORO_DNS_NESTED_CB_TEST  first=${DNS_ANSWER}
  ...  nested=${DNS_ANSWER}
  Expect Symbol With Exact Options  CORO_DNS_NESTED_DEPENDENT  dependency_done=true
  Coroutines Still Work

Numbers returned by a symbol
  [Documentation]  A finite number that is not zero is the weight (the
  ...              symbols have score 1); zero, NaN, infinity and a string
  ...              insert nothing. Plain and coroutine symbols agree
  Scan File  ${MESSAGE}  Coro-Test=CORO_WEIGHT_TEST
  FOR  ${suffix}  IN  ${EMPTY}  _CORO
    Expect Symbol With Score And Exact Options  CORO_WEIGHT_HALF${suffix}  0.5  half
    Expect Symbol With Score  CORO_WEIGHT_FRACTION${suffix}  2.7
    Expect Symbol With Score And Exact Options  CORO_WEIGHT_OVERRIDE${suffix}  3  override
    Do Not Expect Symbol  CORO_WEIGHT_ZERO${suffix}
    Do Not Expect Symbol  CORO_WEIGHT_NAN${suffix}
    Do Not Expect Symbol  CORO_WEIGHT_INF${suffix}
    Do Not Expect Symbol  CORO_WEIGHT_STRING${suffix}
    Log Since Test Start Should Contain
    ...  invalid return value for CORO_WEIGHT_NAN${suffix}: nan, ignored
    Log Since Test Start Should Contain
    ...  invalid return value for CORO_WEIGHT_INF${suffix}: inf, ignored
    Log Since Test Start Should Contain
    ...  invalid return value for CORO_WEIGHT_STRING${suffix}: string
  END
  Coroutines Still Work

Periodic that fails keeps its interval
  [Documentation]  A failed run is planned again with the last interval; a
  ...              periodic with no interval stops on its error; returning
  ...              false stops a periodic
  Wait Until Keyword Succeeds  30x  0.5s  Periodic Errors Are Over
  Expect Symbol With Exact Options  CORO_PERIODIC_ERRORS  state=done  runs=4  zero=1  num=3
  # No more runs
  Sleep  1s
  Scan File  ${MESSAGE}  Coro-Test=CORO_PERIODIC_ERROR_TEST
  Expect Symbol With Exact Options  CORO_PERIODIC_ERRORS  state=done  runs=4  zero=1  num=3
  Log Since Test Start Should Contain Times
  ...  it is planned again with its last interval, 0.1  3
  Log Since Test Start Should Contain Times
  ...  it is stopped as it has no interval to be planned with  1
  # Registered with no Lua caller
  Log Since Test Start Should Contain  call to periodic script (registered at unknown) failed
  Coroutines Still Work

Lua control handler that fails, then works
  [Documentation]  The worker answers the command whose handler has failed
  ...              at once, with status EINVAL (22), and the handler serves the
  ...              next one
  Set Control Mode  fail
  ${status} =  Normal Worker Control Status  reresolve
  Should Be Equal As Integers  ${status}  ${CONTROL_FAILED}
  Log Since Test Start Should Contain In Order  coro control: call 1 of reresolve
  ...  control handler fails on purpose
  ${status} =  Normal Worker Control Status  reresolve
  Should Be Equal As Integers  ${status}  0
  Log Since Test Start Should Contain  coro control: call 2 of reresolve
  Log Since Test Start Should Not Contain  unknown request id
  Coroutines Still Work

Two Lua control commands at once
  [Documentation]  Each one waits for a request of its own (4s) and gets the
  ...              reply of the worker
  Set Control Mode  http
  ${first} =  Start Process  ${RSPAMADM}  control  -j  -t  15
  ...  -s  ${RSPAMD_TMPDIR}/rspamd.sock  reresolve
  ${second} =  Start Process  ${RSPAMADM}  control  -j  -t  15
  ...  -s  ${RSPAMD_TMPDIR}/rspamd.sock  reresolve
  FOR  ${process}  IN  ${first}  ${second}
    ${result} =  Wait For Process  ${process}  timeout=30s  on_timeout=kill
    ${status} =  Control Reply Status Of Normal Worker  ${result}
    Should Be Equal As Integers  ${status}  0
  END
  Log Since Test Start Should Contain  coro control: call 1: request done: 200
  Log Since Test Start Should Contain  coro control: call 2: request done: 200
  Log Since Test Start Should Not Contain  unknown request id
  Coroutines Still Work

Lua control handler added twice, then replaced by itself
  [Documentation]  The second handler of reload serves it, the first one has
  ...              been released. The second one replaces itself by a third one
  ...              and fails: the command gets EINVAL (22), the third handler
  ...              serves the next one
  Rspamd Log Should Contain  replace the Lua handler of the control command reload
  ${status} =  Normal Worker Control Status  reload
  Should Be Equal As Integers  ${status}  ${CONTROL_FAILED}
  Log Since Test Start Should Contain In Order
  ...  coro control: the second reload handler has run
  ...  replace the Lua handler of the control command reload
  ...  the second reload handler replaces itself and fails
  ${status} =  Normal Worker Control Status  reload
  Should Be Equal As Integers  ${status}  0
  Log Since Test Start Should Contain  coro control: the third reload handler has run
  Rspamd Log Should Not Contain  coro control: the first reload handler has run
  Coroutines Still Work

DKIM verify callback uses its task argument
  Scan File  ${MESSAGE}  Coro-Test=CORO_DKIM_VERIFY_TASK_TEST
  Expect Symbol With Exact Options  CORO_DKIM_VERIFY_TASK  verified=false
  ...  domain=coro-dkim.test  same_task=true
  Coroutines Still Work

Map callbacks set twice
  [Documentation]  map:set_callback() and map:on_load() called twice at
  ...              config load: the maps are read with the second callbacks,
  ...              and the first ones are garbage collected
  Scan File  ${MESSAGE}  Coro-Test=CORO_MAP_REPLACED_TEST
  Expect Symbol With Exact Options  CORO_MAP_REPLACED  set_callback=released
  ...  on_load=released
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Rspamd Log Should Contain  coro replaced map: the second on_load has run, key=true
  Rspamd Log Should Contain  coro replaced map: the second callback has run
  Rspamd Log Should Not Contain  coro replaced map: a replaced
  Coroutines Still Work

HTTP request with arguments that are not a table
  Scan File  ${MESSAGE}  Coro-Test=CORO_HTTP_ARGS_TEST
  Expect Symbol With Exact Options  CORO_HTTP_ARGS  positional=error:table expected
  ...  string=error:table expected
  Coroutines Still Work

Sync HTTP request that fails while it is started
  [Documentation]  TLS to a closed port: on Linux the connection fails inside
  ...              request(), which returns the error of the connection
  Scan File  ${MESSAGE}  Coro-Test=CORO_HTTP_START_ERROR_TEST
  Expect Symbol  CORO_HTTP_START_ERROR_TEST
  ${linux} =  Evaluate  sys.platform.startswith('linux')  modules=sys
  IF  ${linux}
    Expect Symbol With Exact Options  CORO_HTTP_START_ERROR_TEST  err=ssl connection error
    ...  resp=nil
  END
  Coroutines Still Work

Sync HTTP request to an upstream that fails while it is started
  [Documentation]  The upstream is charged with one failure
  Scan File  ${MESSAGE}  Coro-Test=CORO_HTTP_UPSTREAM_FAIL_TEST
  Expect Symbol With Option  CORO_HTTP_UPSTREAM_FAIL_TEST  failures=1
  ${linux} =  Evaluate  sys.platform.startswith('linux')  modules=sys
  IF  ${linux}
    Expect Symbol With Exact Options  CORO_HTTP_UPSTREAM_FAIL_TEST  err=ssl connection error
    ...  failures=1
  END
  Coroutines Still Work

HTTP request of a plain symbol cancelled by the task timeout
  [Documentation]  The callback of the first request (4s) starts a second
  ...              one, in flight at the task timeout (6s). The session cleanup
  ...              finishes the symbol: the postfilter that depends on it runs
  Scan File  ${MESSAGE}  Coro-Test=CORO_HTTP_CANCELLED_PLAIN_TEST
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  Expect Symbol With Exact Options  CORO_HTTP_CANCELLED_PLAIN_TEST  first=200
  Expect Symbol With Exact Options  CORO_HTTP_CANCELLED_PLAIN_DEPENDENT  dependency_done=true
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Coroutines Still Work

Async TCP request cancelled by the task timeout
  [Documentation]  A BLPOP of 30s sent to redis: the session cleanup at the
  ...              task timeout (6s) closes the connection and finishes the
  ...              symbol
  Expect Cancelled Request  CORO_TCP_CANCELLED_TEST
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  Coroutines Still Work

Async redis request cancelled by the task timeout
  [Documentation]  A BLPOP of 8s: the session cleanup at the task timeout (6s)
  ...              finishes the symbol, the reply that comes later is dropped
  Expect Cancelled Request  CORO_REDIS_ASYNC_CANCELLED_TEST
  # The BLPOP ends on the server at 8s
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  Log Since Test Start Should Not Contain  cancelled async redis: callback
  Coroutines Still Work

Async redis connection used again after the task timeout
  [Documentation]  The BLPOP (8s) of a connection that the Lua code keeps is
  ...              cancelled by the session cleanup at the task timeout (6s),
  ...              which finishes its symbol. A postfilter adds a command to
  ...              the connection then: it is refused, as it would charge the
  ...              finished symbol once more. The BLPOP reply that comes at 8s
  ...              is read and dropped
  Expect Cancelled Request  CORO_REDIS_ASYNC_REUSED_TEST
  Expect Symbol With Exact Options  CORO_REDIS_ASYNC_REUSED_ADD_CMD
  ...  add_cmd=false:Connection is terminated
  ${tag} =  Log Tag Of  reused async redis: BLPOP sent
  Wait Until Keyword Succeeds  30x  0.2s  Log Since Test Start Should Contain
  ...  <${tag}>; lua_redis; lua_redis_callback: got async reply from redis
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  Log Since Test Start Should Not Contain  reused async redis: BLPOP callback
  Log Since Test Start Should Not Contain  reused async redis: PING callback
  Coroutines Still Work

Sync redis command that is never executed, cancelled by the task timeout
  [Documentation]  The coroutine returns after add_cmd(): the command alone
  ...              holds the symbol until the session cleanup at the task
  ...              timeout (6s) closes the connection
  Expect Cancelled Request  CORO_REDIS_NOEXEC_CANCELLED_TEST
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  Coroutines Still Work

UDP request cancelled by the task timeout
  [Documentation]  The read waits for a reply that never comes: the session
  ...              cleanup at the task timeout (6s) finishes the symbol
  Expect Cancelled Request  CORO_UDP_CANCELLED_TEST
  Log Since Test Start Should Not Contain  cancelled udp: callback
  Coroutines Still Work

Async redis subscription cancelled by the task timeout
  [Documentation]  The subscription holds the symbol after its confirmation
  ...              has come: the session cleanup at the task timeout (6s)
  ...              finishes the symbol
  Expect Cancelled Request  CORO_REDIS_SUBSCRIBE_CANCELLED_TEST
  Log Since Test Start Should Contain  cancelled redis subscription: callback: nil table
  Coroutines Still Work

Async redis subscription kept after its task
  [Documentation]  The session cleanup at the task timeout (6s) finishes the
  ...              subscription, whose connection the Lua code keeps: it is
  ...              still subscribed. A message published when the task is gone
  ...              is read and dropped, the callback is not called for it
  Expect Cancelled Request  CORO_REDIS_SUBSCRIBE_KEPT_TEST
  Log Since Test Start Should Contain  kept redis subscription: nil subscribe
  ${tag} =  Log Tag Of  kept redis subscription: subscribing
  ${position} =  Get File Size  ${RSPAMD_TMPDIR}/rspamd.log
  ${receivers} =  Publish To Redis  coro_redis_subscribe_kept  hello
  Should Be Equal As Integers  ${receivers}  1
  Wait Until Keyword Succeeds  30x  0.2s  Log Since Position Should Contain  ${position}
  ...  <${tag}>; lua_redis; lua_redis_callback: got async reply from redis
  Log Since Test Start Should Not Contain  kept redis subscription: nil message
  Coroutines Still Work

Async redis subscription without a task
  [Documentation]  Made by the scanner worker at start: nothing finishes it,
  ...              it gets every message published to its channel
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Rspamd Log Should Contain  taskless redis subscription: nil subscribe 1
  FOR  ${i}  IN RANGE  2
    ${receivers} =  Publish To Redis  coro_redis_taskless  hello${i}
    Should Be Equal As Integers  ${receivers}  1
    Wait Until Keyword Succeeds  30x  0.2s
    ...  Log Since Test Start Should Contain  taskless redis subscription: nil message hello${i}
  END
  Coroutines Still Work

Sync TCP read cancelled by the task timeout
  [Documentation]  The coroutine waits for the reply of a BLPOP of 30s at the
  ...              task timeout (6s). It is not resumed: the session cleanup
  ...              closes the connection and terminates the coroutine, which
  ...              finishes the symbol: the postfilters that depend on it run,
  ...              and every operation one of them starts fails at once
  Redis Blocked Clients Should Be  0
  Scan File  ${MESSAGE}  Coro-Test=CORO_TCP_SYNC_CANCELLED_TEST
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  # Only the result inserted before read_once(): the coroutine never returns
  Expect Symbol With Exact Options  CORO_TCP_SYNC_CANCELLED_TEST  waiting
  Expect Symbol With Exact Options  CORO_TCP_SYNC_CANCELLED_DEPENDENT  dependency_done=true
  Expect Symbol With Exact Options  CORO_TCP_SYNC_CANCELLED_REUSE  read=false:connection is closed
  ...  write=false:connection is closed  close=none
  Log Since Test Start Should Contain  coro tcp cancel: waiting in read_once(), write=true
  # Long before the BLPOP would have ended (30s)
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  Log Since Test Start Should Not Contain  coro tcp cancel: resumed after read_once()
  Log Since Test Start Should Contain  coroutine of symbol CORO_TCP_SYNC_CANCELLED_TEST is terminated
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Coroutines Still Work

Sync TCP write cancelled by the task timeout
  [Documentation]  The peer is a socket of the test that never accepts, so
  ...              nothing reads the data: the write of 16 MB waits at the
  ...              task timeout (6s). The session cleanup closes the
  ...              connection and terminates the coroutine, which finishes the
  ...              symbol
  ${port} =  Start Listener
  Scan File  ${MESSAGE}  Coro-Test=CORO_TCP_SYNC_WRITE_CANCELLED_TEST  Coro-Port=${port}
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  # Only the result inserted before write(): the coroutine never returns
  Expect Symbol With Exact Options  CORO_TCP_SYNC_WRITE_CANCELLED_TEST  waiting
  Expect Symbol With Exact Options  CORO_TCP_SYNC_WRITE_CANCELLED_DEPENDENT  dependency_done=true
  Expect Symbol With Exact Options  CORO_TCP_SYNC_WRITE_CANCELLED_REUSE
  ...  read=false:connection is closed  write=false:connection is closed  close=none
  Log Since Test Start Should Contain  coro tcp write cancel: waiting in write()
  Log Since Test Start Should Not Contain  coro tcp write cancel: resumed after write()
  Log Since Test Start Should Contain
  ...  coroutine of symbol CORO_TCP_SYNC_WRITE_CANCELLED_TEST is terminated
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Coroutines Still Work
  [Teardown]  Close Test Sockets

Sync TCP connect cancelled by the task timeout
  [Documentation]  The accept queue of a socket of the test is full, so Linux
  ...              drops the SYN of the connection: the connection is being
  ...              made at the task timeout (6s). The session cleanup
  ...              terminates the coroutine, which finishes the symbol, and
  ...              frees the connection, which has no Lua handle yet
  ${linux} =  Evaluate  sys.platform.startswith('linux')  modules=sys
  Skip If  not ${linux}  The connection is not certain to hang elsewhere
  ${port} =  Start Listener
  # The backlog is 1: two connections fill the queue
  Connect To Listener  ${port}
  Connect To Listener  ${port}
  Scan File  ${MESSAGE}  Coro-Test=CORO_TCP_SYNC_CONNECT_CANCELLED_TEST  Coro-Port=${port}
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  # Only the result inserted before connect_sync(): the coroutine never returns
  Expect Symbol With Exact Options  CORO_TCP_SYNC_CONNECT_CANCELLED_TEST  waiting
  Expect Symbol With Exact Options  CORO_TCP_SYNC_CONNECT_CANCELLED_DEPENDENT  dependency_done=true
  Log Since Test Start Should Contain  coro tcp connect cancel: waiting in connect_sync()
  Log Since Test Start Should Not Contain  coro tcp connect cancel: resumed after connect_sync()
  Log Since Test Start Should Contain
  ...  coroutine of symbol CORO_TCP_SYNC_CONNECT_CANCELLED_TEST is terminated
  Log Since Test Start Should Not Contain  probably a leaked async counter
  Coroutines Still Work
  [Teardown]  Close Test Sockets

Periodic waits on a sync redis connection of a task
  [Documentation]  A coroutine symbol sends a BLPOP of 30s and starts a
  ...              periodic that waits in exec() for the reply. The task
  ...              timeout (6s) cancels the command: the symbol is finished,
  ...              the run of the periodic is terminated and planned again
  ...              (0.1s), and the next run stops the periodic
  Expect Terminated Periodic  redis

Periodic waits on a sync TCP connection of a task
  [Documentation]  The same with read_once() on a sync TCP connection to redis
  Expect Terminated Periodic  tcp

UDP request with a negative retransmit count
  Scan File  ${MESSAGE}  Coro-Test=CORO_UDP_RETRANSMITS_TEST
  Expect Symbol With Exact Options  CORO_UDP_RETRANSMITS_TEST  udp=false:read timeout
  ...  fast=true
  Coroutines Still Work

Scanner worker terminates
  [Documentation]  The last test: it stops rspamd, so it cannot check that
  ...              coroutines still work. A coroutine waits in a sync redis
  ...              exec() (a BLPOP of 30s) when the worker terminates. The
  ...              finish script of the worker, resumed by the DNS reply of the
  ...              last event of its task, removes another event of the task
  Scan File  ${MESSAGE}  Coro-Test=CORO_SHUTDOWN_PARK_TEST
  Expect Symbol With Exact Options  CORO_SHUTDOWN_PARK  periodic=added
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Log Since Test Start Should Contain  coro shutdown: waiting in exec()
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  1
  # The suite teardown cannot do it any more
  Check Controller Errors
  Set Suite Variable  ${CONTROLLER_ERRORS}  False
  # To the main process only, which terminates each worker once
  Send Signal To Process  SIGTERM  ${RSPAMD_PROCESS}
  ${result} =  Wait For Process  ${RSPAMD_PROCESS}  timeout=60s  on_timeout=kill
  Log  ${result.rc}
  ${linux} =  Evaluate  sys.platform.startswith('linux')  modules=sys
  IF  ${linux}
    Log Since Test Start Should Contain
    ...  coro finish script: dns=${DNS_ANSWER}, http=once, dns_again=${DNS_ANSWER}
  ELSE
    Log Since Test Start Should Contain  dns_again=${DNS_ANSWER}
  END
  Log Since Test Start Should Contain In Order  coro finish script:
  ...  terminated normally  main: terminating...
  No Crash Since Test Start
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0

*** Keywords ***
Coroutines Setup
  Run Dummy Http
  Run Redis
  Rspamd Setup

Coroutines Teardown
  Rspamd Teardown
  Redis Teardown
  Dummy Http Teardown
  # rspamc processes left by a failed test
  Terminate All Processes  kill=True

Coroutines Test Setup
  IF  $WORKER_PID is None
    Scan Alive Symbol
    Set Suite Variable  ${WORKER_PID}  ${SCAN_RESULT}[symbols][CORO_WORKER_PID][options][0]
  END
  ${size} =  Get File Size  ${RSPAMD_TMPDIR}/rspamd.log
  Set Test Variable  ${LOG_POSITION}  ${size}
  ${reports} =  List Files In Directory  ${RSPAMD_TMPDIR}  rspamd-asan*  absolute=True
  Set Test Variable  ${ASAN_REPORTS_BEFORE}  ${reports}
  ${sockets} =  Create List
  Set Test Variable  ${TEST_SOCKETS}  ${sockets}

Scan Alive Symbol
  Scan File  ${MESSAGE}  Coro-Test=CORO_ALIVE_TEST
  Expect Symbol With Exact Options  CORO_ALIVE_TEST  dns=${DNS_ANSWER}
  Expect Symbol  CORO_WORKER_PID

Log Since Position
  [Documentation]  rspamd.log from the byte offset ${position} on
  [Arguments]  ${position}
  ${path} =  Set Variable  ${RSPAMD_TMPDIR}/rspamd.log
  ${text} =  Evaluate
  ...  pathlib.Path($path).read_bytes()[int($position):].decode('utf-8', 'replace')
  ...  modules=pathlib
  RETURN  ${text}

Log Since Position Should Contain
  [Arguments]  ${position}  ${expected}
  ${text} =  Log Since Position  ${position}
  Should Contain  ${text}  ${expected}
  ...  msg=rspamd.log has no "${expected}" after the position ${position}  values=False

Log Since Test Start
  ${text} =  Log Since Position  ${LOG_POSITION}
  RETURN  ${text}

Log Tag Of
  [Documentation]  The log tag (of the task) of the first line logged since the
  ...              test has started that contains ${line}
  [Arguments]  ${line}
  ${text} =  Log Since Test Start
  ${match} =  Evaluate  re.search(r'<([^>\\s]+)>;[^\\n]*' + re.escape($line), $text)  modules=re
  Should Not Be Equal  ${match}  ${NONE}
  ...  msg=rspamd.log has no "${line}" since the test has started  values=False
  RETURN  ${match.group(1)}

Log Since Test Start Should Contain
  [Arguments]  ${expected}
  ${text} =  Log Since Test Start
  Should Contain  ${text}  ${expected}
  ...  msg=rspamd.log has no "${expected}" since the test has started  values=False

Log Since Test Start Should Not Contain
  [Arguments]  ${unexpected}
  ${text} =  Log Since Test Start
  Should Not Contain  ${text}  ${unexpected}
  ...  msg=rspamd.log has "${unexpected}" since the test has started  values=False

Log Since Test Start Should Contain In Order
  [Documentation]  Each string is found after the end of the previous one
  [Arguments]  @{expected}
  ${text} =  Log Since Test Start
  ${start} =  Set Variable  ${0}
  FOR  ${line}  IN  @{expected}
    ${pos} =  Evaluate  $text.find($line, $start)
    Should Be True  ${pos} >= 0
    ...  msg=rspamd.log has no "${line}" after the previous expected line since the test has started
    ${start} =  Evaluate  $pos + len($line)
  END

No Crash Since Test Start
  ${text} =  Log Since Test Start
  Should Not Contain  ${text}  terminated abnormally
  ...  msg=A process has crashed during the test, see rspamd.log  values=False
  ${reports} =  List Files In Directory  ${RSPAMD_TMPDIR}  rspamd-asan*  absolute=True
  FOR  ${report}  IN  @{reports}
    IF  $report not in $ASAN_REPORTS_BEFORE
      ${asan} =  Get File  ${report}  encoding_errors=ignore
      Should Not Contain  ${asan}  ERROR: AddressSanitizer
      ...  msg=AddressSanitizer report ${report}  values=False
    END
  END

Rspamd Log Should Contain
  [Documentation]  Anywhere in the log, also before the test has started
  [Arguments]  ${expected}
  ${text} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  Should Contain  ${text}  ${expected}  msg=rspamd.log has no "${expected}"  values=False

Redis Blocked Clients Should Be
  [Arguments]  ${expected}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  INFO  clients
  ${blocked} =  Evaluate  re.search(r'^blocked_clients:(\\d+)', $result.stdout, re.M)  modules=re
  Should Not Be Equal  ${blocked}  ${NONE}
  ...  msg=redis INFO clients: ${result.stdout} ${result.stderr}  values=False
  Should Be Equal As Integers  ${blocked.group(1)}  ${expected}

Publish To Redis
  [Documentation]  Returns how many clients have got the message
  [Arguments]  ${channel}  ${message}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  PUBLISH  ${channel}  ${message}
  Should Be Equal As Integers  ${result.rc}  0
  ...  msg=redis-cli PUBLISH: ${result.stdout} ${result.stderr}  values=False
  RETURN  ${result.stdout}

Start Listener
  [Documentation]  A TCP socket of the test on a free port, with a backlog of 1,
  ...              that never accepts. Returns the port; Close Test Sockets
  ...              closes the socket
  ${listener} =  Evaluate  socket.create_server(('127.0.0.1', 0), backlog=1)  modules=socket
  Evaluate  $TEST_SOCKETS.append($listener)
  ${port} =  Evaluate  $listener.getsockname()[1]
  RETURN  ${port}

Connect To Listener
  [Documentation]  A connection of the test, closed by Close Test Sockets
  [Arguments]  ${port}
  ${sock} =  Evaluate  socket.create_connection(('127.0.0.1', int($port)), 2)  modules=socket
  Evaluate  $TEST_SOCKETS.append($sock)

Close Test Sockets
  FOR  ${sock}  IN  @{TEST_SOCKETS}
    Call Method  ${sock}  close
  END

Periodic Runs Are Over
  Scan File  ${MESSAGE}  Coro-Test=CORO_PERIODIC_TEST
  Expect Symbol With Option  CORO_PERIODIC  state=done

Periodic Errors Are Over
  Scan File  ${MESSAGE}  Coro-Test=CORO_PERIODIC_ERROR_TEST
  Expect Symbol With Option  CORO_PERIODIC_ERRORS  state=done

Log Since Test Start Should Contain Times
  [Arguments]  ${expected}  ${times}
  ${text} =  Log Since Test Start
  ${count} =  Evaluate  $text.count($expected)
  Should Be Equal As Integers  ${count}  ${times}
  ...  msg=rspamd.log has "${expected}" ${count} times since the test has started, not ${times}
  ...  values=False

Rspamd Log Should Not Contain
  [Documentation]  Anywhere in the log, also before the test has started
  [Arguments]  ${unexpected}
  ${text} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  Should Not Contain  ${text}  ${unexpected}  msg=rspamd.log has "${unexpected}"  values=False

Set Control Mode
  [Documentation]  What the Lua control handler does with the next commands
  [Arguments]  ${mode}
  Scan File  ${MESSAGE}  Coro-Test=CORO_CONTROL_MODE_TEST  Coro-Mode=${mode}
  Expect Symbol With Exact Options  CORO_CONTROL_MODE  mode=${mode}

Control Reply Status Of Normal Worker
  [Documentation]  The status in the reply of the scanner worker to a control
  ...              command run by rspamadm control -j
  [Arguments]  ${result}
  Log  ${result.stdout}
  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0  msg=rspamadm control: ${result.stderr}
  Should Not Be Empty  ${result.stdout}  msg=No reply to rspamadm control: ${result.stderr}
  ${reply} =  Evaluate  json.loads($result.stdout)  modules=json
  ${statuses} =  Evaluate
  ...  [w.get('status') for w in $reply['workers'].values() if w.get('type') == 'normal']
  Length Should Be  ${statuses}  1  msg=No reply of the normal worker: ${result.stdout}
  RETURN  ${statuses}[0]

Normal Worker Control Status
  [Documentation]  Runs a control command, returns the status in the reply of
  ...              the scanner worker
  [Arguments]  ${command}
  ${result} =  Run Process  ${RSPAMADM}  control  -j  -t  15
  ...  -s  ${RSPAMD_TMPDIR}/rspamd.sock  ${command}  timeout=30s  on_timeout=kill
  ${status} =  Control Reply Status Of Normal Worker  ${result}
  RETURN  ${status}

Expect Cancelled Request
  [Documentation]  A scan of the symbol whose request is in flight at the task
  ...              timeout (6s): the postfilter <symbol without _TEST>_DEPENDENT
  ...              that depends on it runs
  [Arguments]  ${test}
  Scan File  ${MESSAGE}  Coro-Test=${test}
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  Expect Symbol With Exact Options  ${test}  sent
  ${dependent} =  Evaluate  $test[:-len('_TEST')] + '_DEPENDENT'
  Expect Symbol With Exact Options  ${dependent}  dependency_done=true
  Log Since Test Start Should Not Contain  probably a leaked async counter

Expect Terminated Periodic
  [Documentation]  A scan of CORO_PERIODIC_TASK_CONN_TEST: its periodic waits on
  ...              a sync connection of the task (${kind}) at the task timeout
  ...              (6s)
  [Arguments]  ${kind}
  Redis Blocked Clients Should Be  0
  Scan File  ${MESSAGE}  Coro-Test=CORO_PERIODIC_TASK_CONN_TEST  Coro-Conn=${kind}
  Should Be True  4 < ${SCAN_RESULT}[time_real] < 9.5
  Expect Symbol With Exact Options  CORO_PERIODIC_TASK_CONN_TEST  periodic_waiting=true
  Expect Symbol With Exact Options  CORO_PERIODIC_TASK_CONN_DEPENDENT  dependency_done=true
  Wait Until Keyword Succeeds  30x  0.2s
  ...  Log Since Test Start Should Contain  periodic of a task ${kind} connection: run 2
  Log Since Test Start Should Contain In Order
  ...  periodic of a task ${kind} connection: waiting
  ...  periodic script (registered at
  ...  ) is terminated: the operation it waits for is cancelled
  ...  periodic of a task ${kind} connection: run 2
  Log Since Test Start Should Not Contain  periodic of a task ${kind} connection: resumed
  Log Since Test Start Should Not Contain  probably a leaked async counter
  # Long before the BLPOP would have ended (30s)
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  # The second run has stopped the periodic
  Sleep  0.5s
  Log Since Test Start Should Contain Times  periodic of a task ${kind} connection: run  1
  Coroutines Still Work

Expect Async Callback Results
  Expect Symbol With Exact Options  CORO_TIMER_CB  sleep=error:coroutine
  Expect Symbol With Exact Options  CORO_DNS_CB  async=${DNS_ANSWER}  dns=error:coroutine
  Expect Symbol With Exact Options  CORO_HTTP_CB  async=200  http=error:coroutine
  ...  tcp=error:coroutine

Coroutines Still Work
  [Documentation]  The same worker process (not one restarted after a crash)
  ...              still suspends and resumes coroutine symbols
  No Crash Since Test Start
  Scan Alive Symbol
  Should Be Equal  ${SCAN_RESULT}[symbols][CORO_WORKER_PID][options][0]  ${WORKER_PID}
  ...  msg=The scanner worker has been restarted, it must have crashed
  No Crash Since Test Start
