*** Settings ***
Documentation   APIs that suspend their caller (sync DNS, HTTP, TCP, redis,
...             ev_base:sleep): concurrent tasks in one coroutine symbol, calls
...             from places that cannot be suspended, coroutines that outlive
...             their task, tasks that are finishing, async sleep callbacks,
...             replies that come while nobody waits for them, callbacks
...             registered by a coroutine that is suspended or gone, symbol
...             results, periodics.
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
  ...              server, and terminates the coroutine
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
  Do Not Expect Symbol  CORO_REDIS_CANCEL_TEST
  # Long before the BLPOP would have ended (30s)
  Wait Until Keyword Succeeds  30x  0.2s  Redis Blocked Clients Should Be  0
  Log Since Test Start Should Contain  coro redis cancel: waiting in exec()
  Log Since Test Start Should Not Contain  coro redis cancel: resumed after exec()
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

Periodic suspended for longer than its interval
  [Documentation]  Each run sleeps 0.5s, the interval is 0.1s: no run starts
  ...              while another one is suspended
  Wait Until Keyword Succeeds  30x  0.5s  Periodic Runs Are Over
  Expect Symbol With Exact Options  CORO_PERIODIC  state=done  started=4  finished=4
  ...  max_active=1
  Coroutines Still Work

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

Scan Alive Symbol
  Scan File  ${MESSAGE}  Coro-Test=CORO_ALIVE_TEST
  Expect Symbol With Exact Options  CORO_ALIVE_TEST  dns=${DNS_ANSWER}
  Expect Symbol  CORO_WORKER_PID

Log Since Test Start
  ${path} =  Set Variable  ${RSPAMD_TMPDIR}/rspamd.log
  ${text} =  Evaluate
  ...  pathlib.Path($path).read_bytes()[int($LOG_POSITION):].decode('utf-8', 'replace')
  ...  modules=pathlib
  RETURN  ${text}

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

Periodic Runs Are Over
  Scan File  ${MESSAGE}  Coro-Test=CORO_PERIODIC_TEST
  Expect Symbol With Option  CORO_PERIODIC  state=done

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
