*** Settings ***
Documentation   APIs that suspend their caller (sync DNS, HTTP, TCP, redis,
...             ev_base:sleep): concurrent tasks in one coroutine symbol, calls
...             from places that cannot be suspended, coroutines that outlive
...             their task, tasks that are finishing, async sleep callbacks.
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
