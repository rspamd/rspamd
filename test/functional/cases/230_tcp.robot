*** Settings ***
Suite Setup      Servers Setup
Suite Teardown   Servers Teardown
Library          Process
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Tags       notparallel
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/tcp.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Simple TCP request
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [SIMPLE_TCP_ASYNC_TEST]}
  Expect Symbol  HTTP_ASYNC_RESPONSE
  Expect Symbol  HTTP_ASYNC_RESPONSE_2

SSL TCP request
  [Documentation]  These two were disabled with all the other "broken" tests: they
  ...              talked to the port of dummy_https, which is no longer a TLS server
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [SIMPLE_TCP_ASYNC_SSL_TEST]}
  Expect Symbol With Exact Options  TCP_SSL_RESPONSE  hello
  Expect Symbol With Exact Options  TCP_SSL_RESPONSE_2  hello

SSL Large TCP request
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [LARGE_TCP_ASYNC_SSL_TEST]}
  Expect Symbol  TCP_SSL_LARGE
  Expect Symbol  TCP_SSL_LARGE_2

TLS reads data that OpenSSL has already decrypted
  [Documentation]  A response of one TLS record is bigger than the read buffer, the server
  ...              stays idle after it: without draining OpenSSL the request times out
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_TLS_BIG_TEST]}
  Expect Symbol With Exact Options  TCP_TLS_BIG  r1=16299  r2=99999

TLS peer that never answers, error callback closes the connection
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_TLS_SILENT_TEST]}
  Expect Symbol With Exact Options  TCP_TLS_SILENT  ssl error: IO timeout

TLS handshake failure goes to on_error, which closes the connection
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_TLS_HS_FAIL_TEST]}
  Expect Symbol With Exact Options  TCP_TLS_HS_ERROR  ssl error
  Do Not Expect Symbol  TCP_TLS_HS_REGULAR_CB

TLS request with nothing queued and with on_connect
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_TLS_EMPTY_TEST]}
  Expect Symbol  TCP_TLS_CONNECTED
  Expect Symbol With Exact Options  TCP_TLS_EMPTY  nil  hello

starttls is refused when plaintext is buffered
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_STARTTLS_INJECT_TEST]}
  Expect Symbol With Exact Options  TCP_STARTTLS_INJECT  ready=READY
  ...  refused=true  starttls refused  plain=INJECTED

starttls followed by add_read and a write
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_STARTTLS_TEST]}
  Expect Symbol With Exact Options  TCP_STARTTLS  ready=READY
  ...  greeting=greeting  reply=hello

starttls verifies the peer unless told not to
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_STARTTLS_VERIFY_TEST]}
  Expect Symbol With Exact Options  TCP_STARTTLS_VERIFY  ssl error

starttls reports a failure found at once to the next handler
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_STARTTLS_SYNC_FAIL_TEST]}
  Expect Symbol With Exact Options  TCP_STARTTLS_SYNC_FAIL  started=false  result=ssl error
  ...  handler=ssl error

Sync API TCP request
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [SIMPLE_TCP_TEST]}
  Expect Symbol  HTTP_SYNC_RESPONSE
  Should Contain  ${SCAN_RESULT}[symbols][HTTP_SYNC_RESPONSE][options][0]  hello world
  Should Contain  ${SCAN_RESULT}[symbols][HTTP_SYNC_RESPONSE_2][options][0]  hello post

Sync API TCP get request
  #Check url  /request  get  HTTP_SYNC_EOF_get  hello world
  Check url  /request  get  HTTP_SYNC_CONTENT_get  hello world

# Broken due to dummy_https issues, disable for now
#Sync API TCP post request
#  Check url  /request  post  HTTP_SYNC_EOF_post  hello post
#  Check url  /content-length  post  HTTP_SYNC_CONTENT_post  hello post

Phased timeouts on success path
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [PHASED_TIMEOUT_TEST]}
  Expect Symbol  PHASED_TCP_OK
  Do Not Expect Symbol  PHASED_TCP_ERROR

on_error fires on connect refused
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [ON_ERROR_REFUSED_TEST]}
  Expect Symbol  ON_ERROR_FIRED
  Do Not Expect Symbol  ON_ERROR_REGULAR_CB_FIRED

on_error not fired post-connect
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [ON_ERROR_POST_CONNECT_TEST]}
  Expect Symbol  POST_CONNECT_READ_TIMEOUT
  Do Not Expect Symbol  POST_CONNECT_ON_ERROR_FIRED
  Do Not Expect Symbol  POST_CONNECT_READ_OK

Empty write handlers complete and invalid write data is rejected
  [Documentation]  add_write() with "", {""} and {} used to abort rspamd
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_EMPTY_WRITE_TEST]}
  Expect Symbol With Exact Options  TCP_EMPTY_WRITE  writes=4  HTTP/1.1 200 OK
  Expect Symbol With Exact Options  TCP_WRITE_INVALID  false,false,false,false

Fatal error does not call handlers added by a callback
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_FATAL_READD_TEST]}
  Expect Symbol With Exact Options  TCP_FATAL_READD  call1

shift_callback inside a callback does not skip the next handler
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SHIFT_CB_TEST]}
  Expect Symbol With Exact Options  TCP_SHIFT_CB  r1=HTTP/1.1 200 OK  ran=3  distinct=true

close in a callback stops the queued handlers
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_CLOSE_IN_CB_TEST]}
  Expect Symbol With Exact Options  TCP_CLOSE_IN_CB  r1
  Do Not Expect Symbol  TCP_CLOSE_EXTRA

Sync API invalid and empty writes, buffered reads, closed handle
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_MISC_TEST]}
  Expect Symbol With Exact Options  TCP_SYNC_MISC  rejected=4  empty=true,true,true
  ...  write=true  line=true:HTTP/1.1 200 OK  leftover=true:true
  ...  closed_write=false:connection is closed  closed_read=false:connection is closed

Sync API connection used by another coroutine
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_XTHREAD_A_TEST, TCP_SYNC_XTHREAD_B_TEST]}
  Expect Symbol With Exact Options  TCP_SYNC_XTHREAD  true:true  HTTP/1.1 200 OK

Sync API read until EOF reports a reset
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_RESET_TEST]}
  Expect Symbol With Exact Options  TCP_SYNC_RESET  ok=false  eof=false
  ...  IO read error while trying to read data: Connection reset by peer

Sync API connect refused fails cleanly
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_REFUSED_TEST]}
  Expect Symbol With Exact Options  TCP_SYNC_REFUSED
  ...  1:false:Socket error detected: Connection refused
  ...  2:false:Socket error detected: Connection refused
  ...  3:false:Socket error detected: Connection refused

Handle kept after the connection is over is dead
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_DEAD_HANDLE_TEST]}
  Expect Symbol With Exact Options  TCP_DEAD_HANDLE  close=true
  ...  add_read=false:connection is closed  add_write=false:connection is closed
  ...  shift=false:connection is closed  starttls=false:starttls: connection is closed

handlers are refused after close in a callback
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_CLOSE_THEN_ADD_TEST]}
  Expect Symbol With Exact Options  TCP_CLOSE_THEN_ADD  add_read=false:connection is closed
  ...  add_write=false:connection is closed
  Do Not Expect Symbol  TCP_CLOSE_THEN_ADD_LATE

close from outside the callbacks finishes the connection
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_CLOSE_OUTSIDE_TEST]}
  Expect Symbol With Exact Options  TCP_CLOSE_OUTSIDE  shift=false:connection is closed
  ...  add_read=false:connection is closed
  Do Not Expect Symbol  TCP_CLOSE_OUTSIDE_LATE

Sync API refuses TLS
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_SSL_TEST]}
  Expect Symbol With Exact Options  TCP_SYNC_SSL  ok=false  tls_error=true

Sync API operation pending when the task is destroyed
  [Documentation]  task_timeout (10s) ends the task while read_once() waits for a silent peer
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_PENDING_TEST, TCP_SYNC_PENDING_ALIVE_TEST]}
  Expect Symbol  TCP_SYNC_PENDING_ALIVE
  # the peer must have been reachable, or the test has not tested the pending read
  Do Not Expect Symbol  TCP_SYNC_PENDING_ERROR

Sync API handle dropped and collected while its operation resumes the coroutine
  [Documentation]  __gc must not destroy a connection that an operation still holds
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_GC_TEST]}
  Do Not Expect Symbol  TCP_SYNC_GC_ERROR
  Expect Symbol With Exact Options  TCP_SYNC_GC  write=true  read=true:true

Sync API unclosed handle collected by a postfilter
  [Documentation]  The connection is released while the postfilter runs the collector
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_UNCLOSED_POST_TEST, TCP_SYNC_UNCLOSED_POST_GC_TEST]}
  Expect Symbol  TCP_SYNC_UNCLOSED_POST_DONE
  Expect Symbol  TCP_SYNC_UNCLOSED_POST_GC

Sync API unclosed handle collected by a dependent symbol
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_UNCLOSED_DEP_TEST, TCP_SYNC_UNCLOSED_DEP_GC_TEST]}
  Expect Symbol  TCP_SYNC_UNCLOSED_DEP_DONE
  Expect Symbol  TCP_SYNC_UNCLOSED_DEP_GC

Sync API operations have their own timeout
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_TIMEOUT_TEST]}
  Expect Symbol With Exact Options  TCP_SYNC_TIMEOUT  first=false:IO timeout
  ...  second=false:IO timeout  fast=true

A text with bad data stays valid and a sent text outlives its Lua variable
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_TEXT_BADDATA_TEST]}
  Expect Symbol With Exact Options  TCP_TEXT_BADDATA  ret=false  text=owned text
  ...  foreign=true:false  single=true:true:second

TCP write of a text whose Lua variable is dropped and collected
  [Documentation]  The write starts after the symbol returns, the text must still be alive
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_TEXT_DROPPED_TEST]}
  Expect Symbol With Exact Options  TCP_TEXT_DROPPED  err=nil  status=200

Request with bad parameters fails cleanly
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_ONLOAD_TEST]}
  Expect Symbol  TCP_ONLOAD
  ${opts} =  Convert To List  ${SCAN_RESULT}[symbols][TCP_ONLOAD][options]
  Length Should Be  ${opts}  6
  Should Contain  ${opts}[0]  noconfig=error:
  Should Contain  ${opts}[0]  config
  Should Contain  ${opts}[1]  badport=error:
  Should Contain  ${opts}[1]  invalid port
  Should Contain  ${opts}[2]  negport=error:
  Should Be Equal  ${opts}[3]  baddata=returned:false
  Should Be Equal  ${opts}[4]  noread=returned:true
  Should Be Equal  ${opts}[5]  emptytable=returned:true

*** Keywords ***
Servers Setup
  Run Dummy Http
  Run Dummy Ssl
  Run Dummy Tcp Reset
  Rspamd Setup

Servers Teardown
  Dummy Http Teardown
  Rspamd Teardown
  Teardown Dummy Ssl
  Terminate Process  ${DUMMY_TCP_RESET_PROC}
  Wait For Process  ${DUMMY_TCP_RESET_PROC}

Run Dummy Tcp Reset
  [Arguments]
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_tcp_reset-${RSPAMD_PORT_DUMMY_HTTPS}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_tcp_reset-${RSPAMD_PORT_DUMMY_HTTPS}.log
  ${result} =  Start Dummy Service  dummy_tcp_reset.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_tcp_reset.py  ${RSPAMD_PORT_DUMMY_HTTPS}  ${pid}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_HTTPS}
  Set Suite Variable  ${DUMMY_TCP_RESET_PROC}  ${result}

Run Dummy Ssl
  [Arguments]
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_ssl-${RSPAMD_PORT_DUMMY_SSL}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_ssl-${RSPAMD_PORT_DUMMY_SSL}.log
  Set Suite Variable  ${DUMMY_SSL_PID_FILE}  ${pid}
  Start Dummy Service  dummy_ssl.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_ssl.py  ${RSPAMD_TESTDIR}/util/server.pem  ${RSPAMD_PORT_DUMMY_SSL}  ${pid}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_SSL}

Teardown Dummy Ssl
  ${ssl_pid} =  Get File  ${DUMMY_SSL_PID_FILE}
  Shutdown Process With Children  ${ssl_pid}

Check url
  [Arguments]  ${url}  ${method}  ${expect_symbol}  @{expect_options}
  Scan File  ${MESSAGE}  URL=${url}  Method=${method}
  ...  Settings={symbols_enabled = [HTTP_TCP_TEST]}
  Expect Symbol With Exact Options  ${expect_symbol}  @{expect_options}
