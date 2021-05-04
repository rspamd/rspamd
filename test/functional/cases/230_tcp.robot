*** Settings ***
Suite Setup      Servers Setup
Suite Teardown   Servers Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
# ${CONFIG}       ${TESTDIR}/configs/http.conf
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Simple TCP request
  Scan File  ${MESSAGE}
  Expect Symbol  HTTP_ASYNC_RESPONSE
  Expect Symbol  HTTP_ASYNC_RESPONSE_2

SSL TCP request
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  TCP_SSL_RESPONSE  hello
  Expect Symbol With Exact Options  TCP_SSL_RESPONSE_2  hello

SSL Large TCP request
  Scan File  ${MESSAGE}
  Expect Symbol  TCP_SSL_LARGE
  Expect Symbol  TCP_SSL_LARGE_2

Sync API TCP request
  Scan File  ${MESSAGE}
  Expect Symbol  HTTP_SYNC_RESPONSE
  Should Contain  ${SCAN_RESULT}[symbols][HTTP_SYNC_RESPONSE][options][0]  hello world
  Should Contain  ${SCAN_RESULT}[symbols][HTTP_SYNC_RESPONSE_2][options][0]  hello post

Sync API TCP get request
  Check url  /request  get  HTTP_SYNC_EOF_get  hello world
  Check url  /content-length  get  HTTP_SYNC_CONTENT_get  hello world

Sync API TCP post request
  Check url  /request  post  HTTP_SYNC_EOF_post  hello post
  Check url  /content-length  post  HTTP_SYNC_CONTENT_post  hello post

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Suite Variable  ${LUA_SCRIPT}
  Generic Setup

Servers Setup
  Run Dummy Http
  Run Dummy Ssl
  New Setup  LUA_SCRIPT=${TESTDIR}/lua/tcp.lua  URL_TLD=${URL_TLD}

Servers Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}
  ${ssl_pid} =  Get File  /tmp/dummy_ssl.pid
  Shutdown Process With Children  ${ssl_pid}
  Normal Teardown

Run Dummy Http
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid  timeout=2 second

Run Dummy Ssl
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_ssl.py  ${TESTDIR}/util/server.pem
  Wait Until Created  /tmp/dummy_ssl.pid  timeout=2 second

Check url
  [Arguments]  ${url}  ${method}  ${expect_symbol}  @{expect_options}
  Scan File  ${MESSAGE}  URL=${url}  Method=${method}
  Expect Symbol With Exact Options  ${expect_symbol}  @{expect_options}
