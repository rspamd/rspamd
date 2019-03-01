*** Settings ***
Test Setup      Http Setup
Test Teardown   Http Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
# ${CONFIG}       ${TESTDIR}/configs/http.conf
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Test Cases ***
Simple TCP request
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  HTTP_ASYNC_RESPONSE
  Check Rspamc  ${result}  HTTP_ASYNC_RESPONSE_2


Sync API TCP request
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  HTTP_SYNC_RESPONSE
  Check Rspamc  ${result}  HTTP_SYNC_RESPONSE_2
  Check Rspamc  ${result}  hello world
  Check Rspamc  ${result}  hello post

Sync API TCP get request
  Check url  /request  get  HTTP_SYNC_EOF_get (0.00)[hello world]
  Check url  /content-length  get  HTTP_SYNC_CONTENT_get (0.00)[hello world]

Sync API TCP post request
  Check url  /request  post  HTTP_SYNC_EOF_post (0.00)[hello post]
  Check url  /content-length  post  HTTP_SYNC_CONTENT_post (0.00)[hello post]

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Global Variable  ${LUA_SCRIPT}
  Generic Setup

Http Setup
  Run Dummy Http
  Lua Setup  ${TESTDIR}/lua/tcp.lua

Http Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}
  Normal Teardown

Run Dummy Http
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid


Check url
  [Arguments]  ${url}  ${method}  @{expect_results}
  ${result} =  Scan Message With Rspamc  --header=url:${url}  --header=method:${method}  ${MESSAGE}
  : FOR  ${expect}  IN  @{expect_results}
  \  Check Rspamc  ${result}  ${expect}
