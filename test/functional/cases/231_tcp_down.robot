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

Sync API TCP get request when server is down
  [Documentation]  We don't create HTTP server here, that's why
  ...              all requests fail with "connection refused"
  Check url  /request  get  HTTP_ASYNC_RESPONSE (0.00)[Socket error detected: Connection refused]
  Check url  /content-length  HTTP_SYNC_WRITE_ERROR (0.00)[Socket error detected: Connection refused]


*** Keywords ***
Http Setup
  New Setup  LUA_SCRIPT=${TESTDIR}/lua/tcp.lua  URL_TLD=${URL_TLD}

Http Teardown
  Normal Teardown

Check url
  [Arguments]  ${url}  ${method}  @{expect_results}
  ${result} =  Scan Message With Rspamc  --header=url:${url}  --header=method:${method}  ${MESSAGE}
  FOR  ${expect}  IN  @{expect_results}
    Check Rspamc  ${result}  ${expect}
  END
