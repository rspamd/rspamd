*** Settings ***
Test Setup      New Setup
Test Teardown   Normal Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/tcp.lua
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Test Cases ***

Sync API TCP get request when server is down
  [Documentation]  We don't create HTTP server here, that's why
  ...              all requests fail with "connection refused"
  Check url  /request  get  HTTP_ASYNC_RESPONSE (0.00)[Socket error detected: Connection refused]
  Check url  /content-length  HTTP_SYNC_WRITE_ERROR (0.00)[Socket error detected: Connection refused]


*** Keywords ***
Check url
  [Arguments]  ${url}  ${method}  @{expect_results}
  ${result} =  Scan Message With Rspamc  --header=url:${url}  --header=method:${method}  ${MESSAGE}
  FOR  ${expect}  IN  @{expect_results}
    Check Rspamc  ${result}  ${expect}
  END
