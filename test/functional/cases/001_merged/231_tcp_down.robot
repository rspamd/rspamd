*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml

*** Test Cases ***
Sync API TCP get request when server is down
  [Documentation]  We don't create HTTP server here, that's why
  ...              all requests fail with "connection refused"
  Check url  /request  get  HTTP_ASYNC_RESPONSE  Socket error detected: Connection refused
  Check url  /content-length  get  HTTP_SYNC_WRITE_ERROR  Socket error detected: Connection refused

*** Keywords ***
Check url
  [Arguments]  ${url}  ${method}  ${expect_symbol}  @{expect_options}
  Scan File  ${MESSAGE}  URL=${url}  Method=${method}
  ...  Settings={symbols_enabled = [SIMPLE_TCP_ASYNC_TEST, SIMPLE_TCP_TEST]}
  Expect Symbol With Exact Options  ${expect_symbol}  @{expect_options}
