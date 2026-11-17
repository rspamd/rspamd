*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Tags       notparallel
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/tcp.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat


*** Test Cases ***
Sync API TCP get request when server is down
  [Documentation]  We don't create HTTP server here, that's why
  ...              all requests fail with "connection refused"
  Check url  /request  get  HTTP_ASYNC_RESPONSE  Socket error detected: Connection refused
  Check url  /content-length  get  HTTP_SYNC_WRITE_ERROR  Socket error detected: Connection refused

Sync API connect refused fails cleanly
  [Documentation]  Repeated refused sync connections return an error each time
  ...              (the connection objects used to leak)
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_SYNC_REFUSED_TEST]}
  Expect Symbol With Exact Options  TCP_SYNC_REFUSED
  ...  1:false:Socket error detected: Connection refused
  ...  2:false:Socket error detected: Connection refused
  ...  3:false:Socket error detected: Connection refused

Fatal error does not call handlers added by a callback when server is down
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [TCP_FATAL_READD_TEST]}
  Expect Symbol With Exact Options  TCP_FATAL_READD  call1

*** Keywords ***
Check url
  [Arguments]  ${url}  ${method}  ${expect_symbol}  @{expect_options}
  Scan File  ${MESSAGE}  URL=${url}  Method=${method}
  ...  Settings={symbols_enabled = [SIMPLE_TCP_ASYNC_TEST, SIMPLE_TCP_TEST]}
  Expect Symbol With Exact Options  ${expect_symbol}  @{expect_options}
