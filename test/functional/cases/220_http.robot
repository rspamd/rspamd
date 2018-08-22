*** Settings ***
# Test Setup      Http Setup
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
${MESSAGE2}     ${TESTDIR}/messages/freemail.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
HTTP
  Run Dummy Http
  [Setup]  Lua Setup  ${TESTDIR}/lua/http.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  HTTP_DNS_200
  Check Rspamc  ${result}  HTTP_200


*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Test Variable  ${LUA_SCRIPT}
  Generic Setup

Http Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  # Shutdown Process With Children  ${http_pid}
  Normal Teardown

Run Dummy Http
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid
