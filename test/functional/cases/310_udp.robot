*** Settings ***
Test Setup      UDP Setup
Test Teardown   UDP Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Test Cases ***
Simple UDP request
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  UDP_SUCCESS (0.00)[helloworld]

Sendonly UDP request
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  UDP_SENDTO

Errored UDP request
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  UDP_FAIL (0.00)[read timeout]

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Global Variable  ${LUA_SCRIPT}
  Generic Setup

UDP Setup
  Run Dummy UDP
  Lua Setup  ${TESTDIR}/lua/udp.lua

UDP Teardown
  ${udp_pid} =  Get File  /tmp/dummy_udp.pid
  Shutdown Process With Children  ${udp_pid}
  Normal Teardown

Run Dummy UDP
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_udp.py  5005
  Wait Until Created  /tmp/dummy_udp.pid
