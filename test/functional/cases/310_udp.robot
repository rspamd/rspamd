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
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  UDP_SUCCESS  helloworld

Sendonly UDP request
  Scan File  ${MESSAGE}
  Expect Symbol  UDP_SENDTO

Errored UDP request
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  UDP_FAIL  read timeout

*** Keywords ***
UDP Setup
  Run Dummy UDP
  New Setup  LUA_SCRIPT=${TESTDIR}/lua/udp.lua  URL_TLD=${URL_TLD}

UDP Teardown
  ${udp_pid} =  Get File  /tmp/dummy_udp.pid
  Shutdown Process With Children  ${udp_pid}
  Normal Teardown

Run Dummy UDP
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_udp.py  5005
  Wait Until Created  /tmp/dummy_udp.pid
