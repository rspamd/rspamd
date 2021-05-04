*** Settings ***
Test Setup      UDP Setup
Test Teardown   UDP Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/udp.lua
${RSPAMD_SCOPE}       Test
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

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
  Rspamd Setup

UDP Teardown
  ${udp_pid} =  Get File  /tmp/dummy_udp.pid
  Shutdown Process With Children  ${udp_pid}
  Rspamd Teardown

Run Dummy UDP
  [Arguments]
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_udp.py  5005
  Wait Until Created  /tmp/dummy_udp.pid
