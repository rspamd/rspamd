*** Settings ***
Test Setup      UDP Setup
Test Teardown   UDP Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_UDP}       {symbols_enabled = [UDP_FAIL,UDP_SENDTO,UDP_SUCCESS]}

*** Test Cases ***
Simple UDP request
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_UDP}
  Expect Symbol With Exact Options  UDP_SUCCESS  helloworld

Sendonly UDP request
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_UDP}
  Expect Symbol  UDP_SENDTO

Errored UDP request
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_UDP}
  Expect Symbol With Exact Options  UDP_FAIL  read timeout

*** Keywords ***
UDP Setup
  Run Dummy UDP

UDP Teardown
  ${udp_pid} =  Get File  /tmp/dummy_udp.pid
  Shutdown Process With Children  ${udp_pid}

Run Dummy UDP
  [Arguments]
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_udp.py  5005
  Wait Until Created  /tmp/dummy_udp.pid
