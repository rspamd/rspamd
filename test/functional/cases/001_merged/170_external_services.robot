*** Settings ***
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE2}         ${RSPAMD_TESTDIR}/messages/freemail.eml
${MESSAGE}          ${RSPAMD_TESTDIR}/messages/spam_message.eml
${MESSAGE3}         ${RSPAMD_TESTDIR}/messages/ham.eml
${SETTINGS_RAZOR}   {symbols_enabled = [RAZOR_CHECK]}

*** Test Cases ***
RAZOR MISS
  ${process} =  Run Dummy Razor  ${RSPAMD_PORT_RAZOR}
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_RAZOR}
  Do Not Expect Symbol  RAZOR
  Do Not Expect Symbol  RAZOR_FAIL
  [Teardown]  Terminate Process  ${process}

RAZOR HIT
  ${process} =  Run Dummy Razor  ${RSPAMD_PORT_RAZOR}  1
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_RAZOR}
  Expect Symbol  RAZOR
  Do Not Expect Symbol  RAZOR_FAIL
  [Teardown]  Terminate Process  ${process}

RAZOR CONNECTION REFUSED
  # No dummy service is started on this port for this test: razor_check
  # exhausts its retransmits against the (nothing-listening) upstream and
  # falls back to yield_result(..., 'fail'), so RAZOR_FAIL should fire.
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_RAZOR}
  Expect Symbol  RAZOR_FAIL
  Do Not Expect Symbol  RAZOR

*** Keywords ***
Run Dummy Razor
  [Arguments]  ${port}  ${spam}=  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_razor-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_razor-${port}.log
  ${process} =  Start Dummy Service  dummy_razor.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_razor.py  ${port}  ${spam}  ${pid}
  RETURN    ${process}
