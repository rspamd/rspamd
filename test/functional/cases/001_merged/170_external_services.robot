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
${MESSAGE_PEEKABOO}   ${RSPAMD_TESTDIR}/messages/content_url.eml
${SETTINGS_PEEKABOO}  {symbols_enabled = [PEEKABOO_CHECK, PEEKABOO_REPORT]}

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

PEEKABOO HIT
  # dummy_peekaboo's report-poll counter is process-global (not keyed by
  # job_id): the 1st poll of the process always 404s (in-progress), every
  # later poll returns the --mode result. So the 1st Scan File observes
  # PEEKABOO_IN_PROCESS and the 2nd (fresh job_id, same dummy process)
  # observes the final verdict.
  ${process} =  Run Dummy Peekaboo  ${RSPAMD_PORT_PEEKABOO}  bad
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO_IN_PROCESS
  Do Not Expect Symbol  PEEKABOO
  Do Not Expect Symbol  PEEKABOO_FAIL
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO
  Do Not Expect Symbol  PEEKABOO_FAIL
  [Teardown]  Terminate Process  ${process}

PEEKABOO GOOD
  ${process} =  Run Dummy Peekaboo  ${RSPAMD_PORT_PEEKABOO}  good
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO_IN_PROCESS
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO_GOOD
  Do Not Expect Symbol  PEEKABOO
  Do Not Expect Symbol  PEEKABOO_FAIL
  [Teardown]  Terminate Process  ${process}

PEEKABOO FAILED
  ${process} =  Run Dummy Peekaboo  ${RSPAMD_PORT_PEEKABOO}  failed
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO_IN_PROCESS
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO_FAIL
  Do Not Expect Symbol  PEEKABOO
  [Teardown]  Terminate Process  ${process}

PEEKABOO IN PROCESS
  # Single scan only: the dummy's first (and only) report poll 404s, so
  # only PEEKABOO_IN_PROCESS should ever fire for this test.
  ${process} =  Run Dummy Peekaboo  ${RSPAMD_PORT_PEEKABOO}  bad
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO_IN_PROCESS
  Do Not Expect Symbol  PEEKABOO
  Do Not Expect Symbol  PEEKABOO_FAIL
  [Teardown]  Terminate Process  ${process}

PEEKABOO CONNECTION REFUSED
  # No dummy service is started on this port for this test: peekaboo_check
  # exhausts its retransmits against the (nothing-listening) upstream and
  # falls back to yield_result(..., 'fail'), so PEEKABOO_FAIL should fire.
  Scan File  ${MESSAGE_PEEKABOO}
  ...  Settings=${SETTINGS_PEEKABOO}
  Expect Symbol  PEEKABOO_FAIL
  Do Not Expect Symbol  PEEKABOO

*** Keywords ***
Run Dummy Razor
  [Arguments]  ${port}  ${spam}=  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_razor-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_razor-${port}.log
  ${process} =  Start Dummy Service  dummy_razor.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_razor.py  ${port}  ${spam}  ${pid}
  RETURN    ${process}

Run Dummy Peekaboo
  [Arguments]  ${port}  ${mode}=bad  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_peekaboo-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_peekaboo-${port}.log
  ${process} =  Start Dummy Service  dummy_peekaboo.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_peekaboo.py  ${port}  ${mode}  ${pid}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${port}
  RETURN    ${process}
