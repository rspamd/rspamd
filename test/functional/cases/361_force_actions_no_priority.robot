*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/force_actions_no_priority.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/url7.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
FORCE ACTIONS without priorities skips an already selected action
  Scan File  ${MESSAGE}  Settings-Id=id_same_reject
  Expect Action  reject
  Do Not Expect Symbol  FORCE_ACTION_FORCE_SAME_REJECT
  Expect Symbol  FA_SAME_WITNESS

FORCE ACTIONS without priorities a match stops the scan
  Scan File  ${MESSAGE}  Settings-Id=id_stop
  Expect Action  add header
  Expect Symbol  FORCE_ACTION_FORCE_STOP_ADD_HEADER
  Do Not Expect Symbol  FA_STOP_WITNESS

FORCE ACTIONS rule without priority is not starved by a low one
  Scan File  ${MESSAGE}  Settings-Id=id_unset_outranks_low
  Expect Action  no action
  Expect Symbol  FORCE_ACTION_FORCE_UNSET_A_LOW_REJECT
  Expect Symbol  FA_UNSET_COMPOSITE
  Expect Symbol  FORCE_ACTION_FORCE_UNSET_B_NO_ACTION
