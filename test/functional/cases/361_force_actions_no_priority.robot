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
