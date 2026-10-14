*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/force_actions_legacy.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/url7.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
FORCE ACTIONS legacy rule with composite in expression
  [Documentation]  The legacy format also registers such a rule as a postfilter
  Scan File  ${MESSAGE}  Settings-Id=id_legacy_composite
  Expect Action  reject
  Expect Symbol  FA_LEGACY_COMPOSITE
  Expect Symbol With Exact Options  FA_ACTION_PROBE  reject

FORCE ACTIONS legacy rule without composite
  Scan File  ${MESSAGE}  Settings-Id=id_legacy_plain
  Expect Action  add header

FORCE ACTIONS legacy actions matching at once are ordered by name
  [Documentation]  Registration follows the sorted action names, so "add header"
  ...  runs first and its result stops the scan
  Scan File  ${MESSAGE}  Settings-Id=id_legacy_tie
  Expect Action  add header
