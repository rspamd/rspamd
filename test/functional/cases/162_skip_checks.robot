*** Settings ***
Suite Setup     Skipchecks Setup
Suite Teardown  Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Test skipped checks
  Scan File  ${MESSAGE}
  Expect Symbol  FORGED_MUA_OUTLOOK
  Expect Symbol  MISSING_MID
  Do Not Expect Symbol  DATE_IN_PAST

Test skipped checks - inverse
  Scan File  ${MESSAGE}  Settings={symbols_disabled=["MISSING_MID"]}
  Do Not Expect Symbol  MISSING_MID
  Expect Symbol  FORGED_MUA_OUTLOOK
  Expect Symbol  DATE_IN_PAST

*** Keywords ***
Skipchecks Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/skip_checks.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
