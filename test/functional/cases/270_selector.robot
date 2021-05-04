*** Settings ***
Test Setup      Regex Setup
Test Teardown   Regex Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${RSPAMD_TESTDIR}/configs/selector.conf
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/subject1.eml
${UTF_MESSAGE}  ${RSPAMD_TESTDIR}/messages/utf.eml
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SCOPE}  Suite


*** Test Cases ***
Newlines 
  Scan File  ${MESSAGE}  User=test@user.com  Pass=all
  Expect Symbol  CONFIG_SELECTOR_RE_RCPT_SUBJECT
  Expect Symbol  LUA_SELECTOR_RE


*** Keywords ***
Regex Setup
  New Setup

Regex Teardown
  Normal Teardown
