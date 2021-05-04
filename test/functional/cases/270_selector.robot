*** Settings ***
Test Setup      Regex Setup
Test Teardown   Regex Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/selector.conf
${MESSAGE}      ${TESTDIR}/messages/subject1.eml
${UTF_MESSAGE}  ${TESTDIR}/messages/utf.eml
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SCOPE}  Suite


*** Test Cases ***
Newlines 
  Scan File  ${MESSAGE}  User=test@user.com  Pass=all
  Expect Symbol  CONFIG_SELECTOR_RE_RCPT_SUBJECT
  Expect Symbol  LUA_SELECTOR_RE


*** Keywords ***
Regex Setup
  New Setup  URL_TLD=${URL_TLD}

Regex Teardown
  Normal Teardown
