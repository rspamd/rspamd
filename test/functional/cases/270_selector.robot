*** Settings ***
Test Setup      Regex Setup
Test Teardown   Regex Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/subject1.eml
${UTF_MESSAGE}  ${TESTDIR}/messages/utf.eml
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SCOPE}  Test


*** Test Cases ***
Newlines 
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --user  test@user.com
  Check Rspamc  ${result}  CONFIG_SELECTOR_RE_RCPT_SUBJECT
  Check Rspamc  ${result}  LUA_SELECTOR_RE


*** Keywords ***
Regex Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/selector.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Regex Teardown
  Normal Teardown
