*** Settings ***
Test Setup      Rules Setup
Test Teardown   Rules Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE1}      ${TESTDIR}/messages/fws_fn.eml
${MESSAGE2}      ${TESTDIR}/messages/fws_fp.eml
${MESSAGE3}      ${TESTDIR}/messages/fws_tp.eml
${MESSAGE4}      ${TESTDIR}/messages/broken_richtext.eml
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SCOPE}  Test


*** Test Cases ***
Broken MIME
  ${result} =  Scan Message With Rspamc  ${MESSAGE3}
  Check Rspamc  ${result}  MISSING_SUBJECT

Issue 2584
  ${result} =  Scan Message With Rspamc  ${MESSAGE1}
  Check Rspamc  ${result}  BROKEN_CONTENT_TYPE  inverse=1
  Should Not Contain  ${result.stdout}  MISSING_SUBJECT
  Should Not Contain  ${result.stdout}  R_MISSING_CHARSET

Issue 2349
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  MULTIPLE_UNIQUE_HEADERS  inverse=1

Broken Rich Text
  ${result} =  Scan Message With Rspamc  ${MESSAGE4}
  Check Rspamc  ${result}  BROKEN_CONTENT_TYPE

*** Keywords ***
Rules Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/regexp.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Rules Teardown
  Normal Teardown
