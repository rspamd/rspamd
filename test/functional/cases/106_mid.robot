*** Settings ***
Suite Setup     MID Setup
Suite Teardown  Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
MID - invalid Message-ID
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/fws_fp.eml
  Check Rspamc  ${result}  INVALID_MSGID (1.70)
  Should Not Contain  ${result.stdout}  MISSING_MID
  Should Not Contain  ${result.stdout}  INVALID_MSGID_ALLOWED

MID - invalid Message-ID allowed
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/invalid_mid_allowed.eml
  Check Rspamc  ${result}  INVALID_MSGID_ALLOWED (1.00)
  Should Not Contain  ${result.stdout}  MISSING_MID
  Should Not Contain  ${result.stdout}  INVALID_MSGID (

MID - missing Message-ID
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/freemail.eml
  Check Rspamc  ${result}  MISSING_MID (2.50)
  Should Not Contain  ${result.stdout}  MISSING_MID_ALLOWED
  Should Not Contain  ${result.stdout}  INVALID_MSGID

MID - missing Message-ID allowed
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/onsubdomain_pass_relaxed.eml
  Check Rspamc  ${result}  MISSING_MID_ALLOWED (1.00)
  Should Not Contain  ${result.stdout}  MISSING_MID (
  Should Not Contain  ${result.stdout}  INVALID_MSGID

*** Keywords ***
MID Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/mid.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
