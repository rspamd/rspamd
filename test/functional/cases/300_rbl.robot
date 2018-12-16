*** Settings ***
Suite Setup     Rbl Setup
Suite Teardown  Rbl Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
RBL FROM MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  1.2.3.4
  Check Rspamc  ${result}  FAKE_RBL_CODE_2  inverse=True

RBL FROM HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  4.3.2.1
  Check Rspamc  ${result}  FAKE_RBL_CODE_2

RBL FROM MULTIPLE HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  4.3.2.3
  Check Rspamc  ${result}  FAKE_RBL_CODE_2  FAKE_RBL_CODE_3

RBL FROM UNKNOWN HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  4.3.2.2
  Check Rspamc  ${result}  FAKE_RBL_UNKNOWN

RBL RECEIVED HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  8.8.8.8
  Check Rspamc  ${result}  FAKE_RECEIVED_RBL_CODE_3

RBL FROM HIT WL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  4.3.2.4
  Check Rspamc  ${result}  FAKE_RBL_CODE_2  inverse=True

*** Keywords ***
Rbl Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/rbl.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Rbl Teardown
  Normal Teardown
  Terminate All Processes    kill=True