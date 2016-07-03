*** Settings ***
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/fuzzy.conf
${FLAG1_NUMBER}  50
${FLAG1_SYMBOL}  R_TEST_FUZZY_DENIED
${FLAG2_NUMBER}  51
${FLAG2_SYMBOL}  R_TEST_FUZZY_WHITE
${MESSAGE}      ${TESTDIR}/messages/bad_message.eml
${RSPAMD_SCOPE}  Suite

*** Keywords ***
Fuzzy Add Test
  Set Suite Variable  ${RSPAMD_FUZZY_ADD}  0
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -w  10  -f
  ...  ${FLAG1_NUMBER}  fuzzy_add  ${MESSAGE}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  ${FLAG1_SYMBOL}
  Set Suite Variable  ${RSPAMD_FUZZY_ADD}  1

Fuzzy Delete Test
  Run Keyword If  ${RSPAMD_FUZZY_ADD} == 0  Fail  "Fuzzy Add was not run"
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -f  ${FLAG1_NUMBER}  fuzzy_del
  ...  ${MESSAGE}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Follow Rspamd Log
  Should Not Contain  ${result.stdout}  ${FLAG1_SYMBOL}
  Should Be Equal As Integers  ${result.rc}  0

Fuzzy Overwrite Test
  ${flag_numbers} =  Create List  ${FLAG1_NUMBER}  ${FLAG2_NUMBER}
  : FOR  ${i}  IN  @{flag_numbers}
  \  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -w  10
  \  ...  -f  ${i}  fuzzy_add  ${MESSAGE}
  \  Check Rspamc  ${result}
  Sync Fuzzy Storage
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Follow Rspamd Log
  Should Not Contain  ${result.stdout}  ${FLAG1_SYMBOL}
  Should Contain  ${result.stdout}  ${FLAG2_SYMBOL}
  Should Be Equal As Integers  ${result.rc}  0
