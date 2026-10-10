*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Test Template   Scan Is Accounted Once

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/scan_finalization.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/simple.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Normal Worker V2       ${RSPAMD_PORT_NORMAL}      Scan File
Normal Worker V3       ${RSPAMD_PORT_NORMAL}      Scan File V3
Controller V2          ${RSPAMD_PORT_CONTROLLER}  Scan File
Controller V3          ${RSPAMD_PORT_CONTROLLER}  Scan File V3
Self Scan V2           ${RSPAMD_PORT_PROXY}       Scan File
Self Scan V3           ${RSPAMD_PORT_PROXY}       Scan File V3

*** Keywords ***
Read Scan Counters
  ${response} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat
  Should Be Equal As Integers  ${response}[0]  200
  ${stats} =  Check JSON  ${response}[1]
  RETURN  ${stats}

Scan Is Accounted Once
  [Arguments]  ${port}  ${scan_keyword}
  ${before} =  Read Scan Counters
  Set Test Variable  ${RSPAMD_PORT_NORMAL}  ${port}
  Run Keyword  ${scan_keyword}  ${MESSAGE}
  Expect Symbol  SIMPLE_TEST
  Expect Action  no action
  ${after} =  Read Scan Counters
  Should Be Equal As Integers  ${after}[scanned]  ${{int($before['scanned']) + 1}}
  Should Be Equal As Integers  ${after}[actions][no action]  ${{int($before['actions']['no action']) + 1}}
  ${again} =  Read Scan Counters
  Should Be Equal  ${after}[scanned]  ${again}[scanned]
