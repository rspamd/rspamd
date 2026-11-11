*** Settings ***
Documentation    Regression test for history reset over the Redis backend
...              (issue #2910). Reset must clear ALL rows, including the
...              newest one that LPUSH places at list index 0.
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library          Process
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py


*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/history_redis.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}        Suite
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat


*** Test Cases ***
Reset clears all Redis history rows
  Scan File  ${MESSAGE}
  # LPUSH is async — wait until the scan's row is visible before resetting
  Wait Until Keyword Succeeds  10x  0.5s  History Should Have Rows  1
  ${result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /historyreset
  Should Be Equal As Integers  ${result}[0]  200
  Check JSON  ${result}[1]
  # Regression: must be 0, not 1. Before the DEL fix LTRIM kept index 0.
  Wait Until Keyword Succeeds  10x  0.5s  History Should Have Rows  0


*** Keywords ***
History Should Have Rows
  [Arguments]  ${expected}
  @{result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /history
  ${history} =  Check JSON  ${result}[1]
  ${n} =  Get Length  ${history}[rows]
  Should Be Equal As Integers  ${n}  ${expected}
