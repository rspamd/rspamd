*** Settings ***
Suite Setup     Rspamadm Setup
Suite Teardown  Rspamadm Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Timeout    1 minute

*** Variables ***
${LOGSTATS_LOG}    ${RSPAMD_TESTDIR}/data/logstats_test.data

*** Test Cases ***
Logstats JSON output
  ${result} =  Rspamadm  logstats  --json  ${LOGSTATS_LOG}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  "total"
  Should Contain  ${result.stdout}  "no action"
  Should Contain  ${result.stdout}  "reject"
  Should Contain  ${result.stdout}  "add header"
  Should Contain  ${result.stdout}  "greylist"
  Should Contain  ${result.stdout}  "symbols"

Logstats text output
  ${result} =  Rspamadm  logstats  ${LOGSTATS_LOG}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  Messages scanned: 10
  Should Contain  ${result.stdout}  === Summary
  Should Contain  ${result.stdout}  no action
  Should Contain  ${result.stdout}  reject
  Should Contain  ${result.stdout}  add header
  Should Contain  ${result.stdout}  greylist

Logstats symbol filter
  ${result} =  Rspamadm  logstats  -s  BAYES_SPAM  ${LOGSTATS_LOG}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  BAYES_SPAM
  Should Not Contain  ${result.stdout}  R_SPF_ALLOW
  Should Contain  ${result.stdout}  Messages scanned: 10

Logstats alpha score warning
  ${result} =  Rspamadm  logstats  ${LOGSTATS_LOG}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  WARNING:
  Should Contain  ${result.stdout}  DKIM_TRACE
  Should Contain  ${result.stdout}  alpha_score

Logstats stdin
  ${result} =  Run Process  ${RSPAMADM}
  ...  --var\=TMPDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=DBDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=LOCAL_CONFDIR\=/nonexistent
  ...  logstats  --json  -
  ...  stdin=${LOGSTATS_LOG}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  "total"
  Should Contain  ${result.stdout}  "no action"

Logstats scan time
  ${result} =  Rspamadm  logstats  ${LOGSTATS_LOG}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  scan time min/avg/max
