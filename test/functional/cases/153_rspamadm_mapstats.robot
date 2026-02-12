*** Settings ***
Suite Setup     Rspamadm Setup
Suite Teardown  Rspamadm Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Timeout    1 minute

*** Variables ***
${MAPSTATS_LOG}     ${RSPAMD_TESTDIR}/data/mapstats_test.data
${MAPSTATS_CONF}    ${RSPAMD_TESTDIR}/configs/mapstats_test.conf

*** Test Cases ***
Mapstats map loading
  ${result} =  Run Mapstats
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  TEST_PLAIN
  Should Contain  ${result.stdout}  TEST_IP
  Should Contain  ${result.stdout}  TEST_RE
  Should Contain  ${result.stdout}  [OK]

Mapstats plain map comments
  ${result} =  Run Mapstats
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  \# Test domain
  Should Contain  ${result.stdout}  \# Scored entry

Mapstats IP map comments
  ${result} =  Run Mapstats
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  \# Private network
  Should Contain  ${result.stdout}  \# Internal

Mapstats regexp map comments
  ${result} =  Run Mapstats
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  \# Test pattern

Mapstats plain match counts
  ${result} =  Run Mapstats
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  example.com
  Should Contain  ${result.stdout}  test.org

Mapstats regexp match
  ${result} =  Run Mapstats
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  test-string-

*** Keywords ***
Run Mapstats
  ${result} =  Rspamadm  --var\=TESTDIR\=${RSPAMD_TESTDIR}  mapstats  -c  ${MAPSTATS_CONF}  ${MAPSTATS_LOG}
  RETURN  ${result}
