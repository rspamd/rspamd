*** Settings ***
Test Teardown   Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                  ${RSPAMD_TESTDIR}/configs/password.conf
${CONTROLLER_ERRORS}       False
${RSPAMD_CATENA_PASSWORD}  "$2$xu1581gidj5cyp4yjgo68qbj6jz1j8o3$j9yg4k58jy3fj8suijxx9d7pea6a6obtufq9kfenosyq8erm87ky"
${RSPAMD_PBKDF_PASSWORD}   "$1$rhzzahtm8a5homdhh7z4qiiy7j8pzp4u$k5toro136brshjjuy9t39r785td69qodmd39qzygxuyehn9tqauy"
${RSPAMD_ENABLE_CATENA_PASSWORD}   "$2$irotou88u89r1gj53pqnom96qo36hgkn$d4dt3466db7ccqx96k18yz9b1brx8hmk3b4w6erf4oqpmf9sag6y"
${RSPAMD_SCOPE}            Test

*** Test Cases ***
PASSWORD - PBKDF
  [Setup]  Password Setup  ${RSPAMD_PBKDF_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  nq1  stat
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - PBKDF WRONG
  [Setup]  Password Setup  ${RSPAMD_PBKDF_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  q1q1  stat
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - CATENA
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  nq1  stat
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - CATENA WRONG
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  q  stat
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - ENABLE
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  nq2  stat_reset
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - ENABLE WITH NORMAL
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  nq1  stat_reset
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - ENABLE INCORRECT
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  q2q2  stat_reset
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - ENABLE EQUAL TO NORMAL PRIV COMMAND
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  nq1  stat_reset
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - ENABLE EQUAL TO NORMAL NON PRIV COMMAND
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  nq1  stat
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - ENABLE EQUAL TO NORMAL WRONG PASSWORD
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -P  nq2  stat
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - FAILURES ARE THROTTLED
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  # Verifying a password runs an expensive KDF, so a source that keeps failing
  # must stop being served before it can stall the controller's event loop
  ${allowed} =  Set Variable  ${0}
  ${code} =  Set Variable  ${0}
  FOR  ${i}  IN RANGE  30
    ${code} =  Controller Auth Status  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  wrong${i}
    Exit For Loop If  ${code} == 429
    Should Be Equal As Integers  ${code}  401
    ${allowed} =  Evaluate  ${allowed} + 1
  END
  Should Be Equal As Integers  ${code}  429
  Should Be True  ${allowed} >= 10

PASSWORD - THROTTLING RESET BY A SUCCESSFUL AUTH
  [Setup]  Password Setup  ${RSPAMD_CATENA_PASSWORD}  ${RSPAMD_ENABLE_CATENA_PASSWORD}
  FOR  ${i}  IN RANGE  5
    ${code} =  Controller Auth Status  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  wrong${i}
    Should Be Equal As Integers  ${code}  401
  END
  ${code} =  Controller Auth Status  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  nq1
  Should Be Equal As Integers  ${code}  200
  # The budget is replenished, so these still get a verdict rather than a 429
  FOR  ${i}  IN RANGE  10
    ${code} =  Controller Auth Status  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  other${i}
    Should Be Equal As Integers  ${code}  401
  END

*** Keywords ***
Password Setup
  [Arguments]  ${RSPAMD_PASSWORD}  ${RSPAMD_ENABLE_PASSWORD}
  Set Test Variable  ${RSPAMD_PASSWORD}
  Set Test Variable  ${RSPAMD_ENABLE_PASSWORD}
  Rspamd Setup
