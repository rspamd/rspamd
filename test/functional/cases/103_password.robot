*** Settings ***
Test Teardown   Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/password.conf
${CONTROLLER_ERRORS}  False
${RSPAMD_SCOPE}  Test
${PBKDF_PASSWORD}  "$1$rhzzahtm8a5homdhh7z4qiiy7j8pzp4u$k5toro136brshjjuy9t39r785td69qodmd39qzygxuyehn9tqauy"
${CATENA_PASSWORD}  "$2$xu1581gidj5cyp4yjgo68qbj6jz1j8o3$j9yg4k58jy3fj8suijxx9d7pea6a6obtufq9kfenosyq8erm87ky"

*** Test Cases ***
PASSWORD - PBKDF
  [Setup]  Password Setup  ${PBKDF_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  nq1  stat
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - PBKDF WRONG
  [Setup]  Password Setup  ${PBKDF_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q1q1  stat
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - CATENA
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  nq1  stat
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - CATENA WRONG
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q  stat
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - ENABLE
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  nq2  stat_reset
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - ENABLE WITH NORMAL
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  nq1  stat_reset
  Should Be Equal As Integers  ${result.rc}  1

PASSWORD - ENABLE INCORRECT
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q2q2  stat_reset
  Should Be Equal As Integers  ${result.rc}  1

*** Keywords ***
Password Setup
  [Arguments]  ${PASSWORD}  ${ENABLE_PASSWORD}=nq2
  Set Test Variable  ${PASSWORD}
  Set Test Variable  ${ENABLE_PASSWORD}
  New Setup  PASSWORD=${PASSWORD}  ENABLE_PASSWORD=${ENABLE_PASSWORD}
