*** Settings ***
Test Teardown   Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/password.conf
${RSPAMD_SCOPE}  Test
${PBKDF_PASSWORD}  "$1$nxnwqu5t6ruqfzb4h7bs47ogmdk9sb74$c8mbmcfyd6aic1sm48qzxuzkw4nhx6te6h7owgxz63bcd7fqu1dy"
${CATENA_PASSWORD}  "$2$9dydyukfndmi8zzp7rbdsu43y7a3iucg$1nketaa9pjqwwzzjxogcrniphw4y5fanixudpwzza85tcb56yzub"

*** Test Cases ***
PASSWORD - PBKDF
  [Setup]  Password Setup  ${PBKDF_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q1  stat
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - PBKDF WRONG
  [Setup]  Password Setup  ${PBKDF_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q1q1  stat
  Check Rspamc  ${result}  Unauthorized

PASSWORD - CATENA
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q1  stat
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - CATENA WRONG
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q  stat
  Check Rspamc  ${result}  Unauthorized

PASSWORD - ENABLE
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q2  stat_reset
  Check Rspamc  ${result}  Messages scanned:

PASSWORD - ENABLE WITH NORMAL
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q1  stat_reset
  Check Rspamc  ${result}  Unauthorized

PASSWORD - ENABLE INCORRECT
  [Setup]  Password Setup  ${CATENA_PASSWORD}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -P  q2q2  stat_reset
  Check Rspamc  ${result}  Unauthorized

*** Keywords ***
Password Setup
  [Arguments]  ${PASSWORD}  ${ENABLE_PASSWORD}=q2
  Set Test Variable  ${PASSWORD}
  Set Test Variable  ${ENABLE_PASSWORD}
  Generic Setup
