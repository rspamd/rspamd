*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/trivial.conf
${GTUBE}        ${TESTDIR}/messages/gtube.eml
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
GTUBE
  ${result} =  Scan Message With Rspamc  ${GTUBE}
  Check Rspamc  ${result}  GTUBE (

GTUBE - Encrypted
  ${result} =  Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  --key  ${KEY_PUB1}
  ...  ${GTUBE}
  Check Rspamc  ${result}  GTUBE (

GTUBE - Scan File feature
  ${result} =  Scan File  ${LOCAL_ADDR}  ${PORT_NORMAL}  ${GTUBE}
  Follow Rspamd Log
  Should Contain  ${result}  GTUBE

GTUBE - Scan File feature (encoded)
  ${encoded} =  Encode Filename  ${GTUBE}
  ${result} =  Scan File  ${LOCAL_ADDR}  ${PORT_NORMAL}  ${encoded}
  Follow Rspamd Log
  Should Contain  ${result}  GTUBE

GTUBE - SPAMC
  ${result} =  Spamc  ${LOCAL_ADDR}  ${PORT_NORMAL}  ${GTUBE}
  Follow Rspamd Log
  Should Contain  ${result}  GTUBE

GTUBE - RSPAMC
  ${result} =  Rspamc  ${LOCAL_ADDR}  ${PORT_NORMAL}  ${GTUBE}
  Follow Rspamd Log
  Should Contain  ${result}  GTUBE
