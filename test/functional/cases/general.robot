*** Settings ***
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Suite Setup     Generic Setup
Suite Teardown  Generic Teardown

*** Variables ***
${CONFIG}           ${TESTDIR}/configs/trivial.conf
${GTUBE}            ${TESTDIR}/messages/gtube.eml
&{RSPAMD_KEYWORDS}  KEY_PUBLIC=${KEY_PUB1}  KEY_PRIVATE=${KEY_PVT1}  LOCAL_ADDR=${LOCAL_ADDR}  PORT_NORMAL=${PORT_NORMAL}  TESTDIR=${TESTDIR}
${RSPAMD_SCOPE}     Suite

*** Test Cases ***
GTUBE
  ${result} =  Scan Message With Rspamc  ${GTUBE}
  Follow Rspamd Log
  Should Contain  ${result.stdout}  GTUBE (

GTUBE - Encrypted
  ${result} =  Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  --key  ${KEY_PUB1}  ${GTUBE}
  Follow Rspamd Log
  Should Contain  ${result.stdout}  GTUBE (

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
