*** Settings ***
Suite Setup     New Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/trivial.conf
${GTUBE}        ${TESTDIR}/messages/gtube.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
GTUBE
  Scan File  ${GTUBE}
  Expect Symbol  GTUBE

GTUBE - Encrypted
  ${result} =  Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  --key  ${KEY_PUB1}
  ...  ${GTUBE}
  Check Rspamc  ${result}  GTUBE (

GTUBE - Scan File feature
  Scan File By Reference  ${GTUBE}
  Expect Symbol  GTUBE

GTUBE - Scan File feature (encoded)
  ${encoded} =  Encode Filename  ${GTUBE}
  Scan File By Reference  ${encoded}
  Expect Symbol  GTUBE

GTUBE - SPAMC
  ${result} =  Spamc  ${LOCAL_ADDR}  ${PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

GTUBE - RSPAMC
  ${result} =  Rspamc  ${LOCAL_ADDR}  ${PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

EMAILS DETECTION 1
  Scan File  ${TESTDIR}/messages/emails1.eml  URL-Format=Extended
  Expect Email  jim@example.net
  Expect Email  bob@example.net
  Expect Email  rupert@example.net

EMAILS DETECTION ZEROFONT
  Scan File  ${TESTDIR}/messages/zerofont.eml
  Expect Symbol  MANY_INVISIBLE_PARTS
  Expect Symbol  ZERO_FONT
