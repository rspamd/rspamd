*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/trivial.conf
${GTUBE}           ${RSPAMD_TESTDIR}/messages/gtube.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
GTUBE
  Scan File  ${GTUBE}
  Expect Symbol  GTUBE

GTUBE - Encrypted
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --key  ${RSPAMD_KEY_PUB1}
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
  ${result} =  Spamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

GTUBE - RSPAMC
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

EMAILS DETECTION 1
  Scan File  ${RSPAMD_TESTDIR}/messages/emails1.eml  URL-Format=Extended
  Expect Email  jim@example.net
  Expect Email  bob@example.net
  Expect Email  rupert@example.net

EMAILS DETECTION ZEROFONT
  Scan File  ${RSPAMD_TESTDIR}/messages/zerofont.eml
  Expect Symbol  MANY_INVISIBLE_PARTS
  Expect Symbol  ZERO_FONT
