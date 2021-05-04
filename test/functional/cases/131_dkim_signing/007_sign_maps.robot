*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dkim_signing/sign_maps.conf
${MESSAGE_FAIL}    ${RSPAMD_TESTDIR}/messages/dmarc/fail_none1.eml
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
TEST SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Check Rspamc  ${result}  DKIM-Signature:
  Should Contain  ${result.stdout}  DKIM_SIGNED

TEST NOT SIGNED - FROM WRONG DOMAIN
  ${result} =  Scan Message With Rspamc  ${MESSAGE_FAIL}  -u  bob@cacophony.za.org
  Check Rspamc  ${result}  DKIM-Signature:  inverse=1
  Should Not Contain  ${result.stdout}  DKIM_SIGNED
