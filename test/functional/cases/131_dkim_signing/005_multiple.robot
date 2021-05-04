*** Settings ***
Suite Setup     New Setup
Suite Teardown  Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/dkim_signing/multiple.conf
${MESSAGE}      ${TESTDIR}/messages/dmarc/fail_none.eml
${MESSAGE_FAIL}      ${TESTDIR}/messages/dmarc/fail_none1.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
TEST DOUBLE SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Check Rspamc  ${result}  (?s)DKIM-Signature.+DKIM-Signature  re=1
  Should Contain  ${result.stdout}  DKIM_SIGNED
