*** Settings ***
Suite Setup     ARC Signing Setup
Suite Teardown  Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/arc_signing/redis.conf
${MESSAGE}      ${TESTDIR}/messages/dmarc/fail_none.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
TEST SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Should Contain  ${result.stdout}  ARC_SIGNED

TEST NOT SIGNED - USERNAME WRONG DOMAIN
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@example.tk
  Should Not Contain  ${result.stdout}  ARC_SIGNED

*** Keywords ***
ARC Signing Setup
  Run Redis
  Redis HSET  TEST_DKIM_SELECTORS  cacophony.za.org  arc
  ${key} =  Get File  ${TESTDIR}/configs/dkim.key
  Redis HSET  TEST_DKIM_KEYS  arc.cacophony.za.org  ${key}
  New Setup
