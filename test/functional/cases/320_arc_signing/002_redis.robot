*** Settings ***
Suite Setup     ARC Signing Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/arc_signing/redis.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
TEST SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Should Contain  ${result.stdout}  ARC_SIGNED

TEST NOT SIGNED - USERNAME WRONG DOMAIN
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@example.tk
  Should Not Contain  ${result.stdout}  ARC_SIGNED

*** Keywords ***
ARC Signing Setup
  Rspamd Redis Setup
  Redis HSET  TEST_DKIM_SELECTORS  cacophony.za.org  arc
  ${key} =  Get File  ${RSPAMD_TESTDIR}/configs/dkim.key
  Redis HSET  TEST_DKIM_KEYS  arc.cacophony.za.org  ${key}
