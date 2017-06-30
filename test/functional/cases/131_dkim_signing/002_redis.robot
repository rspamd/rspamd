*** Settings ***
Suite Setup     DKIM Signing Setup
Suite Teardown  DKIM Signing Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/dmarc/fail_none.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
TEST SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@rspamd.tk
  Check Rspamc  ${result}  DKIM-Signature:
  Should Contain  ${result.stdout}  DKIM_SIGNED (1.00)

TEST NOT SIGNED - USERNAME WRONG DOMAIN
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@example.tk
  Check Rspamc  ${result}  DKIM-Signature:  inverse=1
  Should Not Contain  ${result.stdout}  DKIM_SIGNED (1.00)

*** Keywords ***
DKIM Signing Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/dkim_signing/redis.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
  Run Redis
  Redis HSET  TEST_DKIM_SELECTORS  rspamd.tk  test
  ${key} =  Get File  ${TESTDIR}/configs/dkim.key
  Redis HSET  TEST_DKIM_KEYS  test.rspamd.tk  ${key}

DKIM Signing Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}
