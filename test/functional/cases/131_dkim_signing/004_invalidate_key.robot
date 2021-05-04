*** Settings ***
Force Tags 	isbroken
Suite Setup     Key Invalidation Setup
Suite Teardown  Key Invalidation Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/dkim_signing/invalidate.conf
${MESSAGE}      ${TESTDIR}/messages/dmarc/fail_none.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
TEST SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Check Rspamc  ${result}  DKIM-Signature:
  Should Contain  ${result.stdout}  DKIM_SIGNED

TEST NOT SIGNED - MISSING KEY
  [Setup] 	Delete Key
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Check Rspamc  ${result}  DKIM-Signature:  inverse=1
  Should Not Contain  ${result.stdout}  DKIM_SIGNED

TEST NOT SIGNED - KEY NO LONGER MATCHES
  [Setup]	Move Key
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Check Rspamc  ${result}  DKIM-Signature:  inverse=1
  Should Not Contain  ${result.stdout}  DKIM_SIGNED

*** Keywords ***
Key Invalidation Setup
  ${key_dir}  Make Temporary Directory
  Set Suite Variable  ${KEY_DIR}  ${key_dir}
  Copy File  ${TESTDIR}/configs/dkim-eddsa.key  ${KEY_DIR}/dkim-eddsa.key
  New Setup

Delete Key
  Remove File  ${KEY_DIR}/dkim-eddsa.key

Move Key
  Copy File  ${TESTDIR}/configs/dkim.key  ${KEY_DIR}/dkim-eddsa.key
  Set Modified Time  ${KEY_DIR}/dkim-eddsa.key  NOW + 3s

Key Invalidation Teardown
  Cleanup Temporary Directory  ${KEY_DIR}
  Normal Teardown
