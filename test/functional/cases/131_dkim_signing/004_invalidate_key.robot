*** Settings ***
Force Tags 	isbroken
Suite Setup     Key Invalidation Setup
Suite Teardown  Key Invalidation Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dkim_signing/invalidate.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

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
  Set Suite Variable  ${RSPAMD_KEY_DIR}  ${key_dir}
  Copy File  ${RSPAMD_TESTDIR}/configs/dkim-eddsa.key  ${RSPAMD_KEY_DIR}/dkim-eddsa.key
  Rspamd Setup

Delete Key
  Remove File  ${RSPAMD_KEY_DIR}/dkim-eddsa.key

Move Key
  Copy File  ${RSPAMD_TESTDIR}/configs/dkim.key  ${RSPAMD_KEY_DIR}/dkim-eddsa.key
  Set Modified Time  ${RSPAMD_KEY_DIR}/dkim-eddsa.key  NOW + 3s

Key Invalidation Teardown
  Cleanup Temporary Directory  ${RSPAMD_KEY_DIR}
  Rspamd Teardown
