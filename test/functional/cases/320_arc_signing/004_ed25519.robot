*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}           ${RSPAMD_TESTDIR}/configs/arc_signing/ed25519.conf
${MESSAGE_RSA}      ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${MESSAGE_ED25519}  ${RSPAMD_TESTDIR}/messages/dmarc/ed25519_from.eml
${REDIS_SCOPE}      Suite
${RSPAMD_SCOPE}     Suite
${RSPAMD_URL_TLD}   ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
ARC ED25519 BASIC SIGNING
  ${result} =  Scan Message With Rspamc  ${MESSAGE_ED25519}  -u  bob@ed25519.za.org  --mime
  Should Contain  ${result.stdout}  ARC_SIGNED
  Should Contain  ${result.stdout}  a=ed25519-sha256

ARC RSA BASIC SIGNING
  ${result} =  Scan Message With Rspamc  ${MESSAGE_RSA}  -u  bob@cacophony.za.org  --mime
  Should Contain  ${result.stdout}  ARC_SIGNED
  Should Contain  ${result.stdout}  a=rsa-sha256
