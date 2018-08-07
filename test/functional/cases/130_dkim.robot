*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/dkim.conf
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
DKIM Sign
  Set Suite Variable  ${RAN_SIGNTEST}  0
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/spam_message.eml  --mime  --header=dodkim=1
  Check Rspamc  ${result}  DKIM-Signature
  Set Suite Variable  ${SIGNED_MESSAGE}  ${TMPDIR}/dkim_sign_test.eml
  Create File  ${SIGNED_MESSAGE}  ${result.stdout}
  Set Suite Variable  ${RAN_SIGNTEST}  1

DKIM Self Verify
  Run Keyword If  ${RAN_SIGNTEST} == 0  Fail  "Sign test was not run"
  ${result} =  Scan Message With Rspamc  ${SIGNED_MESSAGE}
  Check Rspamc  ${result}  R_DKIM_ALLOW

DKIM Verify ED25519 PASS
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/ed25519.eml
  Check Rspamc  ${result}  R_DKIM_ALLOW

DKIM Verify ED25519 REJECT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/ed25519-broken.eml
  Check Rspamc  ${result}  R_DKIM_REJECT