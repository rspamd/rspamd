*** Settings ***
Suite Setup     DKIM Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/dkim.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
DKIM PERMFAIL NXDOMAIN
  Scan File  ${TESTDIR}/messages/dmarc/bad_dkim2.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_PERMFAIL

DKIM PERMFAIL BAD RECORD
  Scan File  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_PERMFAIL

DKIM TEMPFAIL SERVFAIL UNALIGNED
  Scan File  ${TESTDIR}/messages/dmarc/bad_dkim3.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_TEMPFAIL

DKIM NA NOSIG
  Scan File  ${TESTDIR}/messages/utf.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_NA

DKIM Sign
  Set Suite Variable  ${RAN_SIGNTEST}  0
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/spam_message.eml  --mime  --header=dodkim=1
  Check Rspamc  ${result}  DKIM-Signature
  Set Suite Variable  ${SIGNED_MESSAGE}  ${TMPDIR}/dkim_sign_test.eml
  Create File  ${SIGNED_MESSAGE}  ${result.stdout}
  Set Suite Variable  ${RAN_SIGNTEST}  1

DKIM Self Verify
  Run Keyword If  ${RAN_SIGNTEST} == 0  Fail  "Sign test was not run"
  Scan File  ${SIGNED_MESSAGE}
  Expect Symbol  R_DKIM_ALLOW

DKIM Verify ED25519 PASS
  Scan File  ${TESTDIR}/messages/ed25519.eml
  Expect Symbol  R_DKIM_ALLOW

DKIM Verify ED25519 REJECT
  Scan File  ${TESTDIR}/messages/ed25519-broken.eml
  Expect Symbol  R_DKIM_REJECT

*** Keywords ***
DKIM Setup
  New Setup
