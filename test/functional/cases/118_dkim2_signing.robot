*** Settings ***
Suite Setup     DKIM2 Signing Setup
Suite Teardown  Rspamd Teardown
Library         Collections
Library         OperatingSystem
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dkim2_signing.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SIGNER}          ${RSPAMD_TESTDIR}/util/dkim2_sign.py
${MAIL_FROM}       bounce@example.com
${RCPT_TO}         list@example.net

*** Keywords ***
DKIM2 Signing Setup
  Rspamd Setup
  ${result} =  Run Process  python3  ${SIGNER}
  ...  --rsa-key  ${RSPAMD_TESTDIR}/configs/dkim.key
  ...  --ed-key  ${RSPAMD_TESTDIR}/configs/dkim-eddsa-pem.key
  ...  unsigned  ${RSPAMD_TMPDIR}/unsigned.eml
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}

Sign Message
  [Documentation]  Scans as a submission and writes the message with the new header fields
  [Arguments]  ${output}  ${from}=${MAIL_FROM}  ${rcpt}=${RCPT_TO}
  Scan File  ${RSPAMD_TMPDIR}/unsigned.eml  User=alice@example.com  From=${from}  Rcpt=${rcpt}
  Expect Symbol With Exact Options  DKIM2_SIGNED  example.com:s=rsa
  ${added} =  Set Variable  ${SCAN_RESULT}[milter][add_headers]
  ${mi} =  Set Variable  ${added}[Message-Instance][value]
  ${sig} =  Set Variable  ${added}[DKIM2-Signature][value]
  ${original} =  Get Binary File  ${RSPAMD_TMPDIR}/unsigned.eml
  ${signed} =  Evaluate  ('DKIM2-Signature: ' + $sig + '\\r\\nMessage-Instance: ' + $mi + '\\r\\n').replace('\\r\\n', '\\n').replace('\\n', '\\r\\n').encode() + $original
  Create Binary File  ${output}  ${signed}

*** Test Cases ***
DKIM2 Sign And Verify
  Sign Message  ${RSPAMD_TMPDIR}/signed.eml
  Scan File  ${RSPAMD_TMPDIR}/signed.eml  From=${MAIL_FROM}  Rcpt=${RCPT_TO}
  Expect Symbol With Exact Options  R_DKIM2_ALLOW  example.com:i=1:m=1/1

DKIM2 Signature Is Bound To The Envelope
  Sign Message  ${RSPAMD_TMPDIR}/signed.eml
  Scan File  ${RSPAMD_TMPDIR}/signed.eml  From=${MAIL_FROM}  Rcpt=victim@example.org
  Expect Symbol With Exact Options  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 RCPT TO victim@example.org did not match

DKIM2 Sign Several Recipients
  Sign Message  ${RSPAMD_TMPDIR}/signed_many.eml  rcpt=list@example.net,bob@example.org,carol@example.com
  Scan File  ${RSPAMD_TMPDIR}/signed_many.eml  From=${MAIL_FROM}  Rcpt=bob@example.org
  Expect Symbol With Exact Options  R_DKIM2_ALLOW  example.com:i=1:m=1/1

DKIM2 Sign Subdomain MAIL FROM
  Sign Message  ${RSPAMD_TMPDIR}/signed_sub.eml  from=bounce@mail.example.com
  Scan File  ${RSPAMD_TMPDIR}/signed_sub.eml  From=bounce@mail.example.com  Rcpt=${RCPT_TO}
  Expect Symbol With Exact Options  R_DKIM2_ALLOW  example.com:i=1:m=1/1

DKIM2 Not Signed Without Envelope
  Scan File  ${RSPAMD_TMPDIR}/unsigned.eml  User=alice@example.com
  Do Not Expect Symbol  DKIM2_SIGNED

DKIM2 Not Signed Foreign MAIL FROM
  [Documentation]  d= must be the MAIL FROM domain or its parent
  Scan File  ${RSPAMD_TMPDIR}/unsigned.eml  User=alice@example.com  From=bounce@example.org  Rcpt=${RCPT_TO}
  Do Not Expect Symbol  DKIM2_SIGNED

DKIM2 Not Signed Twice
  [Documentation]  Only an original message is signed
  Sign Message  ${RSPAMD_TMPDIR}/signed.eml
  Scan File  ${RSPAMD_TMPDIR}/signed.eml  User=alice@example.com  From=${MAIL_FROM}  Rcpt=${RCPT_TO}
  Do Not Expect Symbol  DKIM2_SIGNED
