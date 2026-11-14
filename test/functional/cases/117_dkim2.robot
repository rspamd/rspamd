*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dkim2.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SIGNER}          ${RSPAMD_TESTDIR}/util/dkim2_sign.py
# The envelope of the original message and of the forwarded one
${ORIG_FROM}       bounce@example.com
${ORIG_RCPT}       list@example.net
${FWD_FROM}        bounces@lists.example.net
${FWD_RCPT}        bob@example.org

*** Keywords ***
Scan DKIM2 Message
  [Documentation]  Signatures carry timestamps, so the messages are made on the fly
  [Arguments]  ${scenario}  ${from}=${ORIG_FROM}  ${rcpt}=${ORIG_RCPT}
  ${result} =  Run Process  python3  ${SIGNER}
  ...  --rsa-key  ${RSPAMD_TESTDIR}/configs/dkim.key
  ...  --ed-key  ${RSPAMD_TESTDIR}/configs/dkim-eddsa-pem.key
  ...  ${scenario}  ${RSPAMD_TMPDIR}/${scenario}.eml
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  Scan File  ${RSPAMD_TMPDIR}/${scenario}.eml  From=${from}  Rcpt=${rcpt}

Expect DKIM2 Result
  [Arguments]  ${symbol}  ${option}
  Expect Symbol With Exact Options  ${symbol}  ${option}

*** Test Cases ***
DKIM2 NA
  Scan File  ${RSPAMD_TESTDIR}/messages/utf.eml
  Expect Symbol  R_DKIM2_NA

DKIM2 PASS Originator
  Scan DKIM2 Message  simple
  Expect DKIM2 Result  R_DKIM2_ALLOW  example.com:i=1:m=1/1

DKIM2 PASS Unsigned Header Fields Change
  Scan DKIM2 Message  unsigned_header
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 PASS Bare RSAPublicKey Record
  Scan DKIM2 Message  pkcs1_key
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 PASS SHA512 Hashes
  Scan DKIM2 Message  sha512
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 PASS Hash Alternative
  Scan DKIM2 Message  hash_alternative
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 PASS Hybrid Signatures
  Scan DKIM2 Message  hybrid
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 PASS Signature Alternative
  Scan DKIM2 Message  alternative
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 PASS Forwarded And Modified
  Scan DKIM2 Message  forwarded  from=${FWD_FROM}  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_ALLOW  example.net:i=2:m=2/2

DKIM2 PASS Forwarded Unchanged
  Scan DKIM2 Message  forwarded_unchanged  from=bounces@example.net  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_ALLOW  example.net:i=2:m=1/1

DKIM2 PASS From Rewritten By List
  Scan DKIM2 Message  from_rewrite  from=${FWD_FROM}  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_ALLOW  example.net:i=2:m=2/2

DKIM2 PASS Imaginary Hop
  Scan DKIM2 Message  imaginary_hop  from=fwd@example.org  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_ALLOW  example.org:i=3:m=1/1

DKIM2 PASS Bounce
  Scan DKIM2 Message  bounce  from=${EMPTY}  rcpt=bounce@example.com
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 PASS Subdomain Signs For Parent
  Scan DKIM2 Message  subdomain_from  from=bounce@mail.example.com
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 FAIL Subdomain Signing Forbidden
  Scan DKIM2 Message  strict_from  from=bounce@mail.strict.example
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  mail.strict.example:i=1:m=1/1:provisional:DKIM2-Signature i=1 From strict.example forbids subdomain signing

DKIM2 FAIL Body Changed
  Scan DKIM2 Message  tampered_body
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=0/1:Message-Instance m=1 body hash sha256 mismatch

DKIM2 FAIL Header Added
  Scan DKIM2 Message  tampered_header
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=0/1:Message-Instance m=1 header hash sha256 mismatch

DKIM2 PASS Unusual Header Name
  Scan DKIM2 Message  odd_header_name
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 FAIL Unusual Header Added
  Scan DKIM2 Message  odd_header_added
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=0/1:Message-Instance m=1 header hash sha256 mismatch

DKIM2 FAIL Text Hidden After CR
  Scan DKIM2 Message  hidden_after_cr
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=0/1:Message-Instance m=1 header hash sha256 mismatch

DKIM2 PERMERROR Not A Header Field
  Scan DKIM2 Message  garbage_line
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  message header cannot be verified: a line that is not a header field

DKIM2 FAIL From Confusion
  Scan DKIM2 Message  from_confusion
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:provisional:DKIM2-Signature i=1 From has more than one address

DKIM2 FAIL Unparsable RCPT TO
  Scan DKIM2 Message  simple  rcpt=victim
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 RCPT TO ? did not match

DKIM2 FAIL Unparsable MAIL FROM
  Scan DKIM2 Message  simple  from=a..b@@example.com
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 MAIL FROM ? did not match

DKIM2 PASS Envelope Unknown
  [Documentation]  A scan without the SMTP envelope cannot check it
  ${result} =  Run Process  python3  ${SIGNER}
  ...  --rsa-key  ${RSPAMD_TESTDIR}/configs/dkim.key
  ...  --ed-key  ${RSPAMD_TESTDIR}/configs/dkim-eddsa-pem.key
  ...  simple  ${RSPAMD_TMPDIR}/noenv.eml
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  Scan File  ${RSPAMD_TMPDIR}/noenv.eml
  Expect Symbol  R_DKIM2_ALLOW

DKIM2 FAIL Incorrect Signature
  Scan DKIM2 Message  bad_signature
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 selector rsa incorrect signature

DKIM2 FAIL Expired
  Scan DKIM2 Message  expired
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:provisional:DKIM2-Signature i=1 signature expired

DKIM2 FAIL From The Future
  Scan DKIM2 Message  future
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:provisional:DKIM2-Signature i=1 signature is from the future

DKIM2 FAIL MAIL FROM
  Scan DKIM2 Message  simple  from=other@example.com
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 MAIL FROM other@example.com did not match

DKIM2 FAIL RCPT TO
  Scan DKIM2 Message  simple  rcpt=bcc@example.net
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 RCPT TO bcc@example.net did not match

DKIM2 FAIL Foreign From
  Scan DKIM2 Message  foreign_from
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:provisional:DKIM2-Signature i=1 matching From is not authentic

DKIM2 FAIL Two Addresses In From
  Scan DKIM2 Message  two_from
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.com:i=1:m=1/1:provisional:DKIM2-Signature i=1 From has more than one address

DKIM2 FAIL From Hijacked By Reviser
  Scan DKIM2 Message  from_hijack  from=${FWD_FROM}  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.net:i=2:m=2/2:provisional:DKIM2-Signature i=2 matching From is not authentic

DKIM2 FAIL Undeclared Change
  Scan DKIM2 Message  undeclared_change  from=${FWD_FROM}  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.net:i=2:m=1/2:provisional:Message-Instance m=1 body hash sha256 mismatch

DKIM2 FAIL Replay
  Scan DKIM2 Message  replay  from=spam@example.org  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.org:i=2:m=1/1:provisional:DKIM2-Signature i=2 mf= does not match the rt= of i=1

DKIM2 FAIL Trailing nd
  Scan DKIM2 Message  trailing_nd  from=fwd@example.org  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_REJECT
  ...  example.net:i=2:m=1/1:DKIM2-Signature i=2 unexpected nd= tag

DKIM2 PERMERROR Null Recipe
  Scan DKIM2 Message  null_recipe  from=${FWD_FROM}  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.net:i=2:m=1/2:provisional:Message-Instance m=2 has a null recipe

DKIM2 PERMERROR Duplicate Keys In Recipe
  Scan DKIM2 Message  duplicate_keys  from=bounces@example.net  rcpt=${FWD_RCPT}
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.net:i=2:m=1/2:provisional:Message-Instance m=2 recipe "b" is invalid

DKIM2 PERMERROR Unknown Algorithm
  Scan DKIM2 Message  unknown_alg
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 selector pq algorithm unknown

DKIM2 PERMERROR Hybrid With Unknown Algorithm
  Scan DKIM2 Message  hybrid_unknown
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 selector pq algorithm unknown

DKIM2 PERMERROR Revoked Key
  Scan DKIM2 Message  revoked
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 public key revoked has been revoked

DKIM2 PERMERROR No Key
  Scan DKIM2 Message  nokey
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 public key absent does not exist

DKIM2 PERMERROR Multiple Key Records
  Scan DKIM2 Message  two_records
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 public key two has multiple records

DKIM2 PERMERROR Key Algorithm Mismatch
  Scan DKIM2 Message  key_mismatch
  Expect DKIM2 Result  R_DKIM2_PERMFAIL
  ...  example.com:i=1:m=1/1:DKIM2-Signature i=1 public key ed algorithm mismatch

DKIM2 PERMERROR Exploded Originator
  Scan DKIM2 Message  exploded_first
  Expect DKIM2 Result  R_DKIM2_PERMFAIL  DKIM2-Signature i=1 has an exploded flag

DKIM2 PERMERROR Instance Gap
  Scan DKIM2 Message  gap
  Expect DKIM2 Result  R_DKIM2_PERMFAIL  Message-Instance m=1 missing

DKIM2 PERMERROR Unsigned Instance
  Scan DKIM2 Message  unsigned_instance
  Expect DKIM2 Result  R_DKIM2_PERMFAIL  Message-Instance m=2 is not signed
