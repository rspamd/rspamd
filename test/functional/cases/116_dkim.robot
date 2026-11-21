*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dkim.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
DKIM PERMFAIL NXDOMAIN
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim2.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_PERMFAIL

DKIM PERMFAIL BAD RECORD
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_PERMFAIL

DKIM TEMPFAIL SERVFAIL UNALIGNED
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim3.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_TEMPFAIL

DKIM NA NOSIG
  Scan File  ${RSPAMD_TESTDIR}/messages/utf.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_NA

DKIM Ignore Unknown Tags
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/dkim_unknown_tags.eml
  Expect Symbol  R_DKIM_ALLOW

DKIM Reject Oversized Header List
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_huge_hlist.eml
  ...  IP=37.48.67.26
  Do Not Expect Symbol  R_DKIM_ALLOW

DKIM Accept Large Header List Below Limit
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_large_hlist.eml
  ...  IP=37.48.67.26
  Expect Symbol  R_DKIM_PERMFAIL

DKIM Unparseable Signatures Count Towards Limit
  [Documentation]  Five signatures that do not parse use up max_sigs, so a
  ...  valid signature of an unrelated domain below them is left out, and the
  ...  truncation is reported with the counts
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_many_sigs_unaligned.eml
  Do Not Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Exact Options  DKIM_SIGS_TRUNCATED  total=6  checked=5

DKIM Aligned Signature Beyond Limit Is Still Checked
  [Documentation]  The author's signature is the oldest one, so it is the
  ...  first to fall behind max_sigs: it is still checked as its domain is
  ...  aligned with From, and nothing is reported as left out
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_many_sigs.eml
  Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Option  R_DKIM_ALIGNED  strict
  Do Not Expect Symbol  DKIM_SIGS_TRUNCATED

DKIM Aligned Signatures Beyond Limit Are Taken From The Bottom
  [Documentation]  Two signatures above the author's one claim its domain as
  ...  well: the two extra checks go to the lowest candidates, which include the
  ...  real signature
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_many_sigs_decoys_above.eml
  Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Option  R_DKIM_ALIGNED  strict
  Expect Symbol With Exact Options  DKIM_SIGS_TRUNCATED  total=8  checked=7

DKIM Aligned Signatures Beyond Limit Are Limited Too
  [Documentation]  The extra checks are a budget of their own: claims of the
  ...  author's domain below the real signature use it up, which costs a pass
  ...  and can never earn one
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_many_sigs_decoys_below.eml
  Do Not Expect Symbol  R_DKIM_ALLOW
  Do Not Expect Symbol  R_DKIM_ALIGNED
  Expect Symbol With Exact Options  DKIM_SIGS_TRUNCATED  total=8  checked=7

DKIM Signatures At Limit Are Still Checked
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_sigs_at_limit.eml
  Expect Symbol  R_DKIM_ALLOW
  Do Not Expect Symbol  DKIM_SIGS_TRUNCATED

DKIM Signature With Unusable Key Name Does Not Hide Others
  [Documentation]  No DNS request can be made for a d= with a label of more
  ...  than 63 octets, so no reply ever comes for that signature. It must end
  ...  as a permanent error of its own and not hold back the result of the
  ...  valid signature below it. It claims the author's domain, so it must not
  ...  be a temporary failure either: that would leave an aligned signature
  ...  unresolved at the will of whoever wrote the header
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_unusable_key_name.eml
  Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Option  R_DKIM_ALIGNED  strict
  Expect Symbol  R_DKIM_PERMFAIL
  Do Not Expect Symbol  R_DKIM_TEMPFAIL

DKIM Sign
  Set Suite Variable  ${RAN_SIGNTEST}  0
  ${result} =  Scan Message With Rspamc  ${RSPAMD_TESTDIR}/messages/spam_message.eml  --mime  --header=dodkim=1
  Check Rspamc  ${result}  DKIM-Signature
  Set Suite Variable  ${SIGNED_MESSAGE}  ${RSPAMD_TMPDIR}/dkim_sign_test.eml
  Create File  ${SIGNED_MESSAGE}  ${result.stdout}
  Set Suite Variable  ${RAN_SIGNTEST}  1

DKIM Self Verify
  IF  ${RAN_SIGNTEST} == 0
    Fail  "Sign test was not run"
  END
  Scan File  ${SIGNED_MESSAGE}
  Expect Symbol  R_DKIM_ALLOW

DKIM Verify ED25519 PASS
  Scan File  ${RSPAMD_TESTDIR}/messages/ed25519.eml
  Expect Symbol  R_DKIM_ALLOW

DKIM Verify ED25519 REJECT
  Scan File  ${RSPAMD_TESTDIR}/messages/ed25519-broken.eml
  Expect Symbol  R_DKIM_REJECT

DKIM Verify Unknown Key Type
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_broken_key.eml
  Expect Symbol  R_DKIM_PERMFAIL

DKIM Reject Oversized Key Record
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_key_too_long.eml
  Expect Symbol  R_DKIM_PERMFAIL

DKIM Reject Oversized Key Modulus
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_key_too_wide.eml
  Expect Symbol  R_DKIM_PERMFAIL

DKIM Accept Large Key Below Limit
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_key_wide_ok.eml
  Expect Symbol  R_DKIM_REJECT

DKIM Verify Revoked Key (missing p=)
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_revoked_key.eml
  Expect Symbol  R_DKIM_PERMFAIL

DKIM Sign ED25519 PEM
  ${result} =  Scan Message With Rspamc  ${RSPAMD_TESTDIR}/messages/spam_message.eml  --mime  --header=dodkim=ed25519
  Check Rspamc  ${result}  ed25519-sha256
  Set Suite Variable  ${SIGNED_ED25519_MESSAGE}  ${RSPAMD_TMPDIR}/dkim_sign_ed25519_pem_test.eml
  Create File  ${SIGNED_ED25519_MESSAGE}  ${result.stdout}
