*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                     ${RSPAMD_TESTDIR}/configs/dkim.conf
${RSPAMD_DKIM_TRUSTED_ONLY}   true
${RSPAMD_SCOPE}               Suite
${RSPAMD_URL_TLD}             ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
DKIM Trusted Only Checks A Trusted Domain
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/dkim_unknown_tags.eml
  Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Exact Options  DKIM_TRACE  taugh.com:+

DKIM Trusted Only Ignores An Untrusted Domain
  [Documentation]  The signature is valid, but its domain is not in the map:
  ...  it is not checked and nothing is reported about it
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_unaligned_verified.eml
  Do Not Expect Symbol  R_DKIM_ALLOW
  Do Not Expect Symbol  R_DKIM_REJECT
  Do Not Expect Symbol  DKIM_TRACE

DKIM Trusted Only Untrusted Signature Does Not Hide A Trusted One
  [Documentation]  A signature of a domain that is not in the map is skipped
  ...  and never gets a result, which must not hold back the result of the
  ...  trusted signature next to it
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_untrusted_and_trusted.eml
  Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Exact Options  DKIM_TRACE  taugh.com:+
