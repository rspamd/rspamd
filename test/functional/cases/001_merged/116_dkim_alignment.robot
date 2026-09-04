*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_DKIM}     {symbols_enabled = [DKIM_CHECK]}
${SETTINGS_DMARC}    {symbols_enabled = [DKIM_CHECK, SPF_CHECK, DMARC_CHECK]}

*** Test Cases ***
DKIM ALIGNED STRICT
  [Documentation]  A verified signature whose d= equals the From domain is
  ...  aligned in the strict sense, which is reported as the symbol option
  Scan File  ${RSPAMD_TESTDIR}/messages/ed25519.eml
  ...  Settings=${SETTINGS_DKIM}
  Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Option  R_DKIM_ALIGNED  strict

DKIM ALIGNED RELAXED
  [Documentation]  A verified signature from the organisational domain of the
  ...  From domain is aligned in the relaxed sense only
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  Settings=${SETTINGS_DKIM}
  Expect Symbol  R_DKIM_ALLOW
  Expect Symbol With Option  R_DKIM_ALIGNED  relaxed

DKIM NOT ALIGNED
  [Documentation]  A signature that verifies for an unrelated domain authorises
  ...  nothing about the author, so no alignment is reported
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_unaligned_verified.eml
  ...  Settings=${SETTINGS_DKIM}
  Expect Symbol  R_DKIM_ALLOW
  Do Not Expect Symbol  R_DKIM_ALIGNED

DKIM NOT ALIGNED WITHOUT A SINGLE AUTHOR
  [Documentation]  Alignment needs an unambiguous author. A From header naming
  ...  two addresses has none, so a signature that would otherwise align earns
  ...  nothing, the same precondition DMARC applies
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_multi_from_signed.eml
  ...  Settings=${SETTINGS_DKIM}
  Expect Symbol  R_DKIM_ALLOW
  Do Not Expect Symbol  R_DKIM_ALIGNED

DKIM ALIGNED TEMPFAIL
  [Documentation]  A signature aligned with the author whose key could not be
  ...  resolved is tracked apart from one that verified, so a policy can tell an
  ...  unresolved alignment from an absent one
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_aligned_tempfail.eml
  ...  Settings=${SETTINGS_DKIM}
  Expect Symbol  R_DKIM_TEMPFAIL
  Do Not Expect Symbol  R_DKIM_ALIGNED

DMARC READS AN UNRESOLVED ALIGNMENT AS A TEMPORARY ERROR
  [Documentation]  The point of tracking it apart: a policy must not report a
  ...  definitive failure while an aligned signature is still unresolved
  Scan File  ${RSPAMD_TESTDIR}/messages/dkim_aligned_tempfail.eml
  ...  IP=37.48.67.26
  ...  Settings=${SETTINGS_DMARC}
  Expect Symbol  DMARC_DNSFAIL
  Do Not Expect Symbol  DMARC_POLICY_SOFTFAIL

DKIM NOT ALIGNED WITHOUT SIGNATURE
  [Documentation]  Alignment is a property of a verified signature, an unsigned
  ...  message has nothing to align
  Scan File  ${RSPAMD_TESTDIR}/messages/utf.eml
  ...  Settings=${SETTINGS_DKIM}
  Expect Symbol  R_DKIM_NA
  Do Not Expect Symbol  R_DKIM_ALIGNED
