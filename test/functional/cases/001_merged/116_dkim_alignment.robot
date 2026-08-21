*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_DKIM}    {symbols_enabled = [DKIM_CHECK]}

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
  Scan File  ${RSPAMD_TESTDIR}/messages/ed25519-broken.eml
  ...  Settings=${SETTINGS_DKIM}
  Do Not Expect Symbol  R_DKIM_ALIGNED

DKIM NOT ALIGNED WITHOUT SIGNATURE
  [Documentation]  Alignment is a property of a verified signature, an unsigned
  ...  message has nothing to align
  Scan File  ${RSPAMD_TESTDIR}/messages/utf.eml
  ...  Settings=${SETTINGS_DKIM}
  Expect Symbol  R_DKIM_NA
  Do Not Expect Symbol  R_DKIM_ALIGNED
