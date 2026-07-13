*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE1}           ${RSPAMD_TESTDIR}/messages/phishing1.eml
${MESSAGE2}           ${RSPAMD_TESTDIR}/messages/phishing2.eml
${MESSAGE3}           ${RSPAMD_TESTDIR}/messages/phishing3.eml
${MESSAGE_QSAFE}      ${RSPAMD_TESTDIR}/messages/phishing_query_safe.eml
${MESSAGE_QMULTI}     ${RSPAMD_TESTDIR}/messages/phishing_query_multi.eml
${MESSAGE_QNESTED}    ${RSPAMD_TESTDIR}/messages/phishing_query_nested.eml
${MESSAGE_QNESTFIRE}  ${RSPAMD_TESTDIR}/messages/phishing_query_nested_fire.eml
${MESSAGE_QOVERCAP}   ${RSPAMD_TESTDIR}/messages/phishing_query_overcap.eml
${MESSAGE_XTLD}       ${RSPAMD_TESTDIR}/messages/phishing_same_label_cross_tld.eml
${SETTINGS_PHISHING}  {symbols_enabled = [PHISHING,STRICT_PHISHING,STRICTER_PHISHING]}

*** Test Cases ***
TEST PHISHING
  Scan File  ${MESSAGE1}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING

TEST PHISHING STRICT ONE
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  STRICT_PHISHING

TEST PHISHING STRICT TWO
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  STRICTER_PHISHING

TEST PHISHING NO FP FOR SAME LABEL UNDER DIFFERENT PUBLIC SUFFIX
  # The displayed domain and the href target share the registrable label and
  # differ only in the public suffix (brand.co.za shown over brand.com) -- a
  # common legitimate cross-TLD brand link, not phishing.
  Scan File  ${MESSAGE_XTLD}
  ...  Settings=${SETTINGS_PHISHING}
  Do Not Expect Symbol  PHISHING

TEST PHISHING NO FP WHEN HREF QUERY DEST EQUALS DISPLAY TEXT
  # href host differs from the displayed domain, but the href's query embeds a
  # destination URL equal to the displayed domain (a wrapper/redirector that
  # points back at the shown domain) -- not phishing.
  Scan File  ${MESSAGE_QSAFE}
  ...  Settings=${SETTINGS_PHISHING}
  Do Not Expect Symbol  PHISHING

TEST PHISHING FIRES WHEN HREF QUERY HAS MULTIPLE URLS
  # The href query embeds two URLs (one matching the displayed domain, one not).
  # Multiple embedded URLs are ambiguous, so the single-target wrapper exception
  # does not apply and phishing must still fire on the host mismatch.
  Scan File  ${MESSAGE_QMULTI}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING

TEST PHISHING NO FP WHEN NESTED QUERY LEAF EQUALS DISPLAY TEXT
  # The href wraps a wrapper: its query holds one URL (mid) whose query in turn
  # holds one URL (the displayed domain). Following the single-target chain to
  # the leaf, it equals the displayed domain -- not phishing.
  Scan File  ${MESSAGE_QNESTED}
  ...  Settings=${SETTINGS_PHISHING}
  Do Not Expect Symbol  PHISHING

TEST PHISHING FIRES WHEN NESTED QUERY LEAF DIFFERS FROM DISPLAY TEXT
  # The href wraps a wrapper whose own host equals the displayed domain, but its
  # query wraps a further URL (the leaf) pointing elsewhere. The single-target
  # chain must be followed to the leaf: an intermediate match does not suppress,
  # so phishing fires on the leaf vs display mismatch.
  Scan File  ${MESSAGE_QNESTFIRE}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING

TEST PHISHING FIRES WHEN NESTED CHAIN EXCEEDS NESTING CAP
  # The href wraps a single-target chain deeper than RSPAMD_URL_QUERY_MAX_NESTING.
  # The deepest URL we are willing to follow happens to match the displayed
  # domain, but the real leaf is one more level down and points elsewhere.
  # Since the walk exits via budget exhaustion rather than reaching a natural
  # end, the intermediate match must not suppress phishing.
  Scan File  ${MESSAGE_QOVERCAP}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING
