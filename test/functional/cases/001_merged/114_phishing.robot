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
${MESSAGE_QTRUSTED}   ${RSPAMD_TESTDIR}/messages/phishing_query_trusted.eml
${MESSAGE_QSTRICT}    ${RSPAMD_TESTDIR}/messages/phishing_query_strict.eml
${SETTINGS_PHISHING}  {symbols_enabled = [PHISHING,PHISHING_QUERY,URL_DISPLAY_MISMATCH,STRICT_PHISHING,STRICTER_PHISHING,TEST_PHISHING_WRAPPER]}

*** Test Cases ***
TEST PHISHING
  Scan File  ${MESSAGE1}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Do Not Expect Symbol  PHISHING_QUERY

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
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Do Not Expect Symbol  PHISHING_QUERY

TEST PHISHING QUERY MATCH IS A SEPARATE LOWER SCORE SIGNAL
  # A matching query target cannot prove that the outer server redirects there.
  Scan File  ${MESSAGE_QSAFE}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Expect Symbol With Score  PHISHING_QUERY  1
  Do Not Expect Symbol  PHISHING

TEST PHISHING FIRES WHEN HREF QUERY HAS MULTIPLE URLS
  # The href query embeds two URLs (one matching the displayed domain, one not).
  # Multiple embedded URLs are ambiguous, so the single-target wrapper exception
  # does not apply and phishing must still fire on the host mismatch.
  Scan File  ${MESSAGE_QMULTI}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_QUERY

TEST PHISHING NESTED QUERY MATCH IS A SEPARATE LOWER SCORE SIGNAL
  # Only the unambiguous leaf counts; intermediate matches cannot lower scoring.
  Scan File  ${MESSAGE_QNESTED}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Expect Symbol With Score  PHISHING_QUERY  1
  Do Not Expect Symbol  PHISHING

TEST PHISHING FIRES WHEN NESTED QUERY LEAF DIFFERS FROM DISPLAY TEXT
  # The href wraps a wrapper whose own host equals the displayed domain, but its
  # query wraps a further URL (the leaf) pointing elsewhere. The single-target
  # chain must be followed to the leaf: an intermediate match does not suppress,
  # so phishing fires on the leaf vs display mismatch.
  Scan File  ${MESSAGE_QNESTFIRE}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_QUERY

TEST PHISHING FIRES WHEN NESTED CHAIN EXCEEDS NESTING CAP
  # The href wraps a single-target chain deeper than RSPAMD_URL_QUERY_MAX_NESTING.
  # The deepest URL we are willing to follow happens to match the displayed
  # domain, but the real leaf is one more level down and points elsewhere.
  # Since the walk exits via budget exhaustion rather than reaching a natural
  # end, the intermediate match must not suppress phishing.
  Scan File  ${MESSAGE_QOVERCAP}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_QUERY

TEST PHISHING KNOWN WRAPPER EXCLUDES SCORING BUT RETAINS MISMATCH
  Scan File  ${MESSAGE_QTRUSTED}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Expect Symbol  TEST_PHISHING_WRAPPER
  Do Not Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_QUERY

TEST PHISHING QUERY MATCH DOES NOT BYPASS STRICT DOMAIN PROTECTION
  Scan File  ${MESSAGE_QSTRICT}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Expect Symbol  STRICT_PHISHING
  Expect Symbol With Score  PHISHING_QUERY  1

TEST PHISHING QUERY MATCH NORMALISES IDN SPELLINGS
  Scan File  ${RSPAMD_TESTDIR}/messages/phishing_query_idn.eml
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Expect Symbol With Score  PHISHING_QUERY  1
  Do Not Expect Symbol  PHISHING

TEST PHISHING AUTHENTICATED WRAPPER EXCLUDES SCORING BUT RETAINS MISMATCH
  Scan File  ${RSPAMD_TESTDIR}/messages/phishing_query_dmarc.eml
  ...  IP=8.8.4.4  From=foo@spf.cacophony.za.org
  ...  Settings={symbols_enabled=[PHISHING,PHISHING_QUERY,URL_DISPLAY_MISMATCH,DMARC_CHECK,DKIM_CHECK,SPF_CHECK]}
  Expect Symbol  DMARC_POLICY_ALLOW
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Do Not Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_QUERY

TEST PHISHING QUERY SYMBOL CAN ENABLE ITS PARENT CHECK
  Scan File  ${MESSAGE_QSAFE}
  ...  Settings={symbols_enabled=[PHISHING_QUERY]}
  Expect Symbol With Score  PHISHING_QUERY  1
