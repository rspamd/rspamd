*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Test Cases ***

URL Suspect - Issue 5731 - Long User Field
  # Test that URLs with oversized user fields are parsed and scored
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_long_user.eml
  Expect Symbol With Exact Options  URL_USER_LONG  129
  Do Not Expect Symbol  URL_USER_VERY_LONG

URL Suspect - Very Long User Field
  # Test that very long user fields get appropriate symbol
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_very_long_user.eml
  Expect Symbol With Exact Options  URL_USER_VERY_LONG  300

URL Suspect - Numeric IP
  # Test numeric IP detection
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_numeric_ip.eml
  Expect Symbol  URL_NUMERIC_IP
  Do Not Expect Symbol  URL_NUMERIC_IP_USER

URL Suspect - Numeric IP with User
  # Test numeric IP with user field (more suspicious)
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_numeric_ip_user.eml
  Expect Symbol  URL_NUMERIC_IP_USER

URL Suspect - Suspicious TLD
  # Test suspicious TLD detection
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_bad_tld.eml
  Expect Symbol  URL_SUSPICIOUS_TLD

URL Suspect - Multiple At Signs
  # Test multiple @ sign detection
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_multiple_at.eml
  Expect Symbol  URL_MULTIPLE_AT_SIGNS

URL Suspect - Normal URL
  # Test that normal URLs don't trigger symbols
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_normal.eml
  Do Not Expect Symbol  URL_USER_PASSWORD
  Do Not Expect Symbol  URL_NUMERIC_IP
  Do Not Expect Symbol  URL_SUSPICIOUS_TLD
