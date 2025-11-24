*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Test Cases ***

URL Suspect - Issue 5731 - Long User Field
  # Test that URLs with oversized user fields are parsed and scored
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_long_user.eml
  ...  Settings={symbols_enabled = [URL_SUSPECT_CHECK, URL_USER_LONG, URL_USER_VERY_LONG, URL_USER_PASSWORD]}
  Expect Symbol With Exact Options  URL_USER_LONG  129
  Do Not Expect Symbol  URL_USER_VERY_LONG

URL Suspect - Very Long User Field
  # Test that very long user fields get appropriate symbol
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_very_long_user.eml
  ...  Settings={symbols_enabled = [URL_SUSPECT_CHECK, URL_USER_LONG, URL_USER_VERY_LONG, URL_USER_PASSWORD]}
  Expect Symbol With Exact Options  URL_USER_VERY_LONG  300

URL Suspect - Numeric IP
  # Test numeric IP detection
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_numeric_ip.eml
  ...  Settings={symbols_enabled = [URL_SUSPECT_CHECK, URL_NUMERIC_IP, URL_NUMERIC_IP_USER, URL_NUMERIC_PRIVATE_IP]}
  Expect Symbol  URL_NUMERIC_IP
  Do Not Expect Symbol  URL_NUMERIC_IP_USER

URL Suspect - Numeric IP with User
  # Test numeric IP with user field (more suspicious)
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_numeric_ip_user.eml
  ...  Settings={symbols_enabled = [URL_SUSPECT_CHECK, URL_NUMERIC_IP, URL_NUMERIC_IP_USER, URL_NUMERIC_PRIVATE_IP]}
  Expect Symbol  URL_NUMERIC_IP_USER

URL Suspect - Suspicious TLD
  # Test suspicious TLD detection
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_bad_tld.eml
  ...  Settings={symbols_enabled = [URL_SUSPECT_CHECK, URL_SUSPICIOUS_TLD, URL_NO_TLD]}
  Expect Symbol  URL_SUSPICIOUS_TLD

URL Suspect - Multiple At Signs
  # Test multiple @ sign detection
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_multiple_at.eml
  ...  Settings={symbols_enabled = [URL_SUSPECT_CHECK, URL_MULTIPLE_AT_SIGNS]}
  Expect Symbol  URL_MULTIPLE_AT_SIGNS

URL Suspect - Normal URL
  # Test that normal URLs don't trigger symbols
  Scan File  ${RSPAMD_TESTDIR}/messages/url_suspect_normal.eml
  ...  Settings={symbols_enabled = [URL_SUSPECT_CHECK, URL_USER_PASSWORD, URL_NUMERIC_IP, URL_SUSPICIOUS_TLD]}
  Do Not Expect Symbol  URL_USER_PASSWORD
  Do Not Expect Symbol  URL_NUMERIC_IP
  Do Not Expect Symbol  URL_SUSPICIOUS_TLD

URL Suspect - Obfuscated hxxp
  # Test hxxp:// obfuscation detection
  Scan File  ${RSPAMD_TESTDIR}/messages/url_obfuscated_hxxp.eml
  ...  Settings={symbols_enabled = [URL_OBFUSCATED_TEXT]}
  Expect Symbol  URL_OBFUSCATED_TEXT

URL Suspect - Obfuscated Bracket Dots
  # Test bracket dots obfuscation detection: example[.]com
  Scan File  ${RSPAMD_TESTDIR}/messages/url_obfuscated_bracket_dots.eml
  ...  Settings={symbols_enabled = [URL_OBFUSCATED_TEXT]}
  Expect Symbol  URL_OBFUSCATED_TEXT

URL Suspect - Obfuscated Word Dot
  # Test word dot obfuscation detection: example dot com
  Scan File  ${RSPAMD_TESTDIR}/messages/url_obfuscated_word_dot.eml
  ...  Settings={symbols_enabled = [URL_OBFUSCATED_TEXT]}
  Expect Symbol  URL_OBFUSCATED_TEXT

URL Suspect - Obfuscated Spaced Protocol
  # Test spaced protocol obfuscation: h t t p s : / /
  Scan File  ${RSPAMD_TESTDIR}/messages/url_obfuscated_spaced.eml
  ...  Settings={symbols_enabled = [URL_OBFUSCATED_TEXT]}
  Expect Symbol  URL_OBFUSCATED_TEXT
