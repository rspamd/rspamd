*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml

*** Test Cases ***
RBL FROM MISS
  Scan File  ${MESSAGE}  IP=1.2.3.4
  ...  Settings={symbols_enabled = [FAKE_RBL_UNKNOWN_CHECK]}
  Do Not Expect Symbol  FAKE_RBL_CODE_2

RBL FROM HIT
  Scan File  ${MESSAGE}  IP=4.3.2.1
  ...  Settings={symbols_enabled = [FAKE_RBL_UNKNOWN_CHECK]}
  Expect Symbol  FAKE_RBL_CODE_2

RBL FROM MULTIPLE HIT
  Scan File  ${MESSAGE}  IP=4.3.2.3
  ...  Settings={symbols_enabled = [FAKE_RBL_UNKNOWN_CHECK]}
  Expect Symbol  FAKE_RBL_CODE_2
  Expect Symbol  FAKE_RBL_CODE_3

RBL FROM UNKNOWN HIT
  Scan File  ${MESSAGE}  IP=4.3.2.2
  ...  Settings={symbols_enabled = [FAKE_RBL_UNKNOWN_CHECK]}
  Expect Symbol  FAKE_RBL_FAKE_RBL_UNKNOWN

RBL RECEIVED HIT
  Scan File  ${MESSAGE}  IP=8.8.8.8
  ...  Settings={symbols_enabled = [FAKE_RECEIVED_RBL_FAKE_RBL_UNKNOWN]}
  Expect Symbol  FAKE_RECEIVED_RBL_CODE_3

RBL FROM HIT WL
  Scan File  ${MESSAGE}  IP=4.3.2.4
  ...  Settings={symbols_enabled = [FAKE_RBL_UNKNOWN, FAKE_WL_RBL_UNKNOWN]}
  Do Not Expect Symbol  FAKE_RBL_CODE_2
  Expect Symbol With Exact Options  FAKE_WL_RBL_CODE_2  4.3.2.4:from

EMAILBL Compose Map 1
  Scan File  ${RSPAMD_TESTDIR}/messages/url14.eml
  ...  Settings={symbols_enabled = [RSPAMD_EMAILBL]}
  Expect Symbol With Exact Options  RSPAMD_EMAILBL  dirty.sanchez.com:email

EMAILBL Compose Map 2
  Scan File  ${RSPAMD_TESTDIR}/messages/url15.eml
  ...  Settings={symbols_enabled = [RSPAMD_EMAILBL]}
  Expect Symbol With Exact Options  RSPAMD_EMAILBL  very.dirty.sanchez.com:email

EMAILBL Compose Map 3
  Scan File  ${RSPAMD_TESTDIR}/messages/url16.eml
  ...  Settings={symbols_enabled = [RSPAMD_EMAILBL]}
  Expect Symbol With Exact Options  RSPAMD_EMAILBL  41.black.sanchez.com:email

CONTENT URLS
  Scan File  ${RSPAMD_TESTDIR}/messages/content_url.eml
  ...  Settings={symbols_enabled = [URIBL_CONTENTONLY, URIBL_NOCONTENT, URIBL_WITHCONTENT]}
  Expect Symbol With Exact Options  URIBL_NOCONTENT  example.org:url
  Expect Symbol With Option  URIBL_WITHCONTENT  example.com:url
  Expect Symbol With Option  URIBL_WITHCONTENT  example.org:url
  Expect Symbol With Option  URIBL_WITHCONTENT  8.8.8.8:url
  Expect Symbol With Exact Options  URIBL_CONTENTONLY  example.com:url

SELECTORS SEPARATE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml  From=user@example.com  Helo=example.org
  ...  Settings={symbols_enabled = [RBL_SELECTOR_SINGLE, RBL_SELECTOR_MULTIPLE]}
  Expect Symbol With Exact Options  RBL_SELECTOR_SINGLE  example.org:selector
  # Different domains -> different DNS queries -> not merged, one option each
  Expect Symbol With Exact Options  RBL_SELECTOR_MULTIPLE  example.com:sel_from  example.org:sel_helo

SELECTORS COMBINED
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml  From=user@example.org  Helo=example.org
  ...  Settings={symbols_enabled = [RBL_SELECTOR_MULTIPLE]}
  # Same domain -> same DNS query -> merged into a single, comma-joined option
  Expect Symbol With Exact Options  RBL_SELECTOR_MULTIPLE  example.org:sel_from,sel_helo

SELECTORS MERGED FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_MERGED_ERR]}
  # A failing merged query reports every origin, not an arbitrary one
  Expect Symbol With Exact Options  RBL_MERGED_ERR_FAIL
  ...  FAILTEST.EXAMPLE:server fail  failtest.example:server fail
  Expect Symbol With Score  RBL_MERGED_ERR_FAIL  1.0

SELECTORS HASHED TRAILING DOT
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_HASH]}
  # The trailing dot is stripped before hashing, so both spellings hash alike
  Expect Symbol With Exact Options  RBL_SELECTOR_HASH  example.org:plain  example.org.:dotted

SELECTORS COMBINED DISABLED
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_NOMERGE]}
  # merge_checks = false -> one option (and one score shot) per check
  Expect Symbol With Exact Options  RBL_SELECTOR_NOMERGE  example.org:sel_from  example.org:sel_helo
  Expect Symbol With Score  RBL_SELECTOR_NOMERGE  4.0

SELECTORS COMBINED SYMBOL PREFIXES
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_PREFIXES_CHECK]}
  Expect Symbol With Exact Options  RBL_CODE_2  example.org:from
  Expect Symbol With Exact Options  RECEIVED_CODE_2  example.org:received
  # Merging the query does not merge the symbols: each prefix scores in full
  Expect Symbol With Score  RBL_CODE_2  2.0
  Expect Symbol With Score  RECEIVED_CODE_2  3.0

SELECTORS CASE INSENSITIVE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_CASE]}
  Expect Symbol With Exact Options  RBL_SELECTOR_CASE  example.org:lower  EXAMPLE.ORG:upper
  # Both origins are the same listing, so the score is only counted once
  Expect Symbol With Score  RBL_SELECTOR_CASE  2.0

SELECTOR IP USERDATA
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml  IP=1.2.3.4
  ...  Settings={symbols_enabled = [RBL_SELECTOR_IP]}
  Expect Symbol With Exact Options  RBL_SELECTOR_IP  1.2.3.4:selector

SELECTORS RESOLVE IP COMBINED
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_RESOLVE]}
  Expect Symbol With Exact Options  RBL_SELECTOR_RESOLVE_HIT  8.8.8.9:example.ru:first,second

SELECTORS MERGED WHITELIST
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_WL]}
  Expect Symbol With Exact Options  RBL_SELECTOR_WL_HIT  example.org:plain  example.org.:dotted

NUMERIC URLS
  Scan File  ${RSPAMD_TESTDIR}/messages/numeric_urls.eml
  ...  Settings={symbols_enabled = [URIBL_NUMERIC]}
  Expect Symbol With Exact Options  URIBL_NUMERIC  4.3.2.1:url

NUMERIC URLS WITH IMAGES
  Scan File  ${RSPAMD_TESTDIR}/messages/numeric_urls.eml
  ...  Settings={symbols_enabled = [URIBL_NUMERIC_IMAGES]}
  Expect Symbol With Exact Options  URIBL_NUMERIC_IMAGES  4.3.2.1:url  12.11.10.9:url

NUMERIC URLS WITH CONTENT
  Scan File  ${RSPAMD_TESTDIR}/messages/numeric_urls.eml
  ...  Settings={symbols_enabled = [URIBL_NUMERIC_CONTENT]}
  Expect Symbol With Exact Options  URIBL_NUMERIC_CONTENT  4.3.2.1:url  8.7.6.5:url

NUMERIC URLS WITH EVERYTHING
  Scan File  ${RSPAMD_TESTDIR}/messages/numeric_urls.eml
  ...  IP=127.0.0.1
  ...  Settings={symbols_enabled = [URIBL_NUMERIC_EVERYTHING]}
  Expect Symbol With Exact Options  URIBL_NUMERIC_EVERYTHING  12.11.10.9:url  4.3.2.1:url  8.7.6.5:url

NONNUMERIC URLS VANILLA
  Scan File  ${RSPAMD_TESTDIR}/messages/numeric_urls.eml
  ...  Settings={symbols_enabled = [URIBL_NONNUMERIC_VANILLA]}
  # Content
  Do Not Expect Symbol With Option  URIBL_NONNUMERIC_VANILLA  example.com:url
  # Image
  Do Not Expect Symbol With Option  URIBL_NONNUMERIC_VANILLA  judo.za.org:url
  # URL
  Expect Symbol With Option  URIBL_NONNUMERIC_VANILLA  example.org:url
  # Numeric
  Do Not Expect Symbol With Option  URIBL_NONNUMERIC_VANILLA  4.3.2.1:url
  Do Not Expect Symbol With Option  URIBL_NONNUMERIC_VANILLA  1.2.3.4:url

NONNUMERIC URLS WITH EVERYTHING
  Scan File  ${RSPAMD_TESTDIR}/messages/numeric_urls.eml
  ...  Settings={symbols_enabled = [URIBL_NONNUMERIC_EVERYTHING]}
  # Content
  Expect Symbol With Option  URIBL_NONNUMERIC_EVERYTHING  example.com:url
  # Image
  Expect Symbol With Option  URIBL_NONNUMERIC_EVERYTHING  judo.za.org:url
  # URL
  Expect Symbol With Option  URIBL_NONNUMERIC_EVERYTHING  example.org:url
  # Numeric
  Do Not Expect Symbol With Option  URIBL_NONNUMERIC_EVERYTHING  4.3.2.1:url
  Do Not Expect Symbol With Option  URIBL_NONNUMERIC_EVERYTHING  1.2.3.4:url
