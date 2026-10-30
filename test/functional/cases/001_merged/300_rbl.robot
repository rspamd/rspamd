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

# RBL_CALLBACK_WHITE has to be enabled explicitly: it is what turns the hits of
# the whitelist rules into the exclusion list the blacklist rules consult, so
# without it the `Do Not Expect` below would hold for the wrong reason. Same for
# FAKE_RBL_UNKNOWN_CHECK rather than FAKE_RBL_UNKNOWN: the rule has
# symbols_prefixes, so _CHECK is the name of its callback.
RBL FROM HIT WL
  Scan File  ${MESSAGE}  IP=4.3.2.4
  ...  Settings={symbols_enabled = [RBL_CALLBACK_WHITE, FAKE_RBL_UNKNOWN_CHECK, FAKE_WL_RBL_UNKNOWN]}
  Do Not Expect Symbol  FAKE_RBL_CODE_2
  Expect Symbol With Exact Options  FAKE_WL_RBL_CODE_2  4.3.2.4:from

RBL FROM HIT WL IPV6
  Scan File  ${MESSAGE}  IP=2001:db8::1
  ...  Settings={symbols_enabled = [RBL_CALLBACK_WHITE, FAKE_RBL_UNKNOWN_CHECK, FAKE_WL_RBL_UNKNOWN]}
  Do Not Expect Symbol  FAKE_RBL_CODE_2
  Expect Symbol With Exact Options  FAKE_WL_RBL_CODE_2  2001:db8::1:from

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

SELECTORS COMBINED WHITELIST
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml  From=user@example.org  Helo=example.org
  ...  Settings={symbols_enabled = [RBL_CALLBACK_WHITE, RBL_SELECTOR_MERGED_WHITELIST, RBL_SELECTOR_MULTIPLE]}
  Expect Symbol With Exact Options  RBL_SELECTOR_MERGED_WL_HIT  example.org:sel_from,sel_helo
  Do Not Expect Symbol  RBL_SELECTOR_MULTIPLE

SELECTORS MERGED FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_MERGED_ERR]}
  # A failing merged query reports every origin, not an arbitrary one
  Expect Symbol With Exact Options  RBL_MERGED_ERR_FAIL
  ...  FAILTEST.EXAMPLE:server fail  failtest.example:server fail
  Expect Symbol With Score  RBL_MERGED_ERR_FAIL  1.0

SELECTORS MERGED FAIL NOMERGE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_MERGED_ERR_NOMERGE]}
  # merge_checks = false keeps one failure, and one score shot, per origin
  Expect Symbol With Exact Options  RBL_MERGED_ERR_NOMERGE_FAIL
  ...  FAILTEST.EXAMPLE:server fail  failtest.example:server fail
  Expect Symbol With Score  RBL_MERGED_ERR_NOMERGE_FAIL  2.0

SELECTORS SCRIPT TRAILING DOT
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SCRIPT_DOT]}
  # The script names the same query with and without the root dot: one lookup, one score
  Expect Symbol With Exact Options  RBL_SCRIPT_DOT  example.org:plain  example.org.:dotted
  Expect Symbol With Score  RBL_SCRIPT_DOT  2.0

SELECTORS MALFORMED DOTS
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_MALFORMED]}
  # Only one root dot may go: "malformed.." must not turn into the listed "malformed"
  Do Not Expect Symbol  RBL_SELECTOR_MALFORMED

SELECTORS SCRIPT MALFORMED DOTS
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SCRIPT_MALFORMED]}
  Do Not Expect Symbol  RBL_SCRIPT_MALFORMED

SELECTORS RESOLVE IP MALFORMED DOTS
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_RESOLVE_MALFORMED]}
  Expect Symbol With Exact Options  RBL_RESOLVE_MALFORMED_HIT
  ...  8.8.8.9:example.ru:plain  8.8.8.9:example.ru.:dotted

SELECTORS HASHED BASE64 CASE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_B64]}
  # A base64 hash is case-sensitive data, so the query keeps its case
  Expect Symbol With Exact Options  RBL_SELECTOR_B64  example.org:selector

SELECTORS HASHED TRAILING DOT
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_HASH]}
  # A hash covers the value as data, so the dotted spelling is another hash
  Expect Symbol With Exact Options  RBL_SELECTOR_HASH  example.org:plain

SELECTORS SCRIPT CASE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SCRIPT_CASE]}
  # The name returned by process_script is queried with its case intact
  Expect Symbol With Exact Options  RBL_SCRIPT_CASE  example.org:selector

SELECTORS MERGED SHOTS
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SHOTS]}
  # Each listed value spends one shot however many spellings it merges
  Expect Symbol With Exact Options  RBL_SHOTS
  ...  example.org:lower_org  EXAMPLE.ORG:upper_org  example.com:lower_com  EXAMPLE.COM:upper_com
  Expect Symbol With Score  RBL_SHOTS  2.0

SELECTORS MERGED FAIL SHOTS
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_FAIL_SHOTS]}
  # Each failed query spends one shot of _FAIL however many spellings it merges
  Expect Symbol With Exact Options  RBL_FAIL_SHOTS_FAIL
  ...  failtest.example:server fail  FAILTEST.EXAMPLE:server fail
  ...  failtest2.example:server fail  FAILTEST2.EXAMPLE:server fail
  Expect Symbol With Score  RBL_FAIL_SHOTS_FAIL  2.0

SELECTORS DOTTED NAME WHITELISTED
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_SELECTOR_DOT_WL]}
  # "example.org." is queried as "example.org", so the whitelist entry covers it
  Expect Symbol With Exact Options  RBL_SELECTOR_DOT_WL  example.com:other

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

RESOLVE IP PHASE COLLISION
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml  IP=1.2.3.4  Helo=4.3.2.1.test9.uribl
  ...  Settings={symbols_enabled = [RBL_RESOLVE_PHASE]}
  # HELO equals the client IP's RBL query name; the two lookups must stay separate
  Expect Symbol With Exact Options  RBL_RESOLVE_PHASE_DIRECT  1.2.3.4:from
  Expect Symbol With Exact Options  RBL_RESOLVE_PHASE_HELO  127.0.0.2:4.3.2.1.test9.uribl:helo

RESOLVE IP HELO EQUALS REVERSED IP
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml  IP=1.2.3.4  Helo=4.3.2.1
  ...  Settings={symbols_enabled = [RBL_RESOLVE_PHASE]}
  # The HELO is resolved as a name; the client IP is still looked up directly
  Expect Symbol With Exact Options  RBL_RESOLVE_PHASE_DIRECT  1.2.3.4:from
  Expect Symbol With Exact Options  RBL_RESOLVE_PHASE_HELO  127.0.0.2:4.3.2.1:helo

RESOLVE IP SCRIPT DROPS ADDRESS
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RBL_RESOLVE_DROP]}
  # A resolved address dropped by process_script must not stop the others
  Expect Symbol With Exact Options  RBL_RESOLVE_DROP_HIT  8.8.8.9:example.ru:kept

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
