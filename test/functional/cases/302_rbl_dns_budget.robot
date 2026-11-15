*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/rbl_dns_budget.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/rbl_budget.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Keywords ***
Scan With Rule
  [Arguments]  ${rule}
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=helo-budget.com  Hostname=rdns-budget.com
  ...  Settings={symbols_enabled = [${rule}]}

*** Test Cases ***
# Order: from, rdns, helo (connecting peer), replyto, emails (header/envelope
# derived), urls sorted by name. Seven candidates in total.
LIMIT 1 KEEPS ONLY THE CONNECTING IP
  Scan With Rule  RB_L1
  Expect Symbol With Exact Options  RB_L1  1.2.3.4:from
  Expect Symbol With Exact Options  RB_L1_LIMIT  dropped:6

LIMIT 3 KEEPS THE PEER CHECKS
  Scan With Rule  RB_L3
  Expect Symbol With Exact Options  RB_L3  1.2.3.4:from  rdns-budget.com:rdns  helo-budget.com:helo
  Expect Symbol With Exact Options  RB_L3_LIMIT  dropped:4

LIMIT 5 ADDS HEADER DERIVED REQUESTS BEFORE URLS
  Scan With Rule  RB_L5
  Expect Symbol With Exact Options  RB_L5  1.2.3.4:from  rdns-budget.com:rdns  helo-budget.com:helo
  ...  reply-budget.org:replyto  mail-budget.org:email
  Expect Symbol With Exact Options  RB_L5_LIMIT  dropped:2

# Not a clean negative and not a DNS failure either
LIMIT SYMBOL IS NOT A FAILURE SYMBOL
  Scan With Rule  RB_L3
  Do Not Expect Symbol  RB_L3_FAIL

SELECTION IS STABLE ACROSS RUNS
  FOR  ${i}  IN RANGE  5
    Scan With Rule  RB_L5
    Expect Symbol With Exact Options  RB_L5  1.2.3.4:from  rdns-budget.com:rdns  helo-budget.com:helo
    ...  reply-budget.org:replyto  mail-budget.org:email
    Expect Symbol With Exact Options  RB_L5_LIMIT  dropped:2
  END

LIMIT ABOVE THE REQUEST COUNT DOES NOT TRUNCATE
  Scan With Rule  RB_L100
  Expect Symbol With Exact Options  RB_L100  1.2.3.4:from  rdns-budget.com:rdns  helo-budget.com:helo
  ...  reply-budget.org:replyto  mail-budget.org:email  urla-budget.com:url  urlb-budget.com:url
  Do Not Expect Symbol  RB_L100_LIMIT

RULE WITHOUT THE OPTION BEHAVES AS BEFORE
  Scan With Rule  RB_NOLIMIT
  Expect Symbol With Exact Options  RB_NOLIMIT  1.2.3.4:from  rdns-budget.com:rdns  helo-budget.com:helo
  ...  reply-budget.org:replyto  mail-budget.org:email  urla-budget.com:url  urlb-budget.com:url
  Do Not Expect Symbol  RB_NOLIMIT_LIMIT

# helo, rdns and from are forced requests; the rule cap still wins
FORCED REQUESTS OBEY THE RULE CAP
  Scan With Rule  RB_FORCED1
  Expect Symbol With Exact Options  RB_FORCED1  1.2.3.4:from
  Expect Symbol With Exact Options  RB_FORCED1_LIMIT  dropped:2

# Selectors go in sorted name order whatever the declaration order
SELECTOR ONLY LIMIT 1
  Scan With Rule  RB_SEL1
  Expect Symbol With Exact Options  RB_SEL1  sel-a-budget.com:sel_a
  Expect Symbol With Exact Options  RB_SEL1_LIMIT  dropped:2

SELECTOR ONLY LIMIT 2
  Scan With Rule  RB_SEL2
  Expect Symbol With Exact Options  RB_SEL2  sel-a-budget.com:sel_a  sel-b-budget.com:sel_b
  Expect Symbol With Exact Options  RB_SEL2_LIMIT  dropped:1

# Native checks come before selectors
MIXED RULE LIMIT 2
  Scan With Rule  RB_MIXED2
  Expect Symbol With Exact Options  RB_MIXED2  1.2.3.4:from  sel-a-budget.com:sel_a
  Expect Symbol With Exact Options  RB_MIXED2_LIMIT  dropped:1

# Three selectors and helo give three distinct names; dup_one and dup_two share
# one, so helo + that name fill the cap of 2 and only sel_a is dropped. Were
# duplicates charged per selector, dup_two would take the second slot after
# helo, giving dropped:2 and no dup_two option.
DUPLICATE INPUTS CONSUME ONE SLOT
  Scan With Rule  RB_DUP2
  Expect Symbol With Exact Options  RB_DUP2  dup-budget.com:dup_one  dup-budget.com:dup_two
  ...  helo-budget.com:helo
  Expect Symbol With Exact Options  RB_DUP2_LIMIT  dropped:1

# helo and rdns yield the same name: one slot, both labels reported
DUPLICATE NATIVE CHECKS CONSUME ONE SLOT
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=dup-budget.com  Hostname=dup-budget.com
  ...  Settings={symbols_enabled = [RB_DUP_NATIVE]}
  Expect Symbol With Exact Options  RB_DUP_NATIVE  dup-budget.com:rdns  dup-budget.com:helo
  Do Not Expect Symbol  RB_DUP_NATIVE_LIMIT

# A raw selector value must not merge with the hashed native request for the
# same input: two distinct queries. They answer differently, so a merge would
# leave RAWMIX_PLAIN out (the hashed query would carry both labels).
RAW SELECTOR VALUE DOES NOT MERGE WITH HASHED NATIVE INPUT
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=dup-budget.com  Hostname=rdns-budget.com
  ...  Settings={symbols_enabled = [RB_RAWMIX]}
  Expect Symbol With Exact Options  RAWMIX_HASHED  dup-budget.com:helo
  Expect Symbol With Exact Options  RAWMIX_PLAIN  dup-budget.com:selector

# The final query of resolve_ip equals the direct query of `from`, already sent
# in phase 1. The capped rule must report what the uncapped one does, with no
# extra slot and no _LIMIT symbol.
CAPPED RESOLVE IP MERGES INTO SENT QUERY
  Scan With Rule  RB_MERGE_UNCAP
  Expect Symbol With Exact Options  RB_MERGE_UNCAP  1.2.3.4:from
  ...  1.2.3.4:same-budget.com:selector
  Scan With Rule  RB_MERGE_CAP
  Expect Symbol With Exact Options  RB_MERGE_CAP  1.2.3.4:from
  ...  1.2.3.4:same-budget.com:selector
  Do Not Expect Symbol  RB_MERGE_CAP_LIMIT

CAPPED RESOLVE IP MERGE KEEPS PREFIXED SYMBOL
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=helo-budget.com  Hostname=rdns-budget.com
  ...  Settings={symbols_enabled = [RB_MERGE_PFX_CHECK]}
  Expect Symbol With Exact Options  MFA_CODE_2  1.2.3.4:from
  Expect Symbol With Exact Options  MFB_CODE_2  1.2.3.4:same-budget.com:selector
  Do Not Expect Symbol  RB_MERGE_PFX_LIMIT

# resolve_ip, uncapped: A and AAAA for the name, then three final queries
RESOLVE IP WITHOUT LIMIT
  Scan With Rule  RB_RES_NOLIMIT
  Expect Symbol With Exact Options  RB_RES_NOLIMIT
  ...  127.0.0.2:multi-budget.com:selector  127.0.0.3:multi-budget.com:selector
  ...  127.0.0.4:multi-budget.com:selector
  Do Not Expect Symbol  RB_RES_NOLIMIT_LIMIT

# Origin lookups may use at most half of the cap, rounded down: with a cap of 1
# nothing can be resolved
RESOLVE IP CAP 1 SUBMITS NOTHING
  Scan With Rule  RB_RES1
  Do Not Expect Symbol  RB_RES1
  Expect Symbol With Exact Options  RB_RES1_LIMIT  dropped:2

# Cap 2: A lookup (1), AAAA refused, one final query (1)
RESOLVE IP CAP 2 NEVER EXCEEDS THE CAP
  Scan With Rule  RB_RES2
  Expect Symbol With Exact Options  RB_RES2  127.0.0.2:multi-budget.com:selector
  Expect Symbol With Exact Options  RB_RES2_LIMIT  dropped:3

# Cap 4: A and AAAA (2) and two of the three final queries (2)
RESOLVE IP CAP 4 NEVER EXCEEDS THE CAP
  Scan With Rule  RB_RES4
  Expect Symbol With Exact Options  RB_RES4  127.0.0.2:multi-budget.com:selector
  ...  127.0.0.3:multi-budget.com:selector
  Expect Symbol With Exact Options  RB_RES4_LIMIT  dropped:1

# The callback symbol is RB_PFX_CHECK, the limit symbol keeps the rule name
LIMIT SYMBOL WITH SYMBOLS PREFIXES
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=helo-budget.com  Hostname=rdns-budget.com
  ...  Settings={symbols_enabled = [RB_PFX_CHECK]}
  Expect Symbol With Exact Options  PFXA_CODE_2  1.2.3.4:from
  Expect Symbol With Exact Options  RB_PFX_LIMIT  dropped:2

# Direct IP query (from) and an origin lookup leave no room for it: the A
# lookup would take the last slot, so it is not sent at all
RESOLVE IP KEEPS A SLOT FOR FINAL QUERIES
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=multi-budget.com  Hostname=rdns-budget.com
  ...  Settings={symbols_enabled = [RB_RESMIX2]}
  Expect Symbol With Exact Options  RB_RESMIX2  1.2.3.4:from
  Expect Symbol With Exact Options  RB_RESMIX2_LIMIT  dropped:2

RBASE32 WITH HASH LEN
  Scan With Rule  RB_RBASE32_LEN
  Expect Symbol With Exact Options  RB_RBASE32_LEN  example.com:selector

RBASE32 HASH FORMAT
  Scan With Rule  RB_RBASE32
  Expect Symbol With Exact Options  RB_RBASE32  example.com:selector

SELECTOR RESULT IS NOT HASHED AGAIN WITH SELECTOR_HASH FALSE
  Scan With Rule  RB_RAWSEL
  Expect Symbol With Exact Options  RB_RAWSEL  0123456789abcdef:selector

SELECTOR RESULT IS HASHED BY DEFAULT
  Scan With Rule  RB_HASHEDSEL
  Do Not Expect Symbol  RB_HASHEDSEL
