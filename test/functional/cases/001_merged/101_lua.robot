*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_MAP_MAP}     ${RSPAMD_TESTDIR}/configs/maps/map.list
${RSPAMD_RADIX_MAP}   ${RSPAMD_TESTDIR}/configs/maps/ip2.list
${RSPAMD_REGEXP_MAP}  ${RSPAMD_TESTDIR}/configs/maps/regexp.list

*** Test Cases ***
Recipient Parsing Sanity
  Scan File  ${MESSAGE}  Rcpt=rcpt1@foobar,rcpt2@foobar,rcpt3@foobar,rcpt4@foobar
  ...  Settings={symbols_enabled = [TEST_RCPT]}
  Expect Symbol With Exact Options  TEST_RCPT  rcpt1@foobar,rcpt2@foobar,rcpt3@foobar,rcpt4@foobar

TLD parts
  Scan File  ${MESSAGE}  Settings={symbols_enabled = [TEST_TLD]}
  Expect Symbol With Exact Options  TEST_TLD  no worry

Hashes
  Scan File  ${MESSAGE}  Settings={symbols_enabled = [TEST_HASHES]}
  Expect Symbol With Exact Options  TEST_HASHES  no worry

Maps Key Values
  Scan File  ${MESSAGE}  Settings={symbols_enabled = [RADIX_KV, REGEXP_KV, MAP_KV]}
  Expect Symbol With Exact Options  RADIX_KV  no worry
  Expect Symbol With Exact Options  REGEXP_KV  no worry
  Expect Symbol With Exact Options  MAP_KV  no worry

Option Order
  Scan File  ${MESSAGE}  Settings={symbols_enabled = [OPTION_ORDER, TBL_OPTION_ORDER]}
  Expect Symbol With Exact Options  OPTION_ORDER  one  two  three  4  5  a
  Expect Symbol With Exact Options  TBL_OPTION_ORDER  one  two  three  4  5  a

Rule conditions
  Scan File  ${MESSAGE}  Settings={symbols_enabled = [ANY_A]}
  Expect Symbol With Option  ANY_A  hello3
  Expect Symbol With Option  ANY_A  hello1
  Expect Symbol With Option  ANY_A  hello2
