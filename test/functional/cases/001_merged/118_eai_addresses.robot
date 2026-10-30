*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_ADDR}       {symbols_enabled = [INVALID_FROM_8BIT,INVALID_RCPT_8BIT]}

*** Test Cases ***
8BIT ADDRESSES THAT FOLLOW THE SMTPUTF8 SYNTAX
  [Documentation]  Without enable_mime_utf, 8-bit addresses that follow
  ...  draft-ietf-mailmaint-smtputf8-syntax are not flagged either
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_addresses_valid.eml
  ...  Settings=${SETTINGS_ADDR}
  Do Not Expect Symbol  INVALID_FROM_8BIT
  Do Not Expect Symbol  INVALID_RCPT_8BIT

8BIT FROM WITH A DISALLOWED CODE POINT
  [Documentation]  The draft syntax applies without enable_mime_utf too
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_from_bidi.eml
  ...  Settings=${SETTINGS_ADDR}
  Expect Symbol With Option  INVALID_FROM_8BIT  code point

8BIT FROM IN LATIN-1
  [Documentation]  An address in a legacy charset is not an RFC6532
  ...  address, and was flagged before the draft syntax was checked
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_from_latin1.eml
  ...  Settings=${SETTINGS_ADDR}
  Expect Symbol With Option  INVALID_FROM_8BIT  invalid UTF-8

ASCII FROM WITH AN A-LABEL LOCAL PART
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_from_a_label.eml
  ...  Settings=${SETTINGS_ADDR}
  Expect Symbol With Option  INVALID_FROM_8BIT  a-label
  Do Not Expect Symbol  INVALID_RCPT_8BIT

ASCII RECIPIENT WITH AN A-LABEL ATOM
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_rcpt_a_label.eml
  ...  Settings=${SETTINGS_ADDR}
  Expect Symbol With Option  INVALID_RCPT_8BIT  a-label
  Do Not Expect Symbol  INVALID_FROM_8BIT

MIDDLE DOTS REQUIRE LOWERCASE L
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_middle_dot.eml
  ...  Settings=${SETTINGS_ADDR}
  Expect Symbol With Option  INVALID_FROM_8BIT  code point
  Expect Symbol With Option  INVALID_RCPT_8BIT  code point

PERMITTED ASCII ADDRESSES
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_ascii_valid.eml
  ...  Settings=${SETTINGS_ADDR}
  Do Not Expect Symbol  INVALID_FROM_8BIT
  Do Not Expect Symbol  INVALID_RCPT_8BIT
