*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/mid_utf8.conf
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS_ADDR}       {symbols_enabled = [INVALID_FROM_8BIT,INVALID_RCPT_8BIT]}

*** Test Cases ***
EAI ADDRESSES THAT FOLLOW THE SMTPUTF8 SYNTAX
  [Documentation]  In UTF-8 mode, 8-bit addresses that follow
  ...  draft-ietf-mailmaint-smtputf8-syntax are not flagged
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_addresses_valid.eml
  ...  Settings=${SETTINGS_ADDR}
  Do Not Expect Symbol  INVALID_FROM_8BIT
  Do Not Expect Symbol  INVALID_RCPT_8BIT

EAI FROM WITH A DISALLOWED CODE POINT
  [Documentation]  U+202E makes the From address render as another
  ...  address, and the PRECIS IdentifierClass disallows it
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_from_bidi.eml
  ...  Settings=${SETTINGS_ADDR}
  Expect Symbol With Option  INVALID_FROM_8BIT  code point
  Do Not Expect Symbol  INVALID_RCPT_8BIT

EAI RECIPIENT WITH MIXED SCRIPTS
  [Documentation]  One recipient mixes Han and non-ASCII Latin, which the
  ...  draft bans, while the other recipient is fine
  Scan File  ${RSPAMD_TESTDIR}/messages/eai_rcpt_mixed_scripts.eml
  ...  Settings=${SETTINGS_ADDR}
  Expect Symbol With Option  INVALID_RCPT_8BIT  mixed scripts
  Do Not Expect Symbol  INVALID_FROM_8BIT

EAI FROM IN LATIN-1
  [Documentation]  UTF-8 mode used to disable these symbols entirely, but an
  ...  address in a legacy charset is no more valid in UTF-8 mode
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
