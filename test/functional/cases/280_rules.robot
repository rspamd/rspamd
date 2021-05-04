*** Settings ***
Suite Setup      Rspamd Setup
Suite Teardown   Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/regexp.conf
${MESSAGE1}        ${RSPAMD_TESTDIR}/messages/fws_fn.eml
${MESSAGE2}        ${RSPAMD_TESTDIR}/messages/fws_fp.eml
${MESSAGE3}        ${RSPAMD_TESTDIR}/messages/fws_tp.eml
${MESSAGE4}        ${RSPAMD_TESTDIR}/messages/broken_richtext.eml
${MESSAGE5}        ${RSPAMD_TESTDIR}/messages/badboundary.eml
${MESSAGE6}        ${RSPAMD_TESTDIR}/messages/pdf_encrypted.eml
${MESSAGE7}        ${RSPAMD_TESTDIR}/messages/pdf_js.eml
${MESSAGE8}        ${RSPAMD_TESTDIR}/messages/yand_forward.eml
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/newlines.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat


*** Test Cases ***
Broken MIME
  Scan File  ${MESSAGE3}
  Expect Symbol  MISSING_SUBJECT

Issue 2584
  Scan File  ${MESSAGE1}
  Do Not Expect Symbol  BROKEN_CONTENT_TYPE
  Do Not Expect Symbol  MISSING_SUBJECT
  Do Not Expect Symbol  R_MISSING_CHARSET

Issue 2349
  Scan File  ${MESSAGE2}
  Do Not Expect Symbol  MULTIPLE_UNIQUE_HEADERS

Broken Rich Text
  Scan File  ${MESSAGE4}
  Expect Symbol  BROKEN_CONTENT_TYPE

Dynamic Config
  Scan File  ${MESSAGE}
  Expect Symbol With Score  SA_BODY_WORD  10
  Expect Required Score  20

Broken boundary
  Scan File  ${MESSAGE4}
  Expect Symbol  BROKEN_CONTENT_TYPE

PDF encrypted
  Scan File  ${MESSAGE6}
  Expect Symbol  PDF_ENCRYPTED

PDF javascript
  Scan File  ${MESSAGE7}
  Expect Symbol  PDF_JAVASCRIPT

BITCOIN ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  Expect Symbol  BITCOIN_ADDR

BITCOIN ADDR 2
  Scan File  ${RSPAMD_TESTDIR}/messages/btc2.eml
  Expect Symbol  BITCOIN_ADDR

BITCOIN ADDR 3
  Scan File  ${RSPAMD_TESTDIR}/messages/btc3.eml
  Expect Symbol  BITCOIN_ADDR

RCVD_COUNT_ONE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  Expect Symbol  RCVD_COUNT_ONE

RCVD_COUNT_FIVE
  Scan File  ${RSPAMD_TESTDIR}/messages/yand_forward.eml
  Expect Symbol  RCVD_COUNT_FIVE

RCVD_COUNT_SEVEN
  Scan File  ${RSPAMD_TESTDIR}/messages/rcvd7.eml
  Expect Symbol  RCVD_COUNT_SEVEN

FROM_NEQ_ENVFROM
  Scan File  ${MESSAGE8}  From=test@test.net
  Expect Symbol  FROM_NEQ_ENVFROM

PHISH_SENDER_A
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender.eml
  Expect Symbol With Score And Exact Options  MULTIPLE_FROM  9.0  <any@attack.com>  <admin@legitimate.com>
  Expect Symbol With Score And Exact Options  MULTIPLE_UNIQUE_HEADERS  7.0  From

PHISH_SENDER_B
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender2.eml
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_C
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender3.eml
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_D
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender4.eml
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_E
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender5.eml
  Expect Symbol  MULTIPLE_FROM
  Expect Symbol With Exact Options  DMARC_NA  Duplicate From header

PHISH_SENDER_ROUTING_PART
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender6.eml
  Expect Symbol  FROM_INVALID

REPLYTO_ADDR_EQ_FROM
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_addr_eq_from.eml
  Expect Symbol  REPLYTO_ADDR_EQ_FROM

