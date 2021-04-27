*** Settings ***
Suite Setup      Rules Setup
Suite Teardown   Rules Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/plugins.conf
${MESSAGE}       ${TESTDIR}/messages/newlines.eml
${MESSAGE1}      ${TESTDIR}/messages/fws_fn.eml
${MESSAGE2}      ${TESTDIR}/messages/fws_fp.eml
${MESSAGE3}      ${TESTDIR}/messages/fws_tp.eml
${MESSAGE4}      ${TESTDIR}/messages/broken_richtext.eml
${MESSAGE5}      ${TESTDIR}/messages/badboundary.eml
${MESSAGE6}      ${TESTDIR}/messages/pdf_encrypted.eml
${MESSAGE7}      ${TESTDIR}/messages/pdf_js.eml
${MESSAGE8}      ${TESTDIR}/messages/yand_forward.eml
${URL_TLD}       ${TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SCOPE}  Suite


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
  Scan File  ${TESTDIR}/messages/btc.eml
  Expect Symbol  BITCOIN_ADDR

BITCOIN ADDR 2
  Scan File  ${TESTDIR}/messages/btc2.eml
  Expect Symbol  BITCOIN_ADDR

BITCOIN ADDR 3
  Scan File  ${TESTDIR}/messages/btc3.eml
  Expect Symbol  BITCOIN_ADDR

RCVD_COUNT_ONE
  Scan File  ${TESTDIR}/messages/btc.eml
  Expect Symbol  RCVD_COUNT_ONE

RCVD_COUNT_FIVE
  Scan File  ${TESTDIR}/messages/yand_forward.eml
  Expect Symbol  RCVD_COUNT_FIVE

RCVD_COUNT_SEVEN
  Scan File  ${TESTDIR}/messages/rcvd7.eml
  Expect Symbol  RCVD_COUNT_SEVEN

FROM_NEQ_ENVFROM
  Scan File  ${MESSAGE8}  From=test@test.net
  Expect Symbol  FROM_NEQ_ENVFROM

PHISH_SENDER_A
  Scan File  ${TESTDIR}/messages/phish_sender.eml
  Expect Symbol With Score And Exact Options  MULTIPLE_FROM  9.0  <any@attack.com>  <admin@legitimate.com>
  Expect Symbol With Score And Exact Options  MULTIPLE_UNIQUE_HEADERS  7.0  From

PHISH_SENDER_B
  Scan File  ${TESTDIR}/messages/phish_sender2.eml
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_C
  Scan File  ${TESTDIR}/messages/phish_sender3.eml
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_D
  Scan File  ${TESTDIR}/messages/phish_sender4.eml
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_E
  Scan File  ${TESTDIR}/messages/phish_sender5.eml
  Expect Symbol  MULTIPLE_FROM
  Expect Symbol With Exact Options  DMARC_NA  Duplicate From header

PHISH_SENDER_ROUTING_PART
  Scan File  ${TESTDIR}/messages/phish_sender6.eml
  Expect Symbol  FROM_INVALID



*** Keywords ***
Rules Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/regexp.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Rules Teardown
  Normal Teardown
