*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE1}        ${RSPAMD_TESTDIR}/messages/fws_fn.eml
${MESSAGE2}        ${RSPAMD_TESTDIR}/messages/fws_fp.eml
${MESSAGE3}        ${RSPAMD_TESTDIR}/messages/fws_tp.eml
${MESSAGE4}        ${RSPAMD_TESTDIR}/messages/broken_richtext.eml
${MESSAGE5}        ${RSPAMD_TESTDIR}/messages/badboundary.eml
${MESSAGE6}        ${RSPAMD_TESTDIR}/messages/pdf_encrypted.eml
${MESSAGE7}        ${RSPAMD_TESTDIR}/messages/pdf_js.eml
${MESSAGE8}        ${RSPAMD_TESTDIR}/messages/yand_forward.eml
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/newlines.eml

*** Test Cases ***
Broken MIME
  Scan File  ${MESSAGE3}  Settings={symbols_enabled = [MISSING_SUBJECT]}
  Expect Symbol  MISSING_SUBJECT

Issue 2584
  Scan File  ${MESSAGE1}
  ...  Settings={symbols_enabled = [BROKEN_CONTENT_TYPE, MISSING_SUBJECT, R_MISSING_CHARSET]}
  Do Not Expect Symbol  BROKEN_CONTENT_TYPE
  Do Not Expect Symbol  MISSING_SUBJECT
  Do Not Expect Symbol  R_MISSING_CHARSET

Issue 2349
  Scan File  ${MESSAGE2}
  ...  Settings={symbols_enabled = [MULTIPLE_UNIQUE_HEADERS]}
  Do Not Expect Symbol  MULTIPLE_UNIQUE_HEADERS

Broken Rich Text
  Scan File  ${MESSAGE4}
  ...  Settings={symbols_enabled = [BROKEN_CONTENT_TYPE]}
  Expect Symbol  BROKEN_CONTENT_TYPE

Broken boundary
  Scan File  ${MESSAGE4}
  ...  Settings={symbols_enabled = [BROKEN_CONTENT_TYPE]}
  Expect Symbol  BROKEN_CONTENT_TYPE

PDF encrypted
  Scan File  ${MESSAGE6}
  ...  Settings={symbols_enabled = [PDF_ENCRYPTED]}
  Expect Symbol  PDF_ENCRYPTED

PDF javascript
  Scan File  ${MESSAGE7}
  ...  Settings={symbols_enabled = [PDF_JAVASCRIPT]}
  Expect Symbol  PDF_JAVASCRIPT

BITCOIN ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [BITCOIN_ADDR]}
  Expect Symbol  BITCOIN_ADDR

BITCOIN ADDR 2
  Scan File  ${RSPAMD_TESTDIR}/messages/btc2.eml
  ...  Settings={symbols_enabled = [BITCOIN_ADDR]}
  Expect Symbol  BITCOIN_ADDR

BITCOIN ADDR 3
  Scan File  ${RSPAMD_TESTDIR}/messages/btc3.eml
  ...  Settings={symbols_enabled = [BITCOIN_ADDR]}
  Expect Symbol  BITCOIN_ADDR

BITCOIN ADDR 4
  Scan File  ${RSPAMD_TESTDIR}/messages/btc4.eml
  ...  Settings={symbols_enabled = [BITCOIN_ADDR]}
  Expect Symbol With Exact Options  BITCOIN_ADDR  1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
  ...  bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq  bitcoincash:qztslqhavnjcgth9zwu6dw0jjcfy4zahfy7vf0smwp

RCVD_COUNT_ONE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [RCVD_COUNT_ONE]}
  Expect Symbol  RCVD_COUNT_ONE

RCVD_COUNT_FIVE
  Scan File  ${RSPAMD_TESTDIR}/messages/yand_forward.eml
  ...  Settings={symbols_enabled = [RCVD_COUNT_ONE]}
  Expect Symbol  RCVD_COUNT_FIVE

RCVD_COUNT_SEVEN
  Scan File  ${RSPAMD_TESTDIR}/messages/rcvd7.eml
  ...  Settings={symbols_enabled = [RCVD_COUNT_ONE]}
  Expect Symbol  RCVD_COUNT_SEVEN

FROM_NEQ_ENVFROM
  Scan File  ${MESSAGE8}  From=test@test.net
  ...  Settings={symbols_enabled = [FROM_NEQ_ENVFROM]}
  Expect Symbol  FROM_NEQ_ENVFROM

PHISH_SENDER_A
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender.eml
  ...  Settings={symbols_enabled = [MULTIPLE_FROM, MULTIPLE_UNIQUE_HEADERS]}
  Expect Symbol With Score And Exact Options  MULTIPLE_FROM  9.0  <any@attack.com>  <admin@legitimate.com>
  Expect Symbol With Score And Exact Options  MULTIPLE_UNIQUE_HEADERS  7.0  From

PHISH_SENDER_B
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender2.eml
  ...  Settings={symbols_enabled = [BROKEN_HEADERS]}
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_C
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender3.eml
  ...  Settings={symbols_enabled = [BROKEN_HEADERS]}
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_D
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender4.eml
  ...  Settings={symbols_enabled = [BROKEN_HEADERS]}
  Expect Symbol  BROKEN_HEADERS

PHISH_SENDER_E
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender5.eml
  ...  Settings={symbols_enabled = [MULTIPLE_FROM, DMARC_CHECK, DKIM_CHECK, SPF_CHECK]}
  Expect Symbol  MULTIPLE_FROM
  Expect Symbol With Exact Options  DMARC_NA  Duplicate From header

PHISH_SENDER_ROUTING_PART
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender6.eml
  ...  Settings={symbols_enabled = [FROM_INVALID]}
  Expect Symbol  FROM_INVALID

REPLYTO_ADDR_EQ_FROM
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_addr_eq_from.eml
  ...  Settings={symbols_enabled = [REPLYTO_ADDR_EQ_FROM]}
  Expect Symbol  REPLYTO_ADDR_EQ_FROM

