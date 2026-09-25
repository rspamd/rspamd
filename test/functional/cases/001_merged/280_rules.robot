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
${MESSAGE9}        ${RSPAMD_TESTDIR}/messages/docx_content.eml
${MESSAGE10}       ${RSPAMD_TESTDIR}/messages/docx_broken.eml
${MESSAGE11}       ${RSPAMD_TESTDIR}/messages/xlsx_content.eml
${MESSAGE12}       ${RSPAMD_TESTDIR}/messages/pptx_content.eml
${MESSAGE13}       ${RSPAMD_TESTDIR}/messages/docx_template.eml
${MESSAGE14}       ${RSPAMD_TESTDIR}/messages/svg_smuggling.eml
${MESSAGE15}       ${RSPAMD_TESTDIR}/messages/svg_logo.eml
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

DOCX content
  Scan File  ${MESSAGE9}
  ...  Settings={symbols_enabled = [DOCX_CONTENT, DOCX_EXTERNAL_LINKS, DOCX_SUSPICIOUS]}
  Expect Symbol With Exact Options  DOCX_CONTENT  phishing.docx
  Expect Symbol With Exact Options  DOCX_EXTERNAL_LINKS  phishing.docx:2
  Do Not Expect Symbol  DOCX_SUSPICIOUS
  Expect URL  visible.example.com
  Expect URL  relationship.example.com
  Expect URL  field.example.com
  List Should Not Contain Value  ${SCAN_RESULT}[urls]  deleted.example.com

DOCX suspicious
  Scan File  ${MESSAGE10}  Settings={symbols_enabled = [DOCX_SUSPICIOUS]}
  Expect Symbol With Exact Options  DOCX_SUSPICIOUS  broken.docx:package

DOCX remote template
  Scan File  ${MESSAGE13}
  ...  Settings={symbols_enabled = [DOCX_CONTENT, DOCX_SUSPICIOUS, OOXML_REMOTE_TEMPLATE, OOXML_EXTERNAL_DATA, OOXML_MACROS]}
  Expect Symbol With Exact Options  DOCX_CONTENT  template.docx
  Expect Symbol With Exact Options  OOXML_REMOTE_TEMPLATE  template.docx:https://template.example.com/Normal.dotm
  Do Not Expect Symbol  DOCX_SUSPICIOUS
  Do Not Expect Symbol  OOXML_EXTERNAL_DATA
  Do Not Expect Symbol  OOXML_MACROS

XLSX content
  Scan File  ${MESSAGE11}
  ...  Settings={symbols_enabled = [XLSX_CONTENT, XLSX_EXTERNAL_LINKS, XLSX_SUSPICIOUS, OOXML_MACROS, OOXML_EXTERNAL_DATA, OOXML_OLE_OBJECT, OOXML_REMOTE_TEMPLATE]}
  Expect Symbol With Exact Options  XLSX_CONTENT  invoice.xlsm
  Expect Symbol With Exact Options  XLSX_EXTERNAL_LINKS  invoice.xlsm:3
  Expect Symbol With Exact Options  OOXML_MACROS  invoice.xlsm:xlm,vba,_xlnm.Auto_Open
  Expect Symbol With Exact Options  OOXML_EXTERNAL_DATA  invoice.xlsm:externalLinkPath=https://external.example.com/data.xlsx
  Do Not Expect Symbol  XLSX_SUSPICIOUS
  Do Not Expect Symbol  OOXML_OLE_OBJECT
  Do Not Expect Symbol  OOXML_REMOTE_TEMPLATE
  Expect URL  formula.example.com
  Expect URL  sheet.example.com
  Expect URL  drawing.example.com
  Expect URL  shared.example.com

PPTX content
  Scan File  ${MESSAGE12}
  ...  Settings={symbols_enabled = [PPTX_CONTENT, PPTX_EXTERNAL_LINKS, PPTX_SUSPICIOUS, OOXML_MACROS, OOXML_OLE_OBJECT, OOXML_EXTERNAL_DATA]}
  Expect Symbol With Exact Options  PPTX_CONTENT  deck.pptx
  Expect Symbol With Exact Options  PPTX_EXTERNAL_LINKS  deck.pptx:2
  Expect Symbol With Exact Options  OOXML_OLE_OBJECT  deck.pptx:1
  Do Not Expect Symbol  PPTX_SUSPICIOUS
  Do Not Expect Symbol  OOXML_MACROS
  Do Not Expect Symbol  OOXML_EXTERNAL_DATA
  Expect URL  shape.example.com
  Expect URL  run.example.com

SVG smuggling
  Scan File  ${MESSAGE14}
  ...  Settings={symbols_enabled = [SVG_CONTENT, SVG_SUSPICIOUS, SVG_SCRIPT, SVG_FOREIGN_OBJECT, SVG_DATA_URI, SVG_EXTERNAL_LINKS, SVG_EXTERNAL_RESOURCES, SVG_FORM, SVG_REDIRECT]}
  Expect Symbol With Exact Options  SVG_CONTENT  invoice.svg
  Expect Symbol With Exact Options  SVG_SCRIPT  invoice.svg:scripts=2,handlers=1,javascript=2,external=1,atob,Blob,createObjectURL,location
  Expect Symbol With Exact Options  SVG_FOREIGN_OBJECT  invoice.svg:1
  Expect Symbol With Exact Options  SVG_DATA_URI  invoice.svg:text/html
  Expect Symbol With Exact Options  SVG_FORM  invoice.svg:forms=1,passwords=1
  Expect Symbol With Exact Options  SVG_REDIRECT  invoice.svg:meta_refresh,embedded_documents,location
  Expect Symbol  SVG_EXTERNAL_RESOURCES
  Do Not Expect Symbol  SVG_SUSPICIOUS
  Expect URL  phish.example.com
  Expect URL  redirect.example.com
  Expect URL  cdn.example.com
  Expect URL  payload.example.com
  Expect URL  visible.example.com

SVG logo
  Scan File  ${MESSAGE15}
  ...  Settings={symbols_enabled = [SVG_CONTENT, SVG_SUSPICIOUS, SVG_SCRIPT, SVG_FOREIGN_OBJECT, SVG_DATA_URI, SVG_EXTERNAL_LINKS, SVG_EXTERNAL_RESOURCES, SVG_FORM, SVG_REDIRECT]}
  Expect Symbol With Exact Options  SVG_CONTENT  logo.svg
  Expect Symbol With Exact Options  SVG_EXTERNAL_LINKS  logo.svg:1
  Do Not Expect Symbols  SVG_SUSPICIOUS  SVG_SCRIPT  SVG_FOREIGN_OBJECT  SVG_DATA_URI  SVG_EXTERNAL_RESOURCES  SVG_FORM  SVG_REDIRECT
  Expect URL  www.example.com

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

ETHEREUM ADDR MAYBE
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [ETHEREUM_ADDR_MAYBE]}
  Expect Symbol With Exact Options  ETHEREUM_ADDR_MAYBE  0x000000000000000000000000000000000000dEaD

TRON ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [TRON_ADDR]}
  Expect Symbol With Exact Options  TRON_ADDR  T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb

DOGECOIN ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [DOGECOIN_ADDR]}
  Expect Symbol With Exact Options  DOGECOIN_ADDR  D596YFweJQuHY1BbjazZYmAbt8jJPbKehC

XRP ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [XRP_ADDR]}
  Expect Symbol With Exact Options  XRP_ADDR  rrrrrrrrrrrrrrrrrrrrrhoLvTp

MONERO ADDR MAYBE
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [MONERO_ADDR_MAYBE]}
  Expect Symbol With Exact Options  MONERO_ADDR_MAYBE
  ...  4Ah82pJGF9p7kpzb6eU326EFZf2cDnimbTFVeJtx1qtBmUNJAEqN76R7PwPfHt3oWb8R6cKvhgyxQdDn53jFrK6wFx7RJWh

NO BARE BASE58 FALSE POSITIVE
  # crypto.eml still carries a 44 char Base58 run. Nothing may claim it: with no
  # checksum to verify, that shape matches ordinary base64 and token blobs.
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [CRYPTO_ADDR_CHECK]}
  Do Not Expect Symbol With Option  CRYPTO_ADDR_CHECK
  ...  solana:vQBQPEjJmki5fhBboGBWRJhmcFkMvrr4Fu3tMSJ5Edyn

BITCOIN ADDR TAPROOT
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [BITCOIN_ADDR]}
  Expect Symbol With Option  BITCOIN_ADDR  bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqwk0jyn

UPPERCASE BITCOIN ADDRESSES
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto_uppercase.eml
  ...  Settings={symbols_enabled = [BITCOIN_ADDR]}
  Expect Symbol With Exact Options  BITCOIN_ADDR
  ...  BC1QQYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5FCJ4Z3
  ...  BITCOINCASH:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A

LITECOIN ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [LITECOIN_ADDR]}
  Expect Symbol With Exact Options  LITECOIN_ADDR  LKKHMBjCU89fyFNgSRprDoD8Jb25N8uWvd
  ...  ltc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5dyg36p

ZCASH ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [ZCASH_ADDR]}
  Expect Symbol With Exact Options  ZCASH_ADDR  t1Hxw6JqWMnhDK5jRCieg5bFHM2qt7UtQvu

CARDANO ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [CARDANO_ADDR]}
  Expect Symbol With Exact Options  CARDANO_ADDR
  ...  addr1qyqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qz42jwu

COSMOS ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [COSMOS_ADDR]}
  Expect Symbol With Exact Options  COSMOS_ADDR  cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu

STELLAR ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [STELLAR_ADDR]}
  Expect Symbol With Exact Options  STELLAR_ADDR
  ...  GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABOV

TON ADDR
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [TON_ADDR]}
  Expect Symbol With Exact Options  TON_ADDR  EQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIP8B

CRYPTO ADDR CHECK
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [CRYPTO_ADDR_CHECK]}
  Expect Symbol With Exact Options  CRYPTO_ADDR_CHECK
  ...  bitcoin:16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu
  ...  bitcoin:bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqwk0jyn
  ...  litecoin:LKKHMBjCU89fyFNgSRprDoD8Jb25N8uWvd
  ...  litecoin:ltc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5dyg36p
  ...  dogecoin:D596YFweJQuHY1BbjazZYmAbt8jJPbKehC
  ...  tron:T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb
  ...  xrp:rrrrrrrrrrrrrrrrrrrrrhoLvTp
  ...  zcash:t1Hxw6JqWMnhDK5jRCieg5bFHM2qt7UtQvu
  ...  cardano:addr1qyqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qz42jwu
  ...  cosmos:cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu
  ...  stellar:GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABOV
  ...  ton:EQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIP8B
  ...  ethereum:0x000000000000000000000000000000000000dEaD
  ...  monero:4Ah82pJGF9p7kpzb6eU326EFZf2cDnimbTFVeJtx1qtBmUNJAEqN76R7PwPfHt3oWb8R6cKvhgyxQdDn53jFrK6wFx7RJWh

CRYPTO ADDR SELECTOR MAP
  # The selector computes the addresses itself, so no dependency on
  # CRYPTO_ADDR_CHECK is needed and it works with only this symbol enabled
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto.eml
  ...  Settings={symbols_enabled = [CRYPTO_ADDR_SELECTOR_MAP]}
  Expect Symbol With Exact Options  CRYPTO_ADDR_SELECTOR_MAP
  ...  16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu
  ...  4Ah82pJGF9p7kpzb6eU326EFZf2cDnimbTFVeJtx1qtBmUNJAEqN76R7PwPfHt3oWb8R6cKvhgyxQdDn53jFrK6wFx7RJWh

LEAKED PASSWORD SCAM NON BITCOIN
  # The composite used to require BITCOIN_ADDR, so a scam quoting any other
  # currency scored nothing. Monero alone must be enough now.
  Scan File  ${RSPAMD_TESTDIR}/messages/crypto_scam.eml
  ...  Settings={symbols_enabled = [MONERO_ADDR_MAYBE, LEAKED_PASSWORD_SCAM_RE, LEAKED_PASSWORD_SCAM]}
  Expect Symbol  LEAKED_PASSWORD_SCAM

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

PHISH_SENDER_A_1
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender.eml
  ...  Settings={symbols_enabled = [MULTIPLE_FROM]}
  Expect Symbol With Score And Exact Options  MULTIPLE_FROM  8.0  <any@attack.com>  <admin@legitimate.com>

PHISH_SENDER_A_2
  Scan File  ${RSPAMD_TESTDIR}/messages/phish_sender.eml
  ...  Settings={symbols_enabled = [MULTIPLE_UNIQUE_HEADERS]}
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

SUBJECT_HAS_CURRENCY
  Scan File  ${RSPAMD_TESTDIR}/messages/currency.eml
  ...  Settings={symbols_enabled = [SUBJECT_HAS_CURRENCY]}
  Expect Symbol  SUBJECT_HAS_CURRENCY
