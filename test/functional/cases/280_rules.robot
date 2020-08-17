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
  ${result} =  Scan Message With Rspamc  ${MESSAGE3}
  Check Rspamc  ${result}  MISSING_SUBJECT

Issue 2584
  ${result} =  Scan Message With Rspamc  ${MESSAGE1}
  Check Rspamc  ${result}  BROKEN_CONTENT_TYPE  inverse=1
  Should Not Contain  ${result.stdout}  MISSING_SUBJECT
  Should Not Contain  ${result.stdout}  R_MISSING_CHARSET

Issue 2349
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  MULTIPLE_UNIQUE_HEADERS  inverse=1

Broken Rich Text
  ${result} =  Scan Message With Rspamc  ${MESSAGE4}
  Check Rspamc  ${result}  BROKEN_CONTENT_TYPE

Dynamic Config
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  SA_BODY_WORD (10
  Check Rspamc  ${result}  \/ 20

Broken boundary
  ${result} =  Scan Message With Rspamc  ${MESSAGE4}
  Check Rspamc  ${result}  BROKEN_CONTENT_TYPE

PDF encrypted
  ${result} =  Scan Message With Rspamc  ${MESSAGE6}
  Check Rspamc  ${result}  PDF_ENCRYPTED

PDF javascript
  ${result} =  Scan Message With Rspamc  ${MESSAGE7}
  Check Rspamc  ${result}  PDF_JAVASCRIPT

BITCOIN ADDR
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/btc.eml
  Should Contain  ${result.stdout}  BITCOIN_ADDR

BITCOIN ADDR 2
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/btc2.eml
  Should Contain  ${result.stdout}  BITCOIN_ADDR

BITCOIN ADDR 3
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/btc3.eml
  Should Contain  ${result.stdout}  BITCOIN_ADDR

RCVD_COUNT_ONE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/btc.eml
  Should Contain  ${result.stdout}  RCVD_COUNT_ONE

RCVD_COUNT_FIVE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/yand_forward.eml
  Should Contain  ${result.stdout}  RCVD_COUNT_FIVE

RCVD_COUNT_SEVEN
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/rcvd7.eml
  Should Contain  ${result.stdout}  RCVD_COUNT_SEVEN

FROM_NEQ_ENVFROM
  ${result} =  Scan Message With Rspamc  ${MESSAGE8}  --from  test@test.net
  Check Rspamc  ${result}  FROM_NEQ_ENVFROM

PHISH_SENDER_A
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/phish_sender.eml
  Should Contain  ${result.stdout}  MULTIPLE_FROM (9.00)[any@attack.com,admin@legitimate.com]
  Should Contain  ${result.stdout}  MULTIPLE_UNIQUE_HEADERS (7.00)[From]

PHISH_SENDER_B
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/phish_sender2.eml
  Should Contain  ${result.stdout}  BROKEN_HEADERS

PHISH_SENDER_C
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/phish_sender3.eml
  Should Contain  ${result.stdout}  BROKEN_HEADERS

PHISH_SENDER_D
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/phish_sender4.eml
  Should Contain  ${result.stdout}  BROKEN_HEADERS

PHISH_SENDER_E
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/phish_sender5.eml
  Should Contain  ${result.stdout}  MULTIPLE_FROM
  Should Contain  ${result.stdout}  DMARC_NA (0.00)[Duplicate From header]

PHISH_SENDER_ROUTING_PART
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/phish_sender6.eml
  Should Contain  ${result.stdout}  FROM_INVALID

*** Keywords ***
Rules Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/regexp.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Rules Teardown
  Normal Teardown
