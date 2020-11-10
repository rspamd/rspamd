*** Settings ***
Suite Setup     Rbl Setup
Suite Teardown  Rbl Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
RBL FROM MISS
  Scan File  ${MESSAGE}  IP=1.2.3.4
  Do Not Expect Symbol  FAKE_RBL_CODE_2

RBL FROM HIT
  Scan File  ${MESSAGE}  IP=4.3.2.1
  Expect Symbol  FAKE_RBL_CODE_2

RBL FROM MULTIPLE HIT
  Scan File  ${MESSAGE}  IP=4.3.2.3
  Expect Symbol  FAKE_RBL_CODE_2
  Expect Symbol  FAKE_RBL_CODE_3

RBL FROM UNKNOWN HIT
  Scan File  ${MESSAGE}  IP=4.3.2.2
  Expect Symbol  FAKE_RBL_FAKE_RBL_UNKNOWN

RBL RECEIVED HIT
  Scan File  ${MESSAGE}  IP=8.8.8.8
  Expect Symbol  FAKE_RECEIVED_RBL_CODE_3

RBL FROM HIT WL
  Scan File  ${MESSAGE}  IP=4.3.2.4
  Do Not Expect Symbol  FAKE_RBL_CODE_2
  Expect Symbol With Exact Options  FAKE_WL_RBL_CODE_2  4.3.2.4:from

EMAILBL Compose Map 1
  Scan File  ${TESTDIR}/messages/url14.eml
  Expect Symbol With Exact Options  RSPAMD_EMAILBL  dirty.sanchez.com:email

EMAILBL Compose Map 2
  Scan File  ${TESTDIR}/messages/url15.eml
  Expect Symbol With Exact Options  RSPAMD_EMAILBL  very.dirty.sanchez.com:email

EMAILBL Compose Map 3
  Scan File  ${TESTDIR}/messages/url16.eml
  Expect Symbol With Exact Options  RSPAMD_EMAILBL  41.black.sanchez.com:email

CONTENT URLS
  Scan File  ${TESTDIR}/messages/content_url.eml
  Expect Symbol With Exact Options  URIBL_NOCONTENT  example.org:url
  Expect Symbol With Option  URIBL_WITHCONTENT  example.com:url
  Expect Symbol With Option  URIBL_WITHCONTENT  example.org:url
  Expect Symbol With Option  URIBL_WITHCONTENT  8.8.8.8:url
  Expect Symbol With Exact Options  URIBL_CONTENTONLY  example.com:url

SELECTORS
  Scan File  ${TESTDIR}/messages/btc.eml  From=user@example.com  Helo=example.org
  Expect Symbol With Exact Options  RBL_SELECTOR_SINGLE  example.org:selector
  Expect Symbol With Option  RBL_SELECTOR_MULTIPLE  example.com:sel_from
  Expect Symbol With Option  RBL_SELECTOR_MULTIPLE  example.org:sel_helo

SELECTORS COMBINED
  Scan File  ${TESTDIR}/messages/btc.eml  From=user@example.org  Helo=example.org
  Expect Symbol With Option  RBL_SELECTOR_MULTIPLE  example.org:sel_from
  Expect Symbol With Option  RBL_SELECTOR_MULTIPLE  example.org:sel_helo

*** Keywords ***
Rbl Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/rbl.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Rbl Teardown
  Normal Teardown
  Terminate All Processes    kill=True
