*** Settings ***
Suite Setup     Surbl Setup
Suite Teardown  Surbl Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
SURBL resolve ip
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url7.eml
  Should Contain  ${result.stdout}  URIBL_SBL_CSS (1.00)[8.8.8.9:example.ru
  Should Contain  ${result.stdout}  URIBL_XBL (1.00)[8.8.8.8:example.ru
  Should Contain  ${result.stdout}  URIBL_PBL (1.00)[8.8.8.8:example.ru

SURBL Example.com domain
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url4.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL
  Should Contain  ${result.stdout}  DBL_SPAM
  Should Not Contain  ${result.stdout}  DBL_PHISH
  Should Not Contain  ${result.stdout}  URIBL_BLACK

SURBL Example.net domain
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url5.eml
  Should Contain  ${result.stdout}  DBL_PHISH
  Should Not Contain  ${result.stdout}  DBL_SPAM
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL
  Should Not Contain  ${result.stdout}  URIBL_BLACK

SURBL Example.org domain
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url6.eml
  Should Contain  ${result.stdout}  URIBL_BLACK
  Should Not Contain  ${result.stdout}  DBL_SPAM
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL
  Should Not Contain  ${result.stdout}  DBL_PHISH

SURBL Example.ru domain
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url7.eml
  Should Contain  ${result.stdout}  URIBL_GREY
  Should Contain  ${result.stdout}  URIBL_RED
  Should Not Contain  ${result.stdout}  DBL_SPAM
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL
  Should Not Contain  ${result.stdout}  DBL_PHISH
  Should Not Contain  ${result.stdout}  URIBL_BLACK

SURBL Example.ru ZEN domain
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url7.eml
  Should Contain  ${result.stdout}  URIBL_SBL_CSS (
  Should Contain  ${result.stdout}  URIBL_XBL (
  Should Contain  ${result.stdout}  URIBL_PBL (
  Should Not Contain  ${result.stdout}  URIBL_SBL (
  Should Not Contain  ${result.stdout}  DBL_SPAM (
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL (
  Should Not Contain  ${result.stdout}  DBL_PHISH (
  Should Not Contain  ${result.stdout}  URIBL_BLACK (

SURBL Example.com domain image false
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/urlimage.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL_IMAGES
  Should Not Contain  ${result.stdout}  DBL_SPAM (
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL (
  Should Not Contain  ${result.stdout}  DBL_PHISH (
  Should Not Contain  ${result.stdout}  URIBL_BLACK (

SURBL @example.com mail html
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/mailadr.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL (
  Should Contain  ${result.stdout}  DBL_SPAM (
  Should Contain  ${result.stdout}  example.com:email
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL_IMAGES (
  Should Not Contain  ${result.stdout}  DBL_PHISH (
  Should Not Contain  ${result.stdout}  URIBL_BLACK (

SURBL @example.com mail text
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/mailadr2.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL (
  Should Contain  ${result.stdout}  DBL_SPAM (
  Should Contain  ${result.stdout}  example.com:email
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL_IMAGES (
  Should Not Contain  ${result.stdout}  DBL_PHISH (
  Should Not Contain  ${result.stdout}  URIBL_BLACK (

SURBL example.com not encoded url in subject
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/urlinsubject.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL (
  Should Contain  ${result.stdout}  DBL_SPAM (
  Should Not Contain  ${result.stdout}  DBL_PHISH (
  Should Not Contain  ${result.stdout}  URIBL_BLACK (

SURBL example.com encoded url in subject
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/urlinsubjectencoded.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL (
  Should Contain  ${result.stdout}  DBL_SPAM (
  Should Not Contain  ${result.stdout}  DBL_PHISH (
  Should Not Contain  ${result.stdout}  URIBL_BLACK (

WHITELIST
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/whitelist.eml
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL (
  Should Not Contain  ${result.stdout}  DBL_SPAM (
  Should Not Contain  ${result.stdout}  RSPAMD_URIBL_IMAGES (

EMAILBL full address & domain only
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/emailbltext.eml
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_FULL (
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_DOMAINONLY (

EMAILBL full subdomain address
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/emailbltext2.eml
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_FULL (

EMAILBL full subdomain address & domain only
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/emailbltext3.eml
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_DOMAINONLY (0.00)[baddomain.com:email]
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_FULL (0.00)[user.subdomain.baddomain.com:email]

EMAILBL REPLY TO full address
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/replyto.eml
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_FULL (
  Should Not Contain  ${result.stdout}  RSPAMD_EMAILBL_DOMAINONLY (

EMAILBL REPLY TO domain only
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/replyto2.eml
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_DOMAINONLY (
  Should Not Contain  ${result.stdout}  RSPAMD_EMAILBL_FULL (

EMAILBL REPLY TO full subdomain address
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/replytosubdomain.eml
  Should Contain  ${result.stdout}  RSPAMD_EMAILBL_FULL (
  Should Not Contain  ${result.stdout}  RSPAMD_EMAILBL_DOMAINONLY (

SURBL IDN domain
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url8.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL
  Should Contain  ${result.stdout}  DBL_SPAM
  Should Not Contain  ${result.stdout}  DBL_PHISH
  Should Not Contain  ${result.stdout}  URIBL_BLACK

SURBL IDN Punycode domain
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url9.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL
  Should Contain  ${result.stdout}  DBL_SPAM
  Should Not Contain  ${result.stdout}  DBL_PHISH
  Should Not Contain  ${result.stdout}  URIBL_BLACK

SURBL html entity&shy
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url10.eml
  Should Contain  ${result.stdout}  RSPAMD_URIBL

SURBL url compose map 1
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url11.eml
  Should Contain  ${result.stdout}  BAD_SUBDOMAIN (0.00)[clean.dirty.sanchez.com:url]

SURBL url compose map 2
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url12.eml
  Should Contain  ${result.stdout}  BAD_SUBDOMAIN (0.00)[4.very.dirty.sanchez.com:url]

SURBL url compose map 3
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/url13.eml
  Should Contain  ${result.stdout}  BAD_SUBDOMAIN (0.00)[41.black.sanchez.com:url]

*** Keywords ***
Surbl Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/surbl.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Surbl Teardown
  Normal Teardown
  Terminate All Processes    kill=True