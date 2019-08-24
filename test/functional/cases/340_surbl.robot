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

*** Keywords ***
Surbl Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/surbl.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Surbl Teardown
  Normal Teardown
  Terminate All Processes    kill=True