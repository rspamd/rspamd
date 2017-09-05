*** Settings ***
Suite Setup     Whitelist Setup
Suite Teardown  Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${M_DMARC_OK}   ${TESTDIR}/messages/dmarc/pass_none.eml
${M_DMARC_BAD}  ${TESTDIR}/messages/dmarc/fail_none.eml
${UTF_MESSAGE}  ${TESTDIR}/messages/utf.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
WHITELISTS
  ${result} =  Scan Message With Rspamc  ${M_DMARC_OK}  -i  8.8.4.4  -F  foo@spf.cacophony.za.org
  Check Rspamc  ${result}  WHITELIST_DKIM (-1
  Should Contain  ${result.stdout}  STRICT_DMARC (-3
  Should Contain  ${result.stdout}  WHITELIST_DDS (-3
  Should Contain  ${result.stdout}  WHITELIST_DMARC (-2
  Should Contain  ${result.stdout}  WHITELIST_DMARC_DKIM (-2
  Should Contain  ${result.stdout}  WHITELIST_SPF (-1
  Should Not Contain  ${result.stdout}  BLACKLIST_SPF (
  Should Not Contain  ${result.stdout}  BLACKLIST_DKIM (
  Should Not Contain  ${result.stdout}  BLACKLIST_DMARC (

BLACKLIST SHOULD FIRE IF ANY CONSTRAINT FAILED
  ${result} =  Scan Message With Rspamc  ${M_DMARC_OK}  -i  9.8.4.4  -F  foo@spf.cacophony.za.org
  Check Rspamc  ${result}  BLACKLIST_DDS (3
  Should Not Contain  ${result.stdout}  WHITELIST_DDS (
  Should Not Contain  ${result.stdout}  WHITELIST_SPF (

BLACKLISTS
  ${result} =  Scan Message With Rspamc  ${M_DMARC_BAD}  -i  9.8.4.4  -F  foo@cacophony.za.org
  Check Rspamc  ${result}  BLACKLIST_SPF (3
  Should Contain  ${result.stdout}  BLACKLIST_SPF (3
  Should Contain  ${result.stdout}  STRICT_DMARC (3
  Should Contain  ${result.stdout}  BLACKLIST_DDS (3
  Should Contain  ${result.stdout}  BLACKLIST_DMARC (3
  Should Not Contain  ${result.stdout}  WHITELIST_DDS (
  Should Not Contain  ${result.stdout}  WHITELIST_SPF (
  Should Not Contain  ${result.stdout}  WHITEIST_DKIM (
  Should Not Contain  ${result.stdout}  WHITELIST_DMARC (
  Should Not Contain  ${result.stdout}  WHITELIST_DMARC_DKIM (

*** Keywords ***
Whitelist Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/whitelist.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
