*** Settings ***
Suite Setup     SpamAssassin Setup
Suite Teardown  Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Freemail Scan
  ${FREEMAIL_RESULT} =  Scan Message With Rspamc  ${TESTDIR}/messages/freemail.eml
  ...  --from  faked.asdfjisiwosp372@outlook.com
  Set Suite Variable  ${FREEMAIL_RESULT}  ${FREEMAIL_RESULT}
  Check Rspamc  ${FREEMAIL_RESULT}  ${EMPTY}

Freemail From
  Should Contain  ${FREEMAIL_RESULT.stdout}  FREEMAIL_FROM

Freemail From Enddigit
  Should Contain  ${FREEMAIL_RESULT.stdout}  FREEMAIL_ENVFROM_END_DIGIT

Freemail Subject
  Should Contain  ${FREEMAIL_RESULT.stdout}  FREEMAIL_SUBJECT

Metas
  Should Contain  ${FREEMAIL_RESULT.stdout}  TEST_META3

WLBL From Whitelist
  ${BAD_MESSAGE_RESULT} =  Scan Message With Rspamc  ${TESTDIR}/messages/bad_message.eml
  Set Suite Variable  ${BAD_MESSAGE_RESULT}  ${BAD_MESSAGE_RESULT}
  Check Rspamc  ${BAD_MESSAGE_RESULT}  USER_IN_WHITELIST (

WLBL To Whitelist
  Should Contain  ${BAD_MESSAGE_RESULT.stdout}  USER_IN_WHITELIST_TO

WLBL To Blacklist Miss
  Should Not Contain  ${BAD_MESSAGE_RESULT.stdout}  USER_IN_BLACKLIST_TO

WLBL From Blacklist Miss
  Should Not Contain  ${BAD_MESSAGE_RESULT.stdout}  USER_IN_BLACKLIST (

WLBL From Blacklist
  ${UTF_RESULT} =  Scan Message With Rspamc  ${TESTDIR}/messages/utf.eml
  Set Suite Variable  ${UTF_RESULT}  ${UTF_RESULT}
  Check Rspamc  ${UTF_RESULT}  USER_IN_BLACKLIST (

WLBL To Blacklist
  Should Contain  ${UTF_RESULT.stdout}  USER_IN_BLACKLIST_TO

WLBL To Whitelist Miss
  Should Not Contain  ${UTF_RESULT.stdout}  USER_IN_WHITELIST_TO

WLBL From Whitelist Miss
  Should Not Contain  ${UTF_RESULT.stdout}  USER_IN_WHITELIST (

*** Keywords ***
SpamAssassin Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/spamassassin.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
