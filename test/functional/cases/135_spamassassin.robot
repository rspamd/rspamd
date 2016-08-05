*** Settings ***
Suite Setup     SpamAssassin Setup
Suite Teardown  Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Freemail Scan
  Set Suite Variable  ${FREEMAIL_RESULT}  ${EMPTY}
  ${FREEMAIL_RESULT} =  Scan Message With Rspamc  ${TESTDIR}/messages/freemail.eml
  ...  --from  faked.asdfjisiwosp372@outlook.com
  Check Rspamc  ${FREEMAIL_RESULT}  ${EMPTY}
  Set Suite Variable  ${FREEMAIL_RESULT}  ${FREEMAIL_RESULT.stdout}

Freemail From
  Should Contain  ${FREEMAIL_RESULT}  FREEMAIL_FROM

Freemail From Enddigit
  Should Contain  ${FREEMAIL_RESULT}  FREEMAIL_ENVFROM_END_DIGIT

Freemail Subject
  Should Contain  ${FREEMAIL_RESULT}  FREEMAIL_SUBJECT

Metas
  Should Contain  ${FREEMAIL_RESULT}  TEST_META3

*** Keywords ***
SpamAssassin Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/spamassassin.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
