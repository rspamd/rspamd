*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${REDIS_SCOPE}                    Suite
${RSPAMD_SCOPE}                   Suite
${SETTINGS_REPLIES}  {symbols_enabled = [REPLIES_CHECK, REPLIES_SET, REPLY]}

*** Test Cases ***
Reply to 1 sender 1 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  REPLIES_CHECKED
  
Reply to 1 sender another 2 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  REPLIES_CHECKED

Reply to 1 sender 2 recipients 1 rcpt is same
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  REPLIES_CHECKED

Reply to another sender 2 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_2_2.eml
   ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  REPLIES_CHECKED
   


