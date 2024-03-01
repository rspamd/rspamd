*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/replies.conf
${REDIS_SCOPE}                    Suite
${RSPAMD_SCOPE}                   Suite

*** Test Cases ***
Reply to 1 sender 1 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings={symbols_enabled [REPLIES_CHECK]}
  Expect Symbol  REPLIES_CHECK
  
Reply to 1 sender another 2 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings={symbols_enabled [REPLIES_CHECK]}
  Expect Symbol  REPLIES_CHECK

Reply to 1 sender 2 recipients 1 rcpt is same
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings={symbols_enabled [REPLIES_CHECK]}
  Expect Symbol  REPLIES_CHECK

Reply to another sender 2 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_2_2.eml
   ...  Settings={symbols_enabled [REPLIES_CHECK]}
  Expect Symbol  REPLIES_CHECK
   


