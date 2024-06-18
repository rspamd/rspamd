*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/replies.conf
${SETTINGS_REPLIES}    {symbols_enabled = [REPLIES_CHECK, REPLIES_SET, REPLY]}
${SYMBOL}              REPLY
${REDIS_SCOPE}         Suite
${RSPAMD_SCOPE}        Suite

*** Test Cases ***
Reply to 1 sender 1 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/set_replyto_1_1.eml
  ...  IP=8.8.8.8  User=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  IP=8.8.8.8  User=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  ${SYMBOL}

Reply to 1 sender 2 recipients first is set second is not
  Scan File  ${RSPAMD_TESTDIR}/messages/set_replyto_1_2_first.eml
  ...  IP=8.8.8.8  User=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_2.eml
  ...  IP=8.8.8.8  User=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  ${SYMBOL}

Reply to 1 sender 2 recipients 1 rcpt is same
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_2_s.eml
  ...  IP=8.8.8.8  User=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  ${SYMBOL}

Reply to another sender 2 recipients
  Scan File  ${RSPAMD_TESTDIR}/messages/set_replyto_2_2.eml
  ...  IP=8.8.8.8  User=another@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_2_2.eml
  ...  IP=8.8.8.8  User=another@emailbl.com
   ...  Settings=${SETTINGS_REPLIES}
  Expect Symbol  ${SYMBOL}
