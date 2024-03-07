*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/known_senders.conf
${REDIS_SCOPE}                    Suite
${RSPAMD_SCOPE}                   Suite

*** Test Cases ***
UNKNOWN SENDER
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  Settings={symbols_enabled [KNOWN_SENDER]}
  Do Not Expect Symbol  KNOWN_SENDER
  Expect Symbol  UNKNOWN_SENDER

UNKNOWN SENDER BECOMES KNOWN
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  Settings={symbols_enabled [KNOWN_SENDER]}
  Expect Symbol  KNOWN_SENDER
  Do Not Expect Symbol  UNKNOWN_SENDER

UNKNOWN SENDER WRONG DOMAIN
  Scan File  ${RSPAMD_TESTDIR}/messages/empty_part.eml
  ...  Settings={symbols_enabled [KNOWN_SENDER]}
  Do Not Expect Symbol  KNOWN_SENDER
  Do Not Expect Symbol  UNKNOWN_SENDER

UNKNOWN SENDER WRONG DOMAIN RESCAN
  Scan File  ${RSPAMD_TESTDIR}/messages/empty_part.eml
  ...  Settings={symbols_enabled [KNOWN_SENDER]}
  Do Not Expect Symbol  KNOWN_SENDER
  Do Not Expect Symbol  UNKNOWN_SENDER
  
CHECK INCOMING EMAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings={symbols_enabled [CHECK_INC_MAIL]}
  Expect Symbol  CHECK_INC_MAIL
