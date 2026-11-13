*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/known_senders.conf
${SETTINGS_REPLIES}               {symbols_enabled = [REPLIES_CHECK, REPLIES_SET, REPLY]}
${SYMBOL_GLOBAL}                  INC_MAIL_KNOWN_GLOBALLY
${SYMBOL_LOCAL}                   INC_MAIL_KNOWN_LOCALLY
${REDIS_SCOPE}                    Suite
${SPAM_SENDER_KEY}                51656dfdd4e5febda570a45f839201b4
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

INCOMING MAIL SENDER IS UNKNOWN
  Scan File  ${RSPAMD_TESTDIR}/messages/inc_mail_unknown_sender.eml
  ...  Settings={symbols_enabled [${SYMBOL_GLOBAL}, ${SYMBOL_LOCAL}]}
  Do Not Expect Symbol  ${SYMBOL_GLOBAL}
  Do Not Expect Symbol  ${SYMBOL_LOCAL}

INCOMING MAIL SENDER IS KNOWN RECIPIENTS ARE UNKNOWN
  Scan File  ${RSPAMD_TESTDIR}/messages/set_replyto_1_1.eml
  ...  IP=8.8.8.8
  ...  User=xxx@abrakadabra.com
  ...  From=xxx@abrakadabra.com
  ...  Settings=${SETTINGS_REPLIES}
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  IP=8.8.8.8
  ...  Settings=${SETTINGS_REPLIES}
  ...  Rcpt=xxx@abrakadabra.com
  ...  Settings=${SETTINGS_REPLIES}
  ...  From=user@emailbl.com
  Scan File  ${RSPAMD_TESTDIR}/messages/inc_mail_known_sender.eml
  ...  IP=8.8.8.8
  ...  Settings={symbols_enabled [${SYMBOL_GLOBAL}, ${SYMBOL_LOCAL}]}
  Expect Symbol  ${SYMBOL_GLOBAL}
  Do Not Expect Symbol   ${SYMBOL_LOCAL}

INCOMING MAIL SENDER IS KNOWN RECIPIENTS ARE KNOWN
  Scan File  ${RSPAMD_TESTDIR}/messages/set_replyto_1_1.eml
  ...  IP=8.8.8.8  User=user@emailbl.com  From=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  IP=8.8.8.8  User=user@emailbl.com  Rcpt=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Scan File  ${RSPAMD_TESTDIR}/messages/inc_mail_known_sender.eml
  ...  IP=8.8.8.8  User=user@emailbl.com  Rcpt=user@emailbl.com
  ...  Settings=${SETTINGS_REPLIES}
  Scan File  ${RSPAMD_TESTDIR}/messages/inc_mail_known_sender.eml
  ...  IP=8.8.8.8  User=user@emailbl.com  Rcpt=user@emailbl.com
  ...  Settings={symbols_enabled [${SYMBOL_GLOBAL}, ${SYMBOL_LOCAL}]}
  Expect Symbol  ${SYMBOL_GLOBAL}
  Expect Symbol  ${SYMBOL_LOCAL}

STALE SENDER EXPIRES
  # The sender of spam_message.eml was last seen long ago
  Redis Command  ZADD  rs_known_senders  1  ${SPAM_SENDER_KEY}
  Redis Command  ZADD  rs_known_senders  1  stale_sender
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  Settings={symbols_enabled [KNOWN_SENDER]}
  Do Not Expect Symbol  KNOWN_SENDER
  Expect Symbol  UNKNOWN_SENDER
  ${score} =  Redis Command  ZSCORE  rs_known_senders  stale_sender
  Should Be Empty  ${score}
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  Settings={symbols_enabled [KNOWN_SENDER]}
  Expect Symbol  KNOWN_SENDER
  Do Not Expect Symbol  UNKNOWN_SENDER

RECENT SENDER IS REFRESHED
  ${now} =  Get Time  epoch
  ${seen} =  Evaluate  ${now} - 29 * 86400
  Redis Command  ZADD  rs_known_senders  ${seen}  ${SPAM_SENDER_KEY}
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  Settings={symbols_enabled [KNOWN_SENDER]}
  Expect Symbol  KNOWN_SENDER
  ${score} =  Redis Command  ZSCORE  rs_known_senders  ${SPAM_SENDER_KEY}
  Should Be True  ${score} >= ${now} - 5

*** Keywords ***
Redis Command
  [Arguments]  @{args}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}  @{args}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0
  RETURN  ${result.stdout}
