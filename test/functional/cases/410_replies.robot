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
REPLY 1 to 1
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto_1_1.eml
  ...  Settings={symbols_enabled [REPLY]}
  Expect Symbol  REPLY

