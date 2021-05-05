*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                ${RSPAMD_TESTDIR}/configs/stats.conf
${MESSAGE_HAM}           ${RSPAMD_TESTDIR}/messages/ham.eml
${MESSAGE_SPAM}          ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}           Suite
${RSPAMD_REDIS_SERVER}   null
${RSPAMD_SCOPE}          Suite
${RSPAMD_STATS_BACKEND}  redis
${RSPAMD_STATS_HASH}     null
${RSPAMD_STATS_KEY}      null

*** Keywords ***
Broken Learn Test
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_spam  ${MESSAGE_SPAM}
  Check Rspamc  ${result}  Unknown statistics error

Empty Part Test
  Set Test Variable  ${MESSAGE}  ${RSPAMD_TESTDIR}/messages/empty_part.eml
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  Scan File  ${MESSAGE}
  Expect Symbol  BAYES_SPAM

Learn Test
  Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  0
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_spam  ${MESSAGE_SPAM}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_ham  ${MESSAGE_HAM}
  Check Rspamc  ${result}
  Scan File  ${MESSAGE_SPAM}
  Expect Symbol  BAYES_SPAM
  Scan File  ${MESSAGE_HAM}
  Expect Symbol  BAYES_HAM
  Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  1

Relearn Test
  Run Keyword If  ${RSPAMD_STATS_LEARNTEST} == 0  Fail  "Learn test was not run"
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_ham  ${MESSAGE_SPAM}
  Check Rspamc  ${result}
  Scan File  ${MESSAGE_SPAM}
  ${pass} =  Run Keyword And Return Status  Expect Symbol  BAYES_HAM
  Run Keyword If  ${pass}  Pass Execution  What Me Worry
  Do Not Expect Symbol  BAYES_SPAM
