*** Settings ***
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/stats.conf
${MESSAGE_SPAM}      ${TESTDIR}/messages/spam_message.eml
${MESSAGE_HAM}      ${TESTDIR}/messages/ham.eml
${REDIS_SCOPE}  Suite
${REDIS_SERVER}  null
${RSPAMD_SCOPE}  Suite
${STATS_BACKEND}  redis
${STATS_HASH}   null
${STATS_KEY}    null

*** Keywords ***
Broken Learn Test
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE_SPAM}
  Check Rspamc  ${result}  Unknown statistics error

Empty Part Test
  Set Test Variable  ${MESSAGE}  ${TESTDIR}/messages/empty_part.eml
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  Scan File  ${MESSAGE}
  Expect Symbol  BAYES_SPAM

Learn Test
  Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  0
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE_SPAM}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_ham  ${MESSAGE_HAM}
  Check Rspamc  ${result}
  Scan File  ${MESSAGE_SPAM}
  Expect Symbol  BAYES_SPAM
  Scan File  ${MESSAGE_HAM}
  Expect Symbol  BAYES_HAM
  Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  1

Relearn Test
  Run Keyword If  ${RSPAMD_STATS_LEARNTEST} == 0  Fail  "Learn test was not run"
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_ham  ${MESSAGE_SPAM}
  Check Rspamc  ${result}
  Scan File  ${MESSAGE_SPAM}
  ${pass} =  Run Keyword And Return Status  Expect Symbol  BAYES_HAM
  Run Keyword If  ${pass}  Pass Execution  What Me Worry
  Do Not Expect Symbol  BAYES_SPAM

Redis Statistics Setup
  Run Redis
  New Setup  STATS_BACKEND=${STATS_BACKEND}  STATS_HASH=${STATS_HASH}  STATS_KEY=${STATS_KEY}  REDIS_SERVER=${REDIS_SERVER}

Redis Statistics Teardown
  Normal Teardown
