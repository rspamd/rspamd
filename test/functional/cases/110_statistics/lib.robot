*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                 ${RSPAMD_TESTDIR}/configs/stats.conf
${MESSAGE_HAM}            ${RSPAMD_TESTDIR}/messages/ham.eml
${MESSAGE_SPAM}           ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}            Suite
${RSPAMD_REDIS_SERVER}    null
${RSPAMD_SCOPE}           Suite
${RSPAMD_STATS_BACKEND}   redis
${RSPAMD_STATS_HASH}      null
${RSPAMD_STATS_KEY}       null
${RSPAMD_STATS_PER_USER}  ${EMPTY}

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

Learn
  [Arguments]  ${user}  ${class}  ${message}
  IF  "${user}"
    ${result} =  Run Rspamc  -d  ${user}  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_${class}  ${message}
  ELSE
    ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_${class}  ${message}
  END
  Check Rspamc  ${result}

Learn Test
  [Arguments]  ${user}=${EMPTY}
  Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  0
  Set Test Variable  ${kwargs}  &{EMPTY}
  IF  "${user}"
    Set To Dictionary  ${kwargs}  Deliver-To=${user}
  END
  Learn  ${user}  spam  ${MESSAGE_SPAM}
  Learn  ${user}  ham  ${MESSAGE_HAM}
  Scan File  ${MESSAGE_SPAM}  &{kwargs}
  Expect Symbol  BAYES_SPAM
  Scan File  ${MESSAGE_HAM}  &{kwargs}
  Expect Symbol  BAYES_HAM
  Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  1

Relearn Test
  [Arguments]  ${user}=${EMPTY}
  IF  ${RSPAMD_STATS_LEARNTEST} == 0
    Fail  "Learn test was not run"
  END
  Learn  ${user}  ham  ${MESSAGE_SPAM}
  Set Test Variable  ${kwargs}  &{EMPTY}
  IF  "${user}"
    Set To Dictionary  ${kwargs}  Deliver-To=${user}
  END
  Scan File  ${MESSAGE_SPAM}  &{kwargs}
  ${pass} =  Run Keyword And Return Status  Expect Symbol  BAYES_HAM
  IF  ${pass}
    Pass Execution  What Me Worry
  END
  Do Not Expect Symbol  BAYES_SPAM
