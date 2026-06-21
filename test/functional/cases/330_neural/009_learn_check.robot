*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         Collections
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_learn_check.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Symbol-dependent rule trains via a learn-task check pass
  # A symbol-based rule's vector reads symbol scores, so /learnspam must run a
  # full check pass (NEURAL_LEARN_SHORT carries learn_needs_check). The learn
  # task then stores a training vector built from the scored symbols.
  Sleep  2s  Wait for redis and initial check_anns
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  ${spam_set} =  Get Neural Train Set  spam
  Should Not Be Empty  ${spam_set}  msg=/learnspam did not create a neural training set
  ${n} =  Redis SCARD  ${spam_set}
  Should Be True  ${n} >= 1  msg=/learnspam did not store a symbol-derived vector

Check-pass vector is byte-identical to the full-scan vector
  # The same message stored via the full-scan path (/checkv2 + ANN-Train) must
  # dedup into the SAME key. If the learn task had NOT run the check pass, the
  # symbols would not have fired and the stored vector would differ (SCARD 2):
  # SCARD == 1 proves the check pass ran and scored the symbols identically.
  ${spam_set} =  Get Neural Train Set  spam
  Scan File  ${MESSAGE}  ANN-Train=spam
  Expect Symbol  SPAM_SYMBOL1
  Sleep  0.5s  Let the async SADD settle
  ${n} =  Redis SCARD  ${spam_set}
  Should Be Equal As Integers  ${n}  1
  ...  msg=learn-task check-pass vector differs from the full-scan vector

*** Keywords ***
Get Neural Train Set
  [Arguments]  ${class}
  ${res} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  KEYS  rn_SHORT_*_${class}_set
  ${key} =  Evaluate  $res.stdout.strip().split('\\n')[0]
  [Return]  ${key}

Redis SCARD
  [Arguments]  ${key}
  ${res} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  SCARD  ${key}
  ${n} =  Convert To Integer  ${res.stdout.strip()}
  [Return]  ${n}
