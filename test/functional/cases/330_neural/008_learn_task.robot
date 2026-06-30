*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         Collections
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_learn_task.conf
${SPAM_MSG}        ${RSPAMD_TESTDIR}/messages/spam.eml
${HAM_MSG}         ${RSPAMD_TESTDIR}/messages/ham.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Learn task trains a symbols-independent neural rule
  # /learnspam runs a learn task (no scan symbols, no idempotent emitters). The
  # neural learn symbol must still store a training vector for the
  # disable_symbols_input rule under its providers-digest profile key.
  Sleep  2s  Wait for redis and initial check_anns
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_spam  ${SPAM_MSG}
  Check Rspamc  ${result}
  ${spam_set} =  Get Neural Train Set  spam
  Should Not Be Empty  ${spam_set}  msg=/learnspam did not create a neural training set
  ${n} =  Redis SCARD  ${spam_set}
  Should Be True  ${n} >= 1  msg=/learnspam did not store a neural training vector

Learn-task vector is byte-identical to the full-scan vector
  # The same message stored via the full-scan path (/checkv2 + ANN-Train) must
  # land in the SAME providers-digest key and dedup to a single member: the
  # learn-task vector and the scan-path vector are identical.
  ${spam_set} =  Get Neural Train Set  spam
  Scan File  ${SPAM_MSG}  ANN-Train=spam
  Sleep  0.5s  Let the async SADD settle
  ${n} =  Redis SCARD  ${spam_set}
  Should Be Equal As Integers  ${n}  1
  ...  msg=learn-task and full-scan vectors for the same message are not identical

Learn-task corpus trains the model end to end
  # Add a ham sample via /learnham; with max_trains=1 the balanced trigger fires
  # and the model trains purely from the learn-task corpus. Inference must then
  # fire on both classes.
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_ham  ${HAM_MSG}
  Check Rspamc  ${result}
  Sleep  6s  Wait for training to complete and ANN to be reloaded
  Scan File  ${SPAM_MSG}  Settings={groups_enabled=["neural"];symbols_disabled=["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${HAM_MSG}   Settings={groups_enabled=["neural"];symbols_disabled=["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT

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
