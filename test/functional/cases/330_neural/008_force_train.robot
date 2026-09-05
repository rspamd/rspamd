*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         Collections
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_force_train.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Feed training vectors without auto-training
  # ANN-Train scans store vectors into the versioned Redis sets. max_trains is
  # 500, so 10 + 10 vectors are far below the auto-train threshold: the periodic
  # trainer must NOT train the model here.
  Sleep  2s  Wait for redis and initial check_anns
  FOR    ${INDEX}    IN RANGE    4    14
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3", "SPAM_SYMBOL${INDEX}"]}  ANN-Train=spam
    Expect Symbol  SPAM_SYMBOL${INDEX}
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3", "HAM_SYMBOL${INDEX}"]}  ANN-Train=ham
    Expect Symbol  HAM_SYMBOL${INDEX}
  END
  Sleep  1s  Let the async SADDs settle

  # Both training sets must be populated, and no ANN may be served yet.
  ${spam_set} =  Get Neural Train Set  spam
  Should Not Be Empty  ${spam_set}  msg=no spam training set was created by the feed
  ${n_spam} =  Redis SCARD  ${spam_set}
  Should Be True  ${n_spam} >= 10  msg=feed did not store enough spam vectors

  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT

Force train from stored vectors
  # The controller endpoint must train one model from the stored vectors and
  # report the trained metadata, even though the corpus is well below max_trains.
  ${result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/neural/train?rule=SHORT
  Should Be Equal As Integers  ${result}[0]  200
  ${reply} =  Evaluate  json.loads($result[1])  json
  Should Be True  ${reply}[trained]  msg=force-train did not train: ${result}[1]
  Should Be True  ${reply}[spam] >= 10
  Should Be True  ${reply}[ham] >= 10
  Should Be True  ${reply}[version] >= 1
  Should Be True  ${reply}[bytes] > 0

Trained model is served
  Sleep  2s  Wait for the scanner to reload the freshly trained ANN
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT

  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT
  Do Not Expect Symbol  NEURAL_SPAM_SHORT

Force train rejects an unknown rule
  ${result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/neural/train?rule=NOPE
  Should Be Equal As Integers  ${result}[0]  404

*** Keywords ***
Get Neural Train Set
  [Arguments]  ${class}
  # The training set keys use the rn_ prefix (ANN blobs/sets), distinct from the
  # rn3_ profile zset. Return the first rn_SHORT_*_<class>_set key.
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
