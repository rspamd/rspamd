*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         Collections
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_frozen.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Live traffic does not grow a frozen model's pools
  # Identical to 001_autotrain's training drive, but the rule is train.frozen=true.
  # Each scan reaches a spam/ham verdict that would normally auto-store a vector;
  # a frozen model must store NOTHING from live traffic, so no training-set key is
  # ever created.
  Sleep  2s  Wait for redis and initial check_anns
  FOR    ${INDEX}    IN RANGE    4    14
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3", "SPAM_SYMBOL${INDEX}"]}
    Expect Symbol  SPAM_SYMBOL${INDEX}
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3", "HAM_SYMBOL${INDEX}"]}
    Expect Symbol  HAM_SYMBOL${INDEX}
  END
  Sleep  2s  Give any (erroneous) auto-store a chance to land
  ${nkeys} =  Count Neural Train Set Keys
  Should Be Equal As Integers  ${nkeys}  0
  ...  msg=frozen model accrued live training vectors (pools must not grow)

Frozen model does not auto-train
  # With no stored vectors and a short-circuited auto-train trigger, inference
  # must stay dark — nothing has been trained from the live traffic above.
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT

ANN-Train trains a frozen model on demand
  # Freeze stops auto-learn, NOT operator-driven corpus retrains. Pushing a
  # balanced corpus with the ANN-Train header stores vectors, sets the retrain
  # marker and lets the controller train once. Inference must then fire.
  FOR    ${INDEX}    IN RANGE    4    14
    Scan File  ${MESSAGE}  ANN-Train=spam  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3", "SPAM_SYMBOL${INDEX}"]}
    Scan File  ${MESSAGE}  ANN-Train=ham   Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3", "HAM_SYMBOL${INDEX}"]}
  END
  ${nkeys} =  Count Neural Train Set Keys
  Should Be True  ${nkeys} >= 1  msg=ANN-Train did not store vectors on a frozen model
  Sleep  6s  Wait for training to complete and ANN to be reloaded
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT

Check Neural HAM after frozen ANN-Train
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT
  Do Not Expect Symbol  NEURAL_SPAM_SHORT

*** Keywords ***
Count Neural Train Set Keys
  # Number of rn_SHORT_*_set training keys (spam_set / ham_set). The rn3_ profile
  # zset is registered regardless; only training-set keys signal accrued vectors.
  ${res} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  KEYS  rn_SHORT_*_set
  ${count} =  Evaluate  len([k for k in $res.stdout.strip().split('\\n') if k])
  [Return]  ${count}
