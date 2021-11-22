*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Train
  Sleep  2s  Wait for redis mess
  FOR    ${INDEX}    IN RANGE    4    14
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3", "SPAM_SYMBOL${INDEX}"]}
    Expect Symbol  SPAM_SYMBOL${INDEX}
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3", "HAM_SYMBOL${INDEX}"]}
    Expect Symbol  HAM_SYMBOL${INDEX}
  END

Check Neural HAM
  Sleep  5s  Wait for neural to be loaded
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  #Expect Symbol  NEURAL_HAM_SHORT_PCA
  #Do Not Expect Symbol  NEURAL_SPAM_SHORT_PCA

Check Neural SPAM
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  #Expect Symbol  NEURAL_SPAM_SHORT_PCA
  #Do Not Expect Symbol  NEURAL_HAM_SHORT_PCA


Train INVERSE
  FOR    ${INDEX}    IN RANGE    4    14
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3","SPAM_SYMBOL${INDEX}"]; SPAM_SYMBOL1 = -5; SPAM_SYMBOL2 = -5; SPAM_SYMBOL3 = -5; SPAM_SYMBOL${INDEX} = -5;}
    Expect Symbol  SPAM_SYMBOL${INDEX}
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3","HAM_SYMBOL${INDEX}"]; HAM_SYMBOL1 = 5; HAM_SYMBOL2 = 5; HAM_SYMBOL3 = 5; HAM_SYMBOL${INDEX} = 5;}
    Expect Symbol  HAM_SYMBOL${INDEX}
  END

Check Neural HAM INVERSE
  Sleep  5s  Wait for neural to be loaded
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL5",];groups_enabled=["neural"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  #Expect Symbol  NEURAL_SPAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  #Do Not Expect Symbol  NEURAL_HAM_SHORT_PCA

Check Neural SPAM INVERSE
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL5"];groups_enabled=["neural"]}
  Expect Symbol  NEURAL_HAM_SHORT
  #Expect Symbol  NEURAL_HAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  #Do Not Expect Symbol  NEURAL_SPAM_SHORT_PCA