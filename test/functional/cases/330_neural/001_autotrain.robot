*** Settings ***
Suite Setup      Neural Setup
Suite Teardown   Normal Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${RSPAMD_TESTDIR}/configs/neural.conf
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Train
  Sleep  2s  Wait for redis mess
  FOR    ${INDEX}    IN RANGE    0    10
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"]}
    Expect Symbol  SPAM_SYMBOL
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"]}
    Expect Symbol  HAM_SYMBOL
  END

Check Neural HAM
  Sleep  2s  Wait for neural to be loaded
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_SPAM_SHORT_PCA

Check Neural SPAM
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_HAM_SHORT_PCA


Train INVERSE
  FOR    ${INDEX}    IN RANGE    0    10
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"]; SPAM_SYMBOL = -5;}
    Expect Symbol  SPAM_SYMBOL
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"]; HAM_SYMBOL = 5;}
    Expect Symbol  HAM_SYMBOL
  END

Check Neural HAM INVERSE
  Sleep  2s  Wait for neural to be loaded
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT_PCA

Check Neural SPAM INVERSE
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"]}
  Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_SPAM_SHORT_PCA

*** Keywords ***
Neural Setup
  Run Redis
  New Setup
