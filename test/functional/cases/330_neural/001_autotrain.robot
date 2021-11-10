*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural.conf
@{MESSAGES}         ${RSPAMD_TESTDIR}/messages/spam_message.eml    ${RSPAMD_TESTDIR}/messages/ham.eml    ${RSPAMD_TESTDIR}/messages/btc.eml    ${RSPAMD_TESTDIR}/messages/btc2.eml    ${RSPAMD_TESTDIR}/messages/btc3.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***

Train
  Sleep  2s  Wait for redis mess
  FOR    ${MESSAGE}    IN  @{MESSAGES}
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"]}
    Expect Symbol  SPAM_SYMBOL
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"]}
    Expect Symbol  HAM_SYMBOL
  END

Check Neural HAM
  Sleep  2s  Wait for neural to be loaded
  ${MESSAGE} =  Get From List  ${MESSAGES}  0
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_SPAM_SHORT_PCA

Check Neural SPAM
  ${MESSAGE} =  Get From List  ${MESSAGES}  0
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_HAM_SHORT_PCA


Train INVERSE
  FOR    ${MESSAGE}    IN  @{MESSAGES}
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"]; SPAM_SYMBOL = -5;}
    Expect Symbol  SPAM_SYMBOL
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"]; HAM_SYMBOL = 5;}
    Expect Symbol  HAM_SYMBOL
  END

Check Neural HAM INVERSE
  Sleep  2s  Wait for neural to be loaded
  ${MESSAGE} =  Get From List  ${MESSAGES}  0
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Do Not Expect Symbol  NEURAL_HAM_SHORT_PCA

Check Neural SPAM INVERSE
  ${MESSAGE} =  Get From List  ${MESSAGES}  0
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"]}
  Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT_PCA
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Do Not Expect Symbol  NEURAL_SPAM_SHORT_PCA
