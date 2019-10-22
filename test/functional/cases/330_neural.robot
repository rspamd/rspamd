*** Settings ***
Suite Setup      Neural Setup
Suite Teardown   Neural Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Train
  Sleep  2s  Wait for redis mess
  : FOR    ${INDEX}    IN RANGE    0    10
  \  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SPAM_SYMBOL"]}
  \  Check Rspamc  ${result}  SPAM_SYMBOL (1.00)
  \  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["HAM_SYMBOL"]}
  \  Check Rspamc  ${result}  HAM_SYMBOL (-1.00)

Check Neural HAM
  Sleep  2s  Wait for neural to be loaded
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Check Rspamc  ${result}  NEURAL_HAM_SHORT
  Check Rspamc  ${result}  NEURAL_SPAM_SHORT  inverse=1

Check Neural SPAM
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Check Rspamc  ${result}  NEURAL_SPAM_SHORT
  Check Rspamc  ${result}  NEURAL_HAM_SHORT  inverse=1


Train INVERSE
  : FOR    ${INDEX}    IN RANGE    0    10
  \  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SPAM_SYMBOL"]; SPAM_SYMBOL = -1}
  \  Check Rspamc  ${result}  SPAM_SYMBOL (-1.00)
  \  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["HAM_SYMBOL"]; HAM_SYMBOL = 1;}
  \  Check Rspamc  ${result}  HAM_SYMBOL (1.00)

Check Neural HAM INVERSE
  Sleep  2s  Wait for neural to be loaded
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"]}
  Check Rspamc  ${result}  NEURAL_SPAM_SHORT
  Check Rspamc  ${result}  NEURAL_HAM_SHORT  inverse=1

Check Neural SPAM INVERSE
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"]}
  Check Rspamc  ${result}  NEURAL_HAM_SHORT
  Check Rspamc  ${result}  NEURAL_SPAM_SHORT  inverse=1

*** Keywords ***
Neural Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/neural.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
  Run Redis

Neural Teardown
  Shutdown Process With Children  ${REDIS_PID}
  Normal Teardown
