*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_noauto.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Collect training vectors & train manually
  @{HAM_VEC}=    Create List
  @{SPAM_VEC}=    Create List

  FOR    ${INDEX}    IN RANGE    4    14
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3", "SPAM_SYMBOL${INDEX}", "SAVE_NN_ROW"]}
    Expect Symbol  SPAM_SYMBOL${INDEX}
    # Save neural inputs for later
    ${SPAM_ROW} =  Get File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
    Remove File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3", "HAM_SYMBOL${INDEX}", "SAVE_NN_ROW"]}
    Expect Symbol  HAM_SYMBOL${INDEX}
    # Save neural inputs for later
    ${HAM_ROW} =  Get File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
    Remove File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
    ${HAM_ROW} =  Run  ${RSPAMADM} lua -a ${HAM_ROW} ${RSPAMD_TESTDIR}/util/nn_unpack.lua
    ${HAM_ROW} =  Evaluate  json.loads("${HAM_ROW}")
    ${SPAM_ROW} =  Run  ${RSPAMADM} lua -a ${SPAM_ROW} ${RSPAMD_TESTDIR}/util/nn_unpack.lua
    ${SPAM_ROW} =  Evaluate  json.loads("${SPAM_ROW}")
    Append To List    ${HAM_VEC}    ${HAM_ROW}
    Append To List    ${SPAM_VEC}   ${SPAM_ROW}
  END

  ${json1} =  Evaluate  json.dumps({"spam_vec": ${SPAM_VEC}, "ham_vec": ${HAM_VEC}, "rule": "SHORT"})
  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/neural/learn  ${json1}

  # Save variables for use in inverse training
  Set Suite Variable  ${HAM_VEC}
  Set Suite Variable  ${SPAM_VEC}

  Sleep  5s  Wait for neural to be loaded

Check Neural HAM
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT

Check Neural SPAM
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT

Train inverse
  ${json2} =  Evaluate  json.dumps({"spam_vec": ${HAM_VEC}, "ham_vec": ${SPAM_VEC}, "rule": "SHORT"})
  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/neural/learn  ${json2}
  Sleep  5s  Wait for neural to be loaded

Check Neural HAM - inverse
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT

Check Neural SPAM - inverse
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT