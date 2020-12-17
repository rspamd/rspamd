*** Settings ***
Suite Setup      Neural Setup
Suite Teardown   Neural Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${TESTDIR}/configs/neural_noauto.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Collect training vectors & train manually
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL","SAVE_NN_ROW"]}
  Expect Symbol  SPAM_SYMBOL
  # Save neural inputs for later
  ${SPAM_ROW} =  Get File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
  Remove File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL","SAVE_NN_ROW"]}
  Expect Symbol  HAM_SYMBOL
  # Save neural inputs for later
  ${HAM_ROW} =  Get File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
  Remove File  ${SCAN_RESULT}[symbols][SAVE_NN_ROW][options][0]
  ${HAM_ROW} =  Run  ${RSPAMADM} lua -a ${HAM_ROW} ${TESTDIR}/util/nn_unpack.lua
  ${HAM_ROW} =  Evaluate  json.loads("${HAM_ROW}")
  ${SPAM_ROW} =  Run  ${RSPAMADM} lua -a ${SPAM_ROW} ${TESTDIR}/util/nn_unpack.lua
  ${SPAM_ROW} =  Evaluate  json.loads("${SPAM_ROW}")
  ${HAM_VEC} =  Evaluate  [${HAM_ROW}] * 10
  ${SPAM_VEC} =  Evaluate  [${SPAM_ROW}] * 10
  ${json1} =  Evaluate  json.dumps({"spam_vec": ${SPAM_VEC}, "ham_vec": ${HAM_VEC}, "rule": "SHORT"})
  # Save variables for use in inverse training
  Set Suite Variable  ${HAM_VEC}
  Set Suite Variable  ${SPAM_VEC}
  HTTP  POST  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /plugins/neural/learn  ${json1}
  Sleep  2s  Wait for neural to be loaded

Check Neural HAM
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT

Check Neural SPAM
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT

Train inverse
  ${json2} =  Evaluate  json.dumps({"spam_vec": ${HAM_VEC}, "ham_vec": ${SPAM_VEC}, "rule": "SHORT"})
  HTTP  POST  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /plugins/neural/learn  ${json2}
  Sleep  2s  Wait for neural to be loaded

Check Neural HAM - inverse
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_HAM_SHORT
  Expect Symbol  NEURAL_SPAM_SHORT

Check Neural SPAM - inverse
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Expect Symbol  NEURAL_HAM_SHORT

*** Keywords ***
Neural Setup
  ${TMPDIR} =    Make Temporary Directory
  Set Suite Variable        ${TMPDIR}
  Run Redis
  Generic Setup

Neural Teardown
  Shutdown Process With Children  ${REDIS_PID}
  Normal Teardown
