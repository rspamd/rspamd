*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_llm.conf
${SPAM_MSG}        ${RSPAMD_TESTDIR}/messages/spam_message.eml
${HAM_MSG}         ${RSPAMD_TESTDIR}/messages/ham.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Train LLM-backed neural and verify
  Run Dummy Llm

  # Learn spam
  ${result} =  Run Rspamc  -P  secret  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  neural_learn:spam  ${SPAM_MSG}
  Check Rspamc  ${result}

  # Learn ham
  ${result} =  Run Rspamc  -P  secret  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  neural_learn:ham  ${HAM_MSG}
  Check Rspamc  ${result}

  Sleep  5s

  # Check spam inference (dummy_llm returns ones vector for "spam" content)
  Scan File  ${SPAM_MSG}  Settings={groups_enabled=["neural"]}
  Expect Symbol  NEURAL_SPAM

  # Check ham inference (zeros vector)
  Scan File  ${HAM_MSG}  Settings={groups_enabled=["neural"]}
  Expect Symbol  NEURAL_HAM

  Dummy Llm Teardown
