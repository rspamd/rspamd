*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_rotation.conf
${SPAM_MSG}        ${RSPAMD_TESTDIR}/messages/spam.eml
${HAM_MSG}         ${RSPAMD_TESTDIR}/messages/ham.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Train providers-driven ANN
  # max_trains=1 means a single spam + single ham scan triggers training.
  # Metatokens-only vector + disable_symbols_input=true makes the input
  # vector independent of which symbols fire — providers_digest is the
  # only schema fingerprint.
  Sleep  2s  Wait for redis and initial check_anns
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3"]}
  Expect Symbol  SPAM_SYMBOL1
  Scan File  ${HAM_MSG}   Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3"]}
  Expect Symbol  HAM_SYMBOL1

Inference fires before rotation
  Sleep  5s  Wait for training to complete and ANN to be reloaded
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${HAM_MSG}   Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT

Force symcache-style rotation
  # Mutate set.symbols/set.digest in the scanner worker so the next
  # check_anns poll re-runs profile selection.  With the fix, the
  # providers_digest-based match preserves the trained ANN; pre-fix
  # the symbol-digest shift would orphan it.
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["FORCE_ROTATE_NEURAL"];symbols_disabled = ["NEURAL_LEARN","NEURAL_CHECK"]}
  Expect Symbol  FORCE_ROTATE_NEURAL
  Sleep  3s  Wait for check_anns periodic to reload after rotation

Inference still fires after rotation
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${HAM_MSG}   Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT
