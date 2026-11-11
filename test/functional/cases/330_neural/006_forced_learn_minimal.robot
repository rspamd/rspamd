*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         Collections
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_forced_learn.conf
${SPAM_MSG}        ${RSPAMD_TESTDIR}/messages/spam.eml
${HAM_MSG}         ${RSPAMD_TESTDIR}/messages/ham.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Forced-learn minimal scan disables non-neural symbols
  # A disable_symbols_input rule with forced_learn_minimal_scan=true: an
  # ANN-Train scan must run the neural prefilter, which disables every non-neural
  # symbol. SPAM_SYMBOL1 is a plain always-firing filter symbol, so it must NOT
  # appear when ANN-Train is set, and MUST appear on a normal (full) scan.
  Sleep  2s  Wait for redis and initial check_anns
  Scan File  ${SPAM_MSG}  ANN-Train=spam
  Do Not Expect Symbol  SPAM_SYMBOL1
  Do Not Expect Symbol  SPAM_SYMBOL2
  Scan File  ${SPAM_MSG}
  Expect Symbol  SPAM_SYMBOL1

Minimal scan stores the vector under the providers-digest profile key
  # The forced-learn scan above must have stored a training vector under the
  # providers-digest key (rn_SHORT_default_<digest>_<ver>_spam_set), exactly the
  # key the live full-scan path uses (disable_symbols_input keys on
  # providers_digest, not on which symbols fired).
  ${spam_set} =  Get Neural Train Set  spam
  Should Not Be Empty  ${spam_set}  msg=no spam training set created by forced learn
  ${n} =  Redis SCARD  ${spam_set}
  Should Be True  ${n} >= 1  msg=forced-learn scan did not store a training vector

Minimal scan vector is byte-identical to the full-scan vector
  # Re-scan the SAME message through the full pipeline (NEURAL_FORCED_LEARN_CHECK
  # disabled at config-equivalent level is not needed: metatokens are
  # symbols-independent, so the full-scan auto-learn vector equals the minimal
  # one). Storing both into the same Redis SET must dedup to a single member —
  # the byte-for-byte equivalence the feature guarantees.
  ${spam_set} =  Get Neural Train Set  spam
  # ANN-Train scan again (minimal path) — identical vector, dedups
  Scan File  ${SPAM_MSG}  ANN-Train=spam
  # Full-pipeline auto-learn of the same message — identical metatokens vector
  Scan File  ${SPAM_MSG}
  Expect Symbol  SPAM_SYMBOL1
  Sleep  0.5s  Let the async SADDs settle
  ${n} =  Redis SCARD  ${spam_set}
  Should Be Equal As Integers  ${n}  1
  ...  msg=minimal-scan and full-scan vectors for the same message are not identical

Forced-learn corpus trains the model
  # Add one ham vector via a minimal ANN-Train scan: with max_trains=1 the
  # balanced trigger now fires (1 spam + 1 ham) and the model trains from the
  # symbols-independent corpus. Inference must then fire on both classes.
  Scan File  ${HAM_MSG}   ANN-Train=ham
  Do Not Expect Symbol  HAM_SYMBOL1
  Sleep  6s  Wait for training to complete and ANN to be reloaded
  Scan File  ${SPAM_MSG}  Settings={groups_enabled=["neural"];symbols_disabled=["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${HAM_MSG}   Settings={groups_enabled=["neural"];symbols_disabled=["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT

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
