*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/neural_drift_pure.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Train pure-symbols ANN
  # Mirrors 001_autotrain's pure-symbols training: 10 spam + 10 ham scans
  # each producing a distinct vector (one extra SPAM_SYMBOL${INDEX} per
  # scan) so the ANN sees enough variance to converge.
  Sleep  2s  Wait for redis and initial check_anns
  FOR    ${INDEX}    IN RANGE    4    14
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3", "SPAM_SYMBOL${INDEX}"]}
    Expect Symbol  SPAM_SYMBOL${INDEX}
    Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3", "HAM_SYMBOL${INDEX}"]}
    Expect Symbol  HAM_SYMBOL${INDEX}
  END

Inference fires before drift
  Sleep  5s  Wait for training to complete and ANN to be reloaded
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT

40 percent drift keeps the prior profile compatible
  # FORCE_DRIFT_NEURAL_40 swaps ~20% of set.symbols for fresh ones, making
  # the symmetric difference against the trained profile ~40% of
  # |set.symbols|. is_profile_compatible's new 50% cap accepts it
  # (pre-fix: 30% cap would have rejected and inference would go dark).
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["FORCE_DRIFT_NEURAL_40"];symbols_disabled = ["NEURAL_LEARN","NEURAL_CHECK"]}
  Expect Symbol  FORCE_DRIFT_NEURAL_40
  Sleep  3s  Wait for check_anns periodic to reload after drift
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT

60 percent drift rejects the prior profile
  # FORCE_DRIFT_NEURAL_60 swaps ~30% of set.symbols for fresh ones,
  # taking symmetric difference to ~60% of |set.symbols|. Above the 50%
  # cap: is_profile_compatible rejects, set.ann stays unset, no NEURAL_*
  # symbols fire until a fresh ANN trains under the new digest.
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["FORCE_DRIFT_NEURAL_60"];symbols_disabled = ["NEURAL_LEARN","NEURAL_CHECK"]}
  Expect Symbol  FORCE_DRIFT_NEURAL_60
  Sleep  3s  Wait for check_anns periodic to reload after drift
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3","SPAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3","HAM_SYMBOL8"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Do Not Expect Symbol  NEURAL_HAM_SHORT
