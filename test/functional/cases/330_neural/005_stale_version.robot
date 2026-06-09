*** Settings ***
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library         Process
Library         Collections
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
  Sleep  2s  Wait for redis and initial check_anns
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["SPAM_SYMBOL1", "SPAM_SYMBOL2", "SPAM_SYMBOL3"]}
  Expect Symbol  SPAM_SYMBOL1
  Scan File  ${HAM_MSG}   Settings={symbols_enabled = ["HAM_SYMBOL1", "HAM_SYMBOL2", "HAM_SYMBOL3"]}
  Expect Symbol  HAM_SYMBOL1

Inference fires before the tombstone
  Sleep  5s  Wait for training to complete and ANN to be reloaded
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT

Inject a stale higher-version profile tombstone
  # Register a profile whose version exceeds every real one but whose redis_key
  # has no trained blob (an expired/never-written key).  process_existing_ann
  # selects the highest version, so pre-fix this entry would be picked and the
  # missing blob would silently leave inference dark.  The same providers_digest
  # keeps it "compatible", so only the missing-blob fallback can save it.
  ${zset} =  Get Neural Profile Zset
  Set Suite Variable  ${NEURAL_ZSET}  ${zset}
  ${member} =  Get Any Profile Member  ${zset}
  ${tomb} =  Make Stale Tombstone  ${member}
  ${r} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  ZADD  ${zset}  9999999999  ${tomb}
  Should Be Equal As Integers  ${r.rc}  0

Inference still fires despite the stale tombstone
  # Clear the loaded ANN so the next check_anns (watch_interval=0.5) re-runs
  # selection; the dead highest-version entry must be skipped for the live one.
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["FORCE_ROTATE_NEURAL"];symbols_disabled = ["NEURAL_LEARN","NEURAL_CHECK"]}
  Expect Symbol  FORCE_ROTATE_NEURAL
  Sleep  3s  Wait for check_anns to reselect past the tombstone
  Scan File  ${SPAM_MSG}  Settings={symbols_enabled = ["SPAM_SYMBOL1","SPAM_SYMBOL2","SPAM_SYMBOL3"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_SPAM_SHORT
  Scan File  ${HAM_MSG}   Settings={symbols_enabled = ["HAM_SYMBOL1","HAM_SYMBOL2","HAM_SYMBOL3"];groups_enabled=["neural"];symbols_disabled = ["NEURAL_LEARN"]}
  Expect Symbol  NEURAL_HAM_SHORT

*** Keywords ***
Get Neural Profile Zset
  # The profile registry zset is the only key matching the rn3_ prefix
  # (ANN blobs and training sets use the rn_ prefix).
  ${res} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  KEYS  rn3_*
  ${zset} =  Evaluate  $res.stdout.strip().split('\\n')[0]
  Should Not Be Empty  ${zset}  msg=no neural profile zset registered
  [Return]  ${zset}

Get Any Profile Member
  [Arguments]  ${zset}
  ${res} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  ZRANGE  ${zset}  0  0
  ${member} =  Evaluate  $res.stdout.strip()
  Should Not Be Empty  ${member}  msg=no profile member to clone
  [Return]  ${member}

Make Stale Tombstone
  [Arguments]  ${member}
  # Clone a real profile, point it at a non-existent key and bump its version
  # past everything else; keep digest/providers_digest so it stays compatible.
  ${obj} =  Evaluate  json.loads($member)  json
  ${origkey} =  Set Variable  ${obj}[redis_key]
  Set To Dictionary  ${obj}  redis_key=${origkey}_STALE_MISSING  version=${99999}
  ${tomb} =  Evaluate  json.dumps($obj)  json
  [Return]  ${tomb}
